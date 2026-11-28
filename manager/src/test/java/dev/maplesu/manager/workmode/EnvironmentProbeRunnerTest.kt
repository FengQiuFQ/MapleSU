package dev.maplesu.manager.workmode

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import dev.maplesu.manager.runtime.PageReadDeadline
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test

class EnvironmentProbeRunnerTest {
    @Test fun expiredBudgetDoesNotStartAnotherWorker() = runBlocking {
        var starts = 0
        val runner = EnvironmentProbeRunner(startWorker = { starts++; it.start() })
        assertEquals(EnvironmentProbeResult.TimedOut, runner.run(0) { error("expired probe ran") })
        assertEquals(0, starts)
    }

    @Test fun nativeWorkerInheritsTheOriginalPageDeadline() = runBlocking {
        withContext(PageReadDeadline.context(1_000)) {
            val deadline = requireNotNull(PageReadDeadline.currentNanos())
            val result = EnvironmentProbeRunner().run(5_000) { PageReadDeadline.currentNanos() }
            assertEquals(EnvironmentProbeResult.Completed(deadline), result)
        }
    }

    @Test fun workerStartupConsumesTheSameBudgetBeforeSdkSubmission() = runBlocking {
        var calls = 0
        val runner = EnvironmentProbeRunner(startWorker = { thread ->
            CountDownLatch(1).await(80, TimeUnit.MILLISECONDS)
            thread.start()
        })
        assertEquals(EnvironmentProbeResult.TimedOut, runner.run(30) { ++calls })
        assertEquals(0, calls)
    }

    @Test fun completedProbeReturnsItsValue() = runBlocking {
        assertEquals(EnvironmentProbeResult.Completed(42), EnvironmentProbeRunner().run(1_000) { 42 })
    }

    @Test fun failedProbeKeepsTheCause() = runBlocking {
        val error = IllegalStateException("probe failed")
        val result = EnvironmentProbeRunner().run(1_000) { throw error }
        assertSame(error, (result as EnvironmentProbeResult.Failed).cause)
    }

    @Test fun workerStartFailureKeepsTheCauseAndAllowsRetry() = runBlocking {
        val error = OutOfMemoryError("pthread_create failed")
        var launches = 0
        var calls = 0
        val runner = EnvironmentProbeRunner(startWorker = { thread ->
            if (launches++ == 0) throw error
            thread.start()
        })
        val result = runner.run(1_000) { ++calls }
        assertSame(error, (result as EnvironmentProbeResult.Failed).cause)
        assertEquals(0, calls)
        assertEquals(EnvironmentProbeResult.Completed(1), runner.run(1_000) { ++calls })
    }

    @Test fun cancelledWorkerStartPropagatesAndAllowsRetry() = runBlocking {
        var launches = 0
        val runner = EnvironmentProbeRunner(startWorker = { thread ->
            if (launches++ == 0) throw CancellationException("start cancelled")
            thread.start()
        })
        try {
            runner.run(1_000) { 1 }
            fail("Worker start cancellation must propagate")
        } catch (_: CancellationException) { }
        assertEquals(EnvironmentProbeResult.Completed(2), runner.run(1_000) { 2 })
    }

    @Test fun timeoutReturnsWhileUninterruptibleWorkerRemainsSingleFlight() = runBlocking {
        val runner = EnvironmentProbeRunner()
        val release = CountDownLatch(1)
        val exited = CountDownLatch(1)
        val calls = AtomicInteger()
        try {
            val result = withTimeout(1_000) {
                runner.run(50) {
                    calls.incrementAndGet()
                    try { awaitIgnoringInterrupts(release) } finally { exited.countDown() }
                    7
                }
            }
            assertEquals(EnvironmentProbeResult.TimedOut, result)
            repeat(4) {
                assertEquals(EnvironmentProbeResult.Busy, runner.run(50) { calls.incrementAndGet() })
            }
            assertEquals(1, calls.get())
        } finally { release.countDown() }
        assertTrue(exited.await(1, TimeUnit.SECONDS))
        var retry: EnvironmentProbeResult<Int> = EnvironmentProbeResult.Busy
        withTimeout(1_000) {
            while (retry == EnvironmentProbeResult.Busy) {
                retry = runner.run(1_000) { 9 }
                if (retry == EnvironmentProbeResult.Busy) kotlinx.coroutines.yield()
            }
        }
        assertEquals(EnvironmentProbeResult.Completed(9), retry)
    }

    @Test fun cancellationReleasesCallerAndDiscardsLateResult() = runBlocking {
        val runner = EnvironmentProbeRunner()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var published = false
        val job = async(Dispatchers.Default) {
            runner.run(10_000) { entered.countDown(); awaitIgnoringInterrupts(release); 42 }
            published = true
        }
        try {
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            withTimeout(1_000) { job.cancelAndJoin() }
            assertTrue(job.isCancelled)
            assertFalse(published)
            assertEquals(EnvironmentProbeResult.Busy, runner.run(50) { 7 })
        } finally { release.countDown() }
    }

    @Test fun probeCancellationIsPropagated() = runBlocking {
        try {
            EnvironmentProbeRunner().run(1_000) { throw CancellationException("cancelled") }
            fail("Probe cancellation must propagate")
        } catch (_: CancellationException) { }
    }

    private fun awaitIgnoringInterrupts(latch: CountDownLatch) {
        while (true) {
            try { latch.await(); return } catch (_: InterruptedException) { }
        }
    }
}
