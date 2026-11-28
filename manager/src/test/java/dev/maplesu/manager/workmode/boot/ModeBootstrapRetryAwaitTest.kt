package dev.maplesu.manager.workmode.boot

import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.workmode.ActivationSource
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.DetectionRequest
import dev.maplesu.manager.workmode.detect.DetectionResult
import dev.maplesu.manager.workmode.detect.ModeDetector
import dev.maplesu.manager.workmode.detect.ModeState
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.*
import org.junit.Test

class ModeBootstrapRetryAwaitTest {
    private fun field(name: String) = ModeBootstrap::class.java.getDeclaredField(name).apply { isAccessible = true }

    @Test fun productionStartupDoesNotScheduleABlindSecondAttemptAfterFailure() {
        val retry = field("secondPhaseRetry").get(null) as ModeBootstrapRetryState
        try {
            val requested = retry.requestRetry()
            assertEquals(1, retry.tryStart())
            assertNull(retry.finish(resolved = false))
            assertTrue(requested.completion.isCompleted)
            assertNull(retry.pendingCompletion())
        } finally { retry.finish(resolved = true) }
    }

    @Test fun productionPreparationAndDetectorShareOneSessionDeadline() = runBlocking {
        val manager = field("managerProcess")
        val coordinator = field("coordinator")
        val context = field("startupContext")
        val retry = field("secondPhaseRetry").get(null) as ModeBootstrapRetryState
        val wasManager = manager.getBoolean(null)
        val wasCoordinator = coordinator.get(null)
        val wasContext = context.get(null)
        val deadlines = java.util.Collections.synchronizedList(mutableListOf<Long?>())
        val runtime = object : ModeRuntimePort {
            override fun recordDetection(result: DetectionResult) {}
            override fun completeBootstrap(result: DetectionResult) {}
            override fun activate(mode: WorkMode, bootId: String, source: ActivationSource) = false
        }
        ModeRuntime.resetForTest()
        try {
            manager.setBoolean(null, true)
            context.set(null, null)
            coordinator.set(null, ModeBootstrapCoordinator({ ModeBootstrapPipeline(object : ModeDetector {
                override suspend fun detect(request: DetectionRequest): DetectionResult {
                    deadlines += PageReadDeadline.currentNanos()
                    return TestFixtures.detection(ModeState.INDETERMINATE)
                }
            }, runtime) }))
            @Suppress("UNCHECKED_CAST")
            (field("firstPhaseComplete").get(null) as CompletableDeferred<Unit>).complete(Unit)
            val completion = retry.requestRetry().completion
            val beforeDetection: () -> Unit = { deadlines += PageReadDeadline.currentNanos(); Unit }
            ModeBootstrap::class.java.getDeclaredMethod("executePhaseTwo", kotlin.jvm.functions.Function0::class.java)
                .apply { isAccessible = true }.invoke(ModeBootstrap, beforeDetection)
            withTimeoutOrNull(2_000) { completion.await() }
            assertTrue("The bounded startup session must release its own completion", completion.isCompleted)
            assertEquals(2, deadlines.size)
            assertNotNull("The preparation worker must inherit the session deadline", deadlines[0])
            assertTrue("The detector must not extend the preparation session deadline", deadlines[1]!! <= deadlines[0]!!)
        } finally {
            retry.finish(resolved = true)
            manager.setBoolean(null, wasManager)
            coordinator.set(null, wasCoordinator)
            context.set(null, wasContext)
            ModeRuntime.resetForTest()
        }
    }

    @Test fun aRealRetryBypassesTheQueuedFallbackAndMergesOneInflightRequest() = runBlocking {
        val started = field("started").get(null) as AtomicBoolean
        val scheduled = field("secondPhaseScheduled").get(null) as AtomicBoolean
        val manager = field("managerProcess")
        val coordinator = field("coordinator")
        val context = field("startupContext")
        val retry = field("secondPhaseRetry").get(null) as ModeBootstrapRetryState
        val wasStarted = started.get()
        val wasScheduled = scheduled.get()
        val wasManager = manager.getBoolean(null)
        val wasCoordinator = coordinator.get(null)
        val wasContext = context.get(null)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val runtime = object : ModeRuntimePort {
            override fun recordDetection(result: DetectionResult) {}
            override fun completeBootstrap(result: DetectionResult) {}
            override fun activate(mode: WorkMode, bootId: String, source: ActivationSource) = false
        }
        ModeRuntime.resetForTest()
        try {
            started.set(true)
            scheduled.set(false)
            manager.setBoolean(null, true)
            context.set(null, null)
            coordinator.set(null, ModeBootstrapCoordinator({ ModeBootstrapPipeline(object : ModeDetector {
                override suspend fun detect(request: DetectionRequest): DetectionResult {
                    if (calls.incrementAndGet() == 1) {
                        entered.countDown()
                        check(release.await(2, TimeUnit.SECONDS)) { "TEST_RETRY_RELEASE_TIMEOUT" }
                    }
                    return TestFixtures.detection(ModeState.INDETERMINATE)
                }
            }, runtime) }))
            @Suppress("UNCHECKED_CAST")
            (field("firstPhaseComplete").get(null) as CompletableDeferred<Unit>).complete(Unit)
            var fallback: Runnable? = null
            ModeBootstrap.schedulePhaseTwo(2_500) { task, _ -> fallback = task; true }
            val requested = requireNotNull(ModeBootstrap.retryEnvironmentDetection())
            assertTrue("A real retry must start while the old fallback is still queued", entered.await(1, TimeUnit.SECONDS))
            assertSame(requested, ModeBootstrap.retryEnvironmentDetection())
            requireNotNull(fallback).run()
            assertEquals("The old timer must not run beside the current request", 1, calls.get())
            release.countDown()
            assertEquals(true, withTimeoutOrNull(2_000) { requested.await(); true })
            assertEquals("The actual inflight request must run exactly one successor", 2, calls.get())
            requireNotNull(fallback).run()
            assertEquals("A late timer must not reopen the completed request's budget", 2, calls.get())
        } finally {
            release.countDown()
            retry.finish(resolved = true)
            started.set(wasStarted)
            scheduled.set(wasScheduled)
            manager.setBoolean(null, wasManager)
            coordinator.set(null, wasCoordinator)
            context.set(null, wasContext)
            ModeRuntime.resetForTest()
        }
    }

    @Test fun aManualRetryWaitsForItsQueuedAttemptInsteadOfTheLastCompletedRound() = runBlocking {
        val started = field("started").get(null) as AtomicBoolean
        val scheduled = field("secondPhaseScheduled").get(null) as AtomicBoolean
        val manager = field("managerProcess")
        val retry = field("secondPhaseRetry").get(null) as ModeBootstrapRetryState
        val wasStarted = started.get()
        val wasScheduled = scheduled.get()
        val wasManager = manager.getBoolean(null)
        ModeRuntime.resetForTest()
        try {
            started.set(true)
            manager.setBoolean(null, true)
            // Hold the existing timer so the request is definitely queued, not executing.
            scheduled.set(true)
            ModeRuntime.finishDetection()
            val requested: Any? = ModeBootstrap.retryEnvironmentDetection()
            val waiting = async(start = CoroutineStart.UNDISPATCHED) {
                if (requested is Deferred<*>) requested.await()
                else ModeRuntime.awaitDetectionSettled(500)
                true
            }
            assertFalse("manual retry reused the preceding round's completed signal", waiting.isCompleted)
            assertNull(ModeRuntime.active)
            assertNotNull(retry.tryStart())
            ModeRuntime.beginDetection()
            ModeRuntime.finishDetection()
            retry.finish(resolved = false)
            assertTrue((requested as Deferred<*>).isCompleted)
            assertNotNull(withTimeoutOrNull(50) { waiting.await() })
        } finally {
            retry.finish(resolved = true)
            started.set(wasStarted)
            scheduled.set(wasScheduled)
            manager.setBoolean(null, wasManager)
            ModeRuntime.resetForTest()
        }
    }

    @Test fun aRejectedScheduleFinishesItsOwnRequestWithAnExplicitFailure() {
        val started = field("started").get(null) as AtomicBoolean
        val scheduled = field("secondPhaseScheduled").get(null) as AtomicBoolean
        val manager = field("managerProcess")
        val retry = field("secondPhaseRetry").get(null) as ModeBootstrapRetryState
        val wasStarted = started.get()
        val wasScheduled = scheduled.get()
        val wasManager = manager.getBoolean(null)
        ModeRuntime.resetForTest()
        try {
            started.set(true)
            manager.setBoolean(null, true)
            scheduled.set(true)
            val completion = ModeBootstrap.retryEnvironmentDetection()!!
            assertFalse(completion.isCompleted)
            scheduled.set(false)
            var posts = 0
            ModeBootstrap.schedulePhaseTwo(0) { _, _ -> posts++; false }
            assertEquals(1, posts)
            assertFalse(scheduled.get())
            assertTrue(completion.isCompleted)
            assertTrue(ModeRuntime.detectionComplete)
            assertEquals("MODE_PHASE_TWO_SCHEDULE_FAILED", ModeRuntime.detectionFailure)
            assertNull(ModeRuntime.active)
        } finally {
            retry.finish(resolved = true)
            started.set(wasStarted)
            scheduled.set(wasScheduled)
            manager.setBoolean(null, wasManager)
            ModeRuntime.resetForTest()
        }
    }

    @Test fun startupAndAuxiliaryProcessesDoNotQueueManualDetection() {
        val started = field("started").get(null) as AtomicBoolean
        val manager = field("managerProcess")
        val wasStarted = started.get()
        val wasManager = manager.getBoolean(null)
        try {
            started.set(false)
            manager.setBoolean(null, true)
            assertNull(ModeBootstrap.retryEnvironmentDetection())
            started.set(true)
            manager.setBoolean(null, false)
            assertNull(ModeBootstrap.retryEnvironmentDetection())
        } finally {
            started.set(wasStarted)
            manager.setBoolean(null, wasManager)
        }
    }
}
