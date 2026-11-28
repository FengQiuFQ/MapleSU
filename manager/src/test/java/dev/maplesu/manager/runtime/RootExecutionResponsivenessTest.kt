package dev.maplesu.manager.runtime

import dev.maplesu.manager.workmode.WorkMode
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class RootExecutionResponsivenessTest {
    @Test fun officialServiceLaunchSharesItsBudgetAndPreservesAShorterCallerDeadline() {
        var remaining = Long.MAX_VALUE
        val root = object : RootExecutor {
            override val backend = RootBackend.ULTRA_ENV
            override fun available() = true
            override fun run(script: String): RootExecResult {
                remaining = TimeUnit.NANOSECONDS.toMillis(checkNotNull(PageReadDeadline.currentNanos()) - System.nanoTime())
                return RootExecResult(backend, 0, script)
            }
        }
        RootExec.installForTest(RootExecutionRouter(root, modeProvider = { WorkMode.LITE }))
        try {
            assertTrue(RootExec.executeServiceLaunch(null, "launch").ok)
            assertTrue("Service deadline was not installed: $remaining", remaining in 1..5_000)
            runBlocking(PageReadDeadline.context(500)) {
                assertTrue(RootExec.executeServiceLaunch(null, "launch").ok)
                assertTrue("Caller deadline was extended: $remaining", remaining in 1..500)
            }
        } finally { RootExec.resetForTest() }
    }

    @Test fun aServiceDeadlineWaitsForTheExistingRequestWithoutReplayingEitherCommand() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val root = object : RootExecutor {
            override val backend = RootBackend.ULTRA_ENV
            override fun available() = true
            override fun run(script: String): RootExecResult {
                calls.incrementAndGet()
                if (script == "existing") {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                return RootExecResult(backend, 0, script)
            }
        }
        val router = RootExecutionRouter(root, modeProvider = { WorkMode.LITE })
        val workers = Executors.newFixedThreadPool(2)
        try {
            val first = workers.submit<RootExecResult> { router.execute("existing") }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val second = workers.submit<RootExecResult> {
                runBlocking(PageReadDeadline.context(4_000)) { router.execute("launch") }
            }
            // The actual cold-start overlap exceeded the old 1.5-second lock wait.
            Thread.sleep(1_800)
            release.countDown()
            assertTrue(first.get(1, TimeUnit.SECONDS).ok)
            val result = second.get(2, TimeUnit.SECONDS)
            assertTrue(result.detail, result.ok)
            assertEquals("launch", result.output)
            assertEquals(2, calls.get())
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }

    @Test fun aShortInheritedDeadlineDoesNotAcquireANewFullLockBudget() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val root = object : RootExecutor {
            override val backend = RootBackend.ULTRA_ENV
            override fun available() = true
            override fun run(script: String): RootExecResult {
                calls.incrementAndGet(); entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                return RootExecResult(backend, 0, script)
            }
        }
        val router = RootExecutionRouter(root, modeProvider = { WorkMode.LITE })
        val worker = Executors.newSingleThreadExecutor()
        try {
            worker.submit<RootExecResult> { router.execute("existing") }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val at = System.nanoTime()
            val result = runBlocking(PageReadDeadline.context(100)) { router.execute("expired") }
            val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - at)
            assertEquals("ROOT_EXECUTION_DEADLINE_EXCEEDED", result.detail)
            assertEquals(-1007, result.code)
            assertTrue("Inherited deadline overrun: ${elapsed}ms", elapsed < 750)
            assertEquals(1, calls.get())
        } finally { release.countDown(); worker.shutdownNow(); worker.awaitTermination(3, TimeUnit.SECONDS) }
    }

    @Test fun longScriptDoesNotKeepAnotherRootRequestWaitingIndefinitely() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val root = object : RootExecutor {
            override val backend = RootBackend.ULTRA_ENV
            override fun available() = true
            override fun run(script: String): RootExecResult {
                calls.incrementAndGet(); entered.countDown()
                check(release.await(10, TimeUnit.SECONDS))
                return RootExecResult(backend, 0, "done")
            }
        }
        val router = RootExecutionRouter(root, modeProvider = { WorkMode.LITE })
        val workers = Executors.newFixedThreadPool(2)
        try {
            val first = workers.submit<RootExecResult> { router.execute("long-script") }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val second = workers.submit<RootExecResult> { router.execute("id -u") }.get(3, TimeUnit.SECONDS)
            assertFalse(second.ok)
            assertEquals("ROOT_EXECUTION_BUSY", second.detail)
            assertEquals(1, calls.get())
            assertFalse(first.isDone)
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }
}
