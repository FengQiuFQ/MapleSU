package dev.maplesu.manager.runtime

import dev.maplesu.manager.workmode.WorkMode
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class RootExecutionHookConcurrencyTest {
    @Test fun moduleAndPolicyReadsDoNotWaitForALongHookCommand() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val hook = object : RootExecutor {
            override val backend = RootBackend.HOOK
            override fun available() = true
            override fun run(script: String): RootExecResult {
                calls.incrementAndGet()
                if (script == "install") {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                return RootExecResult(backend, 0, script)
            }
        }
        val router = RootExecutionRouter(null, modeProvider = { WorkMode.LITE }, hook = hook)
        val workers = Executors.newFixedThreadPool(3)
        try {
            val installing = workers.submit<RootExecResult> { router.execute("install") }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val inventory = workers.submit<RootExecResult> {
                runBlocking(PageReadDeadline.context(500)) { router.execute("module-inventory") }
            }
            val policy = workers.submit<RootExecResult> { router.executeHook("policy-config") }
            assertEquals("module-inventory", inventory.get(1, TimeUnit.SECONDS).output)
            val result = policy.get(1, TimeUnit.SECONDS)
            assertTrue(result.detail, result.ok)
            assertEquals("policy-config", result.output)
            assertFalse("Read must complete before the long command", installing.isDone)
            assertEquals(3, calls.get())
            release.countDown()
            assertTrue(installing.get(1, TimeUnit.SECONDS).ok)
        } finally {
            release.countDown()
            workers.shutdownNow()
            workers.awaitTermination(3, TimeUnit.SECONDS)
        }
    }

    @Test fun anExplicitHookReadDoesNotWaitForTheSdkQueue() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val ultra = object : RootExecutor {
            override val backend = RootBackend.ULTRA_ENV
            override fun available() = true
            override fun run(script: String): RootExecResult {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                return RootExecResult(backend, 0, script)
            }
        }
        val hook = object : RootExecutor {
            override val backend = RootBackend.HOOK
            override fun available() = true
            override fun run(script: String) = RootExecResult(backend, 0, script)
        }
        val router = RootExecutionRouter(ultra, modeProvider = { WorkMode.LITE },
            ultraIdentity = { true }, hook = hook)
        val worker = Executors.newSingleThreadExecutor()
        try {
            val sdk = worker.submit<RootExecResult> { router.execute("sdk-install") }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val result = runBlocking(PageReadDeadline.context(100)) { router.executeHook("policy-config") }
            assertTrue(result.detail, result.ok)
            assertEquals(RootBackend.HOOK, result.backend)
            assertFalse(sdk.isDone)
        } finally {
            release.countDown()
            worker.shutdownNow()
            worker.awaitTermination(3, TimeUnit.SECONDS)
        }
    }

    @Test fun queuedCommandsSelectTheModeThatIsActiveAfterAdmission() {
        val mode = AtomicReference(WorkMode.KSU)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val selected = CountDownLatch(1)
        val ksu = object : RootExecutor {
            override val backend = RootBackend.KSU
            override fun available() = true
            override fun run(script: String): RootExecResult {
                if (script == "existing") {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                return RootExecResult(backend, 0, script)
            }
        }
        val hook = object : RootExecutor {
            override val backend = RootBackend.HOOK
            override fun available() = true
            override fun run(script: String) = RootExecResult(backend, 0, script)
        }
        val router = RootExecutionRouter(null, modeProvider = {
            mode.get().also { if (Thread.currentThread().name == "queued-root") selected.countDown() }
        }, ksuProvider = { ksu }, hook = hook)
        val first = Executors.newSingleThreadExecutor()
        val queued = Executors.newSingleThreadExecutor { Thread(it, "queued-root") }
        try {
            first.submit<RootExecResult> { router.execute("existing") }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            val request = queued.submit<RootExecResult> { router.execute("inventory") }
            assertTrue(selected.await(1, TimeUnit.SECONDS))
            mode.set(WorkMode.LITE)
            release.countDown()
            assertEquals(RootBackend.HOOK, request.get(2, TimeUnit.SECONDS).backend)
        } finally {
            release.countDown()
            first.shutdownNow()
            queued.shutdownNow()
            first.awaitTermination(3, TimeUnit.SECONDS)
            queued.awaitTermination(3, TimeUnit.SECONDS)
        }
    }

    @Test fun anExpiredHookReadDoesNotSubmitACommand() {
        val calls = AtomicInteger()
        val hook = object : RootExecutor {
            override val backend = RootBackend.HOOK
            override fun available() = true
            override fun run(script: String): RootExecResult {
                calls.incrementAndGet()
                return RootExecResult(backend, 0, script)
            }
        }
        val router = RootExecutionRouter(null, modeProvider = { WorkMode.LITE }, hook = hook)
        val result = runBlocking(PageReadDeadline.context(0)) { router.executeHook("expired") }
        assertFalse(result.ok)
        assertEquals("ROOT_EXECUTION_DEADLINE_EXCEEDED", result.detail)
        assertEquals(-1007, result.code)
        assertEquals(0, calls.get())
    }
}
