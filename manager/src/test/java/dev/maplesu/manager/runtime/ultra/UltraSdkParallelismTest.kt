package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.PageReadDeadline
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Actual Kotlin submission boundary; native resource-conflict tests own transaction ordering. */
class UltraSdkParallelismTest {
    private fun client(current: () -> Boolean = { true }): UltraRuntimeClient {
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply {
            isAccessible = true
        }.get(null) as sun.misc.Unsafe
        return (unsafe.allocateInstance(UltraRuntimeClient::class.java) as UltraRuntimeClient).also {
            fun field(name: String, value: Any?) = UltraRuntimeClient::class.java.getDeclaredField(name).apply {
                isAccessible = true
            }.set(it, value)
            field("identityCurrent", current)
            field("lock", Any())
        }
    }

    private fun raw(operation: String, error: String = "OK", code: Int = 0) =
        """{"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,"operation":"$operation","ok":${error == "OK"},"sdkError":"$error","sdkErrorCode":$code,"data":{}}"""

    private fun submit(client: UltraRuntimeClient, operation: String, body: () -> String?): NativeReceipt =
        UltraRuntimeClient::class.java.getDeclaredMethod("call", String::class.java,
            kotlin.jvm.functions.Function0::class.java).apply { isAccessible = true }
            .invoke(client, operation, body) as NativeReceipt

    @Test fun aStalledRootCommandDoesNotBlockIndependentSubmissionsAcrossClients() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(7)
        val operations = listOf("get_maplesu_environment_state", "get_module_policy_settings",
            "get_su_auth_list", "get_all_modules_list", "run_root_cmd", "get_root_status_report")
        val submissions = AtomicInteger()
        try {
            val slow = workers.submit<NativeReceipt> {
                submit(client(), "run_root_cmd") {
                    entered.countDown(); check(release.await(10, TimeUnit.SECONDS)); raw("run_root_cmd")
                }
            }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val replies = operations.map { operation -> workers.submit<NativeReceipt> {
                submit(client(), operation) { submissions.incrementAndGet(); raw(operation) }
            } }.map { it.get(3, TimeUnit.SECONDS) }
            assertEquals(operations, replies.map { it.operation })
            assertTrue(replies.all { it.succeeded })
            assertEquals(operations.size, submissions.get())
            assertFalse(slow.isDone)
            release.countDown()
            assertTrue(slow.get(2, TimeUnit.SECONDS).succeeded)
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }

    @Test fun aThirdIndependentSnapshotIsDelegatedToNativeInsteadOfAJavaSlotLimit() {
        val entered = CountDownLatch(3)
        val release = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(3)
        try {
            val replies = listOf("get_su_auth_list", "get_all_modules_list", "get_maplesu_environment_state").map { operation ->
                workers.submit<NativeReceipt> { submit(client(), operation) {
                    entered.countDown(); check(release.await(10, TimeUnit.SECONDS)); raw(operation)
                } }
            }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertTrue(replies.none { it.isDone })
            release.countDown()
            replies.forEach { assertTrue(it.get(2, TimeUnit.SECONDS).succeeded) }
        } finally { release.countDown(); workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS) }
    }

    @Test fun realNativeConflictErrorsKeepTheirCodeAndAreNeverReplayed() {
        val submissions = AtomicInteger()
        val reply = submit(client(), "set_module_policy_settings") {
            submissions.incrementAndGet(); raw("set_module_policy_settings", "MAPLESU_SDK_BUSY", -1005)
        }
        assertEquals("MAPLESU_SDK_BUSY", reply.sdkError)
        assertEquals(-1005, reply.sdkErrorCode)
        assertEquals(1, submissions.get())
    }

    @Test fun interruptedAndExpiredCallsDoNotSubmit() {
        val submissions = AtomicInteger()
        val result = AtomicReference<Pair<NativeReceipt, Boolean>>()
        val thread = Thread {
            Thread.currentThread().interrupt()
            val receipt = submit(client(), "get_all_modules_list") {
                submissions.incrementAndGet(); raw("get_all_modules_list")
            }
            result.set(receipt to Thread.currentThread().isInterrupted)
        }
        thread.start(); thread.join(2_000)
        assertFalse(thread.isAlive)
        assertEquals("MAPLESU_SDK_INTERRUPTED", result.get().first.sdkError)
        assertTrue(result.get().second)
        @Suppress("UNCHECKED_CAST")
        val deadline = PageReadDeadline::class.java.getDeclaredField("deadline").apply {
            isAccessible = true
        }.get(null) as ThreadLocal<Long?>
        deadline.set(System.nanoTime() - 1)
        try {
            val expired = submit(client(), "get_su_auth_list") {
                submissions.incrementAndGet(); raw("get_su_auth_list")
            }
            assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", expired.sdkError)
            assertEquals(-1007, expired.sdkErrorCode)
            val raw = org.json.JSONObject(expired.raw)
            assertEquals(expired.sdkError, raw.getString("sdkError"))
            assertEquals(expired.sdkErrorCode, raw.getInt("sdkErrorCode"))
            assertEquals(0, submissions.get())
        } finally { deadline.remove() }
    }

    @Test fun aBodyFailureDoesNotPreventTheNextIndependentSubmission() {
        val submissions = AtomicInteger()
        val failed = submit(client(), "get_su_auth_list") {
            submissions.incrementAndGet(); error("controlled JNI body failure")
        }
        assertEquals("MAPLESU_BRIDGE_EXCEPTION", failed.sdkError)
        val next = submit(client(), "get_all_modules_list") {
            submissions.incrementAndGet(); raw("get_all_modules_list")
        }
        assertTrue(next.succeeded)
        assertEquals(2, submissions.get())
    }

    @Test fun changedCallerIdentityIsRejectedBeforeSubmission() {
        val submissions = AtomicInteger()
        val result = UltraRuntimeClient::class.java.getDeclaredMethod("callWithIdentity", String::class.java,
            kotlin.jvm.functions.Function0::class.java).apply { isAccessible = true }
            .invoke(client { false }, "get_module_policy_settings", { ->
                submissions.incrementAndGet(); raw("get_module_policy_settings")
            }) as NativeReceipt
        assertEquals("SDK_IDENTITY_SCOPE_CHANGED", result.sdkError)
        assertEquals(0, submissions.get())
    }
}
