package dev.maplesu.manager.runtime.ultra

import java.io.File
import java.net.URLDecoder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

/** Production SDK admission with fixture JNI/shell boundaries; no Android device access. */
class UltraPolicyToolsAdmissionTest {
    private fun client(current: () -> Boolean = { true }, runner: RootScriptRunner? = null): UltraRuntimeClient {
        val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null) as sun.misc.Unsafe
        return (unsafe.allocateInstance(UltraRuntimeClient::class.java) as UltraRuntimeClient).also { c ->
            for ((name, value) in mapOf("rootCommands" to runner, "lock" to Any(), "identityCurrent" to current))
                UltraRuntimeClient::class.java.getDeclaredField(name).apply { isAccessible = true }.set(c, value)
        }
    }
    private fun decode(value: String?) = value?.let { URLDecoder.decode(it, "UTF-8") }
    private val reports = """
        printf 'MAPLESU_TOOL_HOST:updated hash\n'
        printf 'MAPLESU_TOOL_POLICY:updated hash\n'
        printf 'MAPLESU_TOOL_BUSYBOX:updated hash\n'
        printf 'MAPLESU_TOOL_SEPOLICY:updated hash\n'
        printf 'MAPLESU_TOOL_KSUD:updated hash\n'
        printf 'MAPLESU_TOOL_LINK:resetprop resetprop 1.0\n'
    """.trimIndent()

    @Test fun blockedReadDoesNotDelayRepairAndPublishesExactlyOnce() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val writes = AtomicInteger()
        val admissions = AtomicInteger()
        val commands = mutableSetOf<String>()
        val holder = client({ entered.countDown(); check(release.await(10, TimeUnit.SECONDS)); false })
        val writer = client(runner = RootScriptRunner { script ->
            writes.incrementAndGet()
            val shell = listOf("/bin/sh", "C:/Program Files/Git/bin/bash.exe").first { File(it).canExecute() }
            val process = ProcessBuilder(shell, "-c", script).start()
            check(process.waitFor(5, TimeUnit.SECONDS))
            SuExecResult(process.exitValue(), process.inputStream.bufferedReader().use { it.readText() })
        })
        val worker = Executors.newSingleThreadExecutor()
        try {
            val pending = worker.submit<NativeReceipt> { holder.suAuthList() }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            val failure = UltraPolicyBackendDeployment.prepareTools(reports, { script ->
                admissions.incrementAndGet()
                commands += script
                writer.runRootCommand(script)
            }, ::decode)
            release.countDown()
            assertEquals("SDK_IDENTITY_SCOPE_CHANGED", pending.get(2, TimeUnit.SECONDS).sdkError)
            assertNull("A blocked unrelated read aborted an explicit environment repair", failure)
            assertEquals("The publication script must execute exactly once", 1, writes.get())
            assertEquals("An unrelated read must not create a global admission conflict", 1, admissions.get())
            assertEquals("Admission must retain the same command receipt", 1, commands.size)
        } finally {
            release.countDown(); worker.shutdownNow(); worker.awaitTermination(3, TimeUnit.SECONDS)
        }
    }

    @Test fun missingCompletionIsNeverReplayed() {
        var calls=0
        val failure=UltraPolicyBackendDeployment.prepareTools("write-once", {
            calls++; NativeReceipt.rootCommand(SuExecResult(0,"partial result"))
        }, ::decode)
        assertEquals("MODULE_TOOLS_RESULT_UNCONFIRMED",failure)
        assertEquals(1,calls)
    }

    @Test fun submittedFailureIsNeverReplayed() {
        var calls=0
        val failure=UltraPolicyBackendDeployment.prepareTools("write-once", {
            calls++; NativeReceipt.rootCommand(SuExecResult(-1,"timeout",timedOut=true))
        }, ::decode)
        assertNotNull(failure)
        assertEquals(1,calls)
    }

    @Test fun busyWaitIsBoundedAndNeverExecutesAScript() {
        var calls=0
        val failure=UltraPolicyBackendDeployment.prepareTools("write-once", {
            calls++; NativeReceipt.bridgeFailure("run_root_cmd","MAPLESU_SDK_BUSY","SDK admission timed out; this request was not submitted.")
        }, ::decode)
        assertEquals("MODULE_TOOLS_TRANSPORT:MAPLESU_SDK_BUSY",failure)
        assertEquals(3,calls)
    }

    @Test fun deadlineIsReturnedOnceWithTheOriginalReceipt() {
        val receipt = NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"run_root_cmd","ok":false,"sdkError":"MAPLESU_SDK_DEADLINE_EXCEEDED","sdkErrorCode":-1007,"reason":"Current request expired before submission."}""")!!
        var calls = 0
        var observed: NativeReceipt? = null
        val failure = UltraPolicyBackendDeployment.prepareTools("write-once", {
            calls++; receipt
        }, ::decode, { observed = it })
        assertEquals("MODULE_TOOLS_TRANSPORT:MAPLESU_SDK_DEADLINE_EXCEEDED", failure)
        assertEquals(1, calls)
        assertSame(receipt, observed)
        assertEquals(-1007, observed!!.sdkErrorCode)
    }

    @Test fun cancellationBeforeRetryIsRespected() {
        var calls=0
        try {
            val failure=UltraPolicyBackendDeployment.prepareTools("write-once", {
                calls++; Thread.currentThread().interrupt()
                NativeReceipt.bridgeFailure("run_root_cmd","MAPLESU_SDK_BUSY","Not submitted")
            }, ::decode)
            assertEquals("MODULE_TOOLS_TRANSPORT:MAPLESU_SDK_BUSY",failure)
            assertEquals(1,calls)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}


