package dev.maplesu.manager.runtime.ultra

import java.net.URLDecoder
import org.junit.Assert.*
import org.junit.Test

class UltraMaintenanceRootReceiptTest {
    @Test fun deviceProbeUsesTheKeylessConstructor() {
        assertNotNull(UltraRuntimeClient::class.java.getConstructor())
    }

    @Test fun successfulScriptPreservesTheCommandReceiptEncoding() {
        val output = "环境 ready + %\n"
        val receipt = NativeReceipt.rootCommand(SuExecResult(0, output))
        assertTrue(receipt.succeeded)
        assertEquals("run_root_cmd", receipt.operation)
        assertEquals("url", receipt.string("encoding"))
        assertEquals(output, URLDecoder.decode(receipt.string("result"), "UTF-8"))
        assertEquals(output.toByteArray(Charsets.UTF_8).size, receipt.int("resultBytes"))
    }

    @Test fun shellFailureIsNotAnSdkSuccess() {
        val receipt = NativeReceipt.rootCommand(SuExecResult(77, "OK is ordinary output"))
        assertFalse(receipt.succeeded)
        assertEquals("MAPLESU_ROOT_COMMAND_EXIT", receipt.sdkError)
        assertEquals(77, receipt.int("exitCode"))
    }

    @Test fun missingTimeoutAndIncompleteIoRemainDistinctFailures() {
        val failures = listOf(
            null to "MAPLESU_ROOT_CHANNEL_UNAVAILABLE",
            SuExecResult(0, "ready", timedOut = true) to "MAPLESU_ROOT_COMMAND_TIMEOUT",
            SuExecResult(0, "ready", failure = "PROCESS_IO_INCOMPLETE") to "MAPLESU_ROOT_COMMAND_IO_FAILURE",
        )
        for ((result, error) in failures) {
            val receipt = NativeReceipt.rootCommand(result)
            assertFalse(receipt.succeeded)
            assertEquals(error, receipt.sdkError)
            assertEquals(receipt.succeeded, NativeReceipt.parse(receipt.raw)?.succeeded)
        }
    }

    @Test fun cleanupPendingAndCleanupFailureNeverBecomeSuccessfulReceipts() {
        val output = "original output\n"
        for (result in listOf(SuExecResult(0, output, cleanupPending = true),
            SuExecResult(0, output, cleanupFailure = "CLOSE_FAILED:IOException"))) {
            val receipt = NativeReceipt.rootCommand(result)
            assertFalse(receipt.succeeded)
            assertEquals("MAPLESU_ROOT_COMMAND_IO_FAILURE", receipt.sdkError)
            assertEquals(0, receipt.int("exitCode"))
            assertEquals(output, URLDecoder.decode(receipt.string("result"), "UTF-8"))
            assertEquals(result.cleanupPending, receipt.bool("cleanupPending"))
            assertEquals(result.cleanupFailure, receipt.string("cleanupFailure"))
        }
    }

    @Test fun cleanupFactsDoNotReplaceThePrimaryTimeoutOrExposePrivateFailureText() {
        val receipt = NativeReceipt.rootCommand(SuExecResult(71, "partial", timedOut = true,
            failure = "EXEC_INTERRUPTED", cleanupPending = true, cleanupFailure = "private-helper command"))
        assertFalse(receipt.succeeded)
        assertEquals("MAPLESU_ROOT_COMMAND_TIMEOUT", receipt.sdkError)
        assertEquals(71, receipt.int("exitCode"))
        assertTrue(receipt.bool("cleanupPending") == true)
        assertEquals("PROCESS_CLEANUP_FAILED", receipt.string("cleanupFailure"))
        assertFalse(receipt.raw.contains("private-helper"))
        assertFalse(receipt.raw.contains("command"))
    }
}
