package dev.maplesu.manager.litehidden

import dev.maplesu.manager.recovery.RecoveryCommandResult
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class RootFileHiddenStateTest {
    @After fun clearInterrupt() { Thread.interrupted() }

    @Test fun admissionBusyBeforeWriteIsRetriedUntilTheWriteIsSubmitted() {
        val responses = ArrayDeque(listOf(
            RecoveryCommandResult(-1, "ULTRA_ROOT_FAILED:MAPLESU_SDK_BUSY"),
            RecoveryCommandResult(0, "LITE_OK\n"),
        ))
        val commands = mutableListOf<String>()
        val state = RootFileHiddenState(HiddenRootRunner { commands += it; responses.removeFirst() }, pause = {})
        assertTrue("a request rejected before submission must not abort activation", state.write(true))
        assertEquals(List(2) { LiteHiddenPaths.stateScript(write = true, value = "1") }, commands)
    }

    @Test fun admissionBusyAfterSuccessfulWriteDoesNotTurnTheReadbackIntoFailure() {
        val responses = ArrayDeque(listOf(
            RecoveryCommandResult(0, "LITE_OK\n"),
            RecoveryCommandResult(-1, "ROOT_EXECUTION_BUSY"),
            RecoveryCommandResult(-1, "ULTRA_ROOT_FAILED:MAPLESU_SDK_BUSY"),
            RecoveryCommandResult(0, "1\n"),
        ))
        val commands = mutableListOf<String>()
        val state = RootFileHiddenState(HiddenRootRunner { commands += it; responses.removeFirst() }, pause = {})
        assertTrue(state.write(true))
        assertEquals("the committed ON state must survive transient read admission failures", true, state.read())
        assertEquals(1, commands.count { it == LiteHiddenPaths.stateScript(write = true, value = "1") })
        assertEquals(3, commands.count { it == LiteHiddenPaths.stateReadScript() })
    }

    @Test fun shellFailureAndLostWriteReceiptAreNotReplayed() {
        for (result in listOf(
            RecoveryCommandResult(1, "LITE_OK\n"),
            RecoveryCommandResult(1, "ROOT_EXECUTION_BUSY"),
            RecoveryCommandResult(-1, "ULTRA_ROOT_COMMAND_RESULT_UNCONFIRMED"),
            RecoveryCommandResult(-1, "ULTRA_ROOT_EXCEPTION"),
            RecoveryCommandResult(124, ""),
            RecoveryCommandResult(0, "truncated"),
        )) {
            var calls = 0
            val state = RootFileHiddenState(HiddenRootRunner { calls++; result })
            assertFalse(state.write(true))
            assertEquals(1, calls)
        }
    }

    @Test fun shellReadFailureDoesNotTurnIntoOffOrRetry() {
        var calls = 0
        val state = RootFileHiddenState(HiddenRootRunner { calls++; RecoveryCommandResult(1, "0\n") })
        assertNull(state.read())
        assertEquals(1, calls)
    }

    @Test fun persistentAdmissionBusyHasABoundedFailureForReadsAndWrites() {
        for (write in listOf(true, false)) {
            var calls = 0
            val pauses = mutableListOf<Long>()
            val state = RootFileHiddenState(
                HiddenRootRunner { calls++; RecoveryCommandResult(-1, "ROOT_EXECUTION_BUSY") },
                pause = { pauses += it },
            )
            if (write) assertFalse(state.write(true)) else assertNull(state.read())
            assertEquals(4, calls)
            assertEquals(listOf(150L, 300L, 450L), pauses)
        }
    }

    @Test fun expiredAdmissionNeverReplaysAReadOrWrite() {
        for (write in listOf(true, false)) {
            var calls = 0
            val state = RootFileHiddenState(
                HiddenRootRunner { calls++; RecoveryCommandResult(-1007, "ULTRA_ROOT_FAILED:MAPLESU_SDK_DEADLINE_EXCEEDED") },
                pause = { fail("An expired request must not back off or replay") },
            )
            if (write) assertFalse(state.write(true)) else assertNull(state.read())
            assertEquals(1, calls)
        }
    }

    @Test fun cancellationDuringBackoffDoesNotSubmitAnotherWrite() {
        var calls = 0
        val state = RootFileHiddenState(
            HiddenRootRunner { calls++; RecoveryCommandResult(-1, "ROOT_EXECUTION_BUSY") },
            pause = { throw InterruptedException() },
        )
        assertFalse(state.write(true))
        assertEquals(1, calls)
        assertTrue(Thread.currentThread().isInterrupted)
    }
}
