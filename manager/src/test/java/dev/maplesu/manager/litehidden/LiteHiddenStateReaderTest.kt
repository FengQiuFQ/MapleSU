package dev.maplesu.manager.litehidden

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.recovery.RecoveryCommandResult
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class LiteHiddenStateReaderTest {
    @After fun clearInterrupt() { Thread.interrupted() }

    @Test fun admissionContentionRetriesTheSameReadAndUsesItsRealResult() {
        val replies = ArrayDeque(listOf(
            RootExecResult(RootBackend.NONE, -1, "", "ROOT_EXECUTION_BUSY"),
            RootExecResult(RootBackend.ULTRA_ENV, -1001, "", "ULTRA_ROOT_FAILED:MAPLESU_SDK_BUSY"),
            RootExecResult(RootBackend.ULTRA_ENV, 0, "0\n"),
        ))
        val commands = mutableListOf<String>()
        val pauses = mutableListOf<Long>()
        val read = LiteHiddenStateReader.read(
            execute = { commands += it; replies.removeFirst() },
            pause = { pauses += it },
        )
        assertEquals(LiteHiddenState.OFF, read.state)
        assertNull(read.failure)
        assertEquals(listOf(150L, 300L), pauses)
        assertEquals(List(3) { LiteHiddenPaths.stateReadScript() }, commands)
    }

    @Test fun busyStaysUnknownWhenTheBoundIsExhausted() {
        var calls = 0
        val pauses = mutableListOf<Long>()
        val read = LiteHiddenStateReader.read(
            execute = { calls++; RootExecResult(RootBackend.NONE, -1, "", "ROOT_EXECUTION_BUSY") },
            pause = { pauses += it },
        )
        assertEquals(4, calls)
        assertEquals(3, pauses.size)
        assertEquals(LiteHiddenState.UNKNOWN, read.state)
        assertEquals("ROOT_EXECUTION_BUSY", read.failure)
    }

    @Test fun shellFailureAndMalformedOutputAreNeverRetriedOrTurnedOff() {
        listOf(
            RootExecResult(RootBackend.ULTRA_ENV, 1, "0", "ULTRA_ROOT_COMMAND_EXIT:1"),
            RootExecResult(RootBackend.ULTRA_ENV, -1, "0", "ULTRA_ROOT_COMMAND_RESULT_UNCONFIRMED"),
            RootExecResult(RootBackend.ULTRA_ENV, 0, "garbage"),
            RootExecResult(RootBackend.NONE, 0, "LITE_MISSING", "ROOT_BACKEND_UNAVAILABLE"),
        ).forEach { response ->
            var calls = 0
            val read = LiteHiddenStateReader.read(
                execute = { calls++; response },
                pause = { fail("Only admission failures may retry") },
            )
            assertEquals(1, calls)
            assertEquals(LiteHiddenState.UNKNOWN, read.state)
            assertNotNull(read.failure)
        }
    }

    @Test fun successfulReadsKeepAllThreeStatesDistinct() {
        mapOf("1\n" to LiteHiddenState.ON, "0\n" to LiteHiddenState.OFF,
            "LITE_MISSING\n" to LiteHiddenState.OFF, "" to LiteHiddenState.UNKNOWN,
            "10\n" to LiteHiddenState.UNKNOWN).forEach { (output, expected) ->
            val read = LiteHiddenStateReader.read(
                execute = { RootExecResult(RootBackend.ULTRA_ENV, 0, output) },
                pause = { fail("Successful replies do not retry") },
            )
            assertEquals(expected, read.state)
        }
    }

    @Test fun interruptedBackoffDoesNotSubmitAnotherRead() {
        var calls = 0
        val read = LiteHiddenStateReader.read(
            execute = { calls++; RootExecResult(RootBackend.NONE, -1, "", "ROOT_EXECUTION_BUSY") },
            pause = { throw InterruptedException() },
        )
        assertEquals(1, calls)
        assertEquals(LiteHiddenState.UNKNOWN, read.state)
        assertEquals("ROOT_EXECUTION_INTERRUPTED", read.failure)
        assertTrue(Thread.currentThread().isInterrupted)
    }

    @Test fun expiredAdmissionStopsWithoutAnotherReadOrAnOffState() {
        var calls = 0
        val failure = "ULTRA_ROOT_FAILED:MAPLESU_SDK_DEADLINE_EXCEEDED"
        val read = LiteHiddenStateReader.read(
            execute = { calls++; RootExecResult(RootBackend.ULTRA_ENV, -1007, "", failure) },
            pause = { fail("An expired request must not back off or replay") },
        )
        assertEquals(1, calls)
        assertEquals(LiteHiddenState.UNKNOWN, read.state)
        assertEquals(failure, read.failure)
    }

    @Test fun backendStateReadUsesTheSameMissingAndInvalidSemanticsAsThePage() {
        val state = RootFileHiddenState(HiddenRootRunner { RecoveryCommandResult(0, "LITE_MISSING\n") })
        assertEquals(false, state.read())
        val invalid = RootFileHiddenState(HiddenRootRunner { RecoveryCommandResult(1, "0\n") })
        assertNull(invalid.read())
    }
}
