package dev.maplesu.manager.runtime.authorization

import dev.maplesu.manager.runtime.PageReadDeadline
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

/** Detailed read executes the existing scoped SDK tool once; failures do not become empty grants. */
class SuperuserSnapshotDetailedTest {
    @Test fun aFailedReadKeepsItsOriginalCodeAndDetailWithoutAnEmptySnapshot() {
        var calls = 0
        val detail = "SDK_UID_READ:ERR_MODULE_TEST_CHANNEL:-19999; stage=current-identity"
        val client = ManagerGrantFailureFixture.client { command ->
            calls++
            ManagerGrantFailureFixture.reply(command,
                ManagerGrantFailureFixture.failureLine(SuCodes.SU_AUTH_APPLY_PENDING, 42, true, detail))
        }
        val result = SuperuserControl.snapshotDetailed(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client))
        assertNull(result.snapshot)
        assertEquals(SuCodes.SU_AUTH_APPLY_PENDING, result.code)
        assertEquals(detail, result.detail)
        assertEquals(1, calls)
    }

    @Test fun aMalformedSuccessfulReadKeepsTheStableReadFailureInsteadOfReportingAbsence() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { command ->
            calls++
            ManagerGrantFailureFixture.reply(command, "OK wire=malformed")
        }
        val result = SuperuserControl.snapshotDetailed(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client))
        assertNull(result.snapshot)
        assertEquals(SuCodes.SU_STORE_READ_FAILED, result.code)
        assertEquals("invalid-snapshot", result.detail)
        assertEquals(1, calls)
    }

    @Test fun aChangedScopeDropsThePreviousFailureAndItsDiagnostic() {
        var current = true
        var calls = 0
        val client = ManagerGrantFailureFixture.client(current = { current }) { command ->
            calls++
            current = false
            ManagerGrantFailureFixture.reply(command,
                ManagerGrantFailureFixture.failureLine(SuCodes.AUTH_DENIED, 42, true, "old owner detail"))
        }
        val result = SuperuserControl.snapshotDetailed(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client) { current })
        assertNull(result.snapshot)
        assertEquals("SU_AUTH_SCOPE_CHANGED", result.code)
        assertEquals("", result.detail)
        assertEquals(1, calls)
    }

    @Test fun aSuccessfulReadReturnsTheActualDecodedSnapshotWithNoFailure() {
        var calls = 0
        val observed = AuthorizationSnapshot(true, emptyMap(), rev = 42)
        val client = ManagerGrantFailureFixture.client { command ->
            calls++
            ManagerGrantFailureFixture.reply(command, "OK wire=${SuperuserWire.encode(observed)}")
        }
        val result = SuperuserControl.snapshotDetailed(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client))
        assertEquals(observed, result.snapshot)
        assertNull(result.code)
        assertEquals("", result.detail)
        assertEquals(1, calls)
    }

    @Test fun anExpiredReadKeepsAdmissionDetailWithoutSubmittingAnotherCommand() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { calls++; error("Expired read submitted") }
        val result = runBlocking(PageReadDeadline.context(0)) {
            SuperuserControl.snapshotDetailed(ManagerGrantFailureFixture.context(),
                ManagerGrantFailureFixture.scope(client))
        }
        assertNull(result.snapshot)
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, result.code)
        assertEquals("ULTRA_ROOT_FAILED:MAPLESU_SDK_DEADLINE_EXCEEDED", result.detail)
        assertEquals(0, calls)
    }
}
