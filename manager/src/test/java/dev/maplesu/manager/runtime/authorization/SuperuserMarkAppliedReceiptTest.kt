package dev.maplesu.manager.runtime.authorization

import android.content.Context
import dev.maplesu.manager.runtime.ultra.SuExecResult
import dev.maplesu.manager.runtime.ultra.UltraAuthorization
import java.io.File
import org.junit.Assert.*
import org.junit.Test

/** Actual watermark transport/parser and full commit entry; only the SDK child boundary is a fixture. */
class SuperuserMarkAppliedReceiptTest {
    private val decision = SuperuserControl.Result(true, 3, pendingApply = true, detail = "decision-committed")
    private val mirror = MirrorOutcome.failure("SDK_UID_LIST_UNREADABLE")

    private fun mark(scope: UltraAuthorization.Scope, outcome: MirrorOutcome = mirror,
                     committed: SuperuserControl.Result? = decision): SuperuserControl.Result {
        val method = SuperuserControl::class.java.getDeclaredMethod("markApplied", Context::class.java,
            String::class.java, java.lang.Long.TYPE, MirrorOutcome::class.java,
            UltraAuthorization.Scope::class.java, SuperuserControl.Result::class.java, String::class.java)
            .apply { isAccessible = true }
        return method.invoke(SuperuserControl, ManagerGrantFailureFixture.context(), "ULTRA_ALLOWLIST", 3L,
            outcome, scope, committed, outcome.detail) as SuperuserControl.Result
    }

    @Test fun aFailedMirrorSameRevisionPendingReceiptRecordsDeliveryFailureWithoutTransportFailure() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { command ->
            calls++
            ManagerGrantFailureFixture.reply(command,
                "OK rev=3 pending=1 detail=SDK_UID_LIST_UNREADABLE code=OK")
        }
        val result = mark(ManagerGrantFailureFixture.scope(client))
        assertTrue("The decision and its pending watermark were committed", result.ok)
        assertFalse(result.succeeded)
        assertTrue(result.pendingApply)
        assertEquals(3L, result.rev)
        assertNull("A recorded failed mirror is not a transport failure", result.code)
        assertEquals("SDK_UID_LIST_UNREADABLE", result.detail)
        assertEquals(1, calls)
    }

    @Test fun aKnownWatermarkFailureRetainsThePreviouslyConfirmedDecisionAndOriginalFailure() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { command ->
            calls++
            ManagerGrantFailureFixture.reply(command, ManagerGrantFailureFixture.failureLine(
                SuCodes.SU_JOURNAL_WRITE_FAILED, 4, true, "watermark journal write failed"))
        }
        val result = mark(ManagerGrantFailureFixture.scope(client))
        assertTrue(result.ok)
        assertEquals(3L, result.rev)
        assertTrue(result.pendingApply)
        assertFalse(result.succeeded)
        assertEquals(SuCodes.SU_JOURNAL_WRITE_FAILED, result.code)
        assertTrue(result.detail.contains("watermark journal write failed"))
        assertTrue(result.detail.contains("decision-committed"))
        assertTrue(result.detail.contains("SDK_UID_LIST_UNREADABLE"))
        assertEquals(1, calls)
    }

    @Test fun aLostWatermarkResponseDoesNotEraseTheOriginalDecisionOrReplayIt() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { calls++; SuExecResult(-1, "partial", timedOut = true) }
        val result = mark(ManagerGrantFailureFixture.scope(client))
        assertTrue(result.ok)
        assertEquals(3L, result.rev)
        assertTrue(result.pendingApply)
        assertFalse(result.succeeded)
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, result.code)
        assertTrue(result.detail.contains("ULTRA_ROOT_FAILED:MAPLESU_ROOT_COMMAND_TIMEOUT;sdkCode=-1001"))
        assertTrue(result.detail.contains("decisionRev=3 markApplied=unknown"))
        assertTrue(result.detail.contains("SDK_UID_LIST_UNREADABLE"))
        assertEquals(1, calls)
    }

    @Test fun aMalformedWatermarkDoesNotBecomeAnUnknownDecision() {
        val client = ManagerGrantFailureFixture.client { command ->
            ManagerGrantFailureFixture.reply(command, "OK rev=3 detail=missing-pending")
        }
        val result = mark(ManagerGrantFailureFixture.scope(client))
        assertTrue(result.ok)
        assertEquals(3L, result.rev)
        assertTrue(result.pendingApply)
        assertFalse(result.succeeded)
        assertEquals(SuCodes.SU_STORE_WRITE_FAILED, result.code)
        assertTrue(result.detail.contains("invalid-result:missing-pending"))
    }

    @Test fun aStaleWatermarkRetainsThisDecisionRevisionAndBothRevisionDiagnostics() {
        val client = ManagerGrantFailureFixture.client { command ->
            ManagerGrantFailureFixture.reply(command, "OK rev=4 pending=1 detail=STALE_MIRROR_REVISION:3:4 code=OK")
        }
        val result = mark(ManagerGrantFailureFixture.scope(client))
        assertTrue(result.ok)
        assertEquals(3L, result.rev)
        assertTrue(result.pendingApply)
        assertFalse(result.succeeded)
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, result.code)
        assertTrue(result.detail.contains("expectedRev=3 observedRev=4 pending=true"))
    }

    @Test fun aSuccessMirrorPendingReceiptNeverConfirmsDelivery() {
        val client = ManagerGrantFailureFixture.client { command ->
            ManagerGrantFailureFixture.reply(command, "OK rev=3 pending=1 detail=still-pending code=OK")
        }
        val result = mark(ManagerGrantFailureFixture.scope(client), MirrorOutcome.success())
        assertTrue(result.ok)
        assertFalse(result.succeeded)
        assertTrue(result.pendingApply)
        assertEquals(3L, result.rev)
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, result.code)
    }

    @Test fun aReceiptWithoutAPreviousDecisionDoesNotInventACommit() {
        val client = ManagerGrantFailureFixture.client { command ->
            ManagerGrantFailureFixture.reply(command, ManagerGrantFailureFixture.failureLine(
                SuCodes.SU_JOURNAL_WRITE_FAILED, 3, true, "decisionRev=3 forged-text-only"))
        }
        val result = mark(ManagerGrantFailureFixture.scope(client), committed = null)
        assertFalse(result.ok)
        assertFalse(result.succeeded)
        assertEquals(SuCodes.SU_JOURNAL_WRITE_FAILED, result.code)
        assertEquals("decisionRev=3 forged-text-only", result.detail)
    }

    @Test fun aScopeLostAfterTheDecisionBlocksMarkSubmissionWithoutDiscardingTheDecision() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { calls++; error("Changed scope submitted mark") }
        val result = mark(ManagerGrantFailureFixture.scope(client) { false })
        assertTrue(result.ok)
        assertEquals(3L, result.rev)
        assertTrue(result.pendingApply)
        assertFalse(result.succeeded)
        assertEquals("SU_AUTH_SCOPE_CHANGED", result.code)
        assertEquals(0, calls)
    }

    @Test fun anUnansweredOriginalGrantStaysUnknownWithoutSubmittingSnapshotOrMark() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { calls++; SuExecResult(-1, "partial", timedOut = true) }
        val result = SuperuserControl.grant(ManagerGrantFailureFixture.context(), 10123,
            ManagerGrantFailureFixture.scope(client))
        assertFalse(result.ok)
        assertFalse(result.succeeded)
        assertEquals(0L, result.rev)
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, result.code)
        assertEquals(1, calls)
    }

    @Test fun aFullCommitKeepsTheConfirmedDecisionAndSnapshotMarkFailure() {
        val context = ManagerGrantFailureFixture.context()
        val marker = File(context.dataDir, "superuser-pending-apply")
        val oldMarker = marker.takeIf(File::isFile)?.readBytes()
        val cache = DirectPolicy::class.java.getDeclaredField("snapshot").apply { isAccessible = true }
        val oldCache = cache.get(null)
        val calls = mutableListOf<String>()
        val client = ManagerGrantFailureFixture.client { command ->
            val operation = when {
                "'mark-applied'" in command -> "mark"
                "'snapshot'" in command -> "snapshot"
                "'grant'" in command -> "grant"
                else -> error("Unexpected operation")
            }
            calls += operation
            ManagerGrantFailureFixture.reply(command, when (operation) {
                "grant" -> "OK rev=3 pending=1 detail=decision-committed code=OK"
                "snapshot" -> "OK wire=malformed"
                else -> ManagerGrantFailureFixture.failureLine(SuCodes.SU_JOURNAL_WRITE_FAILED, 3, true,
                    "watermark journal write failed")
            })
        }
        try {
            val result = SuperuserControl.grant(context, 10123, ManagerGrantFailureFixture.scope(client))
            assertEquals(listOf("grant", "snapshot", "mark"), calls)
            assertTrue(result.ok)
            assertEquals(3L, result.rev)
            assertTrue(result.pendingApply)
            assertFalse(result.succeeded)
            assertEquals(SuCodes.SU_JOURNAL_WRITE_FAILED, result.code)
            assertTrue(result.detail.contains("watermark journal write failed"))
            assertTrue(result.detail.contains("snapshot-unavailable"))
            assertTrue(result.detail.contains("decision-committed"))
            assertTrue(marker.isFile)
        } finally {
            cache.set(null, oldCache)
            if (oldMarker == null) marker.delete() else marker.writeBytes(oldMarker)
        }
    }
}
