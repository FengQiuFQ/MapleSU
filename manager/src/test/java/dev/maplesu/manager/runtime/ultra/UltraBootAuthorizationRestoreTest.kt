package dev.maplesu.manager.runtime.ultra

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test
import org.json.JSONObject

class UltraBootAuthorizationRestoreTest {
    private fun unsubmitted(error: String): UltraAuthorizationRestoreResult {
        val detail = JSONObject().put("schemaVersion", 1).put("operationResultAvailable", true)
            .put("operation", 4).put("resultCode", "-19999").put("primaryErrorCode", "-19999")
            .put("primaryPhase", 43).put("diagnosticsComplete", true)
            .put("commitState", 1).put("restoreState", 2).put("deliveryState", 1)
            .put("recoveryCount", 0).put("recoveryTotal", 0).put("recovery", org.json.JSONArray())
            .put("transport", JSONObject().put("status", 1).put("errno", 0)
                .put("childWaitStatus", 0).put("valid", true))
        val receipt = NativeReceipt.parse(JSONObject().put("backend", "maplesu_ultra")
            .put("ok", false).put("sdkError", error).put("sdkErrorCode", -19999)
            .put("data", JSONObject().put("authorizationResult", detail)).toString())!!
        return UltraAuthorizationRestoreResult.refresh(UltraAuthorizationAttempt.from(receipt)).withStatus(error)
    }

    @Test fun unstructuredTransientErrorsNeverReplayAMutation() {
        for (error in listOf("MAPLESU_SDK_BUSY", "ERR_MODULE_SU_LIST_NOT_FOUND", "MAPLESU_SDK_DEADLINE_EXCEEDED")) {
            var calls = 0
            val state = UltraBootAuthorizationRestore { error("no receipt proves pre-commit") }
            assertEquals(error, state.ensure("boot", "owner") { calls++; error })
            assertEquals(1, calls)
        }
    }

    @Test fun expiredMaintenanceReturnsItsReceiptWithoutWaitingOrRepeating() {
        val receipt = NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"refresh_authorizations","ok":false,"sdkError":"MAPLESU_SDK_DEADLINE_EXCEEDED","sdkErrorCode":-1007,"reason":"Current request expired before submission."}""")!!
        val attempt = UltraAuthorizationRestoreResult.refresh(UltraAuthorizationAttempt.from(receipt))
            .withStatus("MAPLESU_SDK_DEADLINE_EXCEEDED")
        val state = UltraBootAuthorizationRestore { fail("An expired maintenance pass must return before backoff") }
        var calls = 0
        var published: UltraAuthorizationRestoreResult? = null
        assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", state.maintainAttempt({ false }, {
            calls++; attempt
        }, { published = it }))
        assertEquals(1, calls)
        assertSame(attempt, published)
        assertSame(receipt, published!!.refresh!!.receipt)
        assertFalse(attempt.retryableBeforeCommit)
    }





    @Test fun disabledBrokerStopsBeforeStartingOrAfterItsPendingPause() {
        for (disabledAtStart in listOf(true, false)) {
            var disabled = disabledAtStart
            var calls = 0
            val state = UltraBootAuthorizationRestore { disabled = true }
            assertEquals("SUSPENDED", state.ensureWhenIdentityAvailable("boot", "owner-fingerprint", { disabled }) {
                calls++; "MANAGER_IDENTITY_PENDING"
            })
            assertEquals(if (disabledAtStart) 0 else 1, calls)
        }
    }

    @Test fun interruptedIdentityPausePreservesTheFlagAndDoesNotCacheSuccess() {
        val state = UltraBootAuthorizationRestore { throw InterruptedException() }
        var calls = 0
        try {
            assertEquals("MAPLESU_SDK_INTERRUPTED", state.ensureWhenIdentityAvailable("boot", "owner-fingerprint", { false }) {
                calls++; "MANAGER_IDENTITY_PENDING"
            })
            assertEquals(1, calls)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertEquals("OK", state.ensure("boot", "owner-fingerprint") { calls++; "OK" })
        assertEquals(2, calls)
    }

    @Test fun alreadyInterruptedBrokerDoesNotReadIdentityOrWriteAuthorization() {
        val state = UltraBootAuthorizationRestore { error("unexpected pause") }
        try {
            Thread.currentThread().interrupt()
            assertEquals("MAPLESU_SDK_INTERRUPTED", state.ensureWhenIdentityAvailable("boot", "owner-fingerprint",
                { error("interrupted scope") }) { error("interrupted write") })
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun backgroundLoopDoesNotReplayDefiniteFailuresOrCompletedRevocation() {
        for (result in listOf("OK", "ERR_MODULE_PARAM", "MANAGER_AUTH_REVOKE_UNVERIFIED", "SUSPENDED")) {
            var calls = 0
            val state = UltraBootAuthorizationRestore { error("unexpected identity retry") }
            assertEquals(result, state.ensureWhenIdentityAvailable("boot", "owner-fingerprint", { false }) { calls++; result })
            assertEquals(1, calls)
        }
    }



    @Test fun temporarilyUnavailableUidMappingsRecoverWithoutAnotherUserAction() {
        val pauses = mutableListOf<Long>()
        val state = UltraBootAuthorizationRestore { pauses += it }
        var calls = 0
        assertEquals("OK", state.ensureAttempt("boot", "owner-fingerprint") {
            calls++
            if (calls == 1) unsubmitted("ERR_MODULE_SU_LIST_NOT_FOUND") else UltraAuthorizationRestoreResult.local()
        }.status)
        assertEquals(2, calls)
        assertEquals(listOf(250L), pauses)
        assertEquals("OK", state.ensure("boot", "owner-fingerprint") { error("already restored") })
    }

    @Test fun exhaustedTransientFailuresStayUncachedAndCanRecoverOnTheNextRequest() {
        val pauses = mutableListOf<Long>()
        val state = UltraBootAuthorizationRestore { pauses += it }
        var calls = 0
        assertEquals("MAPLESU_SDK_BUSY", state.ensureAttempt("boot", "owner-fingerprint") { calls++; unsubmitted("MAPLESU_SDK_BUSY") }.status)
        assertEquals(3, calls)
        assertEquals(listOf(250L, 750L), pauses)
        assertEquals("OK", state.ensure("boot", "owner-fingerprint") { calls++; "OK" })
        assertEquals(4, calls)
    }

    @Test fun permanentFailuresAndSuspensionNeverReplayTheOperation() {
        for (failure in listOf("SUSPENDED", "ERR_MODULE_NO_ROOT", "ERR_MODULE_PARAM", "READBACK_MISMATCH")) {
            val state = UltraBootAuthorizationRestore { error("unexpected retry") }
            var calls = 0
            assertEquals(failure, state.ensure("boot", "owner-fingerprint") { calls++; failure })
            assertEquals(1, calls)
        }
    }

    @Test fun suspensionBetweenRetriesStopsBeforeAnotherRefresh() {
        var suspended = false
        var calls = 0
        val state = UltraBootAuthorizationRestore { suspended = true }
        assertEquals("SUSPENDED", state.ensureAttempt("boot", "owner-fingerprint", { suspended }) {
            calls++
            unsubmitted("ERR_MODULE_SU_LIST_NOT_FOUND")
        }.status)
        assertEquals(1, calls)
    }

    @Test fun interruptedBackoffPreservesCancellationAndNeverCachesSuccess() {
        val state = UltraBootAuthorizationRestore { throw InterruptedException() }
        var calls = 0
        try {
            assertEquals("MAPLESU_SDK_INTERRUPTED", state.ensureAttempt("boot", "owner-fingerprint") { calls++; unsubmitted("MAPLESU_SDK_BUSY") }.status)
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(1, calls)
        } finally { Thread.interrupted() }
        assertEquals("OK", state.ensure("boot", "owner-fingerprint") { calls++; "OK" })
        assertEquals(2, calls)
    }

    @Test fun suspensionDuringSuccessPreventsCachingAndKeepsTheOriginalAttempt() {
        var suspended = false
        var calls = 0
        val state = UltraBootAuthorizationRestore { error("no retry") }
        val result = state.ensureAttempt("boot", "owner", { suspended }) {
            calls++; suspended = true; UltraAuthorizationRestoreResult.local()
        }
        assertEquals("SUSPENDED", result.status)
        suspended = false
        assertEquals("OK", state.ensureAttempt("boot", "owner", { suspended }) {
            calls++; UltraAuthorizationRestoreResult.local()
        }.status)
        assertEquals(2, calls)
    }

    @Test fun reOpeningManagerKeepsTheSuccessfulBootAndOwnerRestoration() {
        val state = UltraBootAuthorizationRestore()
        var calls = 0
        repeat(5) { assertEquals("OK", state.ensure("boot", "fingerprint") { calls++; "OK" }) }
        assertEquals(1, calls)
    }

    @Test fun failedRefreshRetriesAndNeverCachesAnEarlierDifferentScope() {
        val state = UltraBootAuthorizationRestore()
        assertEquals("OK", state.ensure("boot", "old") { "OK" })
        assertEquals("FAILED", state.ensure("boot", "new") { "FAILED" })
        var calls = 0
        assertEquals("OK", state.ensure("boot", "old") { calls++; "OK" })
        assertEquals(1, calls)
    }

    @Test fun unknownBootNewBootAndNewOwnerIdentityEachNeedRealRestoration() {
        val state = UltraBootAuthorizationRestore()
        var calls = 0
        for ((boot, key) in listOf(null to "owner-fingerprint", null to "owner-fingerprint", "boot-a" to "owner-fingerprint",
            "boot-b" to "owner-fingerprint", "boot-b" to "new-owner")) {
            assertEquals("OK", state.ensure(boot, key) { calls++; "OK" })
        }
        assertEquals(5, calls)
    }

    @Test fun concurrentRecoveryRequestsSubmitOneSuccessfulSdkWrite() {
        val state = UltraBootAuthorizationRestore()
        val writes = AtomicInteger()
        val pool = Executors.newFixedThreadPool(6)
        try {
            val results = pool.invokeAll((1..24).map {
                Callable { state.ensure("boot", "owner-fingerprint") { writes.incrementAndGet(); "OK" } }
            })
            results.forEach { assertEquals("OK", it.get(2, TimeUnit.SECONDS)) }
            assertEquals(1, writes.get())
        } finally { pool.shutdownNow() }
    }
}
