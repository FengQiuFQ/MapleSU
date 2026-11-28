package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.authorization.ManagerGrantFailureFixture
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Actual receipt/state/facade consumers execute; only the Android/JNI boundary is a fixture. */
class UltraUidReadDiagnosticTest {
    private val uid = 10123
    private val name = "dev.maplesu.manager"

    private fun readData(available: Boolean = true): JSONObject = JSONObject()
        .put("schemaVersion", 1).put("operationResultAvailable", available)
        .put("resultCode", if (available) "-19934" else "-19914")
        .put("primaryPhase", if (available) 10 else 8).put("primaryErrno", 32)
        .put("authMode", 3).put("recordCount", 0)
        .put("transport", JSONObject().put("status", 3).put("errno", 32)
            .put("childWaitStatus", 256).put("valid", true)).apply {
            if (available) {
                for (key in listOf("root", "read", "close")) put(key,
                    JSONObject().put("code", if (key == "read") "-19934" else "0")
                        .put("systemErrno", if (key == "read") 32 else 0).put("completed", key != "read"))
                put("readback", JSONObject().put("code", "-19934").put("systemErrno", 32)
                    .put("phase", 10).put("capabilities", "18446744073709551615")
                    .put("revision", "9007199254740993").put("count", 0).put("schema", 3)
                    .put("management", JSONObject().put("status", -4).put("effects", 8)
                        .put("result", "18446744073709551615").put("command", 30)
                        .put("completed", true).put("hasHandle", true)))
            }
        }

    private fun readReceipt(data: JSONObject = readData(), ok: Boolean = false): NativeReceipt =
        NativeReceipt(1, UltraRuntimeClient.BACKEND, 1, "get_su_uid_profiles", ok,
            if (ok) "OK" else "ERR_MODULE_OPEN_FILE", if (ok) 0 else -19934,
            "PRIVATE_REASON", JSONObject().put("uidReadResult", data).put("handle", "PRIVATE_HANDLE"),
            "PRIVATE_RAW")

    private fun writeReceipt(): NativeReceipt {
        val result = JSONObject().put("schemaVersion", 1).put("operationResultAvailable", true)
            .put("operation", 1).put("resultCode", "0").put("primaryErrorCode", "0")
            .put("primaryPhase", 0).put("diagnosticsComplete", true).put("commitState", 2)
            .put("restoreState", 1).put("deliveryState", 2).put("recoveryCount", 0)
            .put("recoveryTotal", 0).put("recovery", JSONArray())
            .put("transport", JSONObject().put("status", 1).put("errno", 0)
                .put("childWaitStatus", 0).put("valid", true))
        return NativeReceipt(1, UltraRuntimeClient.BACKEND, 1, "set_su_uid_profile", true,
            "OK", 0, "PRIVATE_WRITE_REASON", JSONObject().put("authorizationResult", result), "PRIVATE_WRITE_RAW")
    }

    private class Port(var profiles: List<SuUidProfile>?, val readReceipt: NativeReceipt,
                       val writeReceipt: NativeReceipt, val afterRead: () -> Unit = {}) : SuAuthPort {
        var reads = 0
        var writes = 0
        override val supportsUidProfiles = true
        override fun uidProfiles(): List<SuUidProfile>? { reads++; afterRead(); return profiles }
        override fun uidProfileReadError() = "SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934"
        override fun uidProfileReadReceipt() = readReceipt
        override fun setUidProfile(uid: Int, packageName: String, allow: Boolean): NativeReceipt {
            writes++
            return writeReceipt
        }
        override fun snapshot(): List<String>? = error("Unexpected package read")
        override fun add(packageName: String): NativeReceipt = error("Unexpected package write")
        override fun remove(packageName: String): NativeReceipt = error("Unexpected package revoke")
    }

    @Test fun scalarSummaryRetainsAllTypedPhasesAndExactWideDecimals() {
        val summary = readReceipt().uidReadDiagnosticSummary()
        for (field in listOf("uidRead=true", "available=true", "result=-19934", "phase=10", "errno=32",
            "authMode=3", "recordCount=0", "transport=3", "transportErrno=32", "childWait=256",
            "childWaitStatusValid=true", "rootCode=0", "rootCompleted=true", "readCode=-19934",
            "readSystemErrno=32", "readCompleted=false", "closeCode=0", "closeCompleted=true",
            "readbackCode=-19934", "readbackSystemErrno=32", "readbackPhase=10",
            "capabilities=18446744073709551615", "revision=9007199254740993", "count=0", "schema=3",
            "managementStatus=-4", "managementEffects=8", "managementResult=18446744073709551615",
            "managementCommand=30", "managementCompleted=true", "managementHasHandle=true")) {
            assertTrue("Missing $field: $summary", summary.contains(field))
        }
    }

    @Test fun signedAndUnsignedLimitsKeepTheirOriginalDecimalStrings() {
        val data = readData().put("resultCode", "-9223372036854775808").put("primaryPhase", 4294967295L)
        data.getJSONObject("read").put("code", "9223372036854775807")
        data.getJSONObject("readback").put("revision", "18446744073709551615")
        val summary = readReceipt(data).uidReadDiagnosticSummary()
        assertTrue(summary.contains("result=-9223372036854775808"))
        assertTrue(summary.contains("phase=4294967295"))
        assertTrue(summary.contains("readCode=9223372036854775807"))
        assertTrue(summary.contains("revision=18446744073709551615"))
    }

    @Test fun unavailableFrameKeepsTransportWithoutClaimingNoAttemptOrPayload() {
        val summary = readReceipt(readData(false)).uidReadDiagnosticSummary()
        assertTrue(summary.contains("uidRead=true available=false result=-19914 phase=8 errno=32"))
        assertTrue(summary.contains("transport=3"))
        assertFalse(summary.contains("attempted=false"))
        assertFalse(summary.contains("rootCode"))
        assertFalse(summary.contains("readbackCode"))
    }

    @Test fun phaseZeroRetainsPreCloseManagementWithoutRelabelingItAsTypedRead() {
        val data = readData()
        data.getJSONObject("readback").put("phase", 0)
        val summary = readReceipt(data).uidReadDiagnosticSummary()
        assertTrue(summary.contains("readbackPhase=0"))
        assertTrue(summary.contains("managementCommand=30"))
        assertTrue(summary.contains("managementHasHandle=true"))
        assertFalse(summary.contains("typedRead=true"))
        assertFalse(summary.contains("readbackVerified=true"))
    }

    @Test fun scalarProjectionExcludesUnknownTextRawReasonCommandsAndHandleValues() {
        val data = readData().put("reason", "PRIVATE_TYPED_REASON").put("token", "PRIVATE_TOKEN")
        data.getJSONObject("root").put("raw", "PRIVATE_STEP_RAW")
        data.getJSONObject("readback").getJSONObject("management")
            .put("handle", "PRIVATE_MANAGEMENT_HANDLE").put("commandText", "PRIVATE_COMMAND")
        val summary = readReceipt(data).uidReadDiagnosticSummary()
        assertTrue(summary.contains("uidRead=true"))
        assertFalse(summary.contains("PRIVATE"))
        assertFalse(summary.contains("token"))
        assertFalse(summary.contains("raw"))
        assertFalse(summary.contains("handle="))
    }

    @Test fun schemaAndScalarTypeMismatchesDoNotBecomeFactsThroughJsonCoercion() {
        val cases = listOf<Pair<String, Any>>("schemaVersion" to "1", "schemaVersion" to 2,
            "operationResultAvailable" to "true", "resultCode" to -19934, "resultCode" to "-019934",
            "resultCode" to "9223372036854775808", "primaryPhase" to "10", "primaryPhase" to 0.1,
            "primaryPhase" to -1, "primaryErrno" to "32", "primaryErrno" to 2147483648L,
            "authMode" to false, "recordCount" to 4294967296L)
        for ((key, value) in cases) assertEquals("$key=$value", "uidRead=false",
            readReceipt(readData().put(key, value)).uidReadDiagnosticSummary())
    }

    @Test fun malformedNestedPayloadAndAbsentRequiredFieldsDoNotBecomeFacts() {
        val mutations: List<(JSONObject) -> Unit> = listOf(
            { it.remove("transport") },
            { it.getJSONObject("transport").put("valid", "true") },
            { it.getJSONObject("transport").put("errno", "32") },
            { it.getJSONObject("transport").put("childWaitStatus", 1.0) },
            { it.remove("root") },
            { it.getJSONObject("read").put("completed", 1) },
            { it.getJSONObject("close").put("code", "00") },
            { it.getJSONObject("readback").put("capabilities", "18446744073709551616") },
            { it.getJSONObject("readback").put("revision", 9007199254740993L) },
            { it.getJSONObject("readback").getJSONObject("management").put("hasHandle", "false") },
            { it.getJSONObject("readback").getJSONObject("management").put("result", "-1") },
        )
        for ((index, mutate) in mutations.withIndex()) {
            val data = readData()
            mutate(data)
            assertEquals("case=$index", "uidRead=false", readReceipt(data).uidReadDiagnosticSummary())
        }
        assertEquals("uidRead=false", readReceipt(readData(false).put("root", JSONObject())).uidReadDiagnosticSummary())
        assertEquals("uidRead=false", NativeReceipt.bridgeFailure("get_su_uid_profiles", "EIO", null).uidReadDiagnosticSummary())
    }

    @Test fun uidReceiptSummaryIsAvailableWithoutAnAuthorizationWriteResult() {
        val receipt = readReceipt()
        assertNull(receipt.authorizationResult)
        val summary = receipt.authorizationDiagnosticSummary()
        assertTrue(summary.contains("sdk=ERR_MODULE_OPEN_FILE code=-19934 detail=false"))
        assertTrue(summary.contains("uidRead=true"))
        assertTrue(summary.contains("readCode=-19934"))
        assertFalse(summary.contains("PRIVATE"))
    }

    @Test fun independentReadReceiptSurvivesAttemptTransformationsAndNeverReplacesWriteEvidence() {
        val write = writeReceipt()
        val read = readReceipt()
        val original = UltraAuthorizationAttempt.from(write).withReadReceipt(read)
        val attempt = original.withReadback(true).withPreparation(
            UltraAuthorizationAttempt.Preparation(true, false, "ERR_MODULE_OPEN_FILE")).withFailure("READBACK_FAILED")
        assertSame(write, attempt.receipt)
        assertSame(read, attempt.readReceipt)
        assertTrue(attempt.decisionCommitted)
        assertTrue(attempt.decisionVerified)
        assertTrue(attempt.pendingApply)
        assertFalse(attempt.succeeded)
        assertTrue(attempt.diagnosticSummary.contains("readReceipt=["))
        assertTrue(attempt.diagnosticSummary.contains("readCode=-19934"))
        assertFalse(attempt.diagnosticSummary.contains("PRIVATE"))
        assertSame(read, attempt.withFailure("LATER_ERROR").readReceipt)
    }

    @Test fun readSuccessAloneDoesNotConfirmAnUnknownWriteOrNativeDelivery() {
        val write = NativeReceipt.bridgeFailure("set_su_uid_profile", "UNKNOWN_WRITE", "PRIVATE_WRITE")
        val read = readReceipt(ok = true)
        val port = Port(listOf(SuUidProfile(uid, true, name)), read, write)
        val attempt = UltraAuthorizationState().setUidGranted(port, uid, name, true)
        assertSame(write, attempt.receipt)
        assertSame(read, attempt.readReceipt)
        assertTrue(attempt.decisionVerified)
        assertFalse(attempt.decisionCommitted)
        assertTrue(attempt.commitUnknown)
        assertFalse(attempt.succeeded)
        assertEquals(1, port.writes)
        assertEquals(1, port.reads)
    }

    @Test fun failedWriteReadbackKeepsBothOriginalReceiptsAndRevokesCachedCapability() {
        val read = readReceipt()
        val write = writeReceipt()
        val port = Port(null, read, write)
        val state = UltraAuthorizationState()
        val attempt = state.setUidGranted(port, uid, name, true)
        assertSame(write, attempt.receipt)
        assertSame(read, attempt.readReceipt)
        assertEquals("SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934", attempt.error)
        assertTrue(attempt.decisionCommitted)
        assertTrue(attempt.pendingApply)
        assertFalse(state.snapshot.loaded)
        assertFalse(state.snapshot.uidProfilesLoaded)
        assertTrue(state.snapshot.deliveryIncomplete)
        assertEquals(1, port.reads)
        assertEquals(1, port.writes)
    }

    @Test fun successfulWriteReadbackRetainsItsReadReceiptWithoutChangingSuccess() {
        val read = readReceipt(ok = true)
        val write = writeReceipt()
        val port = Port(listOf(SuUidProfile(uid, true, name)), read, write)
        val state = UltraAuthorizationState()
        val attempt = state.setUidGranted(port, uid, name, true)
        assertSame(write, attempt.receipt)
        assertSame(read, attempt.readReceipt)
        assertTrue(attempt.succeeded)
        assertTrue(attempt.decisionCommitted)
        assertTrue(attempt.decisionVerified)
        assertTrue(state.snapshot.uidProfilesLoaded)
        assertFalse(state.snapshot.deliveryIncomplete)
        assertEquals(1, port.reads)
        assertEquals(1, port.writes)
    }

    @Test fun changedScopeAfterReadDropsReadDiagnosticAndDoesNotPublishOldProfiles() {
        var current = true
        val write = writeReceipt()
        val port = Port(listOf(SuUidProfile(uid, true, name)), readReceipt(), write) { current = false }
        val state = UltraAuthorizationState()
        val attempt = state.setUidGranted(port, uid, name, true, { current })
        assertEquals("SU_AUTH_SCOPE_CHANGED", attempt.error)
        assertSame(write, attempt.receipt)
        assertNull(attempt.readReceipt)
        assertFalse(attempt.decisionVerified)
        assertFalse(state.snapshot.loaded)
        assertFalse(attempt.diagnosticSummary.contains("uidRead=true"))
        assertEquals(1, port.reads)
        assertEquals(1, port.writes)
    }

    @Test fun refreshFailureKeepsTheSameReadReceiptAndOriginalStableFailure() {
        val read = readReceipt()
        val port = Port(null, read, writeReceipt())
        val result = UltraAuthorizationState().refreshDetailed(port)
        assertEquals("SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934", result.error)
        assertSame(read, result.readReceipt)
        assertFalse(result.succeeded)
        assertTrue(result.diagnosticSummary.contains("readCode=-19934"))
        assertEquals(1, port.reads)
        assertEquals(0, port.writes)
    }

    @Test fun successfulRefreshKeepsReadDiagnosticsAndDoesNotAssertDelivery() {
        val read = readReceipt(ok = true)
        val port = Port(listOf(SuUidProfile(uid, true, name)), read, writeReceipt())
        val state = UltraAuthorizationState()
        val result = state.refreshDetailed(port)
        assertTrue(result.succeeded)
        assertSame(read, result.readReceipt)
        assertTrue(result.diagnosticSummary.contains("uidRead=true"))
        assertTrue(state.snapshot.loaded)
        assertTrue(state.snapshot.uidProfilesLoaded)
        assertFalse(result.diagnosticSummary.contains("deliveryConfirmed=true"))
        assertEquals(1, port.reads)
        assertEquals(0, port.writes)
    }

    @Test fun refreshScopeChangeDropsOldReadDiagnosticsInsteadOfAttachingThemToNewScope() {
        var current = true
        val port = Port(null, readReceipt(), writeReceipt()) { current = false }
        val state = UltraAuthorizationState()
        val result = state.refreshDetailed(port, { current })
        assertEquals("SU_AUTH_SCOPE_CHANGED", result.error)
        assertNull(result.readReceipt)
        assertFalse(state.snapshot.loaded)
        assertFalse(result.diagnosticSummary.contains("uidRead=true"))
        assertEquals(1, port.reads)
    }

    @Test fun legacyRefreshSignatureStillReadsOnlyOnceAndKeepsItsStableError() {
        val port = Port(null, readReceipt(), writeReceipt())
        assertEquals("SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934", UltraAuthorizationState().refresh(port))
        assertEquals(1, port.reads)
        assertEquals(0, port.writes)
    }

    @Test fun selfWhitelistReadFailureRetainsOriginalReceiptAndTypedSummary() {
        val read = readReceipt()
        val port = Port(null, read, writeReceipt())
        val result = UltraSelfWhitelist.ensureAuthority(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(ManagerGrantFailureFixture.client()), SuperuserControl.Result(true, 42), port)
        assertSame(read, result.receipt)
        assertSame(read, result.readReceipt)
        assertFalse(result.succeeded)
        assertTrue(result.summary.contains("readCode=-19934"))
        assertFalse(result.summary.contains("PRIVATE"))
        assertEquals(1, port.reads)
        assertEquals(0, port.writes)
    }

    @Test fun selfWhitelistSummaryKeepsIndependentReadAndWriteWithoutSensitiveText() {
        val write = writeReceipt()
        val read = readReceipt()
        val result = UltraSelfWhitelist.Result(false, false, false, true, false,
            "READBACK_FAILED", write, "PRIVATE_DETAIL", read)
        assertSame(write, result.receipt)
        assertSame(read, result.readReceipt)
        assertFalse(result.succeeded)
        assertTrue(result.summary.contains("commit=2"))
        assertTrue(result.summary.contains("readReceipt=["))
        assertTrue(result.summary.contains("readCode=-19934"))
        assertFalse(result.toString().contains("PRIVATE"))
    }

    @Test fun actualFacadeRefreshExposesTheCurrentReadReceiptWithoutRetryingJni() {
        val client = ManagerGrantFailureFixture.client()
        UltraRuntimeClient::class.java.getDeclaredField("loadFailure").apply { isAccessible = true }
            .set(client, "PRIVATE_BRIDGE_OFFLINE")
        val scope = ManagerGrantFailureFixture.scope(client)
        val result = UltraAuthorization.refreshDetailed(scope)
        assertFalse(result.succeeded)
        assertSame(scope, result.scope)
        assertEquals("SDK_UID_READ:MAPLESU_BRIDGE_UNAVAILABLE:-1001", result.error)
        assertNotNull(result.snapshot)
        val receipt = result.readReceipt
        assertNotNull(receipt)
        assertSame(result.snapshot!!.receipt, receipt)
        assertEquals("get_su_uid_profiles", receipt!!.operation)
        assertEquals(-1001, receipt.sdkErrorCode)
        assertTrue(result.diagnosticSummary.contains("code=-1001"))
        assertFalse(result.diagnosticSummary.contains("PRIVATE"))
    }

    @Test fun clientPortReportsTheSameActualSnapshotOnceForEachRead() {
        val client = ManagerGrantFailureFixture.client()
        UltraRuntimeClient::class.java.getDeclaredField("loadFailure").apply { isAccessible = true }
            .set(client, "PRIVATE_BRIDGE_OFFLINE")
        val reads = mutableListOf<UltraRuntimeClient.SuUidProfilesSnapshot>()
        val port = UltraSelfWhitelist.clientPort(client, reads::add)
        assertNull(port.uidProfiles())
        assertEquals(1, reads.size)
        assertSame(reads.single().receipt, port.uidProfileReadReceipt())
        assertNull(port.uidProfiles())
        assertEquals(2, reads.size)
        assertNotSame(reads[0], reads[1])
        assertSame(reads[1].receipt, port.uidProfileReadReceipt())
        assertEquals("SDK_UID_READ:MAPLESU_BRIDGE_UNAVAILABLE:-1001", port.uidProfileReadError())
    }
}
