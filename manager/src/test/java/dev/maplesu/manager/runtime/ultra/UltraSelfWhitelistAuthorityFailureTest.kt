package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.runtime.authorization.ManagerGrantFailureFixture
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import dev.maplesu.manager.runtime.authorization.SuCodes
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraSelfWhitelistAuthorityFailureTest {
    private class ProfilePort(val read: () -> List<SuUidProfile>? = { null },
                              val receipt: NativeReceipt? = null, val error: String? = null) : SuAuthPort {
        var reads = 0
        override fun uidProfiles(): List<SuUidProfile>? { reads++; return read() }
        override fun uidProfileReadError(): String? = error
        override fun uidProfileReadReceipt(): NativeReceipt? = receipt
        override fun snapshot(): List<String>? = error("Unexpected package snapshot")
        override fun add(packageName: String): NativeReceipt = error("Unexpected authority write")
        override fun remove(packageName: String): NativeReceipt = error("Unexpected revoke")
    }

    @Test fun authorityFailureKeepsItsOriginalDetailAndStableFailureCode() {
        val detail = "ULTRA_ROOT_FAILED:ERR_MODULE_OPEN_FILE;sdkCode=-19934;phase=7;credentials.effects=8"
        val authority = SuperuserControl.Result(false, 42, SuCodes.SU_AUTH_APPLY_PENDING, true, detail)
        val port = ProfilePort()
        val result = UltraSelfWhitelist.ensureAuthority(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(ManagerGrantFailureFixture.client()), authority, port)
        assertEquals(SuCodes.SU_AUTH_APPLY_PENDING, result.failure)
        assertEquals(detail, result.detail)
        assertFalse(result.succeeded)
        assertNull(result.receipt)
        assertEquals(0, port.reads)
    }

    @Test fun failedUidReadKeepsTheSameNativeReceiptAndItsOriginalFailureClass() {
        val receipt = NativeReceipt(1, UltraRuntimeClient.BACKEND, 1, "get_su_uid_profiles", false,
            "ERR_MODULE_OPEN_FILE", -19934, "private reason", JSONObject().put("handle", "private handle"), "private raw")
        val port = ProfilePort(receipt = receipt, error = "SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934")
        val result = UltraSelfWhitelist.ensureAuthority(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(ManagerGrantFailureFixture.client()), SuperuserControl.Result(true, 42), port)
        assertEquals("SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934", result.failure)
        assertSame(receipt, result.receipt)
        assertFalse(result.succeeded)
        assertFalse(result.attempted)
        assertEquals(1, port.reads)
        assertTrue(result.summary.contains("code=-19934"))
        assertFalse(result.summary.contains("private"))
    }

    @Test fun currentScopeChangeDropsPreviousAuthorityDiagnosticsBeforeUidRead() {
        val port = ProfilePort()
        val authority = SuperuserControl.Result(false, 42, SuCodes.AUTH_DENIED, true, "old scope detail")
        val result = UltraSelfWhitelist.ensureAuthority(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(ManagerGrantFailureFixture.client()) { false }, authority, port)
        assertEquals("SU_AUTH_SCOPE_CHANGED", result.failure)
        assertNull(result.detail)
        assertNull(result.receipt)
        assertEquals(0, port.reads)
    }

    @Test fun aScopeChangedDuringUidReadNeverAttachesThePreviousReadReceipt() {
        var current = true
        val receipt = NativeReceipt.bridgeFailure("get_su_uid_profiles", "ERR_MODULE_OPEN_FILE", "old scope detail", -19934)
        val port = ProfilePort(read = { current = false; null }, receipt = receipt, error = "SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934")
        val result = UltraSelfWhitelist.ensureAuthority(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(ManagerGrantFailureFixture.client()) { current },
            SuperuserControl.Result(true, 42), port)
        assertEquals("SU_AUTH_SCOPE_CHANGED", result.failure)
        assertNull(result.detail)
        assertNull(result.receipt)
        assertEquals(1, port.reads)
    }

    @Test fun clientPortKeepsTheLatestOriginalUidReadReceiptWithoutJniOrStickyErrors() {
        val client = ManagerGrantFailureFixture.client()
        UltraRuntimeClient::class.java.getDeclaredField("loadFailure").apply { isAccessible = true }
            .set(client, "fixture bridge offline")
        val port = UltraSelfWhitelist.clientPort(client)
        assertNull(port.uidProfileReadReceipt())
        runBlocking(PageReadDeadline.context(0)) { assertNull(port.uidProfiles()) }
        val deadline = port.uidProfileReadReceipt()
        assertNotNull(deadline)
        assertEquals("get_su_uid_profiles", deadline!!.operation)
        assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", deadline.sdkError)
        assertEquals(-1007, deadline.sdkErrorCode)
        assertEquals("SDK_UID_READ:MAPLESU_SDK_DEADLINE_EXCEEDED:-1007", port.uidProfileReadError())
        assertNull(port.uidProfiles())
        val latest = port.uidProfileReadReceipt()
        assertNotNull(latest)
        assertNotSame(deadline, latest)
        assertEquals("MAPLESU_BRIDGE_UNAVAILABLE", latest!!.sdkError)
        assertEquals("SDK_UID_READ:MAPLESU_BRIDGE_UNAVAILABLE:-1001", port.uidProfileReadError())
    }

    @Test fun optionalAuthorityDetailsNeverBecomeRawLogSummaryText() {
        val receipt = NativeReceipt(1, UltraRuntimeClient.BACKEND, 1, "get_su_uid_profiles", false,
            "ERR_MODULE_OPEN_FILE", -19934, "private reason", JSONObject().put("command", "private command"), "private raw")
        val result = UltraSelfWhitelist.Result(false, false, false, false, false,
            "SDK_UID_READ:ERR_MODULE_OPEN_FILE:-19934", receipt, "private detail token handle")
        assertTrue(result.summary.contains("code=-19934"))
        assertFalse(result.summary.contains("private"))
        assertFalse(result.toString().contains("private"))
    }
}
