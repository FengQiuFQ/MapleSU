package dev.maplesu.manager.runtime.authorization

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.runtime.ultra.RootScriptRunner
import dev.maplesu.manager.runtime.ultra.SuExecResult
import dev.maplesu.manager.runtime.ultra.UltraAuthorization
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import java.io.File
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import sun.misc.Unsafe

/** Android objects are boundaries; the current SDK runner, Root receipt and tool parser execute. */
internal object ManagerGrantFailureFixture {
    private val unsafe: Unsafe get() = Unsafe::class.java.getDeclaredField("theUnsafe")
        .apply { isAccessible = true }.get(null) as Unsafe

    private class GrantContext private constructor() : ContextWrapper(null) {
        lateinit var info: ApplicationInfo
        lateinit var folder: File
        override fun getApplicationContext(): Context = this
        override fun getApplicationInfo(): ApplicationInfo = info
        override fun getPackageName(): String = "dev.maplesu.manager"
        override fun getFilesDir(): File = File(folder, "files")
        override fun getNoBackupFilesDir(): File = File(folder, "no-backup")
        override fun getDataDir(): File = folder
        override fun createDeviceProtectedStorageContext(): Context = this
    }

    fun context(): Context = (unsafe.allocateInstance(GrantContext::class.java) as GrantContext).apply {
        info = (unsafe.allocateInstance(ApplicationInfo::class.java) as ApplicationInfo).apply {
            uid = 10123
            sourceDir = "/fixture/manager/base.apk"
        }
        folder = File(System.getProperty("java.io.tmpdir"), "maplesu-manager-grant-fixture")
    }

    fun client(current: () -> Boolean = { true },
               runner: (String) -> SuExecResult? = { error("Unexpected Root submission") }): UltraRuntimeClient =
        (unsafe.allocateInstance(UltraRuntimeClient::class.java) as UltraRuntimeClient).also { client ->
            for ((name, value) in mapOf("rootCommands" to RootScriptRunner(runner), "identityCurrent" to current)) {
                UltraRuntimeClient::class.java.getDeclaredField(name).apply { isAccessible = true }.set(client, value)
            }
        }

    fun scope(client: UltraRuntimeClient, current: () -> Boolean = { true }) =
        UltraAuthorization.Scope(client, current, current)

    fun reply(command: String, line: String): SuExecResult {
        val nonce = Regex("MAPLESU_ROOT_EXIT:([a-zA-Z0-9-]+):").find(command)!!.groupValues[1]
        return SuExecResult(0, "$line\n\nMAPLESU_ROOT_EXIT:$nonce:0\n")
    }

    fun failureLine(code: String, revision: Long, pending: Boolean, detail: String): String {
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(detail.toByteArray(Charsets.UTF_8))
        return "ERR $code receipt=su1 rev=$revision pending=${if (pending) 1 else 0} detail=$encoded"
    }
}

class SuperuserManagerGrantFailureTest {
    @Test fun aFailedSnapshotKeepsItsOriginalCodeDetailRevisionAndPendingState() {
        var calls = 0
        val detail = "stage=mirror code=-19934 effects=8\ncurrent receipt retained"
        val client = ManagerGrantFailureFixture.client { command ->
            calls++
            ManagerGrantFailureFixture.reply(command,
                ManagerGrantFailureFixture.failureLine(SuCodes.SU_AUTH_APPLY_PENDING, 42, true, detail))
        }
        val result = SuperuserControl.ensureManagerGrant(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client))
        assertFalse(result.succeeded)
        assertEquals(SuCodes.SU_AUTH_APPLY_PENDING, result.code)
        assertEquals(42L, result.rev)
        assertTrue(result.pendingApply)
        assertEquals(detail, result.detail)
        assertEquals(1, calls)
    }

    @Test fun sdkRootFailureRetainsItsOriginalTransportDetailWithoutReplay() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { calls++; SuExecResult(-1, "partial", timedOut = true) }
        val result = SuperuserControl.ensureManagerGrant(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client))
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, result.code)
        assertEquals("ULTRA_ROOT_FAILED:MAPLESU_ROOT_COMMAND_TIMEOUT;sdkCode=-1001", result.detail)
        assertEquals(0L, result.rev)
        assertFalse(result.pendingApply)
        assertEquals(1, calls)
    }

    @Test fun anExpiredSnapshotPreservesAdmissionDetailWithoutSubmittingRoot() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { calls++; error("Expired snapshot submitted") }
        val result = runBlocking(PageReadDeadline.context(0)) {
            SuperuserControl.ensureManagerGrant(ManagerGrantFailureFixture.context(),
                ManagerGrantFailureFixture.scope(client))
        }
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, result.code)
        assertEquals("ULTRA_ROOT_FAILED:MAPLESU_SDK_DEADLINE_EXCEEDED", result.detail)
        assertEquals(0, calls)
    }

    @Test fun aScopeChangedDuringSnapshotNeverAttachesThePreviousAuthorityFailure() {
        var current = true
        var calls = 0
        val client = ManagerGrantFailureFixture.client(current = { current }) { command ->
            calls++
            current = false
            ManagerGrantFailureFixture.reply(command,
                ManagerGrantFailureFixture.failureLine(SuCodes.AUTH_DENIED, 42, true, "old scope detail"))
        }
        val result = SuperuserControl.ensureManagerGrant(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client) { current })
        assertEquals("SU_AUTH_SCOPE_CHANGED", result.code)
        assertEquals("", result.detail)
        assertEquals(0L, result.rev)
        assertFalse(result.pendingApply)
        assertEquals(1, calls)
    }

    @Test fun malformedSuccessfulSnapshotStaysAReadFailureAndIsNotReplayed() {
        var calls = 0
        val client = ManagerGrantFailureFixture.client { command ->
            calls++
            ManagerGrantFailureFixture.reply(command, "OK wire=malformed")
        }
        val result = SuperuserControl.ensureManagerGrant(ManagerGrantFailureFixture.context(),
            ManagerGrantFailureFixture.scope(client))
        assertEquals(SuCodes.SU_STORE_READ_FAILED, result.code)
        assertFalse(result.succeeded)
        assertEquals(1, calls)
    }
}
