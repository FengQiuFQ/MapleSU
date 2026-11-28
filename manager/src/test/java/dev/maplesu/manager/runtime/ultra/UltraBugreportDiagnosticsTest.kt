// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import com.maplesu.core.ui.util.BugreportArchive
import java.io.File
import java.net.URLEncoder
import java.util.zip.GZIPInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UltraBugreportDiagnosticsTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun receipt(result: String = "", ok: Boolean = true): NativeReceipt = NativeReceipt.parse(
        JSONObject().put("backend", "maplesu_ultra").put("ok", ok)
            .put("sdkError", if (ok) "OK" else "EIO")
            .put("sdkErrorCode", if (ok) 0 else -1)
            .put("data", JSONObject().put("encoding", "url")
                .put("result", URLEncoder.encode(result, "UTF-8"))).toString(),
    )!!

    private inner class Port : UltraBugreportDiagnostics.Port {
        val commands = mutableListOf<String>()
        var sdkAvailable = true
        var failPackages = false
        var failBoot = false
        var state = "Running"
        var secret = ""
        var helperPath: String? = null
        var busyDmesgReads = 0
        var recoveryOutput: String? = null
        var policyOutput: String? = null
        var rootReceipt: NativeReceipt? = null
        override fun installedHelperPath() = helperPath
        override fun sdkBuildIdentity() = NativeReceipt.parse(
            JSONObject().put("backend", "maplesu_ultra").put("ok", sdkAvailable).put("sdkError", if (sdkAvailable) "OK" else "EIO")
                .put("sdkErrorCode", if (sdkAvailable) 0 else -1)
                .put("data", JSONObject().put("buildId", "test-su-exec")
                    .put("sdkSha256", "sdk-digest").put("helperBuildId", "helper-build")).toString(),
        )!!
        override fun environment() = receipt(state, sdkAvailable).let {
            val raw = JSONObject(it.raw)
            raw.getJSONObject("data").put("state", state)
            NativeReceipt.parse(raw.toString())!!
        }
        override fun authorizations() = UltraRuntimeClient.SuAuthSnapshot(receipt(ok = sdkAvailable), listOf("dev.maplesu.manager"))
        override fun rootCommand(command: String): NativeReceipt {
            commands += command
            rootReceipt?.let { return it }
            if (command.startsWith("dmesg") && busyDmesgReads-- > 0) {
                return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":false,"sdkError":"MAPLESU_SDK_BUSY"}""")!!
            }
            if (command.contains("recovery_state:") && recoveryOutput != null) return receipt(recoveryOutput!!)
            if (command.contains("module_policy_diagnostics:") && policyOutput != null) return receipt(policyOutput!!)
            return receipt("$command\n$secret\n", sdkAvailable &&
                !(failPackages && command.contains("packages.list")) && !(failBoot && command.contains(".boot_session.work")))
        }
        override fun selfSu(): Pair<Int?, String?> = null to "SU_NOT_ROOT:exit=127:uid=null"
    }

    @Test fun disabledCollectionDoesNotCreatePortOrTouchSdk() {
        val directory = temporary.newFolder()
        UltraBugreportDiagnostics.collect(directory, false) { error("SDK must not be loaded") }
        assertTrue(directory.list()!!.isEmpty())
    }

    @Test fun deadlineDiagnosticsDoNotRetryExpiredCommands() {
        val directory = temporary.newFolder()
        val port = Port().apply {
            rootReceipt = NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"run_root_cmd","ok":false,"sdkError":"MAPLESU_SDK_DEADLINE_EXCEEDED","sdkErrorCode":-1007,"reason":"Current request expired before submission."}""")!!
        }
        UltraBugreportDiagnostics.collect(directory, true) { port }
        assertEquals(6, port.commands.size)
        assertEquals(port.commands.size, port.commands.distinct().size)
        val report = File(directory, "ultra-authorization.txt").readText()
        assertTrue(report.contains("sdkError=MAPLESU_SDK_DEADLINE_EXCEEDED sdkErrorCode=-1007"))
    }

    @Test fun sdkEvidenceIsCollectedEvenWhenNoKeySuIsBroken() {
        val directory = temporary.newFolder()
        val port = Port()
        UltraBugreportDiagnostics.collect(directory, true) { port }
        assertTrue(File(directory, "packages.txt").readText().startsWith("cat /data/system/packages.list\n"))
        assertTrue(File(directory, "dmesg.txt").length() > 0)
        val report = File(directory, "ultra-authorization.txt").readText()
        assertTrue(report.contains("sdk_root_identity"))
        assertTrue(report.contains("buildId=test-su-exec"))
        assertTrue(report.contains("sdkSha256=sdk-digest"))
        assertTrue(report.contains("manager_no_key_su: uid=null failure=SU_NOT_ROOT"))
        assertTrue(report.contains("not a target-app execution proof"))
        assertEquals(6, port.commands.size)
    }

    @Test fun bootReceiptAndProtectionEvidenceUseTheWorkingSdkChannel() {
        val directory = temporary.newFolder()
        val port = Port().apply { helperPath = "/data/Abcd0123456789ef/init"; state = "Fault" }
        UltraBugreportDiagnostics.collect(directory, true) { port }
        val boot = File(directory, "ultra-environment-boot.txt")
        assertTrue("Fault diagnostics must include boot receipts without relying on no-key su", boot.isFile)
        val script = port.commands.single { it.contains(".boot_session.work") }
        for (field in listOf("boot_id", ".safe_flag", ".boot_fail_protect", ".boot_session.duplicate")) {
            assertTrue(script.contains(field))
        }
        assertTrue("boot protection needs the actual flag bytes, not only file sizes",
            script.contains("for suffix in safe_flag boot_fail_protect log.enable"))
        assertTrue(script.contains("init.log.enable"))
        assertFalse(script.contains("init.enable"))
        assertTrue(script.contains("od -An -tx1 -N16"))
        assertFalse(script.contains("rm "))
        assertFalse(script.contains("reboot"))
        assertTrue(File(directory, "ultra-authorization.txt").readText().contains("manager_no_key_su: uid=null"))
        assertTrue(File(directory, "ultra-authorization.txt").readText().contains("state=Fault"))
    }

    @Test fun failedBootReadRemainsAnErrorAndDoesNotSuppressOtherSdkEvidence() {
        val directory = temporary.newFolder()
        UltraBugreportDiagnostics.collect(directory, true) { Port().apply {
            helperPath = "/data/Abcd0123456789ef/init"; failBoot = true; state = "Fault"
        } }
        assertFalse(File(directory, "ultra-environment-boot.txt").exists())
        assertTrue(File(directory, "packages.txt").isFile)
        assertTrue(File(directory, "ultra-authorization.txt").readText()
            .contains("ultra-environment-boot.txt: ok=false sdkError=EIO"))
    }

    @Test fun helperLogsRedactHistoricalCredentialsBeforeWritingStagingFiles() {
        val directory = temporary.newFolder()
        val historicalKey = "OldKey19".repeat(6)
        assertEquals(48, historicalKey.length)
        UltraBugreportDiagnostics.collect(directory, true) { Port().apply {
            helperPath = "/data/Abcd0123456789ef/init"; secret = historicalKey
        } }
        val text = File(directory, "ultra-environment-boot.txt").readText()
        assertFalse(text.contains(historicalKey))
        assertTrue(text.contains("<REDACTED-KEY>"))
    }

    @Test fun invalidHelperPathsNeverBecomeCommands() {
        for (path in listOf("/data/abcd/init", "/data/Abcd0123456789ef/init; id", "/other/init")) {
            val directory = temporary.newFolder()
            val port = Port().apply { helperPath = path }
            UltraBugreportDiagnostics.collect(directory, true) { port }
            assertEquals(6, port.commands.size)
            assertFalse(File(directory, "ultra-environment-boot.txt").exists())
        }
    }

    @Test fun existingEvidenceIsNotOverwritten() {
        val directory = temporary.newFolder()
        File(directory, "logcat.txt").writeText("original")
        val port = Port()
        UltraBugreportDiagnostics.collect(directory, true) { port }
        assertEquals("original", File(directory, "logcat.txt").readText())
        assertFalse(port.commands.any { it.startsWith("logcat") })
    }

    @Test fun oneFailedCommandDoesNotSuppressOtherEvidence() {
        val directory = temporary.newFolder()
        val port = Port().apply { failPackages = true }
        UltraBugreportDiagnostics.collect(directory, true) { port }
        assertFalse(File(directory, "packages.txt").exists())
        assertTrue(File(directory, "dmesg.txt").length() > 0)
        assertTrue(File(directory, "ultra-authorization.txt").readText().contains("EIO"))
    }

    @Test fun failedRootReceiptsKeepPhaseAndErrnoForEveryRecordedOperation() {
        val directory = temporary.newFolder()
        val root = JSONObject().put("phase", 7).put("systemError", 13)
            .put("rootPhase", "task_state").put("rootSystemError", 30).put("rootError", "-19934")
            .put("rootAttempted", true).put("rootReturned", true).put("rootReportReceived", true)
            .put("credentials", JSONObject().put("attempted", true).put("completed", true).put("effects", 12))
            .put("taskState", JSONObject().put("error", "-19934").put("status", 13).put("completed", false))
        val failed = receipt(ok = false).let {
            val raw = JSONObject(it.raw).put("sdkError", "ERR_MODULE_OPEN_FILE").put("sdkErrorCode", -19934)
            raw.getJSONObject("data").put("rootCommand", root)
            NativeReceipt.parse(raw.toString())!!
        }
        UltraBugreportDiagnostics.collect(directory, true) { Port().apply { rootReceipt = failed } }
        val report = File(directory, "ultra-authorization.txt").readText()
        for (label in listOf("sdk_root_identity", "ultra-recovery.txt", "ultra-module-policy.txt", "packages.txt", "dmesg.txt", "logcat.txt")) {
            assertTrue(report.contains("$label: ok=false sdkError=ERR_MODULE_OPEN_FILE sdkErrorCode=-19934\n"))
            assertTrue(report.contains("$label.rootCommand.phase=7\n"))
            assertTrue(report.contains("$label.rootCommand.systemError=13\n"))
            assertTrue(report.contains("$label.rootCommand.rootPhase=task_state\n"))
            assertTrue(report.contains("$label.rootCommand.rootSystemError=30\n"))
            assertTrue(report.contains("$label.rootCommand.credentials.completed=true\n"))
            assertTrue(report.contains("$label.rootCommand.taskState.error=-19934\n"))
        }
        assertEquals(setOf("ultra-authorization.txt"), directory.list()!!.toSet())
    }

    @Test fun receiptsWithoutRootCommandKeepTheirExistingEvidence() {
        val directory = temporary.newFolder()
        UltraBugreportDiagnostics.collect(directory, true) { Port() }
        val report = File(directory, "ultra-authorization.txt").readText()
        assertTrue(report.contains("sdk_root_identity: ok=true sdkError=OK sdkErrorCode=0\n"))
        assertTrue(report.contains("sdk_root_identity_output:\nid; getenforce\n"))
        assertFalse(report.contains(".rootCommand."))
        assertTrue(File(directory, "packages.txt").isFile)
    }

    @Test fun rootDiagnosticsExcludeSensitiveExtraFieldsAndNonScalarValues() {
        val directory = temporary.newFolder()
        val secret = "Secret99".repeat(6)
        val root = JSONObject().put("phase", JSONObject().put("result", secret)).put("systemError", 13)
            .put("rootPhase", "task_state\nrootKey=$secret")
            .put("rootKey", secret).put("command", secret).put("result", secret).put("handle", secret)
            .put("credentials", JSONObject().put("error", "-19934").put("completed", false)
                .put("rootKey", secret).put("command", secret).put("result", secret).put("handle", secret))
            .put("taskState", JSONObject().put("status", 13).put("token", secret).put("nonce", secret))
        val failed = receipt(secret, ok = false).let {
            val raw = JSONObject(it.raw).put("rootKey", secret).put("command", secret)
            raw.getJSONObject("data").put("rootCommand", root).put("raw", secret)
            NativeReceipt.parse(raw.toString())!!
        }
        UltraBugreportDiagnostics.collect(directory, true) { Port().apply { rootReceipt = failed } }
        val report = File(directory, "ultra-authorization.txt").readText()
        assertTrue(report.contains("sdk_root_identity.rootCommand.systemError=13\n"))
        assertTrue(report.contains("sdk_root_identity.rootCommand.credentials.error=-19934\n"))
        assertFalse(report.contains(secret))
        for (field in listOf("phase", "rootPhase", "rootKey", "command", "result", "handle", "raw", "token", "nonce")) {
            assertFalse(report.contains(".rootCommand.$field="))
            assertFalse(report.contains(".rootCommand.credentials.$field="))
            assertFalse(report.contains(".rootCommand.taskState.$field="))
        }
    }

    @Test fun sdkFailureIsNotArchivedAsRootEvidence() {
        val directory = temporary.newFolder()
        UltraBugreportDiagnostics.collect(directory, true) { Port().apply { sdkAvailable = false } }
        assertEquals(setOf("ultra-authorization.txt"), directory.list()!!.toSet())
        assertTrue(File(directory, "ultra-authorization.txt").readText().contains("EIO"))
    }

    @Test fun newDiagnosticsAndSdkCollectedTextAreRedactedInArchive() {
        val directory = temporary.newFolder()
        val key = "Ab9_".repeat(12)
        UltraBugreportDiagnostics.collect(directory, true) { Port().apply {
            secret = key; helperPath = "/data/Abcd0123456789ef/init"; state = "Fault"
        } }
        val archive = BugreportArchive.pack(directory, File(temporary.root, "report.tar.gz"), listOf(key))
        GZIPInputStream(archive.inputStream()).use { gzip ->
            TarArchiveInputStream(gzip).use { tar ->
                while (true) {
                    tar.nextEntry ?: break
                    val text = tar.readBytes().toString(Charsets.UTF_8)
                    assertFalse(text.contains(key))
                    assertFalse(text.contains("Abcd0123456789ef"))
                }
            }
        }
    }

    @Test fun busySdkReadIsRecordedWithoutReplayingTheDiagnosticCommand() {
        val directory = temporary.newFolder()
        val port = Port().apply { busyDmesgReads = 1 }
        UltraBugreportDiagnostics.collect(directory, true) { port }
        assertFalse(File(directory, "dmesg.txt").exists())
        assertEquals(1, port.commands.count { it.startsWith("dmesg") })
        assertTrue(File(directory, "ultra-authorization.txt").readText().contains("sdkError=MAPLESU_SDK_BUSY"))
    }

    @Test fun busyAndOtherFailuresEachKeepOneOriginalAttempt() {
        val directory = temporary.newFolder()
        val port = Port().apply { busyDmesgReads = 100; failPackages = true }
        UltraBugreportDiagnostics.collect(directory, true) { port }
        assertEquals(1, port.commands.count { it.startsWith("dmesg") })
        assertEquals(1, port.commands.count { it.contains("packages.list") })
        assertFalse(File(directory, "dmesg.txt").exists())
        assertTrue(File(directory, "ultra-authorization.txt").readText().contains("sdkError=MAPLESU_SDK_BUSY"))
        assertTrue(File(directory, "logcat.txt").length() > 0)
    }

    @Test fun compatibilityFailureSurvivesExportWithBootAndCandidateIdentity() {
        val directory = temporary.newFolder()
        val evidence = "schema=1 operation=install boot=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n" +
            "kernel=6.6.89 pageSize=4096 btfBytes=1234\n" +
            "candidate=reference-build rejected=MODULE_POLICY_LOADER_NATIVE_ABI_CODE:commit_creds:1234\n" +
            "result=failed reason=MODULE_POLICY_BTF_OFFSET:task_struct.cred\n"
        val port = Port().apply { policyOutput = evidence }
        UltraBugreportDiagnostics.collect(directory, true) { port }
        assertEquals(evidence, File(directory, "ultra-module-policy.txt").readText())
        val command = port.commands.single { it.contains("module_policy_diagnostics:") }
        assertTrue(command.contains("compatibility.previous.log"))
        assertTrue(command.contains("experimental experimental-support"))
        assertTrue(command.contains("tail -c 65536"))
        assertFalse(command.contains("maplesu-policy preflight"))
        val archive = BugreportArchive.pack(directory, File(temporary.root, "policy.tar.gz"))
        var exported = false
        GZIPInputStream(archive.inputStream()).use { gzip ->
            TarArchiveInputStream(gzip).use { tar ->
                while (true) {
                    val entry = tar.nextEntry ?: break
                    if (entry.name == "ultra-module-policy.txt") {
                        assertEquals(evidence, tar.readBytes().toString(Charsets.UTF_8))
                        exported = true
                    }
                }
            }
        }
        assertTrue("compatibility evidence must be present in the exported archive", exported)
    }

    @Test fun recoveryFactsAreCollectedWithoutExportingConfirmationCredentials() {
        val directory = temporary.newFolder()
        val port = Port().apply { recoveryOutput = "recovery_state:\nhidden=0\nhandover=pending\n" }
        UltraBugreportDiagnostics.collect(directory, true) { port }
        val facts = File(directory, "ultra-recovery.txt")
        assertTrue("Ultra diagnostics must include the restore state even without a libsu shell", facts.isFile)
        assertTrue(facts.readText().contains("handover=pending"))
        val script = port.commands.single { it.contains("recovery_state:") }
        assertTrue(script.contains("host.manifest"))
        assertTrue(script.contains("manager-uninstall.receipt"))
        assertFalse(script.contains("cat \"\$R/manager-restore.ticket\""))
        assertFalse(script.contains("cat \"\$R/rootkey\""))
        assertFalse(script.contains("cat \"\$R/identity.json\""))
        assertFalse(script.contains("cat \"\$R/webui.conf\""))
    }
}
