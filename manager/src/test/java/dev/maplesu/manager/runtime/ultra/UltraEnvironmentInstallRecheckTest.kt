package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraEnvironmentInstallRecheckTest {
    @Test fun channelLossAfterTheInitialProbeMustNotSubmitAnInstallation() {
        for (error in listOf("ERR_MODULE_NO_BOOT", "ERR_MODULE_ROOT_KEY", "ERR_MODULE_TEST_CHANNEL",
                             "MAPLESU_SDK_BUSY", "MAPLESU_BRIDGE_CHILD_EXIT")) {
            var submits = 0
            val port = object : UltraEnvironmentInstaller.InstallPort {
                override fun environmentState() = NativeReceipt.parse(
                    """{"backend":"maplesu_ultra","ok":false,"sdkError":"$error","sdkErrorCode":-1001}""")!!
                override fun submitInstall(): NativeReceipt {
                    submits++
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0}""")!!
                }
            }
            val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.ReuseRunning,
                UltraEnvironmentInstaller.Attachments(
                    whitelist = { error("failed observation must not authorize") },
                ))
            assertFalse("failed recheck must preserve $error", result.ok)
            assertEquals(error, result.sdkError)
            assertEquals(0, submits)
        }
    }

    @Test fun unreadableOrUnknownRecheckNeverTurnsIntoAnInstall() {
        for (state in listOf(null, "Unknown", "NoKey", "Fault")) {
            var submits = 0
            val port = object : UltraEnvironmentInstaller.InstallPort {
                override fun environmentState(): NativeReceipt {
                    if (state == null) error("transport lost")
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0,"data":{"state":"$state"}}""")!!
                }
                override fun submitInstall(): NativeReceipt {
                    submits++
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0}""")!!
                }
            }
            val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.ReuseRunning,
                UltraEnvironmentInstaller.Attachments(
                    whitelist = { error("unreadable state must not authorize") }))
            assertFalse(result.ok)
            assertEquals(0, submits)
        }
    }
    @Test fun deadlineBeforeInstallKeepsTheOriginalCodeWithoutInventingAnUnknownSubmission() {
        for (completed in listOf(false, true)) {
            var submissions = 0
            val port = object : UltraEnvironmentInstaller.InstallPort {
                override fun environmentState(): NativeReceipt = error("explicit install")
                override fun submitInstall(): NativeReceipt {
                    submissions++
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"install_maplesu_environment","ok":false,"sdkError":"MAPLESU_SDK_DEADLINE_EXCEEDED","sdkErrorCode":-1007,"reason":"Current request expired before submission.","operationCompleted":$completed}""")!!
                }
            }
            val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.InstallToBundledBuild,
                UltraEnvironmentInstaller.Attachments(whitelist = { error("An expired request does not authorize") },
                    verify = { error("An expired request does not claim installation") }))
            assertFalse(result.ok)
            assertFalse(result.verified)
            assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", result.sdkError)
            assertEquals(-1007, result.sdkErrorCode)
            assertEquals("Current request expired before submission.", result.reason)
            assertTrue(result.detail!!.contains("phase=install"))
            assertEquals(completed, result.submissionUnknown)
            assertEquals(1, submissions)
        }
    }

    @Test fun committedHotloadReplyLossIsPreservedAsUncertain() {
        var submissions = 0
        val port = object : UltraEnvironmentInstaller.InstallPort {
            override fun environmentState(): NativeReceipt = error("explicit install")
            override fun submitInstall(): NativeReceipt {
                submissions++
                return NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"install_maplesu_environment","ok":false,"sdkError":"HOTLOAD_REPLY_LOST","sdkErrorCode":-21002,"operationCompleted":true}""")!!
            }
        }
        val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.InstallToBundledBuild,
            UltraEnvironmentInstaller.Attachments(whitelist = { error("pending does not authorize") },
                verify = { error("pending does not claim installed") }))
        assertFalse(result.ok)
        assertFalse(result.verified)
        assertTrue(result.submissionUnknown)
        assertEquals(-21002, result.sdkErrorCode)
        assertEquals(1, submissions)
    }

    @Test fun completedInstallWithFailedReadbackStopsAfterOneObservationAndKeepsItsReceipt() {
        for (intent in listOf(UltraEnvironmentInstaller.Intent.InstallToBundledBuild,
                              UltraEnvironmentInstaller.Intent.UpgradeToBundledBuild)) {
            for (completed in listOf(false, true)) {
                val calls = mutableListOf<String>()
                val receipt = NativeReceipt.parse("""{"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,"operation":"install_maplesu_environment","ok":true,"sdkError":"OK","sdkErrorCode":0,"reason":"native install completed","operationCompleted":$completed}""")!!
                val port = object : UltraEnvironmentInstaller.InstallPort {
                    override fun environmentState(): NativeReceipt = error("explicit install")
                    override fun submitInstall(): NativeReceipt {
                        calls += "submit"
                        return receipt
                    }
                }
                var marker = true
                val result = UltraEnvironmentUpgrade.submitMarked({
                    UltraEnvironmentInstaller.install(port, intent,
                        UltraEnvironmentInstaller.Attachments(
                            whitelist = { calls += "whitelist"; error("unverified readback does not authorize") },
                            verify = {
                                calls += "verify"
                                IdentityObservation(InstalledIdentity.unknown("current-boot"),
                                    IdentityVerification(false, "IDENTITY_UNREADABLE", null),
                                    "ERR_MODULE_OPEN_FILE:readback:13")
                            },
                            persist = { calls += "persist" },
                            refreshProbe = { calls += "refresh" },
                            initializeAuthority = { calls += "authority"; null },
                        ))
                }, { marker = false })!!
                assertTrue(result.ok)
                assertFalse(result.verified)
                assertFalse("A successful native receipt remains a known submission", result.submissionUnknown)
                assertEquals(receipt.sdkError, result.sdkError)
                assertEquals(receipt.sdkErrorCode, result.sdkErrorCode)
                assertEquals(receipt.reason, result.reason)
                assertEquals("UNVERIFIED:IDENTITY_UNREADABLE readback=ERR_MODULE_OPEN_FILE:readback:13", result.detail)
                assertEquals(listOf("submit", "verify"), calls)
                assertTrue(marker)
                assertEquals(UltraEnvironmentUpgrade.Result.FAILED, UltraEnvironmentUpgrade.resultOf(result))
            }
        }
    }

    @Test fun failedVerificationOrIdentityCommitStopsAuthorizationAndProbeRefresh() {
        for (persistFails in listOf(false, true)) {
            val calls = mutableListOf<String>()
            val port = object : UltraEnvironmentInstaller.InstallPort {
                override fun environmentState(): NativeReceipt = error("explicit install")
                override fun submitInstall(): NativeReceipt {
                    calls += "submit"
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0,"reason":"native committed","operationCompleted":true}""")!!
                }
            }
            val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.UpgradeToBundledBuild,
                UltraEnvironmentInstaller.Attachments(
                    whitelist = { calls += "whitelist"; error("unverified installation does not authorize") },
                    verify = {
                        calls += "verify"
                        if (!persistFails) error("readback exception")
                        IdentityObservation(InstalledIdentity.unknown(), IdentityVerification.passed("current-build"))
                    },
                    persist = { calls += "persist"; error("identity commit failed") },
                    refreshProbe = { calls += "refresh" },
                    initializeAuthority = { calls += "authority"; null },
                ))
            assertTrue(result.ok)
            assertFalse(result.verified)
            assertFalse(result.submissionUnknown)
            assertEquals("OK", result.sdkError)
            assertEquals(0, result.sdkErrorCode)
            assertEquals("native committed", result.reason)
            assertEquals(if (persistFails) "UNVERIFIED:IDENTITY_PERSIST_FAILED"
                         else "UNVERIFIED:VERIFY_EXCEPTION:IllegalStateException", result.detail)
            assertEquals(if (persistFails) listOf("submit", "verify", "persist")
                         else listOf("submit", "verify"), calls)
        }
    }

    @Test fun scopeLossAfterCompletedSubmissionDoesNotRewriteItAsAnUnknownSubmission() {
        val calls = mutableListOf<String>()
        var submitted = false
        val port = object : UltraEnvironmentInstaller.InstallPort {
            override fun environmentState(): NativeReceipt = error("explicit install")
            override fun submitInstall(): NativeReceipt {
                calls += "submit"
                submitted = true
                return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0,"operationCompleted":true}""")!!
            }
        }
        val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.UpgradeToBundledBuild,
            UltraEnvironmentInstaller.Attachments(
                whitelist = { calls += "whitelist"; error("changed scope does not authorize") },
                verify = { calls += "verify"; error("changed scope does not read another identity") },
                refreshProbe = { calls += "refresh" },
                scopeFailure = { if (submitted) "INSTALL_IDENTITY_CHANGED" else null },
            ))
        assertTrue(result.ok)
        assertFalse(result.verified)
        assertFalse(result.submissionUnknown)
        assertEquals("OK", result.sdkError)
        assertEquals(0, result.sdkErrorCode)
        assertEquals("UNVERIFIED:INSTALL_IDENTITY_CHANGED", result.detail)
        assertEquals(listOf("submit"), calls)
    }

}
