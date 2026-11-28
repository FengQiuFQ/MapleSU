package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import dev.maplesu.manager.compat.UltraStateStorage
import dev.maplesu.manager.modules.UltraRootKeyStore
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test
import sun.misc.Unsafe

class UltraStatelessEnvironmentRecoveryTest {
    private class Startup {
        var state = UltraEnvironmentProbe.State.Unknown
        var rootVerified = true
        var submitted = false
        var blocked: String? = null
        var installs = 0
        var installed = false
        var failAfterProbe = false
        var uncertain = false
        val calls = mutableListOf<String>()
        val port = Proxy.newProxyInstance(UltraAutoSetupAttempt.Port::class.java.classLoader,
            arrayOf(UltraAutoSetupAttempt.Port::class.java)) { _, method, _ ->
            calls += method.name
            when (method.name) {
                "blockedReason" -> blocked
                "state" -> state.also { if (failAfterProbe) blocked = "OWNER_CHANGED" }
                "kernelRootVerified" -> rootVerified
                "alreadySubmitted" -> submitted
                "recordAttempt", "refresh" -> Unit
                "markSubmitted" -> true.also { submitted = true }
                "clearUnsubmitted" -> Unit.also { submitted = false }
                "install" -> {
                    installs++
                    if (uncertain) UltraEnvironmentInstaller.Outcome(false, "REPLY_LOST", submissionUnknown = true)
                    else UltraEnvironmentInstaller.Outcome(true, "OK").also { installed = true }
                }
                else -> error("Unexpected startup call: ${method.name}")
            }
        } as UltraAutoSetupAttempt.Port

        fun setup() = UltraAutoSetupAttempt.run(port)
    }

    @Test fun noLocalInstallDataRecoversThroughTheCurrentPatchedCarrier() {
        val startup = Startup()
        val result = UltraStartupWarmup.run(
            UltraStartupWarmup.Input(null, true, false, false, false, false, false, false),
            recoverIdentity = { true },
            setupEnvironment = { startup.setup() },
            pairEnvironment = { startup.installed },
            retryDetection = {},
        )
        assertTrue("A current owner/root must recover without a stored helper path", result.paired)
        assertEquals(1, startup.installs)
        assertTrue(startup.calls.indexOf("kernelRootVerified") < startup.calls.indexOf("install"))
    }

    @Test fun unknownStateWithLiveRootInstallsAndKeepsUnknownUntilReadback() {
        val startup = Startup()
        assertTrue(startup.setup().installed)
        assertEquals(UltraEnvironmentProbe.State.Unknown, startup.state)
        assertEquals(1, startup.installs)
    }

    @Test fun recoveredIdentityDoesNotInvalidateItsInstallScopeBeforeSetup() {
        val startup = Startup()
        var scopeCurrent = true
        val result = UltraStartupWarmup.run(
            UltraStartupWarmup.Input(null, true, false, false, false, false, false, false),
            recoverIdentity = { true },
            setupEnvironment = {
                assertTrue("Detection must not replace the activation before installation", scopeCurrent)
                startup.setup()
            },
            pairEnvironment = { startup.installed },
            retryDetection = { scopeCurrent = false },
        )
        assertTrue(result.paired)
        assertFalse(scopeCurrent)
    }

    @Test fun aHealthyLiveEnvironmentFinishesPairingBeforeDetectionCanReplaceItsScope() {
        var detectionQueued = false
        var activation = 0
        var pairedReason: String? = null
        val result = UltraStartupWarmup.run(
            UltraStartupWarmup.Input(null, true, false, false, false, false, false, false,
                liveEnvironmentReady = true),
            setupEnvironment = { error("A live environment needs no install") },
            pairEnvironment = {
                val captured = activation
                UltraAutoPair.complete(UltraEnvironmentProbe.Snapshot(
                    state = UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
                    current = { captured == activation },
                    verifyManagerSu = {
                        if (detectionQueued) activation++
                        true
                    }, maintain = {},
                ).also { pairedReason = it.reason }.paired
            },
            retryDetection = { detectionQueued = true },
        )
        assertTrue(result.paired)
        assertEquals("RUNNING", pairedReason)
        assertTrue(detectionQueued)
    }

    @Test fun anUnresponsiveCarrierNeverBecomesAnAutomaticInstallLoop() {
        val startup = Startup().apply { rootVerified = false }
        repeat(3) {
            assertEquals("STATE_Unknown", startup.setup().reason)
            assertFalse(startup.submitted)
        }
        assertEquals(0, startup.installs)
    }

    @Test fun aLostInstallReplyRetainsItsRealSubmissionGuard() {
        val startup = Startup().apply { uncertain = true }
        assertEquals("INSTALL_RECONCILIATION_REQUIRED", startup.setup().reason)
        repeat(3) { assertFalse(startup.setup().attempted) }
        assertEquals(1, startup.installs)
        assertTrue(startup.submitted)
    }

    @Test fun liveRootDoesNotOverrideARealFaultOrRemovalOrScopeChange() {
        for (state in listOf(UltraEnvironmentProbe.State.Fault, UltraEnvironmentProbe.State.NoKey)) {
            val startup = Startup().apply { this.state = state }
            assertFalse(startup.setup().attempted)
            assertEquals(0, startup.installs)
        }
        val startup = Startup().apply { failAfterProbe = true }
        assertEquals("OWNER_CHANGED", startup.setup().reason)
        assertEquals(0, startup.installs)
        assertFalse(startup.submitted)
    }

    @Test fun verifiedIdleRecoveryStillUsesTheExistingStartPath() {
        val startup = Startup()
        val result = UltraAutoSetupAttempt.run(startup.port) {
            UltraEnvironmentAutoSetup.Result(true, true, "IDLE_RECOVERED")
        }
        assertTrue(result.installed)
        assertEquals(0, startup.installs)
    }

    @Test fun oldOrDamagedHelperReadbackCanBeReplacedThroughTheCurrentRootChannel() {
        for (root in listOf(false, true)) {
            val startup = Startup().apply { rootVerified = root }
            val result = UltraAutoSetupAttempt.run(startup.port) {
                UltraEnvironmentAutoSetup.Result(false, false, "IDLE_HELPER_UNVERIFIED")
            }
            assertEquals(root, result.installed)
            assertEquals(if (root) 1 else 0, startup.installs)
        }
    }

    @Test fun wrongTypedLegacyRecordIsAbsentRatherThanBlockingOwnerStartup() {
        for ((key, value) in listOf("rootKey" to 7, "keyVerified" to "true",
            "keyVerifiedFor" to 7, "rootKeySuspended" to false)) {
            val record = mutableMapOf<String, Any?>(
                "rootKey" to "A".repeat(48), "keyVerified" to true,
                "keyVerifiedFor" to "not-a-matching-fingerprint", key to value)
            assertNull("Wrong type for $key", UltraLegacyCredential.read(preferences(record)))
        }
    }

    @Test fun removalMarkerPresencePreservesExplicitRemovalEvenWithAWrongValueType() {
        val context = context(mutableMapOf("maplesu-ultra" to mutableMapOf("environmentRemoval" to true)))
        assertTrue(UltraRootKeyStore.isSuspended(context))
    }

    @Test fun damagedImportMarkersDoNotPreventReadingTheCurrentInstallation() {
        val values = mutableMapOf<String, MutableMap<String, Any?>>(
            "maplesu-state-imports" to mutableMapOf("maplesu-ultra" to "bad-type"),
            "maplesu-ultra" to mutableMapOf("maplesu.state.imported.v1" to 7),
            "maplesu-pro" to mutableMapOf("rootKey" to 7),
        )
        val result = UltraStateStorage.preferences(context(values), "maplesu-ultra", Context.MODE_PRIVATE)
        assertEquals(7, result.all["rootKey"])
        assertEquals(true, result.all["maplesu.state.imported.v1"])
        assertTrue(values.getValue("maplesu-pro").isEmpty())
        assertNull(UltraLegacyCredential.read(result))
    }

    @Test fun damagedSessionStateDoesNotBecomeACurrentBootOwner() {
        for (value in listOf(null, 7, false, setOf("session"), "", "malformed", "{}")) {
            val values = mutableMapOf<String, MutableMap<String, Any?>>(
                "maplesu-boot-sdk" to mutableMapOf("session" to value))
            assertNull("Session value=$value", UltraSdkSession.current(context(values)))
        }
    }

    @Test fun failedPriorBootUpgradeContinuationNeverFallsThroughToAnotherInstall() {
        for (resumed in listOf(UltraEnvironmentUpgrade.Result.FAILED, UltraEnvironmentUpgrade.Result.REFUSED)) {
            val startup = Startup()
            repeat(3) {
                val result = UltraEnvironmentAutoSetup.resumedInstallResult(resumed, false) ?: startup.setup()
                assertEquals("SDK_UPGRADE_PENDING", result.reason)
                assertFalse(result.attempted)
                assertFalse(result.installed)
            }
            assertEquals(0, startup.installs)
            assertTrue(startup.calls.isEmpty())
        }
        assertNull(UltraEnvironmentAutoSetup.resumedInstallResult(null, false))
        assertEquals("SDK_UPGRADE_PENDING", UltraEnvironmentAutoSetup.resumedInstallResult(null, true)?.reason)
        assertEquals("SDK_UPGRADE_PENDING", UltraEnvironmentAutoSetup.resumedInstallResult(
            UltraEnvironmentUpgrade.Result.FAILED, true)?.reason)
        assertTrue(UltraEnvironmentAutoSetup.resumedInstallResult(
            UltraEnvironmentUpgrade.Result.SUBMITTED, false)?.installed == true)
    }

    @Test fun confirmedPreparationFailureStopsAutomaticContinuationAndKeepsTheOriginalReceipt() {
        val failure = "SDK:POLICY_BACKEND_PREPARATION_FAILED:MODULE_TOOLS_TRANSPORT:" +
            "ERR_READ_CHILD_ERRCODE;sdkCode=-19914;phase=11;childStatus=256;receiptComplete=0"
        val saved = mutableMapOf<String, Any?>(
            "fullInstallCarrierBoot" to "old-boot", "lastBoot" to "current-boot",
            "lastPhase" to "install", "lastFailure" to failure)
        assertEquals(failure, UltraEnvironmentUpgrade.failedPreparationThisBoot(saved, "current-boot"))
        assertNull(UltraEnvironmentUpgrade.failedPreparationThisBoot(saved, "next-boot"))
        val result = UltraEnvironmentAutoSetup.resumedInstallResult(
            UltraEnvironmentUpgrade.Result.FAILED, false, failure)!!
        assertTrue(result.attempted)
        assertTrue(result.installationFailed)
        assertFalse(result.installed)
        assertEquals(failure, result.reason)
        val repeated = UltraEnvironmentAutoSetup.resumedInstallResult(null, false, failure)!!
        assertFalse(repeated.attempted)
        assertEquals(failure, repeated.reason)
        saved["lastFailure"] = null
        assertNull("A new explicit submission clears the previous diagnostic", 
            UltraEnvironmentUpgrade.failedPreparationThisBoot(saved, "current-boot"))
    }

    @Test fun aKnownPreparationFailureNeverReentersTheSdkFromStartup() {
        val field = UltraEnvironmentAutoSetup::class.java.getDeclaredField("processBootId").apply { isAccessible = true }
        val savedBoot = field.get(null)
        val boot = "11111111-2222-4333-8444-555555555555"
        try {
            field.set(null, boot)
            val values = mutableMapOf<String, MutableMap<String, Any?>>("ultra-env-upgrade" to mutableMapOf(
                "fullInstallCarrierBoot" to "old-boot", "lastBoot" to boot, "lastPhase" to "install",
                "lastFailure" to "SDK:POLICY_BACKEND_PREPARATION_FAILED:MODULE_TOOLS_TRANSPORT:ERR_READ_CHILD_ERRCODE"))
            repeat(3) { assertNull(UltraEnvironmentUpgrade.resumeFullInstall(context(values))) }
            assertEquals("old-boot", values.getValue("ultra-env-upgrade")["fullInstallCarrierBoot"])
        } finally { field.set(null, savedBoot) }
    }

    @Test fun unrelatedOrUncertainFailuresNeverBecomeAConfirmedPreparationFailure() {
        val base = mapOf<String, Any?>("lastBoot" to "boot", "lastPhase" to "install")
        for (failure in listOf(null, 7, "", "SDK:EXCEPTION", "SDK:HOTLOAD_REPLY_LOST",
            "SDK_IDENTITY_SCOPE_CHANGED")) {
            assertNull(UltraEnvironmentUpgrade.failedPreparationThisBoot(base + ("lastFailure" to failure), "boot"))
        }
        assertEquals("SDK_UPGRADE_PENDING", UltraEnvironmentAutoSetup.resumedInstallResult(
            UltraEnvironmentUpgrade.Result.FAILED, true, "SDK:POLICY_BACKEND_PREPARATION_FAILED")?.reason)
    }

    @Test fun preparationReceiptRemainsAvailableToTheExistingUpgradeExportWithoutRoot() {
        val values = mutableMapOf<String, MutableMap<String, Any?>>()
        val app = context(values)
        val diagnostic = "{\"sdkErrorCode\":-19914,\"rootCommand\":{\"phase\":11,\"childStatus\":256}}"
        UltraEnvironmentUpgrade.recordPreparationReceipt(app, diagnostic)
        assertEquals(diagnostic, values.getValue("ultra-env-upgrade")["lastPreparationReceipt"])
        assertTrue(UltraEnvironmentUpgrade.diagnostics(app).contains("preparationReceipt=$diagnostic"))
    }

    @Test fun onlyActualCurrentBootMarkersHoldAnUpgradeSubmission() {
        val field = UltraEnvironmentAutoSetup::class.java.getDeclaredField("processBootId").apply { isAccessible = true }
        val savedBoot = field.get(null)
        val boot = "11111111-2222-4333-8444-555555555555"
        try {
            field.set(null, boot)
            for (key in listOf("submittedBootId", "fullInstallCarrierBoot", "fullInstallEnvironmentBoot")) {
                for (value in listOf(null, "", "old-boot", 7, false, setOf(boot), boot)) {
                    val values = mutableMapOf<String, MutableMap<String, Any?>>(
                        "ultra-env-upgrade" to mutableMapOf(key to value))
                    assertEquals("key=$key value=$value", value == boot,
                        UltraEnvironmentUpgrade.fullInstallPendingThisBoot(context(values)))
                }
            }
        } finally { field.set(null, savedBoot) }
    }

    @Test fun aDamagedIdleSubmissionMarkerDoesNotBlockRecovery() {
        val field = UltraEnvironmentAutoSetup::class.java.getDeclaredField("processBootId").apply { isAccessible = true }
        val savedBoot = field.get(null)
        val boot = "11111111-2222-4333-8444-555555555555"
        try {
            field.set(null, boot)
            for (value in listOf(null, "", "old-boot", 7, false, setOf(boot), boot)) {
                val values = mutableMapOf<String, MutableMap<String, Any?>>(
                    "ultra-idle-recovery" to mutableMapOf("submittedBoot" to value))
                assertEquals("idle value=$value", value == boot,
                    UltraIdleEnvironmentRecovery.submittedThisBoot(context(values)))
            }
        } finally { field.set(null, savedBoot) }
    }

    private class TestContext private constructor() : ContextWrapper(null) {
        lateinit var stored: MutableMap<String, MutableMap<String, Any?>>
        override fun getApplicationContext(): Context = this
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
            preferences(stored.getOrPut(name) { mutableMapOf() })
    }

    internal fun context(values: MutableMap<String, MutableMap<String, Any?>>): Context {
        val field = Unsafe::class.java.getDeclaredField("theUnsafe").apply { isAccessible = true }
        val instance = (field.get(null) as Unsafe).allocateInstance(TestContext::class.java) as TestContext
        instance.stored = values
        return instance
    }

    companion object {
        private fun preferences(values: MutableMap<String, Any?>): SharedPreferences {
            val editor = Proxy.newProxyInstance(SharedPreferences.Editor::class.java.classLoader,
                arrayOf(SharedPreferences.Editor::class.java)) { proxy, method, args ->
                when {
                    method.name == "commit" -> true
                    method.name == "apply" -> Unit
                    method.name == "clear" -> proxy.also { values.clear() }
                    method.name == "remove" -> proxy.also { values.remove(args[0] as String) }
                    method.name.startsWith("put") -> proxy.also { values[args[0] as String] = args[1] }
                    else -> error("Unexpected editor call: ${method.name}")
                }
            } as SharedPreferences.Editor
            return Proxy.newProxyInstance(SharedPreferences::class.java.classLoader,
                arrayOf(SharedPreferences::class.java)) { _, method, args ->
                when (method.name) {
                    "getAll" -> values.toMap()
                    "contains" -> values.containsKey(args[0])
                    "edit" -> editor
                    "getString" -> if (!values.containsKey(args[0])) args[1]
                        else values[args[0]] as String?
                    "getBoolean" -> if (!values.containsKey(args[0])) args[1]
                        else values[args[0]] as Boolean
                    else -> error("Unexpected preference read: ${method.name}")
                }
            } as SharedPreferences
        }
    }
}
