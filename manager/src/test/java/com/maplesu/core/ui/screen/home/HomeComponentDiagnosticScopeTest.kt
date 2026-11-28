package com.maplesu.core.ui.screen.home

import com.maplesu.core.KernelVersion
import com.maplesu.core.ui.util.module.LatestVersionInfo
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient.ManagerOwnerIdentity
import dev.maplesu.manager.workmode.ActivationSource
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.ModeState
import dev.maplesu.manager.workmode.detect.SuReadiness
import org.junit.Assert.*
import org.junit.Test

class HomeComponentDiagnosticScopeTest {
    private val owner = ManagerOwnerIdentity(10498, 21L, "host-r21")
    private val activation = ModeActivation.Active(WorkMode.LITE, "boot-r21",
        ActivationSource.TEST_OVERRIDE, ModeState.MODE_A_ACTIVE, 21L)
    private val diagnostic = HomeUltraComponentDiagnostic(activation, 21L, "boot-r21", owner,
        null, "MODE_DETECT_FAILED", "root:pipe:EACCES:13:receipt=command10,status0,effects8")

    private fun readyState() = HomeUiState(
        kernelVersion = KernelVersion(6, 6, 89), ksuVersion = 10940,
        managerUAPIVersion = 1, kernelUAPIVersion = 1, lkmMode = false,
        isLkmBundled = false, isManager = true, isManagerPrBuild = false,
        isKernelPrBuild = false, requiresNewKernel = false, requiresNewManager = false,
        isRootAvailable = true, rootReadiness = SuReadiness.USABLE,
        isSafeMode = false, isLateLoadMode = false, checkUpdateEnabled = false,
        latestVersionInfo = LatestVersionInfo(), currentManagerVersionCode = 50201,
        systemInfo = SystemInfo("6.6.89", "5.2.1", "fixture", "fixture", "Unknown", 0),
        environmentMode = WorkMode.LITE, liteInstalled = true,
        environmentRuntimeReady = true, sdkRootAvailable = true,
    )

    private fun failedState() = readyState().copy(
        environmentRuntimeReady = false, sdkRootAvailable = false, isRootAvailable = false, rootReadiness = null,
        ultraObservationFailure = HomeEnvironmentFailure.FAILED, ultraObservationDetail = diagnostic.detail,
        ultraObservationCode = diagnostic.failureCode, ultraComponentDiagnostic = diagnostic,
    )

    private fun assertNoCurrentIdentity(current: HomeUiState) {
        assertNull(current.environmentMode)
        assertNull(current.previousEnvironmentMode)
        assertFalse(current.environmentConfirmedAbsent)
        assertTrue(current.environmentUnknown)
        assertTrue(current.environmentNeedsConfirmation)
        assertFalse(current.showInstalledStatus)
        assertFalse(current.showEnvironmentReady)
        assertFalse(current.isManager)
        assertFalse(current.isRootAvailable)
        assertFalse(current.sdkRootAvailable)
        assertFalse(current.environmentRuntimeReady)
        assertNull(current.rootReadiness)
        assertNull(current.ultraObservationCode)
        assertNull(current.ultraObservationDetail)
        assertNull(current.ultraComponentDiagnostic)
        assertFalse(current.environmentChecking)
        assertFalse(current.litePending)
    }

    private fun observation(
        owner: ManagerOwnerIdentity? = this.owner,
        legacy: String? = null,
        activation: ModeActivation = this.activation,
    ) = UltraEnvironmentProbe.Snapshot(
        detail = "MAPLESU_SDK_BUSY", managerOwnerIdentity = owner,
        modeActivation = activation, legacyCredentialFingerprint = legacy,
    )

    @Test fun aCurrentFailureDoesNotNeedAPositiveRootReadToRetainItsOriginalReceipt() {
        val current = observation()
        assertFalse(current.rootAvailable)
        assertFalse(diagnostic.isSupersededBy(activation, 21L, "boot-r21", current))
        assertEquals("MODE_DETECT_FAILED", diagnostic.failureCode)
        assertEquals("root:pipe:EACCES:13:receipt=command10,status0,effects8", diagnostic.detail)
    }

    @Test fun busyWithNoOwnerReplyDoesNotProveAnOwnerChange() {
        assertFalse(diagnostic.isSupersededBy(activation, 21L, "boot-r21", observation(owner = null)))
    }

    @Test fun aMissingBootReadDoesNotDiscardTheCurrentFailure() {
        for (boot in listOf(null, "")) {
            assertFalse(diagnostic.isSupersededBy(activation, 21L, boot, observation(owner = null)))
        }
    }

    @Test fun eachPartOfAnExplicitDifferentOwnerRevokesTheEarlierDiagnostic() {
        for (different in listOf(owner.copy(fullUid = owner.fullUid + 100000),
            owner.copy(epoch = owner.epoch + 1), owner.copy(hostInstance = "new-host"))) {
            assertTrue(diagnostic.isSupersededBy(activation, 21L, "boot-r21", observation(owner = different)))
        }
    }

    @Test fun anEqualActivationValueFromADifferentActivationIsANewScope() {
        val replacement = activation.copy()
        assertEquals(activation, replacement)
        assertNotSame(activation, replacement)
        assertTrue(diagnostic.isSupersededBy(replacement, 21L, "boot-r21", observation(activation = replacement)))
    }

    @Test fun aHealthObservationFromAnotherActivationRevokesTheEarlierDiagnostic() {
        assertTrue(diagnostic.isSupersededBy(activation, 21L, "boot-r21",
            observation(activation = activation.copy())))
    }

    @Test fun aNewRevisionOrBootRevokesTheEarlierDiagnostic() {
        assertTrue(diagnostic.isSupersededBy(activation, 22L, "boot-r21", observation()))
        assertTrue(diagnostic.isSupersededBy(activation, 21L, "boot-r22", observation()))
    }

    @Test fun legacyDiagnosticsUseTheRecordedFingerprintAndKeepMissingReplies() {
        val legacy = diagnostic.copy(managerOwnerIdentity = null, legacyCredentialFingerprint = "legacy-r21")
        assertFalse(legacy.isSupersededBy(activation, 21L, "boot-r21", observation(null, "legacy-r21")))
        assertFalse(legacy.isSupersededBy(activation, 21L, "boot-r21", observation(null)))
        assertTrue(legacy.isSupersededBy(activation, 21L, "boot-r21", observation(null, "legacy-r22")))
        assertTrue(legacy.isSupersededBy(activation, 21L, "boot-r21", observation()))
    }

    @Test fun aLateActivationReplacementClearsIdentityBeforeHistoryCanBeMerged() {
        val previous = readyState()
        val current = failedState().afterFinalEnvironmentScopeCheck(activation, 21L,
            activation.copy(), 21L).mergedOver(previous)
        assertNoCurrentIdentity(current)
    }

    @Test fun aLateDetectionRevisionOrBootChangeDoesNotPublishTheOldIdentity() {
        val previous = readyState()
        assertNoCurrentIdentity(previous.afterFinalEnvironmentScopeCheck(activation, 21L,
            activation, 22L).mergedOver(previous))
        assertNoCurrentIdentity(previous.afterFinalEnvironmentScopeCheck(activation, 21L,
            activation, 21L, currentBootId = "boot-r22", observedBootId = "boot-r21").mergedOver(previous))
    }

    @Test fun theSameFinalScopeKeepsTheCurrentStateWithoutGrantingANewProof() {
        val ready = readyState()
        assertSame(ready, ready.afterFinalEnvironmentScopeCheck(activation, 21L, activation, 21L))
        val failed = failedState()
        assertSame(failed, failed.afterFinalEnvironmentScopeCheck(activation, 21L, activation, 21L,
            currentBootId = "boot-r21", currentObservation = observation(owner = null), observedBootId = "boot-r21"))
        assertFalse(failed.sdkRootAvailable)
    }

    @Test fun aLateDifferentOwnerRevokesTheOldDiagnosticWithoutDemandingARootSuccess() {
        val current = failedState().afterFinalEnvironmentScopeCheck(activation, 21L, activation, 21L,
            currentBootId = "boot-r21", currentObservation = observation(owner.copy(epoch = 22L)))
        assertEquals(WorkMode.LITE, current.environmentMode)
        assertFalse(current.sdkRootAvailable)
        assertFalse(current.environmentRuntimeReady)
        assertFalse(current.showEnvironmentReady)
        assertNull(current.ultraComponentDiagnostic)
        assertNull(current.ultraObservationCode)
        assertEquals("SDK_IDENTITY_SCOPE_CHANGED", current.ultraObservationDetail)
    }
}
