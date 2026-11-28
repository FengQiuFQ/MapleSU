package com.maplesu.core.ui.screen.settings

import dev.maplesu.manager.runtime.ultra.UltraSdkLogging
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraEnvironmentDiagnosticRedactionTest {
    private val key = "A1".repeat(24)

    @Test fun currentRootAndSdkDiagnosticsRedactKeysAndKeepTheOriginalFailure() {
        val root = "operation=root; sdkCode=-19914; key=$key\r\nERR_READ_CHILD_ERRCODE; childExit=256"
        val sdk = "stage=pipe-write; errno=13; rootKey=$key"
        assertEquals(
            "operation=root; sdkCode=-19914; key=<REDACTED-KEY>\r\nERR_READ_CHILD_ERRCODE; childExit=256\n" +
                "stage=pipe-write; errno=13; rootKey=<REDACTED-KEY>",
            environmentDiagnosticDetail(root, sdk),
        )
    }

    @Test fun ownerlessSavedFailureIsRedactedAgainAtTheReadOnlyConsumer() {
        var reads = 0
        val detail = savedUltraInstallFailureDiagnostic(true, null, false, false) {
            reads++
            "SDK:POLICY_BACKEND_PREPARATION_FAILED; key=$key\nreceipt=ERR_MODULE_NO_BOOT"
        }
        assertEquals(1, reads)
        assertEquals("lastFailure=SDK:POLICY_BACKEND_PREPARATION_FAILED; key=<REDACTED-KEY>\nreceipt=ERR_MODULE_NO_BOOT", detail)
        assertFalse(UltraSdkLogging.containsKeyLike(detail))
    }

    @Test fun artifactHashesAndNonSecretErrorDetailsRemainComplete() {
        val detail = "stage=helper; sha256=${"ab".repeat(32)}; sdkCode=-19914; errno=13"
        assertEquals(detail, environmentDiagnosticDetail(detail))
        assertEquals("lastFailure=$detail", environmentDiagnosticDetail(null, persistedFailure = detail))
    }

    @Test fun managerSuOriginalReceiptRemainsSeparateFromSuccessfulEnvironmentReadback() {
        val manager = "reason=MANAGER_SU_UNVERIFIED;stage=client-connect;code=17;receipt=ROOT_BINDER_OWNER_MISSING"
        assertEquals("operation=get_maplesu_environment_state;sdkError=OK;sdkErrorCode=0\n$manager",
            environmentDiagnosticDetail("operation=get_maplesu_environment_state;sdkError=OK;sdkErrorCode=0",
                componentFailureDetail = manager))
    }

    @Test fun unknownEnvironmentOffersManualRecoveryWithoutClaimingAFault() {
        for (root in listOf(false, true)) {
            assertEquals(UltraEnvironmentRecoveryAction.RESTORE,
                environmentRecoveryAction(UltraEnvironmentProbe.State.Unknown, root, true, false, false))
        }
        assertEquals(UltraEnvironmentRecoveryAction.RESTORE,
            environmentRecoveryAction(UltraEnvironmentProbe.State.Fault, false, false, false, false))
    }

    @Test fun repairRecommendationsNeedCurrentExplicitFaultOrAbsenceAndRootEvidence() {
        assertEquals(UltraEnvironmentRecoveryAction.REPAIR,
            environmentRecoveryAction(UltraEnvironmentProbe.State.Fault, false, true, false, false))
        assertEquals(UltraEnvironmentRecoveryAction.REPAIR,
            environmentRecoveryAction(UltraEnvironmentProbe.State.NotInstalled, true, true, false, false))
        for (state in listOf(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.NoKey,
            UltraEnvironmentProbe.State.NotInstalled)) {
            assertEquals(UltraEnvironmentRecoveryAction.NONE,
                environmentRecoveryAction(state, false, true, false, false))
        }
        for ((diagnostic, hook) in listOf(true to false, false to true)) {
            assertEquals(UltraEnvironmentRecoveryAction.NONE,
                environmentRecoveryAction(UltraEnvironmentProbe.State.Fault, true, true, diagnostic, hook))
        }
    }

    @Test fun anAdmissionFailureDoesNotTurnARetainedFaultIntoCurrentRepairEvidence() {
        val owner = dev.maplesu.manager.runtime.ultra.UltraRuntimeClient.ManagerOwnerIdentity(10498, 7L, "host")
        val fault = UltraEnvironmentProbe.Snapshot(state = UltraEnvironmentProbe.State.Fault,
            detail = "operation=get_maplesu_environment_state;sdkError=OK;sdkErrorCode=0",
            managerOwnerIdentity = owner, sdkChannelAvailable = true)
        assertTrue(environmentRepairEvidence(fault))
        for (detail in listOf(
            "operation=get_maplesu_environment_state;sdkError=MAPLESU_SDK_BUSY;sdkErrorCode=-1005",
            "operation=get_maplesu_environment_state;sdkError=MAPLESU_SDK_DEADLINE_EXCEEDED;sdkErrorCode=-1007",
            "operation=get_maplesu_environment_state;sdkError=ERR_MODULE_NO_BOOT;sdkErrorCode=-19998",
            "lastFailure=PREFLIGHT_SUBMITTED_THIS_BOOT",
        )) {
            val current = fault.copy(detail = detail)
            assertFalse(environmentRepairEvidence(current))
            assertEquals(UltraEnvironmentRecoveryAction.RESTORE,
                environmentRecoveryAction(current.state, current.kernelRootVerified,
                    environmentRepairEvidence(current), false, false))
        }
        assertFalse(environmentRepairEvidence(fault.copy(managerOwnerIdentity = null)))
        assertFalse(environmentRepairEvidence(fault.copy(sdkChannelAvailable = false)))
        assertTrue(environmentRepairEvidence(fault.copy(managerOwnerIdentity = null,
            legacyCredentialFingerprint = "current-legacy")))
    }

    @Test fun aFreshReadCannotPublishOverANewerObservationOrReuseAnOldFault() {
        val fresh = UltraEnvironmentProbe.Snapshot(state = UltraEnvironmentProbe.State.Fault,
            observedAtElapsedMs = 42L, observedAtWallClockMs = 42L,
            detail = "operation=get_maplesu_environment_state;sdkError=OK;sdkErrorCode=0")
        val published = fresh.copy(managerSuFailureDetail = "stage=client-connect;receipt=OWNER_MISSING")
        assertTrue(environmentReadStillCurrent(fresh, published, published))
        val busy = published.copy(detail = "MAPLESU_SDK_BUSY", observedAtElapsedMs = 43L)
        assertFalse(environmentReadStillCurrent(fresh, published, busy))
        assertFalse(environmentReadStillCurrent(fresh, busy, busy))
        val running = published.copy(state = UltraEnvironmentProbe.State.Running, observedAtElapsedMs = 44L)
        assertFalse(environmentReadStillCurrent(fresh, published, running))
        assertFalse(environmentReadStillCurrent(fresh, published,
            published.copy(managerSuFailureDetail = "stage=client-connect;receipt=NEW_FAILURE")))
        val admissionFailure = UltraEnvironmentProbe.Snapshot(detail = "MAPLESU_SDK_BUSY")
        assertTrue(environmentReadStillCurrent(admissionFailure, published, published))
        assertFalse(environmentReadStillCurrent(admissionFailure, published, busy))
        assertFalse(environmentRepairEvidence(admissionFailure))
    }

    @Test fun aPrecomposedOrOldSettingsConsumerCannotClearANewerHomeClick() {
        val diagnostic = com.maplesu.core.ui.screen.home.HomeUltraComponentDiagnostic(
            dev.maplesu.manager.workmode.ModeActivation.Unresolved, 21L, "boot-r21",
            null, null, "MANAGER_SU_UNVERIFIED", "stage=client-connect;receipt=OWNER_MISSING")
        try {
            UltraComponentDiagnosticRequests.open(diagnostic)
            UltraComponentDiagnosticRequests.clear(null)
            assertTrue(UltraComponentDiagnosticRequests.clickedDiagnostic === diagnostic)
            val nextClick = diagnostic.copy(detail = "stage=pipe-read;code=13")
            UltraComponentDiagnosticRequests.open(nextClick)
            UltraComponentDiagnosticRequests.clear(diagnostic)
            assertTrue(UltraComponentDiagnosticRequests.clickedDiagnostic === nextClick)
            UltraComponentDiagnosticRequests.clear(nextClick)
            assertNull(UltraComponentDiagnosticRequests.clickedDiagnostic)
        } finally {
            UltraComponentDiagnosticRequests.clear()
        }
    }

    @Test fun hiddenOrPendingHistoryNeverReadsEvenASecretBearingFailure() {
        for ((hidden, pending) in listOf(true to false, false to true)) {
            var reads = 0
            assertNull(savedUltraInstallFailureDiagnostic(true, null, hidden, pending) { reads++; key })
            assertEquals(0, reads)
        }
    }
}
