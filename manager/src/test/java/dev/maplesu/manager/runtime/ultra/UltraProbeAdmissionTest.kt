package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

class UltraProbeAdmissionTest {
    private val owner = UltraRuntimeClient.ManagerOwnerIdentity(android.os.Process.myUid(), 7, "ab".repeat(16))

    private fun receipt(operation: String, error: String = "OK", code: Int = 0, data: String = "{}") =
        requireNotNull(NativeReceipt.parse("""{"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,"operation":"$operation","ok":${code == 0},"sdkError":"$error","sdkErrorCode":$code,"data":$data}"""))

    @Test fun freshOwnerReadDoesNotWaitForTheHealthProbeLockOrGrantRoot() {
        val field = UltraEnvironmentProbe::class.java.getDeclaredField("probeLock").apply { isAccessible = true }
        val healthLock = field.get(null) as ReentrantLock
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val worker = Thread {
            healthLock.lock()
            try { entered.countDown(); release.await() } finally { healthLock.unlock() }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            var reads = 0
            val observed = UltraEnvironmentProbe.observeFreshIdentity(current = { true }, queryOwner = {
                reads++
                UltraRuntimeClient.ManagerOwnerIdentityResult(receipt("query_manager_owner_identity"), owner)
            })
            assertEquals(1, reads)
            assertEquals(owner, observed.managerOwnerIdentity)
            assertEquals(UltraEnvironmentProbe.State.Unknown, observed.state)
            assertFalse(observed.rootAvailable)
            assertFalse(observed.sdkChannelAvailable)
            assertNull(observed.rootProbeDetail)
        } finally { release.countDown(); worker.join(1_000) }
    }

    @Test fun nativeOwnerBusyAndScopeChangesNeverReuseAPreviousIdentity() {
        val previous = UltraEnvironmentProbe.currentSnapshot()
        try {
            UltraEnvironmentProbe.publishSnapshot(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running,
                kernelRootVerified = true, managerOwnerIdentity = owner, sdkChannelAvailable = true))
            for (error in listOf("MAPLESU_SDK_BUSY", "MAPLESU_SDK_INTERRUPTED", "MAPLESU_SDK_DEADLINE_EXCEEDED", "ERR_MODULE_NO_BOOT")) {
                val observed = UltraEnvironmentProbe.observeFreshIdentity(current = { true }, queryOwner = {
                    UltraRuntimeClient.ManagerOwnerIdentityResult(receipt("query_manager_owner_identity", error, -19914), null)
                })
                assertNull(observed.managerOwnerIdentity)
                assertEquals(UltraEnvironmentProbe.State.Unknown, observed.state)
                assertTrue(observed.detail!!.contains(error))
                assertFalse(observed.rootAvailable)
            }
            var reads = 0
            val cancelled = UltraEnvironmentProbe.observeFreshIdentity(current = { false }, queryOwner = {
                reads++; error("A stale scope must not query")
            })
            assertEquals(0, reads)
            assertNull(cancelled.managerOwnerIdentity)
            var current = true
            val changed = UltraEnvironmentProbe.observeFreshIdentity(current = { current }, queryOwner = {
                current = false
                UltraRuntimeClient.ManagerOwnerIdentityResult(receipt("query_manager_owner_identity"), owner)
            })
            assertNull(changed.managerOwnerIdentity)
            val foreignUser = UltraEnvironmentProbe.observeFreshIdentity(current = { true }, queryOwner = {
                UltraRuntimeClient.ManagerOwnerIdentityResult(receipt("query_manager_owner_identity"), owner.copy(fullUid = owner.fullUid + 100000))
            })
            assertNull(foreignUser.managerOwnerIdentity)
        } finally { UltraEnvironmentProbe.publishSnapshot(previous) }
    }

    @Test fun rootFailureReceiptSurvivesAnOkEnvironmentAndCurrentSignedOwner() {
        val environment = receipt("get_env_state", data = """{"state":"Running"}""")
        val failed = receipt("probe_manager_owner_root", "ERR_READ_CHILD_ERRCODE", -19914,
            """{"phase":11,"childStatus":256,"childStatusValid":true,"receiptComplete":false}""")
        val observed = UltraEnvironmentProbe.healthSnapshot(environment,
            ManagerOwnerRootResult(failed, null, null), owner, owner)
        assertEquals(owner, observed.managerOwnerIdentity)
        assertEquals(UltraEnvironmentProbe.State.Running, observed.state)
        assertFalse(observed.rootAvailable)
        assertEquals(failed.raw, observed.rootProbeDetail)
        assertTrue(observed.detail!!.contains("sdkError=OK"))
        assertTrue(observed.rootProbeDetail!!.contains("-19914"))
        assertTrue(observed.rootProbeDetail!!.contains("256"))
    }

    @Test fun anotherOwnerRootProofAndAChangedOwnerNeverGrantCurrentReadiness() {
        val environment = receipt("get_env_state", data = """{"state":"Running"}""")
        val another = owner.copy(epoch = 8)
        val root = ManagerOwnerRootResult(receipt("probe_manager_owner_root"),
            ManagerOwnerRootProof(another, "0000000000000001", 1), true)
        val mismatchedRoot = UltraEnvironmentProbe.healthSnapshot(environment, root, owner, owner)
        assertFalse(mismatchedRoot.rootAvailable)
        assertNotNull(mismatchedRoot.rootProbeDetail)
        val changedOwner = UltraEnvironmentProbe.healthSnapshot(environment, root, owner, another)
        assertEquals(another, changedOwner.managerOwnerIdentity)
        assertFalse(changedOwner.rootAvailable)
        assertFalse(changedOwner.sdkChannelAvailable)
        assertEquals(UltraEnvironmentProbe.State.Unknown, changedOwner.state)
    }

    @Test fun failedHealthConfirmationRetainsThisReadOwnerWithoutClaimingRootOrHealth() {
        val environment = receipt("get_env_state", data = """{"state":"Unknown"}""")
        val failed = receipt("probe_manager_owner_root", "ERR_READ_CHILD_ERRCODE", -19914,
            """{"phase":11,"childStatus":256,"receiptComplete":false}""")
        val observed = UltraEnvironmentProbe.healthSnapshot(environment,
            ManagerOwnerRootResult(failed, null, null), owner, confirmed = null)
        assertEquals(owner, observed.managerOwnerIdentity)
        assertEquals(UltraEnvironmentProbe.State.Unknown, observed.state)
        assertFalse(observed.rootAvailable)
        assertEquals(failed.raw, observed.rootProbeDetail)
    }

    @Test fun nullConfirmationNeverRetainsRootOrSdkCapabilityEvenWithAMatchingProof() {
        val environment = receipt("get_env_state", data = """{"state":"Running"}""")
        val root = ManagerOwnerRootResult(receipt("probe_manager_owner_root"),
            ManagerOwnerRootProof(owner, "0000000000000001", 1), true)
        val observed = UltraEnvironmentProbe.healthSnapshot(environment, root, owner, confirmed = null)
        assertEquals(owner, observed.managerOwnerIdentity)
        assertEquals(UltraEnvironmentProbe.State.Unknown, observed.state)
        assertFalse(observed.rootAvailable)
        assertFalse(observed.sdkChannelAvailable)
        assertEquals(root.receipt.raw, observed.rootProbeDetail)
    }

    @Test fun busyAdmissionPreservesTheLastObservationOnlyForTheSameKeyAndBoot() {
        val probe = UltraEnvironmentProbe
        for (previous in UltraEnvironmentProbe.State.entries) {
            assertEquals(previous, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_BUSY", true))
            assertEquals(UltraEnvironmentProbe.State.Unknown, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_BUSY", false))
        }
    }

    @Test fun anEnvironmentReadRetainsManagerSuFailureForTheSameOwnerAndBoot() {
        val previous = UltraEnvironmentProbe.currentSnapshot()
        val error = "SU_STORE_READ_FAILED;phase=11;sdkCode=-19914"
        val observed = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running,
            managerOwnerIdentity = owner, observedBootId = "boot-a", managerSuFailureDetail = error)
        try {
            UltraEnvironmentProbe.publishSnapshot(observed)
            UltraEnvironmentProbe.publishSnapshot(observed.copy(kernelRootVerified = true,
                sdkChannelAvailable = true, managerSuFailureDetail = null))
            val refreshed = UltraEnvironmentProbe.currentSnapshot()
            assertEquals(error, refreshed.managerSuFailureDetail)
            assertTrue(refreshed.rootAvailable)
            assertTrue(refreshed.sdkChannelAvailable)
        } finally { UltraEnvironmentProbe.publishSnapshot(previous) }
    }

    @Test fun managerSuDiagnosticsRequireTheCurrentFullOwnerOrLegacyAndBoot() {
        val observed = UltraEnvironmentProbe.Snapshot(managerOwnerIdentity = owner, observedBootId = "boot-a")
        assertTrue(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(observed, observed, "boot-a"))
        assertFalse(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(observed, observed, null))
        assertFalse(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(observed, observed, "boot-b"))
        assertFalse(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(observed,
            observed.copy(observedBootId = "boot-b"), "boot-a"))
        assertFalse(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(observed,
            observed.copy(managerOwnerIdentity = owner.copy(epoch = owner.epoch + 1)), "boot-a"))
        val unbound = observed.copy(managerOwnerIdentity = null)
        assertFalse(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(unbound, unbound, "boot-a"))
        val legacy = unbound.copy(legacyCredentialFingerprint = "current-legacy")
        assertTrue(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(legacy, legacy, "boot-a"))
        assertFalse(UltraEnvironmentProbe.managerSuDiagnosticScopeCurrent(legacy,
            legacy.copy(legacyCredentialFingerprint = "other-legacy"), "boot-a"))
    }

    @Test fun aNewBootNeverInheritsManagerSuFailureFromThePreviousBoot() {
        val previous = UltraEnvironmentProbe.currentSnapshot()
        val observed = UltraEnvironmentProbe.Snapshot(managerOwnerIdentity = owner,
            observedBootId = "boot-a", managerSuFailureDetail = "SU_STORE_READ_FAILED")
        try {
            UltraEnvironmentProbe.publishSnapshot(observed)
            UltraEnvironmentProbe.publishSnapshot(observed.copy(observedBootId = "boot-b", managerSuFailureDetail = null))
            assertNull(UltraEnvironmentProbe.currentSnapshot().managerSuFailureDetail)
        } finally { UltraEnvironmentProbe.publishSnapshot(previous) }
    }

    @Test fun cancelledAdmissionContainsNoNewEnvironmentObservation() {
        val probe = UltraEnvironmentProbe
        for (previous in UltraEnvironmentProbe.State.entries) {
            assertEquals(previous, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_INTERRUPTED", true))
            assertEquals(UltraEnvironmentProbe.State.Unknown, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_INTERRUPTED", false))
        }
    }

    @Test fun expiredAdmissionKeepsOnlyTheSameIdentityObservationWithoutANewCapability() {
        for (previous in UltraEnvironmentProbe.State.entries) {
            assertEquals(previous, UltraEnvironmentProbe.stateAfterAdmission(previous,
                UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_DEADLINE_EXCEEDED", true))
            assertEquals(UltraEnvironmentProbe.State.Unknown, UltraEnvironmentProbe.stateAfterAdmission(previous,
                UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_DEADLINE_EXCEEDED", false))
        }
    }

    @Test fun actualFaultAndUninstallationReplaceThePreviousRunningObservation() {
        val probe = UltraEnvironmentProbe
        assertEquals(UltraEnvironmentProbe.State.Fault, probe.stateAfterAdmission(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.Fault, "OK", true))
        assertEquals(UltraEnvironmentProbe.State.NotInstalled, probe.stateAfterAdmission(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.NotInstalled, "OK", true))
        assertEquals(UltraEnvironmentProbe.State.Unknown, probe.stateAfterAdmission(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.Unknown, "BROKEN_TRANSPORT", true))
    }

    @Test fun anUnconfirmedEnvironmentNeverDisplaysSuAsDisabled() {
        val probe = UltraEnvironmentProbe
        assertNull(probe.suEnabledState(UltraEnvironmentProbe.State.Unknown))
        assertNull(probe.suEnabledState(UltraEnvironmentProbe.State.NoKey))
        assertEquals(true, probe.suEnabledState(UltraEnvironmentProbe.State.Running))
        assertEquals(false, probe.suEnabledState(UltraEnvironmentProbe.State.Fault))
        assertEquals(false, probe.suEnabledState(UltraEnvironmentProbe.State.NotInstalled))
    }
}
