package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.*
import org.junit.Test
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.SuUidProfile
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient

class ManagerProfileDeliveryReadTest {
    private val identity = ApplicationIdentity(110123, "fixture.su", listOf("fixture.su"),
        setOf("a".repeat(64)), 1000, 2000, "/fixture/base.apk")

    private fun snapshot(applied: List<SuperuserApplied> = emptyList()): AuthorizationSnapshot =
        AuthorizationSnapshot(enabled = true, grants = mapOf(identity.uid to identity), rev = 4,
            uidRev = mapOf(identity.uid to 4L), applied = applied)

    private fun mark(rev: Long = 4, ok: Boolean = true, detail: String = "",
                     backend: String = "ULTRA_ALLOWLIST") = SuperuserApplied(backend, rev, 2000, ok, detail)

    private fun read(snapshot: AuthorizationSnapshot, current: ManagerAuthorizations.CurrentDeliveryRead? = null) =
        ManagerAuthorizations.profileDetailed(snapshot, identity.packageName, identity, current)

    private fun currentRead(profiles: List<SuUidProfile> = listOf(SuUidProfile(identity.uid, true, identity.packageName)),
                            current: () -> Boolean = { true }, error: String = "OK",
                            entry: Boolean = true): ManagerAuthorizations.CurrentDeliveryRead {
        val raw = "fixture-current-uid-read:$error"
        val receipt = NativeReceipt(1, UltraRuntimeClient.BACKEND, 1, "get_su_uid_profiles", error == "OK",
            error, if (error == "OK") 0 else -19999, null, null, raw)
        return ManagerAuthorizations.CurrentDeliveryRead(UltraRuntimeClient.SuUidProfilesSnapshot(receipt, profiles),
            entryConfirmed = entry, entryCode = "SU_TIMEOUT".takeUnless { entry },
            entryDetail = "SU_TIMEOUT".takeUnless { entry }.orEmpty(), current = current)
    }

    @Test fun durableAllowWithoutAppliedReceiptDoesNotConfirmDelivery() {
        val read = read(snapshot())
        assertEquals(identity.uid, read.profile!!.currentUid)
        assertTrue(read.profile!!.allowSu)
        assertEquals(false, read.deliveryConfirmed)
        assertEquals(SuCodes.SU_AUTH_APPLY_PENDING, read.code)
        assertTrue(read.detail.contains("appliedReceipt=absent"))
    }

    @Test fun failedMirrorKeepsDecisionAndCompleteOriginalDetail() {
        val original = "SDK_UID_LIST_UNREADABLE\nSDK_UID_READ:ERR_MODULE_TEST_CHANNEL:-19999"
        val read = read(snapshot(listOf(mark(ok = false, detail = original))))
        assertTrue(read.profile!!.allowSu)
        assertEquals(false, read.deliveryConfirmed)
        assertTrue(read.detail.contains(original))
        assertTrue(read.detail.contains("decisionRev=4"))
        assertTrue(read.detail.contains("appliedRev=4 appliedOk=false"))
    }

    @Test fun earlierSuccessfulMirrorDoesNotCoverNewDecision() {
        val read = read(snapshot(listOf(mark(rev = 3))))
        assertTrue(read.profile!!.allowSu)
        assertEquals(false, read.deliveryConfirmed)
    }

    @Test fun currentSuccessfulMirrorAndRuntimeReadConfirmItsRevision() {
        val read = read(snapshot(listOf(mark())), currentRead())
        assertEquals(true, read.deliveryConfirmed)
        assertNull(read.code)
        assertEquals("", read.detail)
    }

    @Test fun persistedSuccessfulMirrorWithoutCurrentRuntimeProofDoesNotConfirmDelivery() {
        val read = read(snapshot(listOf(mark())))
        assertTrue(read.profile!!.allowSu)
        assertEquals(false, read.deliveryConfirmed)
    }

    @Test fun sameRevisionLatestFailureWinsOverEarlierSuccess() {
        val read = read(snapshot(listOf(mark(), mark(ok = false, detail = "current-failure"))))
        assertEquals(false, read.deliveryConfirmed)
        assertTrue(read.detail.contains("current-failure"))
    }

    @Test fun sameRevisionLatestSuccessRetiresEarlierFailure() {
        val read = read(snapshot(listOf(mark(ok = false, detail = "old-failure"), mark())), currentRead())
        assertEquals(true, read.deliveryConfirmed)
        assertFalse(read.detail.contains("old-failure"))
    }

    @Test fun lowerRevisionHistoricalBackendDoesNotMaskCurrentBackend() {
        val read = read(snapshot(listOf(mark(), mark(rev = 3, ok = false, backend = "KSU_ALLOWLIST"))), currentRead())
        assertEquals(true, read.deliveryConfirmed)
    }

    @Test fun explicitPendingRevisionStillBlocksDeliveryConfirmation() {
        val read = read(snapshot(listOf(mark())).copy(pendingApplyRev = 4), currentRead())
        assertTrue(read.profile!!.allowSu)
        assertEquals(false, read.deliveryConfirmed)
    }

    @Test fun pendingModeSwitchStillBlocksDeliveryConfirmation() {
        val read = read(snapshot(listOf(mark())).copy(switchPending = true), currentRead())
        assertEquals(false, read.deliveryConfirmed)
    }

    @Test fun completeProfileFieldsAndFullUidSurviveFailedDelivery() {
        val profile = SuProfile.legacy(identity.packageName, identity.uid, true).copy(
            rootUseDefault = false, rootTemplate = "fixture.template", uid = 123, gid = 456,
            groups = listOf(1007, 3003), capabilities = listOf(0, 21), context = "u:r:fixture:s0",
            namespace = 2, nonRootUseDefault = false, umountModules = false)
        val read = read(snapshot(listOf(mark(ok = false))).copy(
            profiles = mapOf(identity.uid to StoredSuProfile(identity, profile)),
            profileRev = mapOf(identity.uid to 4L)))
        val observed = ManagerSuProfiles.fromNative(read.profile!!)
        assertEquals(profile, observed)
        assertEquals(110123, observed.currentUid)
        assertEquals(false, read.deliveryConfirmed)
    }

    @Test fun currentTombstoneKeepsDecisionRevokedEvenWithAnOlderStoredGrant() {
        val read = read(snapshot(listOf(mark())).copy(
            uidRev = mapOf(identity.uid to 2L),
            tombs = listOf(SuperuserTomb(identity.uid, identity.packageName, 3, 2000))))
        assertFalse(read.profile!!.allowSu)
    }

    @Test fun identityChangeDoesNotRestoreAnOldProfile() {
        val profile = SuProfile.legacy(identity.packageName, identity.uid, true)
        val changed = ApplicationIdentity(identity.uid, identity.packageName, listOf(identity.packageName),
            setOf("b".repeat(64)), 1000, 3000, "/fixture/changed.apk")
        val observed = snapshot(listOf(mark())).copy(
            profiles = mapOf(identity.uid to StoredSuProfile(identity, profile)),
            profileRev = mapOf(identity.uid to 4L))
        assertThrows(IllegalStateException::class.java) {
            ManagerAuthorizations.profileDetailed(observed, identity.packageName, changed)
        }
    }

    @Test fun corruptAuthorityDoesNotYieldAProfileOrDeliveryFact() {
        assertThrows(IllegalStateException::class.java) { read(snapshot(listOf(mark())).copy(corrupt = true)) }
    }

    @Test fun anotherPackageCannotUseThisIdentitysDeliveryReceipt() {
        val read = ManagerAuthorizations.profileDetailed(snapshot(listOf(mark())), "fixture.other", identity)
        assertNull(read.profile)
        assertNull(read.deliveryConfirmed)
        assertEquals("PROFILE_IDENTITY_MISMATCH", read.code)
    }

    @Test fun currentSdkFailureKeepsStoredProfileAndRawReadError() {
        val read = read(snapshot(listOf(mark())), currentRead(error = "ERR_MODULE_TEST_CHANNEL"))
        assertTrue(read.profile!!.allowSu)
        assertEquals(false, read.deliveryConfirmed)
        assertEquals("ERR_MODULE_TEST_CHANNEL", read.code)
        assertTrue(read.detail.contains("fixture-current-uid-read:ERR_MODULE_TEST_CHANNEL"))
    }

    @Test fun currentRowForPrimaryUserDoesNotConfirmSecondaryUser() {
        val read = read(snapshot(listOf(mark())), currentRead(listOf(SuUidProfile(10123, true, identity.packageName))))
        assertEquals(110123, read.profile!!.currentUid)
        assertEquals(false, read.deliveryConfirmed)
    }

    @Test fun currentRowForAnotherPackageDoesNotConfirmThisIdentity() {
        val read = read(snapshot(listOf(mark())), currentRead(listOf(SuUidProfile(identity.uid, true, "fixture.other"))))
        assertEquals(false, read.deliveryConfirmed)
    }

    @Test fun missingOrDifferentCurrentDecisionDoesNotConfirmStoredAllow() {
        assertEquals(false, read(snapshot(listOf(mark())), currentRead(emptyList())).deliveryConfirmed)
        assertEquals(false, read(snapshot(listOf(mark())), currentRead(
            listOf(SuUidProfile(identity.uid, false, identity.packageName)))).deliveryConfirmed)
    }

    @Test fun scopeChangeAfterReadDoesNotConfirmDelivery() {
        var current = true
        val proof = currentRead(current = { current })
        current = false
        val read = read(snapshot(listOf(mark())), proof)
        assertEquals(false, read.deliveryConfirmed)
        assertEquals("SU_AUTH_SCOPE_CHANGED", read.code)
        assertNull(read.entryConfirmed)
    }

    @Test fun scopeChangeWhileReadingProfileDoesNotPublishAnEarlierPositive() {
        var observations = 0
        val proof = currentRead(current = { ++observations == 1 })
        val read = read(snapshot(listOf(mark())), proof)
        assertEquals(false, read.deliveryConfirmed)
        assertEquals("SU_AUTH_SCOPE_CHANGED", read.code)
        assertNull(read.entryConfirmed)
    }

    @Test fun currentMirrorDoesNotManufactureStandardSuEntry() {
        val read = read(snapshot(listOf(mark())), currentRead(entry = false))
        assertEquals(true, read.deliveryConfirmed)
        assertEquals(false, read.entryConfirmed)
        assertEquals("SU_TIMEOUT", read.code)
        assertTrue(read.detail.contains("SU_TIMEOUT"))
    }

    @Test fun currentDenyReadbackDoesNotRegrantAndCanConfirmItsDecision() {
        val snapshot = snapshot(listOf(mark())).copy(grants = emptyMap())
        val read = read(snapshot, currentRead(listOf(SuUidProfile(identity.uid, false, identity.packageName))))
        assertFalse(read.profile!!.allowSu)
        assertEquals(true, read.deliveryConfirmed)
    }

    @Test fun newSdkIdentityWithoutStoredDecisionRetainsEditableDefaultProfile() {
        val read = ManagerAuthorizations.sdkProfileDetailed(identity.packageName, identity.uid,
            identity.members.keys, currentRead(emptyList()))
        assertEquals(identity.packageName, read.profile!!.name)
        assertEquals(identity.uid, read.profile!!.currentUid)
        assertFalse(read.profile!!.allowSu)
        assertNull(read.deliveryConfirmed)
        assertNull(read.entryConfirmed)
        assertNull(read.code)
    }

    @Test fun anotherCurrentSharedUidMemberCanConfirmTheSameFullUidDecision() {
        val shared = ApplicationIdentity(identity.uid, listOf(
            ApplicationIdentity.Installation(identity.packageName, identity.signers, 1000, 2000, "/fixture/base.apk"),
            ApplicationIdentity.Installation("fixture.shared", identity.signers, 1000, 2000, "/fixture/shared.apk")))
        val read = ManagerAuthorizations.profileDetailed(snapshot(listOf(mark())).copy(
            grants = mapOf(identity.uid to shared)), "fixture.shared", shared, currentRead())
        assertEquals("fixture.shared", read.profile!!.name)
        assertTrue(read.profile!!.allowSu)
        assertEquals(true, read.deliveryConfirmed)
    }
}
