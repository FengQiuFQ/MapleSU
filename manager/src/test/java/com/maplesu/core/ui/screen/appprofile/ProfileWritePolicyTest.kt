package com.maplesu.core.ui.screen.appprofile

import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.State
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ProfileWritePolicyTest {
    @Test fun olderFailureNeverReplacesANewerRequest() {
        val policy = ProfileWritePolicy("initial")
        val first = policy.request()
        val second = policy.request()
        assertFalse(policy.isLatest(first))
        assertTrue(policy.isLatest(second))
        assertNull(policy.complete(first, "grant", Natives.ProfileWriteResult(false)))
        assertEquals("revoke", policy.complete(second, "revoke", Natives.ProfileWriteResult(true))?.profile)
    }

    @Test fun newestFailureKeepsTheLastCommittedProfile() {
        val policy = ProfileWritePolicy("initial")
        val first = policy.request()
        val second = policy.request()
        assertNull(policy.complete(first, "grant", Natives.ProfileWriteResult(true)))
        val result = policy.complete(second, "revoke", Natives.ProfileWriteResult(false))
        assertEquals("grant", result?.profile)
        assertFalse(result!!.result.decisionCommitted)
    }

    @Test fun multipleFailuresKeepTheConfirmedProfile() {
        val policy = ProfileWritePolicy("initial")
        val first = policy.request()
        val second = policy.request()
        assertNull(policy.complete(first, "first", Natives.ProfileWriteResult(false)))
        assertEquals("initial", policy.complete(second, "second", Natives.ProfileWriteResult(false))?.profile)
    }

    @Test fun latestSuccessPublishesTheFullSubmittedValue() {
        data class Profile(val allow: Boolean, val domain: String, val groups: List<Int>)
        val initial = Profile(false, "custom-domain", listOf(123, 456))
        val policy = ProfileWritePolicy(initial)
        val desired = initial.copy(allow = true)
        val result = policy.complete(policy.request(), desired, Natives.ProfileWriteResult(true))
        assertEquals(desired, result?.profile)
        assertTrue(result!!.result.succeeded)
    }

    @Test fun committedDecisionIsKeptWhileFailedDeliveryNeverBecomesWorkingSu() {
        val policy = ProfileWritePolicy(false)
        val raw = Natives.ProfileWriteResult(true, pendingApply = true,
            code = "SU_TRANSPORT_UNAVAILABLE", detail = "decisionRev=4 markApplied=failed; SDK_UID_LIST_UNREADABLE")
        val completion = policy.complete(policy.request(), true, raw)!!
        assertTrue(completion.profile)
        assertSame(raw, completion.result)
        assertEquals(State.AUTHORIZATION_PENDING, profileDeliveryState(completion.profile, State.WIRED, raw, null))
        assertEquals("decisionRev=4 markApplied=failed; SDK_UID_LIST_UNREADABLE", completion.result.detail)
    }

    @Test fun originalCommitUnknownAndFreshGrantReadKeepTheDecisionWithoutClaimingDelivery() {
        val policy = ProfileWritePolicy(false)
        val raw = Natives.ProfileWriteResult(false, pendingApply = true, commitUnknown = true,
            code = "SU_TRANSPORT_UNAVAILABLE", detail = "expectedRev=4 observedRev=4 pending=true SDK_UID_LIST_UNREADABLE")
        val completion = policy.complete(policy.request(), true, raw, readback = true)!!
        assertTrue(completion.profile)
        assertSame(raw, completion.result)
        assertEquals(State.AUTHORIZATION_PENDING, profileDeliveryState(completion.profile, State.WIRED, raw, null))
        assertEquals(State.AUTHORIZATION_PENDING, profileDeliveryState(completion.profile, State.WIRED, raw, false))
    }

    @Test fun unknownSubmissionWithoutAReadDoesNotPublishTheRequestedGrant() {
        val policy = ProfileWritePolicy(false)
        val raw = Natives.ProfileWriteResult(false, commitUnknown = true, code = "PROFILE_WRITE_TIMEOUT")
        val completion = policy.complete(policy.request(), true, raw)!!
        assertFalse(completion.profile)
        assertEquals(State.NOT_AUTHORIZED, profileDeliveryState(completion.profile, State.WIRED, raw, null))
    }

    @Test fun onlyCurrentAppliedEvidenceClearsFailedDelivery() {
        val raw = Natives.ProfileWriteResult(true, pendingApply = true, code = "SDK_UID_LIST_UNREADABLE")
        assertEquals(State.AUTHORIZATION_PENDING, profileDeliveryState(true, State.WIRED, raw, null))
        assertEquals(State.AUTHORIZATION_PENDING, profileDeliveryState(true, State.WIRED, raw, false))
        assertEquals(State.WIRED, profileDeliveryState(true, State.WIRED, raw, true))
        assertEquals(State.ENTRY_UNAVAILABLE, profileDeliveryState(true, State.ENTRY_UNAVAILABLE, raw, true))
    }

    @Test fun unknownRevocationKeepsItsRawReceiptAndUsesTheCurrentReadbackDecision() {
        val policy = ProfileWritePolicy(true)
        val raw = Natives.ProfileWriteResult(false, commitUnknown = true,
            code = "PROFILE_WRITE_EXCEPTION", detail = "original-receipt")
        val completion = policy.complete(policy.request(), false, raw, readback = false)!!
        assertFalse(completion.profile)
        assertSame(raw, completion.result)
        assertEquals(State.NOT_AUTHORIZED, profileDeliveryState(false, State.WIRED, raw, null))
        assertEquals(State.ENTRY_UNAVAILABLE, profileDeliveryState(true, State.WIRED, raw, null))
    }

    @Test fun pendingAndUnknownNeverEraseAnInstallationMismatch() {
        val raw = Natives.ProfileWriteResult(true, pendingApply = true, commitUnknown = true)
        assertEquals(State.STALE, profileDeliveryState(false, State.STALE, raw, false))
        assertEquals(State.STALE, profileDeliveryState(true, State.STALE, raw, true))
    }

    @Test fun appliedReadOfTheOldProfileDoesNotEraseAFailedRequestedProfileChange() {
        data class Profile(val fullUid: Int, val allow: Boolean, val domain: String)
        val desired = Profile(110472, true, "new-domain")
        val old = desired.copy(domain = "old-domain")
        val pending = Natives.ProfileWriteResult(true, pendingApply = true, code = "PROFILE_SEPOLICY_APPLY_FAILED")
        assertFalse(profileWriteRecovered(pending, desired, old, true))
        assertFalse(profileWriteRecovered(pending, desired, desired.copy(fullUid = 10472), true))
        assertTrue(profileWriteRecovered(pending, desired, desired, true))
        assertFalse(profileWriteRecovered(pending, desired, desired, null))
    }

    @Test fun rejectedValidationIsStillAnOperationFailureWhenTheOldGrantIsApplied() {
        val rejected = Natives.ProfileWriteResult(false, code = "PROFILE_FIELDS_UNSUPPORTED", detail = "original-error")
        assertFalse(profileWriteRecovered(rejected, "requested", "old-confirmed", true))
        assertFalse(profileWriteRecovered(rejected, "requested", "requested", true))
        assertEquals(State.WIRED, profileDeliveryState(true, State.WIRED, rejected, true))
    }

    @Test fun screenPreservesProfileAndSerializesBackendCalls() {
        val source = File("src/main/java/com/maplesu/core/ui/screen/appprofile/AppProfileScreen.kt").readText()
        assertTrue(source.contains("val profileToSave = updatedProfile.copy("))
        assertTrue(source.contains("saveMutex.withLock"))
        assertTrue(source.contains("policy.complete(request, profileToSave, result, observed?.profile)"))
        assertFalse(source.contains("profile = previousProfile"))
        assertFalse(source.contains("profile = profileToSave"))
        assertTrue(source.contains("if (saving || loading || profileScope?.invoke() != true) return@change"))
        assertTrue(source.contains("PageReadDeadline.context(PROFILE_OPERATION_TIMEOUT_MILLIS)"))
        assertTrue(source.contains("Natives.getAppProfileFreshDetailed(packageName, uid)"))
        val write = source.substringAfter("onProfileChange = change@").substringBefore("when (uiMode)")
        assertFalse(write.contains("loadAttempt++"))
        assertFalse(write.contains("if (uiMode == UiMode.Material)"))
        assertTrue(write.contains("diagnosticDialog.show(title, detail)"))
        assertTrue(write.contains("viewModel.markNeedRefresh()"))
    }
}
