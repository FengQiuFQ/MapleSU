package com.maplesu.core.ui.viewmodel

import android.content.pm.PackageInfo
import com.maplesu.core.Natives
import com.maplesu.core.data.model.AppInfo
import com.maplesu.core.ui.screen.superuser.GroupedApps
import com.maplesu.core.ui.screen.superuser.withCurrentDelivery
import dev.maplesu.manager.runtime.State
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.SuUidProfile
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import sun.misc.Unsafe

class SuperuserCurrentDeliveryTest {
    private val unsafe = Unsafe::class.java.getDeclaredField("theUnsafe").let {
        it.isAccessible = true
        it.get(null) as Unsafe
    }

    private fun app(name: String = "fixture.su", pending: Boolean = false, stale: Boolean = false): AppInfo =
        AppInfo("Fixture", unsafe.allocateInstance(PackageInfo::class.java) as PackageInfo,
            Natives.Profile(name, currentUid = 110472, allowSu = true), profileKey = name,
            authorizationPending = pending, authorizationStale = stale)

    private fun row(vararg apps: AppInfo): GroupedApps = GroupedApps(110472, apps.toList(), apps.first(),
        anyAllowSu = true, anyCustom = true, shouldUmount = true)

    private fun read(
        uid: Int = 110472,
        name: String = "fixture.su",
        allow: Boolean = true,
        entry: Boolean? = true,
        ok: Boolean = true,
        current: () -> Boolean = { true },
    ): ManagerAuthorizations.CurrentDeliveryRead {
        val receipt = NativeReceipt(1, UltraRuntimeClient.BACKEND, 1, "get_su_uid_profiles", ok,
            if (ok) "OK" else "ERR_MODULE_TEST_CHANNEL", if (ok) 0 else -19999, null, null, "fixture-current-read")
        return ManagerAuthorizations.CurrentDeliveryRead(
            UltraRuntimeClient.SuUidProfilesSnapshot(receipt, listOf(SuUidProfile(uid, allow, name))),
            entryConfirmed = entry, current = current)
    }

    @Test fun currentAppliedUidAndCurrentEntryRestoreActiveDisplay() {
        val original = row(app())
        val result = original.withCurrentDelivery(read())
        assertEquals(State.WIRED, result.suState)
        assertTrue(result.anyAllowSu)
        assertTrue(result.anyCustom)
        assertTrue(result.shouldUmount)
        assertSame(original.primary, result.primary)
    }

    @Test fun currentAppliedUidWithoutEntryNeverClaimsActiveSu() {
        for (entry in listOf<Boolean?>(null, false))
            assertEquals(State.ENTRY_UNAVAILABLE, row(app()).withCurrentDelivery(read(entry = entry)).suState)
        assertEquals(State.ENTRY_UNAVAILABLE, row(app()).withCurrentDelivery(null).suState)
    }

    @Test fun changedBootOwnerOrExpiredObservationWithdrawsThePreviousPositive() {
        var current = true
        val observation = read(current = { current })
        val original = row(app())
        assertEquals(State.WIRED, original.withCurrentDelivery(observation).suState)
        current = false
        assertEquals(State.ENTRY_UNAVAILABLE, original.withCurrentDelivery(observation).suState)
    }

    @Test fun anotherAndroidUserOrMismatchedDecisionDoesNotConfirmThisFullUid() {
        val original = row(app())
        for (observation in listOf(read(uid = 10472), read(name = "fixture.other"), read(allow = false)))
            assertEquals(State.AUTHORIZATION_PENDING, original.withCurrentDelivery(observation).suState)
        assertEquals(State.ENTRY_UNAVAILABLE, original.withCurrentDelivery(read(ok = false)).suState)
    }

    @Test fun sharedUidAcceptsTheCurrentRepresentativeWithinThisActualGroup() {
        val original = row(app("fixture.member"), app("fixture.representative"))
        assertEquals(State.WIRED, original.withCurrentDelivery(read(name = "fixture.representative")).suState)
        assertEquals(State.AUTHORIZATION_PENDING,
            row(app(pending = true)).withCurrentDelivery(read()).suState)
        assertEquals(State.STALE, row(app(stale = true)).withCurrentDelivery(read()).suState)
    }

    @Test fun copyingAnApplicationForCachesDropsItsEphemeralProof() {
        val original = app().apply { currentDeliveryRead = read() }
        assertTrue(original.currentDeliveryRead != null)
        val cached = original.copy()
        assertNull(cached.currentDeliveryRead)
        assertEquals(original.profile, cached.profile)
        assertEquals(original.profileKey, cached.profileKey)
    }
}
