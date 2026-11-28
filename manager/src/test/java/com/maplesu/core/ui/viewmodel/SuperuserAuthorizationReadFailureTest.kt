package com.maplesu.core.ui.viewmodel

import com.maplesu.core.data.model.AppInfo
import com.maplesu.core.ui.screen.superuser.GroupedApps
import com.maplesu.core.ui.screen.superuser.SuperUserUiState
import dev.maplesu.manager.runtime.State
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import sun.misc.Unsafe

/** Exercise the actual list failure consumer without starting a page, backend or Android process. */
class SuperuserAuthorizationReadFailureTest {
    private val unsafe = Unsafe::class.java.getDeclaredField("theUnsafe").let {
        it.isAccessible = true
        it.get(null) as Unsafe
    }

    private fun row(uid: Int, granted: Boolean, state: State): GroupedApps = GroupedApps(
        uid = uid,
        apps = emptyList(),
        primary = unsafe.allocateInstance(AppInfo::class.java) as AppInfo,
        anyAllowSu = granted,
        anyCustom = true,
        shouldUmount = true,
        suState = state,
    )

    private fun fail(initial: SuperUserUiState, error: Throwable): SuperUserViewModel {
        val viewModel = unsafe.allocateInstance(SuperUserViewModel::class.java) as SuperUserViewModel
        val state = MutableStateFlow(initial)
        for (name in listOf("_uiState", "uiState")) {
            SuperUserViewModel::class.java.getDeclaredField(name).apply {
                isAccessible = true
                set(viewModel, state)
            }
        }
        SuperUserViewModel::class.java.getDeclaredMethod("recordLoadFailure", Throwable::class.java).apply {
            isAccessible = true
            invoke(viewModel, error)
        }
        return viewModel
    }

    @Test fun unreadableCurrentAuthorityKeepsTheDecisionAndWithdrawsWorkingSu() {
        val original = row(10472, true, State.WIRED)
        val error = IllegalStateException("SDK_UID_READ:ERR_MODULE_TEST_CHANNEL:-19999")
        val viewModel = fail(SuperUserUiState(hasLoaded = true, groupedApps = listOf(original)), error)
        val state = viewModel.uiState.value
        assertEquals(State.ENTRY_UNAVAILABLE, state.groupedApps.single().suState)
        assertTrue(state.groupedApps.single().anyAllowSu)
        assertSame(original.primary, state.groupedApps.single().primary)
        assertTrue(state.groupedApps.single().anyCustom)
        assertTrue(state.groupedApps.single().shouldUmount)
        assertSame(error, state.error)
        assertTrue(viewModel.isNeedRefresh)
    }

    @Test fun failedReadWithdrawsTheClaimFromAllVisibleProjections() {
        val original = row(110472, true, State.WIRED)
        val viewModel = fail(SuperUserUiState(
            hasLoaded = true,
            groupedApps = listOf(original),
            searchResults = listOf(original),
            recentlyInstalledResults = listOf(original),
        ), IllegalStateException("HOOK_AUTHORITY_UNAVAILABLE"))
        val state = viewModel.uiState.value
        for (rows in listOf(state.groupedApps, state.searchResults, state.recentlyInstalledResults)) {
            assertEquals(110472, rows.single().uid)
            assertEquals(State.ENTRY_UNAVAILABLE, rows.single().suState)
            assertTrue(rows.single().anyAllowSu)
        }
    }

    @Test fun unreadableListPreservesPendingStaleAndUngrantedDecisions() {
        val rows = listOf(
            row(10472, true, State.AUTHORIZATION_PENDING),
            row(110472, false, State.STALE),
            row(10473, false, State.NOT_AUTHORIZED),
        )
        val viewModel = fail(SuperUserUiState(hasLoaded = true, groupedApps = rows),
            IllegalStateException("SDK_UID_LIST_UNREADABLE"))
        assertEquals(rows.map { it.uid }, viewModel.uiState.value.groupedApps.map { it.uid })
        assertEquals(rows.map { it.suState }, viewModel.uiState.value.groupedApps.map { it.suState })
        assertEquals(rows.map { it.anyAllowSu }, viewModel.uiState.value.groupedApps.map { it.anyAllowSu })
    }
}
