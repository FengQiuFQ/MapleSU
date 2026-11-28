package com.maplesu.core.ui.screen.superuser

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.Stable
import androidx.compose.ui.graphics.Color
import com.maplesu.core.data.model.AppInfo
import com.maplesu.core.ui.component.SearchStatus
import com.maplesu.core.ui.viewmodel.AppSortConfig
import dev.maplesu.manager.runtime.State
import dev.maplesu.manager.runtime.managerSuState
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations

@Immutable
data class GroupedApps(
    val uid: Int,
    val apps: List<AppInfo>,
    val primary: AppInfo,
    val anyAllowSu: Boolean,
    val anyCustom: Boolean,
    val shouldUmount: Boolean,
    val ownerName: String? = null,
    val matchedIdentifiers: Set<String> = emptySet(),
    // Current delivery state from the page's single authority read and mode-specific check.
    // Navigation caches keep the default and do not confer a working SU claim.
    val suState: State = State.NOT_AUTHORIZED,
)

@Stable
data class SuperUserUiState(
    val isRefreshing: Boolean = false,
    val hasLoaded: Boolean = false,
    val suEnabled: Boolean? = null,
    val groupedApps: List<GroupedApps> = emptyList(),
    val recentlyInstalledResults: List<GroupedApps> = emptyList(),
    val userIds: List<Int> = emptyList(),
    val searchStatus: SearchStatus = SearchStatus(""),
    val searchResults: List<GroupedApps> = emptyList(),
    val showSystemApps: Boolean = false,
    val showOnlyPrimaryUserApps: Boolean = false,
    val sortConfig: AppSortConfig = AppSortConfig(),
    /** 模式阻断原因（未判定 / KSU 后端不可用）：非空时页面只读空态并显示原因。 */
    val blockedReason: String? = null,
    val error: Throwable? = null,
    /** Cached decisions stay readable after a failed read, but confer no current SU claim. */
    val authorizationReadFailed: Boolean = false,
)

internal fun GroupedApps.withoutDeliveryConfirmation(): GroupedApps = copy(suState = when {
    suState == State.STALE -> State.STALE
    !anyAllowSu -> State.NOT_AUTHORIZED
    suState == State.AUTHORIZATION_PENDING || apps.any { it.authorizationPending } -> State.AUTHORIZATION_PENDING
    else -> State.ENTRY_UNAVAILABLE
})

internal fun GroupedApps.withCurrentDelivery(read: ManagerAuthorizations.CurrentDeliveryRead?): GroupedApps {
    val current = read?.isCurrent() == true
    val applied = current && apps.any { read?.confirms(uid, it.profileKey, anyAllowSu) == true }
    return copy(suState = managerSuState(anyAllowSu,
        stale = suState == State.STALE || apps.any { it.authorizationStale },
        pending = apps.any { it.authorizationPending } || (current && read?.uidProfiles?.ok == true && !applied),
        entryReady = applied && read?.entryConfirmed == true))
}

internal fun SuperUserUiState.withoutDeliveryConfirmation(): SuperUserUiState = copy(
    groupedApps = groupedApps.map { it.withoutDeliveryConfirmation() },
    recentlyInstalledResults = recentlyInstalledResults.map { it.withoutDeliveryConfirmation() },
    searchResults = searchResults.map { it.withoutDeliveryConfirmation() },
    authorizationReadFailed = true,
)

@Immutable
data class SuperUserActions(
    val onRefresh: () -> Unit,
    val onOpenSulog: () -> Unit,
    val onSearchTextChange: (String) -> Unit,
    val onSearchStatusChange: (SearchStatus) -> Unit,
    val onClearSearch: () -> Unit,
    val onToggleShowSystemApps: () -> Unit,
    val onToggleShowOnlyPrimaryUserApps: () -> Unit,
    val onUpdateSortConfig: (AppSortConfig) -> Unit,
    val onOpenProfile: (GroupedApps) -> Unit,
    val onEnableSu: () -> Unit,
)

@Immutable
data class StatusMeta(
    val label: String,
    val bg: Color,
    val fg: Color
)
