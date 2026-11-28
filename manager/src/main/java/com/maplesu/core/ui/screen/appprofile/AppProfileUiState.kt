package com.maplesu.core.ui.screen.appprofile

import androidx.compose.runtime.Immutable
import com.maplesu.core.Natives
import com.maplesu.core.ui.screen.superuser.GroupedApps
import dev.maplesu.manager.runtime.State

@Immutable
data class AppProfileUiState(
    val uid: Int,
    val packageName: String,
    val profile: Natives.Profile,
    val appGroup: GroupedApps,
    val sharedUserId: String,
    val isLoading: Boolean = false,
    val loadFailed: Boolean = false,
    val isSaving: Boolean = false,
    // Current delivery observation from the bounded page read, separate from the saved decision.
    val suState: State = State.NOT_AUTHORIZED,
    val diagnostic: AppProfileDiagnostic? = null,
) {
    val isUidGroup get() = appGroup.apps.size > 1
}

@Immutable
data class AppProfileDiagnostic(val title: String, val detail: String)

@Immutable
data class AppProfileActions(
    val onBack: () -> Unit,
    val onLaunchApp: (String, Int) -> Unit,
    val onForceStopApp: (String, Int) -> Unit,
    val onRestartApp: (String, Int) -> Unit,
    val onViewTemplate: (String) -> Unit,
    val onManageTemplate: () -> Unit,
    val onProfileChange: (Natives.Profile) -> Unit,
    val onRetry: () -> Unit = {},
    val onShowDiagnostic: () -> Unit = {},
)
