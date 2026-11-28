package com.maplesu.core.ui.screen.appprofile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.DropdownMenuGroup
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.SelectableDropdownMenuItem
import androidx.compose.material3.DropdownMenuPopup
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuDefaults
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.maplesu.core.Natives
import com.maplesu.core.R
import com.maplesu.core.ui.component.AppIconImage
import com.maplesu.core.ui.component.material.ExpressiveScaffold
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedListItem
import com.maplesu.core.ui.component.material.SegmentedSwitchItem
import com.maplesu.core.ui.component.material.SnackBarHost
import com.maplesu.core.ui.component.material.TopBarBackButton
import com.maplesu.core.ui.component.material.expressiveTopAppBarColors
import com.maplesu.core.ui.component.statustag.StatusTag
import com.maplesu.core.ui.util.ownerNameForUid
import com.maplesu.core.ui.util.suStateLabel
import com.maplesu.core.ui.viewmodel.SuperUserViewModel
import dev.maplesu.manager.runtime.State

/**
 * @author weishu
 * @date 2023/5/16.
 */
@Composable
fun AppProfileScreenMaterial(
    state: AppProfileUiState,
    actions: AppProfileActions,
    snackBarHost: SnackbarHostState,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopBar(
                onBack = actions.onBack,
                scrollBehavior = scrollBehavior,
                isUidGroup = state.isUidGroup,
                showActions = !state.appGroup.primary.isWebViewZygote,
                packageName = state.packageName,
                userId = state.uid / 100000,
                onLaunchApp = actions.onLaunchApp,
                onForceStopApp = actions.onForceStopApp,
                onRestartApp = actions.onRestartApp,
            )
        },
        snackbarHost = { SnackBarHost(hostState = snackBarHost, modifier = Modifier.safeDrawingPadding()) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { paddingValues ->
        if (state.isLoading || state.loadFailed) {
            Column(
                modifier = Modifier.padding(paddingValues).fillMaxWidth().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                if (state.isLoading) LoadingIndicator()
                else {
                    Text(stringResource(R.string.failed_to_load_app_profile).format(state.appGroup.primary.label))
                    state.diagnostic?.let {
                        TextButton(onClick = actions.onShowDiagnostic) { Text(stringResource(R.string.ui_polish_diagnostics_show)) }
                    }
                    TextButton(onClick = actions.onRetry) { Text(stringResource(R.string.network_retry)) }
                }
            }
            return@ExpressiveScaffold
        }
        AppProfileInner(
            modifier = Modifier
                .padding(paddingValues)
                .fillMaxHeight()
                .imePadding()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState()),
            packageName = if (state.isUidGroup) {
                ""
            } else {
                state.appGroup.primary.displayIdentifier
            },
            appLabel = if (state.isUidGroup) ownerNameForUid(state.appGroup.primary.uid) else state.appGroup.primary.label,
            appIcon = {
                AppIconImage(
                    packageInfo = state.appGroup.primary.packageInfo,
                    label = state.appGroup.primary.label,
                    modifier = Modifier
                        .padding(top = 4.dp)
                        .size(48.dp)
                )
            },
            appUid = state.uid,
            sharedUserId = if (state.isUidGroup) state.sharedUserId else "",
            appVersionName = if (state.isUidGroup) "" else (state.appGroup.primary.packageInfo.versionName ?: ""),
            appVersionCode = if (state.isUidGroup) 0L else state.appGroup.primary.packageInfo.longVersionCode,
            profile = state.profile,
            isUidGroup = state.isUidGroup,
            isSpecialApp = state.appGroup.primary.special,
            affectedApps = state.appGroup.apps,
            suState = state.suState,
            isSaving = state.isSaving,
            diagnostic = state.diagnostic,
            onShowDiagnostic = actions.onShowDiagnostic,
            onRetry = actions.onRetry,
            onProfileChange = actions.onProfileChange,
        )
    }
}

@Composable
private fun AppProfileInner(
    modifier: Modifier = Modifier,
    packageName: String,
    appLabel: String,
    appIcon: @Composable (() -> Unit),
    appUid: Int,
    sharedUserId: String = "",
    appVersionName: String,
    appVersionCode: Long,
    profile: Natives.Profile,
    isUidGroup: Boolean = false,
    isSpecialApp: Boolean = false,
    affectedApps: List<SuperUserViewModel.AppInfo> = emptyList(),
    suState: State = State.NOT_AUTHORIZED,
    isSaving: Boolean = false,
    diagnostic: AppProfileDiagnostic? = null,
    onShowDiagnostic: () -> Unit = {},
    onRetry: () -> Unit = {},
    onProfileChange: (Natives.Profile) -> Unit,
) {
    val isRootGranted = !isSpecialApp && profile.allowSu
    val userId = appUid / 100000
    val appId = appUid % 100000

    Column(modifier = modifier.padding(bottom = 6.dp + 48.dp + 6.dp /* SnackBar height */)) {
        SegmentedColumn(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            content = buildList<@Composable () -> Unit> {
                add {
                    SegmentedListItem(
                        headlineContent = { Text(appLabel) },
                        supportingContent = {
                            Column {
                                if (isSpecialApp) {
                                    Text(packageName, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                } else if (!isUidGroup) {
                                    Text("$appVersionName ($appVersionCode)", color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    Text(packageName, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                } else {
                                    if (sharedUserId.isNotEmpty()) {
                                        Text(text = sharedUserId, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                    Text(
                                        text = stringResource(R.string.group_contains_apps, affectedApps.size),
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        },
                        leadingContent = appIcon,
                        trailingContent = {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                if (userId != 0) {
                                    StatusTag(
                                        label = "USER $userId",
                                        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                                        backgroundColor = MaterialTheme.colorScheme.tertiaryContainer
                                    )
                                    StatusTag(
                                        label = "UID $appId",
                                        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                                        backgroundColor = MaterialTheme.colorScheme.tertiaryContainer
                                    )
                                } else {
                                    StatusTag(
                                        label = "UID $appUid",
                                        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                                        backgroundColor = MaterialTheme.colorScheme.tertiaryContainer
                                    )
                                }
                            }
                        }
                    )
                }
                if (!isSpecialApp) add {
                    SegmentedSwitchItem(
                        icon = Icons.Filled.Security,
                        title = stringResource(id = R.string.superuser),
                        // The switch only records the grant. Whether a copy was delivered and
                        // whether a bare `su` already resolves are separate facts, and this is
                        // the one place a user can see them for this application.
                        summary = stringResource(if (isSaving) R.string.ui_editing_saving_authorization else suStateLabel(suState)),
                        checked = isRootGranted,
                        enabled = !isSaving,
                        onCheckedChange = { onProfileChange(profile.copy(allowSu = it)) },
                    )
                }
                diagnostic?.let { issue -> add {
                    SegmentedListItem(
                        onClick = onShowDiagnostic,
                        headlineContent = { Text(issue.title) },
                        supportingContent = { Text(stringResource(R.string.ui_polish_diagnostics_show)) },
                        trailingContent = {
                            TextButton(onClick = onRetry, enabled = !isSaving) {
                                Text(stringResource(R.string.work_mode_recheck))
                            }
                        },
                    )
                } }
            }
        )

        if (isUidGroup) {
            val appItems = affectedApps.map<SuperUserViewModel.AppInfo, @Composable () -> Unit> { app ->
                {
                    SegmentedListItem(
                        headlineContent = { Text(app.label) },
                        supportingContent = { Text(app.displayIdentifier) },
                        leadingContent = {
                            AppIconImage(
                                packageInfo = app.packageInfo,
                                label = app.label,
                                modifier = Modifier.size(36.dp)
                            )
                        }
                    )
                }
            }
            SegmentedColumn(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                title = stringResource(R.string.app_profile_affects_following_apps),
                content = appItems
            )
        }
    }
}

@Composable
private fun TopBar(
    onBack: () -> Unit,
    scrollBehavior: TopAppBarScrollBehavior? = null,
    isUidGroup: Boolean = false,
    showActions: Boolean = true,
    packageName: String = "",
    userId: Int = 0,
    onLaunchApp: (String, Int) -> Unit,
    onForceStopApp: (String, Int) -> Unit,
    onRestartApp: (String, Int) -> Unit,
) {
    val haptic = LocalHapticFeedback.current
    LargeFlexibleTopAppBar(
        title = { Text(stringResource(R.string.profile)) },
        navigationIcon = {
            TopBarBackButton(onClick = onBack)
        },
        actions = {
            if (!isUidGroup && showActions) {
                var showDropdown by remember { mutableStateOf(false) }

                IconButton(
                    onClick = { showDropdown = true },
                ) {
                    Icon(
                        imageVector = Icons.Filled.MoreVert,
                        contentDescription = stringResource(id = R.string.settings)
                    )
                    DropdownMenuPopup(
                        expanded = showDropdown,
                        onDismissRequest = { showDropdown = false }
                    ) {
                        val menuItems = listOf(
                            R.string.launch_app to onLaunchApp,
                            R.string.force_stop_app to onForceStopApp,
                            R.string.restart_app to onRestartApp,
                        )
                        DropdownMenuGroup(shapes = MenuDefaults.groupShapes()) {
                            menuItems.forEachIndexed { index, (resId, action) ->
                                SelectableDropdownMenuItem(
                                    selected = false,
                                    onClick = {
                                        haptic.performHapticFeedback(HapticFeedbackType.VirtualKey)
                                        showDropdown = false
                                        action(packageName, userId)
                                    },
                                    text = { Text(stringResource(id = resId)) },
                                    shapes = MenuDefaults.itemShape(index = index, count = menuItems.size),
                                )
                            }
                        }
                    }
                }
            }
        },
        colors = expressiveTopAppBarColors(),
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior
    )
}

@Preview
@Composable
private fun AppProfilePreview() {
    var profile by remember { mutableStateOf(Natives.Profile("")) }
    AppProfileInner(
        packageName = "icu.nullptr.test",
        appLabel = "Test",
        appIcon = { Icon(Icons.Filled.Android, null) },
        appUid = 1,
        appVersionName = "v1.0.0",
        appVersionCode = 12345,
        profile = profile,
        onProfileChange = {
            profile = it
        },
    )
}
