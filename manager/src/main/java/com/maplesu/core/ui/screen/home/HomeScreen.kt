package com.maplesu.core.ui.screen.home

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.maplesu.core.ui.component.maple.*
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.R
import com.maplesu.core.ui.component.dialog.rememberInfoDialog
import com.maplesu.core.ui.screen.settings.rememberUltraEnvironmentPanel
import com.maplesu.core.ui.screen.settings.UltraComponentDiagnosticRequests
import com.maplesu.core.ui.navigation3.Navigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.viewmodel.HomeViewModel
import dev.maplesu.manager.jailbreak.JailbreakSelectionDialog
import dev.maplesu.manager.workmode.ui.WorkModeSwitchSheet

@Composable
fun HomePager(
    viewModel: HomeViewModel,
    navigator: Navigator,
    bottomInnerPadding: Dp,
    isCurrentPage: Boolean = true,
    authorizedCount: Int? = null,
    moduleEnabledCount: Int? = null,
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val uriHandler = LocalUriHandler.current
    val context = LocalContext.current
    val latestIsCurrentPage by rememberUpdatedState(isCurrentPage)
    val initialResumeHandled = rememberSaveable { mutableStateOf(false) }
    var initialPageEntryHandled by rememberSaveable { mutableStateOf(false) }
    var showJailbreakSelection by rememberSaveable { mutableStateOf(false) }

    // A（Lite 隐藏）生效或真实事务期间走「未安装」伪装；普通未知仅保留历史显示。
    // 管理入口由同一份隐藏事实决定，不从显示缓存获得能力。
    //
    // 组合期不读 JNI / prefs / 文件：事实全部来自 HomeViewModel.entryFacts。隐藏事实一变就由
    // HiddenFactsSignal 推过来，不等切页/回前台，否则隐藏刚生效那几帧仍会露出入口（真机实测）。
    val entryFacts by viewModel.entryFacts.collectAsStateWithLifecycle()
    val liteHiddenMasking = entryFacts.hidden.masking
    // 事务确认信号可能先于整页刷新到达；不能在这段间隙继续显示旧的“正在运行”。
    val hiddenConfirming = entryFacts.hidden.confirming
    val displayState = remember(uiState, entryFacts.hidden) {
        uiState.withHiddenFacts(entryFacts.hidden)
    }

    LaunchedEffect(isCurrentPage) {
        if (isCurrentPage) {
            if (initialPageEntryHandled) viewModel.refreshOnForeground()
            viewModel.refreshEntryFacts()
            initialPageEntryHandled = true
        }
    }

    LifecycleResumeEffect(Unit) {
        if (initialResumeHandled.value && latestIsCurrentPage) {
            viewModel.refreshOnForeground()
        }
        // 回前台：模式/隐藏可能已在后台变化。
        viewModel.refreshEntryFacts()
        initialResumeHandled.value = true
        onPauseOrDispose { }
    }

    // 隐藏生效/隐藏确认窗口内：**任何**管理器专属入口都不许出现（不只是状态卡）。
    val suppressEntries = entryFacts.hidden.suppressEntries
    val workModeEntry = if (suppressEntries) {
        dev.maplesu.manager.workmode.ui.WorkModeEntryPolicy.NONE
    } else {
        entryFacts.workModeEntry
    }
    val workModeSwitch = if (suppressEntries) {
        HomeWorkModeSwitchState.HIDDEN
    } else {
        entryFacts.workModeSwitch
    }

    val installedKernelRevision by dev.maplesu.manager.runtime.ultra.UltraEnvironmentUpgrade
        .installedKernelRevision.collectAsStateWithLifecycle()
    val installedKernelKnown = installedKernelRevision.let {
        dev.maplesu.manager.runtime.ultra.UltraEnvironmentUpgrade.installedKernelKnown(context)
    }
    val brandFacts = UltraBrandFacts(
        active = displayState.displayEnvironmentMode,
        installed = if (displayState.showInstalledStatus) HomeInstallSignal.INSTALLED else HomeInstallSignal.UNKNOWN,
        liteHidden = HomeHiddenSignal.of(liteHiddenMasking),
        ksuStealth = HomeHiddenSignal.of(workModeSwitch.blocked == HomeWorkModeSwitchBlock.STEALTH_MASKED),
        hiddenConfirming = hiddenConfirming,
    )
    val aboutShowsModes = !suppressEntries && !hidesModeInfo(brandFacts)
    val ultraVisible = shouldShowUltraBrand(brandFacts)
    // 主卡与顶部字样复用同一个结果；不修改原检测，也不把安装事实当成 root 能力。
    val statusState = remember(displayState, ultraVisible) {
        displayState.copy(ultraBrandVisible = ultraVisible)
    }
    LaunchedEffect(statusState.environmentChecking, statusState.showEnvironmentReady) {
        if (!statusState.environmentChecking && statusState.showEnvironmentReady) {
            UltraComponentDiagnosticRequests.clear()
        }
    }
    // 环境版本与「发现 Ultra 环境更新」：同一份 §2.1 裁决，不可见时不读任何事实。
    val ultraEnvironment = rememberUltraEnvironmentPanel(
        visible = ultraVisible && displayState.environmentMode == dev.maplesu.manager.workmode.WorkMode.LITE,
        upgradeAllowed = workModeSwitch.blocked == HomeWorkModeSwitchBlock.NONE,
        foreground = isCurrentPage,
    )
    val switchPending by dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.pendingFlow.collectAsStateWithLifecycle()
    val showInstalledKernelUpdate = com.maplesu.core.ui.screen.settings.installedUltraUpgradeVisible(
        displayState.environmentMode, installedKernelKnown,
        dev.maplesu.manager.runtime.ultra.UltraEnvironmentUpgrade.installedKernelUpdateRequired(context),
        suppressEntries, switchPending,
    )
    val ultra = rememberUltraWordmarkState(
        visible = ultraVisible,
        foreground = isCurrentPage && navigator.current() in listOf(Route.Main, Route.Home),
    )

    val actions = HomeActions(
        onInstallClick = { navigator.push(Route.Install) },
        onOpenUrl = uriHandler::openUri,
        onJailbreakClick = { showJailbreakSelection = true },
        onEnvironmentRetry = viewModel::checkEnvironmentManually,
        onOpenEnvironmentSettings = {
            UltraComponentDiagnosticRequests.open(displayState.ultraComponentDiagnostic)
            if (Route.Settings in navigator.backStack) navigator.popUntil { it == Route.Settings }
            else navigator.push(Route.Settings)
        },
        onManageModules = { navigator.push(Route.Module) },
        onFeedbackClick = { openFeedbackInBrowser(context) },
    )
    // 唯一落点：工作模式选择框（WorkModeNavigation.Destination.SWITCH_SHEET）。
    var showWorkModeSheet by rememberSaveable { mutableStateOf(false) }
    val jailbreakModeDialog = rememberInfoDialog()
    val jailbreakModeTitle = stringResource(R.string.work_mode_switch_button)
    val jailbreakModeMessage = stringResource(R.string.work_mode_jailbreak_blocked)
    val onOpenWorkMode: () -> Unit = {
        if (workModeSwitch.blocked == HomeWorkModeSwitchBlock.JAILBREAK_ACTIVE) {
            jailbreakModeDialog.show(jailbreakModeTitle, jailbreakModeMessage)
        } else if (workModeSwitch.enabled) {
            showWorkModeSheet = true
        }
    }

    // W20/W21 外部 Root 迁移入口：有 root、未识别本机模式且非安全模式时显示；
    // 隐身时 HomeUiState 已被 asStealthKernelNotReady 归一化 ⇒ 条件自然为 false（00 §3.8 隐身互斥）。

    if (showJailbreakSelection) {
        JailbreakSelectionDialog(onDismiss = { showJailbreakSelection = false },
            onActivated = viewModel::refreshAfterJailbreak)
    }

    // 隐藏一旦生效，选择框随入口一起收起，不留下任何模式信息。
    WorkModeSwitchSheet(
        show = showWorkModeSheet && !suppressEntries && workModeSwitch.enabled,
        onDismiss = { showWorkModeSheet = false },
    )

    CompositionLocalProvider(
        com.maplesu.core.theme.LocalThemeHomeForeground provides isCurrentPage,
        LocalThemeHomeCounts provides ThemeHomeCounts(authorizedCount,moduleEnabledCount),
    ) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> HomePagerMiuix(
            state = statusState,
            ultra = ultra,
            aboutShowsModes = aboutShowsModes,
            ultraEnvironment = ultraEnvironment.takeIf { ultraVisible },
            showInstalledKernelUpdate = showInstalledKernelUpdate,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
            workModeEntry = workModeEntry,
            onOpenWorkMode = onOpenWorkMode,
            workModeSwitch = workModeSwitch,
        )

        UiMode.Material -> HomePagerMaterial(
            state = statusState,
            ultra = ultra,
            aboutShowsModes = aboutShowsModes,
            ultraEnvironment = ultraEnvironment.takeIf { ultraVisible },
            showInstalledKernelUpdate = showInstalledKernelUpdate,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
            workModeEntry = workModeEntry,
            onOpenWorkMode = onOpenWorkMode,
            workModeSwitch = workModeSwitch,
        )
    }
    }
}
