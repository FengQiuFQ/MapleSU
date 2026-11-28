package com.maplesu.core.ui.screen.home

import com.maplesu.core.ui.screen.settings.UltraEnvironmentInstallCardMiuix
import com.maplesu.core.ui.screen.settings.rememberUltraEnvironmentInstallPanel
import com.maplesu.core.ui.screen.settings.UltraEnvironmentUpdatePanel
import com.maplesu.core.ui.screen.settings.UltraEnvironmentUpdateCardMiuix

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.ui.platform.testTag
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Info
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.UriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.KernelVersion
import com.maplesu.core.Natives
import com.maplesu.core.ui.component.maple.*
import com.maplesu.core.R
import com.maplesu.core.ui.component.WarningLevel
import com.maplesu.core.ui.component.dialog.rememberConfirmDialog
import com.maplesu.core.ui.component.miuix.WarningCard
import com.maplesu.core.ui.component.rebootlistpopup.RebootListPopupMiuix
import com.maplesu.core.ui.component.statustag.StatusTag
import com.maplesu.core.ui.theme.LocalEnableBlur
import com.maplesu.core.ui.theme.isInDarkTheme
import com.maplesu.core.ui.util.BlurredBar
import com.maplesu.core.ui.util.miuixBarColor
import com.maplesu.core.ui.util.module.LatestVersionInfo
import com.maplesu.core.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.isDynamicColor
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic
import androidx.compose.foundation.Image
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import com.maplesu.core.ui.util.StatusDecoration
import com.maplesu.core.ui.util.LegacyDataMigration
import com.maplesu.core.ui.util.rememberMigrationRestartPending
import androidx.compose.runtime.getValue
import androidx.compose.foundation.background
import top.yukonga.miuix.kmp.theme.LocalContentColor
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.graphics.Brush

@Composable
fun HomePagerMiuix(
    state: HomeUiState,
    actions: HomeActions,
    bottomInnerPadding: Dp,
    // mode-gate: 工作模式入口（04-ui-contract §2.2 入口 B）；可见性由调用方用
    // decideWorkModeEntry 算好传入，首页不自行判断模式。
    workModeEntry: dev.maplesu.manager.workmode.ui.WorkModeEntryPolicy =
        dev.maplesu.manager.workmode.ui.WorkModeEntryPolicy.NONE,
    onOpenWorkMode: () -> Unit = {},
    // 用户要求(2026-10-30)：首页「切换工作模式」入口必须是**看得见的按钮**，
    // 不能只靠 workModeEntry 那张卡（判定态不满足时它整个不画）。判据见 HomeWorkModeSwitchState。
    workModeSwitch: HomeWorkModeSwitchState = HomeWorkModeSwitchState.HIDDEN,
    aboutShowsModes: Boolean = false,
    // 外部 Root 已确认可用时，进入共用的直接安装流程。
    ultra: UltraWordmarkState? = null,
    // Ultra 环境版本与更新提示；非 Ultra / 隐藏时为 null。
    ultraEnvironment: UltraEnvironmentUpdatePanel? = null,
    showInstalledKernelUpdate: Boolean = false,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = miuixBarColor(blurActive)
    // 「界面扁平化」(flat_home):开启后首页卡片不画底色,只留文字和图标。
    // 由 MainActivity 统一提供(顶栏/底栏也读它),这里直接取即可。
    val flatHome = com.maplesu.core.ui.theme.LocalFlatUi.current
    // 「旧版 7kimisu」提示卡要用它拉起系统卸载界面(v2.2)
    val context = LocalContext.current
    // ⚠️ v0.13.157:这里原来有个 `stealthOn`(隐身时藏「关于 7kimisu」/「支持开发·了解 KernelSU」
    //    两张卡),**已删除**。用户判据:这两张卡是"一个**没有 root 的用户**点进来"就会看到的
    //    东西,隐身必须照常显示 —— 隐身只改"显示什么内容"(比如安装页里需要 root 的两个方法),
    //    不该把没 root 的人也看得到的卡片藏掉。
    //    (「伪装成内核未就绪」仍然由 HomeViewModel 把 UiState 归一化完成,
    //     见 HomeUiState.asStealthKernelNotReady —— 那是内容侧,不是外观侧。)
    Scaffold(
        topBar = {
            TopBar(
                scrollBehavior = scrollBehavior,
                backdrop = backdrop,
                barColor = barColor,
                ultra = ultra,
                showReboot = com.maplesu.core.ui.util.RebootDispatcher.showMenu(
                    state.liteInstalled || state.isManager && state.ksuVersion != null,
                    state.showLiteChecking,
                ),
                lateLoad = state.isLateLoadMode,
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .padding(bottom = bottomInnerPadding)
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                // 注:左边距从 LazyColumn 移到下面具体卡片上，所有卡片统一左右 12dp。
                // (v0.13.28 曾让绿卡贴边满屏宽，v0.13.64 改回与其它卡片一致。)
                contentPadding = innerPadding,
                overscrollEffect = null,
            ) {
                item {
                    // 所有卡片统一左右 12dp 边距(绿卡也一样)。
                    // 数值取自 StatusDecoration：设置里的「自裁取景」要用同一个值算卡片比例。
                    val sideInset = Modifier.fillMaxWidth()
                        .padding(horizontal = StatusDecoration.CARD_SIDE_INSET_DP.dp)
                    Column(
                        modifier = Modifier.padding(top = 12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Column(
                            modifier = sideInset,
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                        HomeBetaBanner(onClick = actions.onFeedbackClick)
                        if (state.showSafeModeBanner) {
                            HomeSafeModeBanner(onManageModules = actions.onManageModules)
                        }
                        if (state.checkUpdateEnabled) {
                            HomeManagerUpdateBannerMiuix(state = state, actions = actions)
                        }
                        if (state.showManagerPrBuildWarning) {
                            WarningCard(stringResource(id = R.string.home_pr_build_warning), level = WarningLevel.Notice)
                        } else if (state.showKernelPrBuildWarning) {
                            WarningCard(stringResource(id = R.string.home_pr_kernel_warning), level = WarningLevel.Notice)
                        }
                        if (state.showGkiWarning) {
                            WarningCard(stringResource(id = R.string.home_gki_warning), level = WarningLevel.Notice)
                        }
                        if (state.requiresNewKernel) {
                            WarningCard(
                                stringResource(
                                    id = if (state.lkmMode == true) R.string.require_kernel_version else R.string.require_kernel_version_gki
                                ),
                                // 这是「需要更新内核」的提示卡,点它就是去安装页;
                                // 隐身下它本来就不会出现(requiresNewKernel = isManager && …,隐身时 isManager=false)。
                                onClick = if (state.lkmMode == true) actions.onInstallClick else null
                            )
                        }
                        if (state.requiresNewManager) {
                            WarningCard(
                                stringResource(
                                    id = R.string.require_manager_version
                                )
                            )
                        }
                        if (state.showLkmUpdate) {
                            WarningCard(
                                message = stringResource(R.string.home_lkm_update_available),
                                level = WarningLevel.Notice,
                                onClick = actions.onInstallClick,
                            )
                        }
                        if (state.showRootWarning) {
                            WarningCard(stringResource(id = R.string.grant_root_failed))
                        }
                        // 🔴 D3(v2.2)：数据目录刚迁移过 → 提示"请重启一次设备"。
                        // 点一下 = 我知道了（以后不再提示，"不超过一次"）。
                        // 用卡片而不用弹窗的理由：① Miuix 的 WindowDialog 一次只能开一个
                        //（见 ui/component/miuix/ModuleIcon.kt 顶部注释），启动期已经有公告弹窗；
                        // ② "重启前别授权新 App"这件事**要一直看得见**，弹窗关掉就忘了。
                        if (rememberMigrationRestartPending()) {
                            WarningCard(
                                stringResource(id = R.string.migration_restart_notice),
                                onClick = { LegacyDataMigration.acknowledgeRestartNotice(context) },
                            )
                        }
                        }
                        // P0：Lite 已安装但后台 root 获取失败 → 状态卡（图片）**上方**固定一行文案。
                        // 与其它警告卡同一套风格（WarningCard 默认 Error），并吃 12dp 边距对齐状态卡。
                        if (state.showLiteRootFailure) {
                            Column(modifier = sideInset) {
                                WarningCard(stringResource(R.string.home_lite_root_failure))
                            }
                        }
                        if (state.showEnvironmentRefreshWarning) {
                            val summary = stringResource(when (state.manualEnvironmentFailure) {
                                HomeEnvironmentFailure.TIMED_OUT -> R.string.home_environment_check_timeout_summary
                                HomeEnvironmentFailure.UNCONFIRMED -> R.string.home_environment_check_unconfirmed_summary
                                HomeEnvironmentFailure.BUSY -> R.string.home_environment_check_busy_summary
                                else -> R.string.home_environment_check_failed_summary
                            })
                            Column(modifier = sideInset) {
                                WarningCard(
                                    message = stringResource(R.string.home_environment_refresh_warning, summary),
                                    level = WarningLevel.Notice,
                                    onClick = actions.onEnvironmentRetry,
                                )
                            }
                        }
                        // 绿色状态卡:跟其它卡片一样吃 12dp 边距(卡宽 = 屏宽 − 24dp)。
                        // 宽度沿革:v0.13.28 改成贴边(满屏宽) → v0.13.64 按用户要求改回原宽。
                        ThemeHomeStatus(state, actions, Modifier.padding(horizontal = StatusDecoration.CARD_SIDE_INSET_DP.dp)) { StatusCard(
                            state = state,
                            actions = actions,
                            flat = flatHome,
                            modifier = Modifier.fillMaxWidth(),
                            ultraVersionLabel = if (state.ultraBrandVisible) ultraEnvironment?.version else null,
                        ) }
                        if (state.showUltraObservationFailure) {
                            val summary = stringResource(when (state.ultraObservationFailure) {
                                HomeEnvironmentFailure.TIMED_OUT -> R.string.home_ultra_observation_timeout_summary
                                HomeEnvironmentFailure.BUSY -> R.string.home_ultra_observation_busy_summary
                                HomeEnvironmentFailure.UNCONFIRMED -> R.string.home_ultra_observation_unconfirmed_summary
                                else -> R.string.home_ultra_observation_failed_summary
                            })
                            Column(modifier = sideInset) {
                                WarningCard(
                                    message = summary,
                                    onClick = actions.onOpenEnvironmentSettings,
                                )
                            }
                        }
                        // 「发现 Ultra 环境更新」：紧贴状态卡下方，写法与交互同 KSU 的管理器更新卡。
                        if (ultraEnvironment != null && !showInstalledKernelUpdate) {
                            UltraEnvironmentUpdateCardMiuix(ultraEnvironment, modifier = sideInset)
                        }
                        if (showInstalledKernelUpdate) {
                            Card(modifier = sideInset) {
                                com.maplesu.core.ui.screen.settings.InstalledUltraUpgradeRowMiuix()
                            }
                        }
                        // 首页「切换工作模式」入口（Miuix）——紧贴状态卡下方，整行按钮。
                        // 与 Material 版共用 HomeWorkModeSwitchState 判据和同一个导航落点。
                        if (workModeSwitch.visible) {
                            Column(modifier = sideInset) {
                                HomeWorkModeSwitchEntryMiuix(
                                    state = workModeSwitch,
                                    onClick = onOpenWorkMode,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                        }
                        // 「安装 / 激活系统环境」：2026-10-29 按用户要求从设置页移到首页。
                        // Ultra 模式统一提供随包 SDK 完整安装。
                        Column(modifier = sideInset) {
                            UltraEnvironmentInstallCardMiuix(
                                rememberUltraEnvironmentInstallPanel(state.environmentMode, state.environmentConfirmedAbsent),
                                onOpenDiagnostics = actions.onOpenEnvironmentSettings,
                            )
                        }
                        // ⚠️ 「安装 / 更新内核」入口（2026-09-17 加）
                        // 以前只有绿卡本身可点，卡上又没写"安装"二字 —— 用户反馈"别的管理器有的基础功能
                        // 我们却没有"，查下来功能其实都在（安装页有：选择文件并修补 / 下载并修补 /
                        // 直接安装 / 安装到未使用槽位 / 使用本地 LKM 文件），**只是入口根本发现不了**。
                        // 所以这里单独摆一张写着字的卡。
                        // 隐身时它自然不出现(隐身下 lkmMode=null、managerNotRecognized=false),
                        // 且安装页本身已经显示成"真·没 root"的样子,不必在这里堵。
                        if (state.lkmMode == true || (state.managerNotRecognized && state.isRootAvailable)) {
                            Column(modifier = sideInset) {
                                InstallKernelCard(
                                    onClick = actions.onInstallClick,
                                    modifier = Modifier.fillMaxWidth(),
                                    flat = flatHome,
                                )
                            }
                        }
                        Column(
                            modifier = sideInset,
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                        InfoCard(
                            systemInfo = state.systemInfo,
                            modifier = Modifier.fillMaxWidth(),
                            flat = flatHome,
                        )
                        About7kCard(showModes = aboutShowsModes, modifier = Modifier.fillMaxWidth(), flat = flatHome)
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun HomeManagerUpdateBannerMiuix(
    state: HomeUiState,
    actions: HomeActions,
) {
    val newVersion = state.latestVersionInfo
    val title = stringResource(id = R.string.module_changelog)
    val updateText = stringResource(id = R.string.module_update)
    val updateDialog = rememberConfirmDialog(onConfirm = { actions.onOpenUrl(newVersion.downloadUrl) })

    AnimatedVisibility(
        visible = state.hasUpdate,
        enter = fadeIn() + expandVertically(),
        exit = shrinkVertically() + fadeOut()
    ) {
        WarningCard(
            message = stringResource(id = R.string.new_version_available, newVersion.versionCode),
            level = WarningLevel.Warning,
            modifier = Modifier.testTag("home_manager_update_banner"),
            onClick = {
                if (newVersion.changelog.isEmpty()) {
                    actions.onOpenUrl(newVersion.downloadUrl)
                } else {
                    updateDialog.showConfirm(
                        title = title,
                        content = newVersion.changelog,
                        markdown = true,
                        confirm = updateText
                    )
                }
            }
        )
    }
}

@Composable
private fun TopBar(
    scrollBehavior: ScrollBehavior,
    backdrop: LayerBackdrop?,
    barColor: Color,
    ultra: UltraWordmarkState?,
    showReboot: Boolean,
    lateLoad: Boolean,
) {
    BlurredBar(backdrop) {
        Box {
        val titlePhoto = themeHomeTitlePhoto()
        val titleFile = titlePhoto?.file
        val defaultTitle = ThemeHomeTitleText(stringResource(R.string.app_name))
        TopAppBar(
            color = barColor,
            title = if (titleFile != null) "" else if (ultra?.visible == true) "$defaultTitle Ultra" else defaultTitle,
            largeTitle = if (titleFile != null) "" else defaultTitle,
            largeTitleColor = if (ultra?.visible == true || titleFile != null) Color.Transparent else MiuixTheme.colorScheme.onSurface,
            titleColor = if (ultra?.visible == true || titleFile != null) Color.Transparent else MiuixTheme.colorScheme.onSurface,
            actions = {
                if (showReboot) RebootListPopupMiuix(lateLoad = lateLoad)
            },
            scrollBehavior = scrollBehavior
        )
        if (titleFile != null) ThemeHomeTitle(Modifier.align(Alignment.CenterStart).padding(start=56.dp).fillMaxWidth().padding(end=80.dp),photo=titlePhoto) { }
        else if (ultra?.visible == true) UltraTopBarOverlayMiuix(ultra, scrollBehavior, stringResource(R.string.app_name), Modifier.matchParentSize())
        }
    }
}

/** 自定义状态卡图片的全部可调项(打包一次读取,避免多个 remember) */
private data class DecorPrefs(
    val largeCard: Boolean,
    val anchor: Int,
    val dim: Float,
    val biasX: Float,
    val biasY: Float,
    val zoom: Float,
    val hideText: Boolean,
)

@Composable
internal fun StatusCard(
    state: HomeUiState,
    actions: HomeActions,
    // 只影响「未安装 / 不支持」这两张兜底卡；绿色主卡永远是绿色
    flat: Boolean = false,
    modifier: Modifier = Modifier,
    // Ultra 当前版本值；身份名由独立标题显示。
    ultraVersionLabel: String? = null,
) {
    // Keep normal content available while automatic observations finish.
    Column {
        // 用户自定义的状态卡图片(没有就用默认的绿色对勾)
        val density = LocalDensity.current
        val themeArt = statusThemeArt()
        val decorRev = com.maplesu.core.ui.util.WallpaperPrefs.observe()
        // 目标解码宽度:卡片现在是「屏宽 − 24dp」,按屏宽降采样略大一点,无害,
        // 平板壁纸 2560×1600 → 降到 1280×800 左右,内存 16MB → 4MB
        val targetWidthPx = with(density) {
            androidx.compose.ui.platform.LocalConfiguration.current.screenWidthDp.dp.roundToPx()
        }
        val decoration = com.maplesu.core.ui.util.rememberStatusDecoration(targetWidthPx)
        // 自定义图的各可调项(取景位置 / 自裁偏移与缩放 / 压暗强度 / 是否隐藏文字)
        val decorPrefs = androidx.compose.runtime.remember(decorRev) {
            val r = com.maplesu.core.data.repository.SettingsRepositoryImpl()
            DecorPrefs(
                largeCard = r.homeLargeCard,
                anchor = r.statusDecorationAnchor,
                dim = r.statusDecorationDim,
                biasX = r.statusDecorationBiasX,
                biasY = r.statusDecorationBiasY,
                zoom = r.statusDecorationZoom,
                hideText = r.statusDecorationHideText,
            )
        }
        val decorAnchor = decorPrefs.anchor
        val decorDim = decorPrefs.dim
        val decorBiasX = decorPrefs.biasX
        val decorBiasY = decorPrefs.biasY
        val decorZoom = decorPrefs.zoom
        val decorHideText = decorPrefs.hideText

        // 2026-10-14 用户定：撤掉「内核未就绪」弹窗与状态文案。
        // 没认主/没 root 时一律回落到原版「未安装 / 点击安装」——点了直接进安装页，
        // 否则没 root 的用户连修补 init_boot 的入口都摸不到。


        when {
            state.showInstalledStatus -> {
                val workingState = buildString {
                    if (state.isSafeMode && !state.showSafeModeBanner) {
                        append(" [${stringResource(id = R.string.safe_mode)}]")
                    }
                }
                val workingMode = when (state.lkmMode) {
                    null -> null
                    true -> "LKM"
                    else -> "GKI"
                }
                // 状态卡文字固定,不再提供自定义
                val customStatusTitle = homeInstalledStatusTitle(state)
                val workingText = (if (customStatusTitle.isBlank()) "" else customStatusTitle + workingState).trim()
                val statusContentColor = when {
                    themeArt.file != null -> themeArt.foreground
                    decoration != null -> Color.White
                    state.showInstalledUnready -> colorScheme.onSurface
                    else -> homeStatusContentColor()
                }

                Row(
                    modifier = modifier
                        .fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Card(
                        // The large layout keeps its proportion and grows when text needs more space.
                        colors = CardDefaults.defaultColors(
                            // Green denotes confirmed readiness; artwork takes priority.
                            color = when {
                                decoration != null || themeArt.file != null -> Color.Transparent
                                state.showInstalledUnready -> colorScheme.surface
                                else -> homeStatusContainerColor()
                            },
                            contentColor = statusContentColor,
                        ),
                        onClick = {
                            if (state.isSafeMode) actions.onManageModules()
                            else if (!state.isLateLoadMode) actions.onInstallClick()
                        },
                        showIndication = !state.isLateLoadMode,
                        pressFeedbackType = PressFeedbackType.Tilt,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column {
                        BoxWithConstraints(Modifier.fillMaxWidth()) {
                            val cardMinHeight = homeStatusCardMinHeight(maxWidth, decorPrefs.largeCard)
                            StatusThemeBackdrop(themeArt)
                            val custom = decoration.takeIf { themeArt.file == null }
                            // 自定义图时给文字加描边:这样即使不压暗也看得清
                            val decorTextStyle = if (custom != null) {
                                MiuixTheme.textStyles.main.copy(
                                    shadow = Shadow(
                                        color = Color.Black.copy(alpha = 0.78f),
                                        offset = Offset(2f, 2f),
                                        blurRadius = 6f,
                                    )
                                )
                            } else {
                                MiuixTheme.textStyles.main
                            }
                            if (custom != null) {
                                // 自定义图:铺满整张卡当背景(取景/自裁可选),再按设定压暗保证文字可读
                                com.maplesu.core.ui.util.StatusDecorationImage(
                                    bitmap = custom,
                                    biasX = if (decorAnchor == 3) decorBiasX else 0f,
                                    biasY = when (decorAnchor) {
                                        1 -> -1f
                                        2 -> 1f
                                        3 -> decorBiasY
                                        else -> 0f
                                    },
                                    zoom = decorZoom,
                                    modifier = Modifier.matchParentSize(),
                                )
                                val textScrimFloor = if (decorHideText) 0f else 0.56f
                                if (decorDim > 0f || textScrimFloor > 0f) {
                                    Box(
                                        modifier = Modifier
                                            .matchParentSize()
                                            .background(
                                                Brush.verticalGradient(
                                                    listOf(
                                                        Color.Black.copy(alpha = maxOf(decorDim, textScrimFloor)),
                                                        Color.Black.copy(alpha = maxOf(decorDim * 0.33f, textScrimFloor)),
                                                    )
                                                )
                                            )
                                    )
                                }
                            } else if (themeArt.file == null) {
                                Box(
                                    modifier = Modifier
                                        .matchParentSize()
                                        .offset(27.dp, 31.dp),
                                    contentAlignment = Alignment.BottomEnd
                                ) {
                                    if (!state.showInstalledStatus || !themeArt.hideIcon) Icon(
                                        modifier = Modifier.size(110.dp).testTag("home-status-default-check"),
                                        imageVector = if (state.showEnvironmentReady) Icons.Rounded.CheckCircleOutline else Icons.Rounded.Info,
                                        tint = if (state.showEnvironmentReady) Color(0xFF36D167) else statusContentColor,
                                        contentDescription = null
                                    )
                                }
                            }
                            CompositionLocalProvider(
                                LocalContentColor provides statusContentColor
                            ) {
                            // 自定义图 + 开了"只留图片"→ 文字全部不画
                            if (custom == null || !decorHideText || state.showSafeModeBanner) {
                            Column(
                                modifier = Modifier.fillMaxWidth().heightIn(min = cardMinHeight)
                                    .padding(horizontal = 16.dp, vertical = 14.dp),
                                verticalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Column {
                                    if (workingText.isNotBlank() && (!state.showInstalledStatus || !themeArt.hideText || state.showSafeModeBanner || state.isSafeMode || state.isLateLoadMode)) {
                                        Text(
                                            text = workingText,
                                            color = statusContentColor,
                                            fontSize = 22.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            style = decorTextStyle,
                                        )
                                        Spacer(Modifier.height(1.dp))
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = homeInstalledStatusSummary(state, ultraVersionLabel),
                                            color = statusContentColor,
                                            modifier = Modifier.weight(1f, fill = false),
                                            fontSize = 15.sp,
                                            style = decorTextStyle,
                                        )
                                        if (state.showCustomLkmBadge) {
                                            Spacer(Modifier.width(8.dp))
                                            StatusTag(
                                                label = stringResource(R.string.home_lkm_custom),
                                                contentColor = if (isDynamicColor) {
                                                    colorScheme.onTertiaryContainer
                                                } else if (isInDarkTheme()) {
                                                    Color(0xFFB8E8C5)
                                                } else {
                                                    Color(0xFF164A29)
                                                },
                                                backgroundColor = if (isDynamicColor) {
                                                    colorScheme.tertiaryContainer
                                                } else if (isInDarkTheme()) {
                                                    Color(0xFF315D3E)
                                                } else {
                                                    Color(0xFFB8E8C5)
                                                },
                                            )
                                        }
                                    }
                                }
                                if (workingMode != null && !themeArt.hideMode) {
                                    Text(
                                        text = workingMode,
                                        modifier = Modifier.padding(top = 16.dp, end = 64.dp),
                                        color = statusContentColor,
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Medium,
                                        style = decorTextStyle,
                                    )
                                }
                            }
                            } else {
                                Spacer(Modifier.fillMaxWidth().height(cardMinHeight))
                            }
                            }
                        }
                        }
                    }
                }
            }

            state.environmentUnknown || state.kernelVersion.isGKI() -> {
                Card(
                    modifier = modifier.fillMaxWidth(),
                    // ⚠️ 2026-09-16 修两轮:
                    //   ① 以前这里让 onClick「什么都不做」→ 用户点下去毫无反应,以为界面坏了。
                    //   ② 后来改成一律弹「重启一次」→ 又把**从别的管理器转过来**的人堵死了
                    //      (他们需要的是安装,不是重启)。
                    //   现在按「本应用有没有拿到 root」分流 —— 这是唯一可靠的判据:
                    //     我们的内核在跑但没认主时,内核不会给本应用 root
                    //     (kernel/supercall/perm.c 的 allowed_for_su_authed);
                    //     而从别的 root 管理器授权后就有 root。
                    // ✅ 这张卡**照常可点** —— 点进去的安装页已经显示成
                    //    "真·没 root 的设备"该有的样子(没有「直接安装(推荐)」/「安装到未使用槽位」,
                    //    只有「选择文件并修补 / 下载文件并修补 / 使用本地 LKM 文件」),
                    //    所以不露馅;反倒是"点不了"本身就可疑(v0.13.149 的教训)。
                    //    ⚠️ 唯一保留的隐身差异:右边的「越狱」按钮不画(见下面 endActions)。
                    //
                    // ⚠️ v0.13.157:隐身时**不再是特例**。v0.13.156 曾在这里插一个
                    //    `stealthOn ->` 首选分支,只弹一句「暂时无法处理，请稍后再试」、
                    //    同时堵住安装页入口 —— **已撤**。用户判据:点「内核未就绪」弹出的那段
                    //    原始说明,正是一个**没有 root 的用户**点进来会看到的东西,
                    //    所以隐身时必须弹它(而不是弹一句"什么都不漏"的自造提示)。
                    onClick = {
                        when {
                            state.environmentUnknown -> actions.onEnvironmentRetry()
                            state.isLateLoadMode -> Unit
                            else -> actions.onInstallClick()
                        }
                    },
                    // 有按压反馈才像个能点的东西(以前这里也是 false,点了彻底没动静)
                    showIndication = !state.isLateLoadMode,
                    pressFeedbackType = PressFeedbackType.Tilt,
                    colors = if (flat) CardDefaults.defaultColors(color = Color.Transparent)
                             else CardDefaults.defaultColors(),
                ) {
                    Column {
                    BasicComponent(
                        // 标题不再是「未安装」:装好了却写"没装"是误导。
                        // 有 root 时直接说「可以安装了」——把下一步摆在脸上。
                        title = if (state.environmentNeedsConfirmation) {
                            stringResource(R.string.home_environment_confirmation_title)
                        } else if (state.environmentUnknown) {
                            stringResource(R.string.home_environment_unknown_title)
                        } else if (state.managerNotRecognized && state.isRootAvailable) {
                            stringResource(R.string.home_can_install)
                        } else {
                            stringResource(R.string.home_not_installed)
                        },
                        summary = if (state.environmentNeedsConfirmation) {
                            stringResource(R.string.home_environment_confirmation_summary)
                        } else if (state.environmentUnknown) {
                            stringResource(R.string.home_environment_unknown_summary)
                        } else if (state.managerNotRecognized && state.isRootAvailable) {
                            stringResource(R.string.home_can_install_summary)
                        } else {
                            stringResource(R.string.home_click_to_install)
                        },
                        startAction = {
                            Icon(
                                if (state.environmentUnknown) Icons.Rounded.Info else Icons.Rounded.ErrorOutline,
                                stringResource(when {
                                    state.environmentNeedsConfirmation -> R.string.home_environment_confirmation_title
                                    state.environmentUnknown -> R.string.home_environment_unknown_title
                                    else -> R.string.home_not_installed
                                }),
                                modifier = Modifier.padding(end = 6.dp),
                                tint = colorScheme.onBackground,
                            )
                        },
                        endActions = {
                            if (!state.environmentUnknown && !state.isLateLoadMode) {
                                TextButton(
                                    text = stringResource(R.string.home_jailbreak),
                                    onClick = actions.onJailbreakClick,
                                    colors = ButtonDefaults.textButtonColors(
                                        color = Color(0xFF2563EB),
                                        textColor = Color.White,
                                    ),
                                )
                            }
                        },
                    )
                    }
                }
            }

            else -> {
                Card(
                    // 同样是安装入口(内核版本不认识时也走安装);照常可点,
                    // 安装页本身已经显示成"真·没 root"的样子(见 InstallScreen 里的说明)
                    // ⚠️ v0.13.157:隐身时**不再是特例**(v0.13.156 加在这里的 stealthOn 堵法已撤)。
                    onClick = {
                        if (!state.isLateLoadMode) {
                            actions.onInstallClick()
                        }
                    },
                    showIndication = !state.isLateLoadMode,
                    pressFeedbackType = PressFeedbackType.Tilt,
                    colors = if (flat) CardDefaults.defaultColors(color = Color.Transparent)
                             else CardDefaults.defaultColors(),
                ) {
                    Column {
                    BasicComponent(
                        title = stringResource(R.string.home_unsupported),
                        summary = stringResource(R.string.home_unsupported_reason),
                        startAction = {
                            Icon(
                                Icons.Rounded.ErrorOutline,
                                stringResource(R.string.home_unsupported),
                                modifier = Modifier.padding(end = 16.dp),
                                tint = colorScheme.onBackground,
                            )
                        }
                    )
                    }
                }
            }
        }
    }
}

/** 首页卡片:开启「界面扁平化」时不画底色,只留文字和图标 */
@Composable
private fun HomeCard(
    flat: Boolean,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    if (flat) {
        Card(
            modifier = modifier,
            colors = CardDefaults.defaultColors(color = Color.Transparent),
            content = content,
        )
    } else {
        Card(modifier = modifier, content = content)
    }
}

@Composable
private fun InstallKernelCard(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    flat: Boolean = false,
) {
    HomeCard(flat = flat, modifier = modifier) {
        ArrowPreference(
            title = stringResource(R.string.maplesu_install_title),
            summary = stringResource(R.string.maplesu_install_summary),
            startAction = {
                Icon(
                    imageVector = Icons.Filled.Build,
                    contentDescription = stringResource(R.string.maplesu_install_title),
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
            onClick = onClick,
        )
    }
}

@Composable
private fun About7kCard(
    showModes: Boolean,
    modifier: Modifier = Modifier,
    flat: Boolean = false,
) {
    var showAbout by rememberSaveable { mutableStateOf(false) }
    val title = stringResource(R.string.about_maple_title)
    HomeCard(flat = flat, modifier = modifier) {
        ArrowPreference(
            title = title,
            summary = stringResource(R.string.about_maple_entry_summary),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Info,
                    contentDescription = title,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
            onClick = { showAbout = true },
        )
    }
    AboutMapleDialogMiuix(show = showAbout, showModes = showModes, onDismiss = { showAbout = false })
}

@Composable
private fun InfoCard(
    systemInfo: SystemInfo,
    modifier: Modifier = Modifier,
    flat: Boolean = false,
) {
    @Composable
    fun InfoText(
        icon: ImageVector,
        title: String,
        content: String,
        bottomPadding: Dp = 24.dp,
        modifier: Modifier = Modifier,
    ) {
        Row(
            modifier = modifier
                .fillMaxWidth()
                .padding(bottom = bottomPadding),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                modifier = Modifier
                    .padding(end = 12.dp)
                    .size(24.dp),
                tint = colorScheme.onSurface,
            )
            Column {
                Text(
                    text = title,
                    fontSize = MiuixTheme.textStyles.headline1.fontSize,
                    fontWeight = FontWeight.Medium,
                    color = colorScheme.onSurface,
                )
                Text(
                    text = content,
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
    }

    val selinuxDisplay = when (systemInfo.selinuxStatus) {
        "Enforcing" -> stringResource(R.string.selinux_status_enforcing)
        "Permissive" -> stringResource(R.string.selinux_status_permissive)
        "Disabled" -> stringResource(R.string.selinux_status_disabled)
        else -> stringResource(R.string.selinux_status_unknown)
    }
    val seccompDisplay = when (systemInfo.seccompStatus) {
        -1 -> stringResource(R.string.seccomp_status_not_supported)
        0 -> stringResource(R.string.seccomp_status_disabled)
        1 -> stringResource(R.string.seccomp_status_strict)
        2 -> stringResource(R.string.seccomp_status_filter)
        else -> stringResource(R.string.seccomp_status_unknown)
    }

    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        HomeCard(flat = flat, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                InfoText(
                    icon = Icons.Filled.Tag,
                    title = stringResource(R.string.home_manager_version),
                    content = systemInfo.managerVersion,
                )
                InfoText(
                    icon = Icons.Filled.DeveloperBoard,
                    title = stringResource(R.string.home_kernel),
                    content = systemInfo.kernelVersion,
                    modifier = Modifier,
                )
                InfoText(
                    icon = Icons.Filled.Smartphone,
                    title = stringResource(R.string.home_device_model),
                    content = systemInfo.deviceModel,
                )
                InfoText(
                    icon = Icons.Filled.Fingerprint,
                    title = stringResource(R.string.home_fingerprint),
                    content = systemInfo.fingerprint,
                    bottomPadding = 0.dp,
                )
            }
        }
        HomeCard(flat = flat, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                InfoText(
                    icon = Icons.Filled.Security,
                    title = stringResource(R.string.home_selinux_status),
                    content = selinuxDisplay,
                )
                InfoText(
                    icon = Icons.Filled.FilterList,
                    title = stringResource(R.string.home_seccomp_status),
                    content = seccompDisplay,
                    bottomPadding = 0.dp,
                )
            }
        }
    }
}

@Preview(name = "Activated")
@Composable
private fun StatusCardActivatedPreview() {
    StatusCard(
        state = previewHomeScreenState(ksuVersion = 12345, lkmMode = true),
        actions = HomeActions({}, {})
    )
}

@Preview(name = "Not Activated")
@Composable
private fun StatusCardNotActivatedPreview() {
    StatusCard(state = previewHomeScreenState(ksuVersion = null, lkmMode = null), actions = HomeActions({}, {}))
}

@Preview(name = "Permissive")
@Composable
private fun StatusCardPermissivePreview() {
    StatusCard(
        state = previewHomeScreenState(ksuVersion = null, lkmMode = null, selinuxStatus = "Permissive"),
        actions = HomeActions({}, {})
    )
}

@Preview(name = "Jailbreak")
@Composable
private fun StatusCardJailbreakPreview() {
    StatusCard(
        state = previewHomeScreenState(ksuVersion = 12345, lkmMode = true, isLateLoadMode = true),
        actions = HomeActions({}, {})
    )
}

private val previewSystemInfo = SystemInfo(
    kernelVersion = "6.12.23-android16-5-g123456789000-abogki123456789-4k",
    managerVersion = "3.0.0 (30000)",
    deviceModel = "Xiaomi 17 Pro Max",
    fingerprint = "Xiaomi/popsicle/popsicle:16/BQ2A.250705.001-BP2A.250605.031.A3/OS3.0.313.0.WPBCNXM:user/release-keys",
    selinuxStatus = "Enforcing",
    seccompStatus = 2
)

private val previewUriHandler = object : UriHandler {
    override fun openUri(uri: String) {}
}

@Composable
private fun HomeScreenPreviewContent(
    ksuVersion: Int?,
    lkmMode: Boolean?,
    isSafeMode: Boolean = false,
    isLateLoadMode: Boolean = false,
    selinuxStatus: String = "Enforcing",
) {
    CompositionLocalProvider(LocalUriHandler provides previewUriHandler) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val actions = HomeActions({}, {})
            StatusCard(
                state = previewHomeScreenState(
                    ksuVersion = ksuVersion,
                    lkmMode = lkmMode,
                    isSafeMode = isSafeMode,
                    isLateLoadMode = isLateLoadMode,
                    selinuxStatus = selinuxStatus,
                ),
                actions = actions
            )
            InfoCard(
                systemInfo = previewSystemInfo.copy(selinuxStatus = selinuxStatus),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Preview(name = "Home Activated", showBackground = true)
@Composable
private fun HomeScreenActivatedPreview() {
    HomeScreenPreviewContent(ksuVersion = 12345, lkmMode = true)
}

@Preview(name = "Home Not Activated", showBackground = true)
@Composable
private fun HomeScreenNotActivatedPreview() {
    HomeScreenPreviewContent(ksuVersion = null, lkmMode = null)
}

@Preview(name = "Home Permissive", showBackground = true)
@Composable
private fun HomeScreenPermissivePreview() {
    HomeScreenPreviewContent(ksuVersion = null, lkmMode = null, selinuxStatus = "Permissive")
}

@Preview(name = "Home Jailbreak", showBackground = true)
@Composable
private fun HomeScreenJailbreakPreview() {
    HomeScreenPreviewContent(ksuVersion = 12345, lkmMode = true, isLateLoadMode = true)
}

private fun previewHomeScreenState(
    ksuVersion: Int?,
    lkmMode: Boolean?,
    isSafeMode: Boolean = false,
    isLateLoadMode: Boolean = false,
    selinuxStatus: String = "Enforcing",
) = HomeUiState(
    kernelVersion = KernelVersion(6, 1, 0),
    ksuVersion = ksuVersion,
    lkmMode = lkmMode,
    isLkmBundled = lkmMode == true,
    isManager = true,
    isManagerPrBuild = false,
    isKernelPrBuild = false,
    requiresNewKernel = false,
    requiresNewManager = false,
    isRootAvailable = ksuVersion != null,
    isSafeMode = isSafeMode,
    isLateLoadMode = isLateLoadMode,
    checkUpdateEnabled = false,
    latestVersionInfo = LatestVersionInfo(),
    currentManagerVersionCode = 10000,
    systemInfo = previewSystemInfo.copy(selinuxStatus = selinuxStatus),
    kernelUAPIVersion = 1,
    managerUAPIVersion = 1,
)
