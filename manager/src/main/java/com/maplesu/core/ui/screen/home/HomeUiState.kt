package com.maplesu.core.ui.screen.home

import androidx.compose.runtime.Immutable
import com.maplesu.core.KernelVersion
import com.maplesu.core.ui.util.module.LatestVersionInfo
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.workmode.detect.ModeState
import dev.maplesu.manager.workmode.detect.SuReadiness
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.WorkMode

enum class HomeEnvironmentFailure { TIMED_OUT, FAILED, UNCONFIRMED, BUSY }

/** Display input from one completed Home session; it contains no Root or readiness proof. */
@Immutable
data class HomeUltraComponentDiagnostic(
    val modeActivation: ModeActivation,
    val detectionRevision: Long,
    val bootId: String,
    val managerOwnerIdentity: UltraRuntimeClient.ManagerOwnerIdentity?,
    val legacyCredentialFingerprint: String?,
    val failureCode: String?,
    val detail: String,
) {
    /** Missing health fields do not prove that the diagnostic's identity changed. */
    internal fun isSupersededBy(
        activation: ModeActivation,
        revision: Long,
        bootId: String?,
        observation: UltraEnvironmentProbe.Snapshot,
    ): Boolean = modeActivation !== activation || detectionRevision != revision ||
        !bootId.isNullOrBlank() && this.bootId != bootId ||
        observation.modeActivation !== modeActivation ||
        observation.managerOwnerIdentity != null && observation.managerOwnerIdentity != managerOwnerIdentity ||
        observation.legacyCredentialFingerprint != null &&
            observation.legacyCredentialFingerprint != legacyCredentialFingerprint
}

@Immutable
data class HomeUiState(
    val kernelVersion: KernelVersion,
    val ksuVersion: Int?,
    val managerUAPIVersion: Int,
    val kernelUAPIVersion: Int?,
    val lkmMode: Boolean?,
    val isLkmBundled: Boolean,
    val isManager: Boolean,
    /**
     * `isManager == false` 的**第二种**原因:内核还没把本 App 认成管理器。
     *
     * `isManager` 为 false 有两种情况,处理方式相反,以前混在一起都显示「点击安装」,
     * 会把用户骗去重刷 LKM(实际白折腾、还有风险):
     *   ① **隐身模式** —— 内核其实仍然认我们(内核的 is_manager() 为真,只是不上报 MANAGER 标志),
     *      `Natives.stealthState()` 能读到 1。界面显示「未安装」是伪装的一部分,正常。
     *   ② **内核没认主** —— 内核里存的 manager appid 与本 App 的 UID 对不上
     *      (**卸载重装会换 UID**,这是主要触发原因)。此时 stealthState() 读不到(返回 -1)。
     *      只要**重启一次设备**,内核开机时的 throne_tracker 会重新扫描 /data/app 认主
     *      —— **不用重刷内核**。
     */
    val managerNotRecognized: Boolean = false,
    val isManagerPrBuild: Boolean,
    val isKernelPrBuild: Boolean,
    val requiresNewKernel: Boolean,
    val requiresNewManager: Boolean,
    val isRootAvailable: Boolean,
    /** Null/UNKNOWN is not a failed command; only an actual SU verdict may raise a warning. */
    val rootReadiness: SuReadiness? = null,
    val isSafeMode: Boolean,
    val isLateLoadMode: Boolean,
    val checkUpdateEnabled: Boolean,
    val latestVersionInfo: LatestVersionInfo,
    val currentManagerVersionCode: Long,
    val systemInfo: SystemInfo,
    /** P0：LITE（或本地 Lite 证据 / 上次已知已安装种子）→ 首帧即按已安装展示。 */
    val liteInstalled: Boolean = false,
    /** P0：Lite 已安装但后台 root 探测失败 → 状态卡图片上方显示固定一行提示。 */
    val liteRootFailure: Boolean = false,
    /** Backend detection is pending; automatic checks never block home content. */
    val litePending: Boolean = false,
    /** Hidden facts remain gated independently of the display-only installation history. */
    val hiddenConfirming: Boolean = false,
    val environmentChecking: Boolean = false,
    val environmentFailure: HomeEnvironmentFailure? = null,
    /** Explicit retry progress is independent of silent automatic observations. */
    val manualEnvironmentChecking: Boolean = false,
    val manualEnvironmentFailure: HomeEnvironmentFailure? = null,
    val environmentConfirmedAbsent: Boolean = false,
    /** 仅供首页渲染：复用顶部 Ultra 字样的当前裁决，不代表 root 命令可用。 */
    val ultraBrandVisible: Boolean = false,
    /** 上次或本次确定的模式，仅用于展示；不激活后端、不授予 root。未安装不继承。 */
    val environmentMode: WorkMode? = null,
    /** Last confirmed installation is display-only; it never activates a backend or grants Root. */
    val previousEnvironmentMode: WorkMode? = null,
    /** Existing SDK/JNI runtime observation, separate from installation records and SU readiness. */
    val environmentRuntimeReady: Boolean = false,
    /** Last confirmed card presentation only; never used as a Root or Manager observation. */
    val cachedEnvironmentReady: Boolean = false,
    /** A current Ultra component observation failure does not revoke its installation identity. */
    val ultraObservationFailure: HomeEnvironmentFailure? = null,
    val ultraObservationDetail: String? = null,
    /** Original bootstrap code retained with this round's diagnostic, never a capability proof. */
    val ultraObservationCode: String? = null,
    val ultraComponentDiagnostic: HomeUltraComponentDiagnostic? = null,
    /** Root proof from this session's fresh SDK health read; ordinary SU stays independent. */
    val sdkRootAvailable: Boolean = false,
) {
    // A temporarily unknown SDK state does not turn a known local mode into external root.
    val showMigrationEntry: Boolean
        get() = isRootAvailable && !isManager && !isSafeMode && environmentMode == null

    val showSafeModeBanner: Boolean
        get() = isSafeMode && environmentMode == WorkMode.LITE && showInstalledStatus && !hiddenConfirming

    val displayEnvironmentMode: WorkMode?
        get() = environmentMode ?: previousEnvironmentMode.takeIf { environmentChecking }

    val environmentUnknown: Boolean
        get() = displayEnvironmentMode == null && !environmentConfirmedAbsent

    val environmentNeedsConfirmation: Boolean
        get() = environmentUnknown && !environmentChecking && !litePending

    val showInstalledStatus: Boolean
        get() = environmentChecking && previousEnvironmentMode != null ||
            !hiddenConfirming && environmentMode != null

    val showEnvironmentReady: Boolean
        get() = showInstalledStatus && !hiddenConfirming && !isSafeMode &&
            ultraObservationFailure == null &&
            (cachedEnvironmentReady && environmentChecking && rootReadiness != SuReadiness.NOT_USABLE ||
                environmentRuntimeReady && environmentFailure == null &&
                (environmentMode == WorkMode.LITE && sdkRootAvailable ||
                    isRootAvailable && rootReadiness == SuReadiness.USABLE))

    val showInstalledUnready: Boolean
        get() = showInstalledStatus && !showEnvironmentReady

    /** Only explicit retries have inline progress; no check replaces the primary card. */
    val showEnvironmentStatusCard: Boolean
        get() = manualEnvironmentChecking

    val showEnvironmentRefreshWarning: Boolean
        get() = !manualEnvironmentChecking && !environmentChecking && !environmentUnknown && manualEnvironmentFailure != null

    val showUltraObservationFailure: Boolean
        get() = ultraObservationFailure != null && displayEnvironmentMode == WorkMode.LITE &&
            showInstalledStatus && !hiddenConfirming

    val isSELinuxPermissive: Boolean
        get() = systemInfo.selinuxStatus == "Permissive"

    val showGkiWarning: Boolean
        get() = ksuVersion != null && lkmMode == false

    // ⚠️ 2026-09-16 关闭「内嵌 LKM 有可用更新」提示。
    //
    // 上游判定是 `ksuVersion != currentManagerVersionCode`，成立的前提是：
    //   管理器 versionCode 与内嵌 .ko 的 KSU_VERSION 来自同一次内核构建 → 两者相等。
    // v0.13.65 为了修「新版装不上」把 versionCode 改成按版本名推导(0.13.65 → 130650)，
    // 而内嵌 .ko 的 KSU_VERSION 实测仍是 32649（8 个 .ko 全部反汇编核对过：
    //   android16-6.12 为 `mov w11, #0x7f89`，android12-5.10 在 .rodata 里）
    // → 两个数永远不等 → 提示必然误报，且会引导用户去重刷/重装 LKM。
    //
    // 关闭是安全的：这不是更新 LKM 的唯一入口，安装页仍可手动选装 LKM。
    // 若将来要恢复，不要再用 currentManagerVersionCode 比较，应改为比较
    // 「本 APK 内嵌的那份 .ko 的版本号」，且用 `>` 而非 `!=`——语义才是「有可用更新」，
    // 也免疫 bundled 比 running 更旧（浅克隆下 KSU_VERSION 会变小）的情况。
    val showLkmUpdate: Boolean
        get() = false

    val showCustomLkmBadge: Boolean
        get() = lkmMode == true && !isLkmBundled

    val showRootWarning: Boolean
        get() = !showSafeModeBanner && ksuVersion != null && !isRootAvailable && rootReadiness == SuReadiness.NOT_USABLE

    /**
     * P0：是否显示「MapleSU_Ultra模式启动失败！」这一行（状态卡图片**上方**，双皮肤同一份判据）。
     *
     * 只有**已安装**才可能显示 —— 这一行是"已安装、但后台 root 没拿到"的补充说明，
     * 不能反过来把首页说成未安装（要求：安装态绝不因 root 失败回退）。
     * 因此 KSU / 未判定（[liteInstalled] = false）与隐身归一化（清掉 [liteInstalled]）都不会出现它。
     */
    val showLiteRootFailure: Boolean
        get() = !isSafeMode && liteInstalled && liteRootFailure && !hiddenConfirming && rootReadiness == SuReadiness.NOT_USABLE

    /** Explicit retry progress only; automatic checks remain silent. */
    val showLiteChecking: Boolean
        get() = manualEnvironmentChecking && !showInstalledStatus

    val showManagerPrBuildWarning: Boolean
        get() = isManager && isManagerPrBuild

    val showKernelPrBuildWarning: Boolean
        get() = isManager && !isManagerPrBuild && isKernelPrBuild

    val hasUpdate: Boolean
        get() = latestVersionInfo.versionCode > currentManagerVersionCode
}

/** 完成环境检查后的首页投影；检测结论不授予安装或 root 能力。 */
internal fun HomeUiState.afterEnvironmentCheck(
    modeResolved: Boolean,
    detectionComplete: Boolean,
    detectionFailure: String?,
    detectedState: ModeState?,
    knownUltra: Boolean = false,
    failureDetail: String? = null,
): HomeUiState {
    val failure = when {
        detectionFailure?.contains("TIMEOUT", ignoreCase = true) == true -> HomeEnvironmentFailure.TIMED_OUT
        detectionFailure?.contains("BUSY", ignoreCase = true) == true -> HomeEnvironmentFailure.BUSY
        detectionFailure != null -> HomeEnvironmentFailure.FAILED
        !detectionComplete -> HomeEnvironmentFailure.UNCONFIRMED
        detectedState == ModeState.INDETERMINATE -> HomeEnvironmentFailure.UNCONFIRMED
        !modeResolved && detectedState == null -> HomeEnvironmentFailure.UNCONFIRMED
        else -> null
    }
    val confirmedAbsent = !knownUltra && environmentConfirmedAbsent
    val identityConfirmed = knownUltra || modeResolved || detectedState in setOf(
        ModeState.MODE_A_ACTIVE, ModeState.MODE_A_INSTALLED_UNBOUND,
        ModeState.MODE_B_ACTIVE, ModeState.MODE_B_KERNEL_ONLY,
    )
    val identityPending = !identityConfirmed && !confirmedAbsent
    val settled = copy(
        environmentMode = if (knownUltra) WorkMode.LITE else environmentMode,
        liteInstalled = liteInstalled || knownUltra,
        environmentConfirmedAbsent = environmentConfirmedAbsent && !knownUltra,
        environmentChecking = identityPending,
        environmentFailure = failure.takeUnless { knownUltra },
        litePending = identityPending,
        sdkRootAvailable = sdkRootAvailable && knownUltra && failure == null,
        environmentRuntimeReady = environmentRuntimeReady && !(knownUltra && failure != null),
        ultraObservationFailure = if (knownUltra) failure else ultraObservationFailure,
        ultraObservationDetail = if (knownUltra) (failureDetail ?: detectionFailure).takeIf { failure != null }
            else ultraObservationDetail,
        ultraObservationCode = if (knownUltra) detectionFailure.takeIf { failure != null } else ultraObservationCode,
        ultraComponentDiagnostic = null,
    )
    return if (confirmedAbsent) {
        settled.copy(environmentMode = null, previousEnvironmentMode = null,
            environmentRuntimeReady = false,
            sdkRootAvailable = false,
            cachedEnvironmentReady = false,
            ultraBrandVisible = false, ksuVersion = null, liteInstalled = false,
            ultraObservationFailure = null, ultraObservationDetail = null, ultraObservationCode = null,
            ultraComponentDiagnostic = null,
            isManager = false, environmentConfirmedAbsent = true,
            isRootAvailable = isRootAvailable && detectedState == ModeState.FOREIGN_SU,
            rootReadiness = rootReadiness.takeIf { detectedState == ModeState.FOREIGN_SU })
    } else settled
}

/** Keep current local installation/hiding facts when a full Root observation fails. */
internal fun HomeUiState.afterEnvironmentProbeFailure(
    local: HomeUiState,
    failure: HomeEnvironmentFailure = HomeEnvironmentFailure.FAILED,
    knownUltra: Boolean = false,
    failureDetail: String? = null,
): HomeUiState {
    val identityPending = !knownUltra && !local.environmentConfirmedAbsent
    return copy(
        environmentMode = if (knownUltra) WorkMode.LITE else local.environmentMode,
        previousEnvironmentMode = local.previousEnvironmentMode,
        liteInstalled = local.liteInstalled || knownUltra,
        hiddenConfirming = local.hiddenConfirming,
        isManager = local.isManager,
        environmentRuntimeReady = false,
        sdkRootAvailable = false,
        // Local mode evidence is not a successful Root command or a manager handshake.
        isRootAvailable = false,
        rootReadiness = null,
        liteRootFailure = local.liteRootFailure,
        environmentConfirmedAbsent = local.environmentConfirmedAbsent && !knownUltra,
        environmentChecking = identityPending,
        environmentFailure = failure.takeUnless { knownUltra },
        litePending = identityPending,
        ultraObservationFailure = failure.takeIf { knownUltra },
        ultraObservationDetail = failureDetail.takeIf { knownUltra },
        ultraObservationCode = null,
        ultraComponentDiagnostic = null,
    )
}

/** The caller supplies one fresh health return after this session has confirmed Ultra identity. */
internal fun HomeUiState.afterUltraEnvironmentHealth(
    observation: UltraEnvironmentProbe.Snapshot,
    expectedOwner: UltraRuntimeClient.ManagerOwnerIdentity?,
    scopeCurrent: Boolean,
): HomeUiState {
    val sameIdentity = if (expectedOwner != null) observation.managerOwnerIdentity == expectedOwner else
        observation.managerOwnerIdentity == null && observation.legacyCredentialFingerprint != null
    val scopeChanged = !scopeCurrent || observation.managerOwnerIdentity != null && !sameIdentity
    val managerSuDetail = observation.managerSuFailureDetail?.takeIf { it.isNotBlank() }
    val detail = observation.rootProbeDetail?.takeIf { it.isNotBlank() }
        ?: if (scopeChanged) "SDK_IDENTITY_SCOPE_CHANGED" else managerSuDetail ?: observation.detail
    val sdkError = detail?.substringAfter("sdkError=", "")?.substringBefore(';')
    val explicitFailure = detail != null && (observation.rootProbeDetail != null || managerSuDetail != null ||
        !detail.contains("sdkError=") || sdkError !in setOf("", "NONE", "OK"))
    val failure = when {
        detail?.contains("TIMEOUT", ignoreCase = true) == true -> HomeEnvironmentFailure.TIMED_OUT
        detail?.contains("BUSY", ignoreCase = true) == true -> HomeEnvironmentFailure.BUSY
        explicitFailure || observation.state == UltraEnvironmentProbe.State.Fault -> HomeEnvironmentFailure.FAILED
        !scopeCurrent || !sameIdentity || observation.state != UltraEnvironmentProbe.State.Running ||
            !observation.rootAvailable -> HomeEnvironmentFailure.UNCONFIRMED
        else -> null
    }
    val healthy = failure == null && !hiddenConfirming && !isSafeMode
    val firstDetail = ultraObservationDetail?.takeIf {
        ultraObservationFailure != null && it.isNotBlank() && it != "home_health_pending" && !scopeChanged
    }
    val environmentDetail = observation.detail?.takeIf { raw ->
        raw.isNotBlank() && (!raw.contains("sdkError=") ||
            raw.substringAfter("sdkError=").substringBefore(';') !in setOf("", "NONE", "OK"))
    }
    val currentDetails = listOfNotNull(
        "SDK_IDENTITY_SCOPE_CHANGED".takeIf { scopeChanged },
        observation.rootProbeDetail?.takeIf { it.isNotBlank() },
        managerSuDetail,
        environmentDetail,
    ).ifEmpty { listOfNotNull(detail) }
    val completeDetail = (listOfNotNull(firstDetail) + currentDetails).distinct().joinToString("\n")
    return copy(
        environmentMode = WorkMode.LITE, liteInstalled = true, environmentConfirmedAbsent = false,
        environmentChecking = false, litePending = false, environmentFailure = null,
        environmentRuntimeReady = healthy,
        sdkRootAvailable = healthy && scopeCurrent && sameIdentity && observation.rootAvailable,
        cachedEnvironmentReady = false,
        isSafeMode = isSafeMode || observation.state == UltraEnvironmentProbe.State.Fault,
        ultraObservationFailure = failure,
        ultraObservationDetail = completeDetail.takeIf { failure != null && it.isNotBlank() },
        ultraObservationCode = ultraObservationCode.takeIf { failure != null && firstDetail != null },
        ultraComponentDiagnostic = null,
    )
}

/** The single final publication rechecks the source scope without another identity probe. */
internal fun HomeUiState.afterFinalEnvironmentScopeCheck(
    observedActivation: ModeActivation?,
    observedRevision: Long?,
    currentActivation: ModeActivation,
    currentRevision: Long,
    currentBootId: String? = null,
    currentObservation: UltraEnvironmentProbe.Snapshot? = null,
    observedBootId: String? = null,
): HomeUiState {
    if (observedActivation == null || observedActivation !== currentActivation || observedRevision != currentRevision ||
        !observedBootId.isNullOrBlank() && !currentBootId.isNullOrBlank() && observedBootId != currentBootId) {
        return copy(
            environmentMode = null, environmentConfirmedAbsent = false, ultraBrandVisible = false,
            ksuVersion = null, kernelUAPIVersion = null, liteInstalled = false,
            environmentRuntimeReady = false, sdkRootAvailable = false,
            isManager = false, isRootAvailable = false, rootReadiness = null,
            liteRootFailure = false, ultraObservationFailure = null, ultraObservationDetail = null,
            ultraObservationCode = null, ultraComponentDiagnostic = null, isLateLoadMode = false,
            environmentChecking = false, litePending = false, environmentFailure = null,
            previousEnvironmentMode = null, cachedEnvironmentReady = false,
        )
    }
    val diagnostic = ultraComponentDiagnostic
    return if (diagnostic != null && currentObservation != null && diagnostic.isSupersededBy(
            currentActivation, currentRevision, currentBootId, currentObservation,
        )) copy(
            sdkRootAvailable = false, environmentRuntimeReady = false, cachedEnvironmentReady = false,
            ultraObservationFailure = HomeEnvironmentFailure.UNCONFIRMED,
            ultraObservationDetail = "SDK_IDENTITY_SCOPE_CHANGED",
            ultraObservationCode = null, ultraComponentDiagnostic = null,
        ) else this
}

/**
 * 后台刷新保留尚未更新的版本信息；普通状态采用当前观测。
 *
 * [buildState][com.maplesu.core.ui.viewmodel.HomeViewModel] 每轮都从默认值开始算，直接覆盖的话：
 *  - 更新卡要等联网回来，每次回前台都会消失再出现；
 * SELinux 的有效缓存由 Checker 管理，真实 Unknown 不继承旧快照。
 *
 * 隐身/隐藏的归一化不受影响：[HomeUiState.checkUpdateEnabled] 为 false 时不保留版本信息
 * （否则更新卡的版本号与下载链接会漏过伪装）。
 */
fun HomeUiState.mergedOver(previous: HomeUiState): HomeUiState {
    val keepLatestVersion = checkUpdateEnabled && latestVersionInfo == LatestVersionInfo()
    val keepPresentation = environmentChecking && previous.showInstalledStatus && !environmentConfirmedAbsent && !isSafeMode &&
        rootReadiness != SuReadiness.NOT_USABLE &&
        (environmentMode == null || environmentMode == previous.displayEnvironmentMode)
    val keepDisplay = environmentChecking && !environmentConfirmedAbsent && environmentMode == null &&
        previousEnvironmentMode == null
    val observationSettled = !environmentChecking && !litePending && environmentFailure == null
    val keepUltraObservation = environmentChecking && ultraObservationFailure == null &&
        !environmentConfirmedAbsent && environmentMode != WorkMode.KSU &&
        previous.displayEnvironmentMode == WorkMode.LITE && previous.ultraObservationFailure != null
    return copy(
        latestVersionInfo = if (keepLatestVersion) previous.latestVersionInfo else latestVersionInfo,
        previousEnvironmentMode = when {
            !environmentChecking -> null
            keepPresentation || keepDisplay -> previous.displayEnvironmentMode
            else -> previousEnvironmentMode
        },
        ksuVersion = if (keepPresentation) previous.ksuVersion else ksuVersion,
        kernelUAPIVersion = if (keepPresentation) previous.kernelUAPIVersion else kernelUAPIVersion,
        lkmMode = if (keepPresentation) previous.lkmMode else lkmMode,
        isLkmBundled = if (keepPresentation) previous.isLkmBundled else isLkmBundled,
        cachedEnvironmentReady = keepPresentation && previous.showEnvironmentReady &&
            ultraObservationFailure == null && !keepUltraObservation,
        ultraObservationFailure = if (keepUltraObservation) previous.ultraObservationFailure else ultraObservationFailure,
        ultraObservationDetail = if (keepUltraObservation) previous.ultraObservationDetail else ultraObservationDetail,
        ultraObservationCode = if (keepUltraObservation) previous.ultraObservationCode else ultraObservationCode,
        ultraComponentDiagnostic = if (keepUltraObservation) previous.ultraComponentDiagnostic else ultraComponentDiagnostic,
        manualEnvironmentChecking = previous.manualEnvironmentChecking,
        manualEnvironmentFailure = previous.manualEnvironmentFailure.takeUnless { observationSettled },
    )
}

/** SDK safety may revoke capabilities; recovery still needs a fresh successful Root probe. */
internal fun HomeUiState.withUltraSafety(safeMode: Boolean, mode: WorkMode?): HomeUiState =
    if (mode == WorkMode.KSU) copy(sdkRootAvailable = false,
        ultraObservationFailure = null, ultraObservationDetail = null,
        ultraObservationCode = null, ultraComponentDiagnostic = null) else copy(
        isSafeMode = safeMode,
        isRootAvailable = isRootAvailable && !safeMode,
        sdkRootAvailable = sdkRootAvailable && !safeMode,
        rootReadiness = if (safeMode) null else rootReadiness,
        cachedEnvironmentReady = cachedEnvironmentReady && !safeMode,
    )

/**
 * **隐身模式**下的首页伪装:把 [HomeUiState] 归一化成「未安装」那一支。
 *
 * 隐身开着时,首页跟「没刷内核/没认主的机器」看起来一模一样 —— 状态卡显示
 * 「未安装 / 点击安装」(原版 KernelSU 的标准样子),点一下进安装页,
 * 安装页本身对没 root 的设备就只给「选文件修补」这条路,不露馅。
 *
 * (2026-10-14 调整:早期版本曾伪装成「内核未就绪」并弹说明窗 —— 那个写法会把
 *  没 root 的用户挡在修补入口外,已按用户要求撤回原版行为。)
 *
 * 做法是**在 UiState 层面归一化**(Miuix / Material 两套界面都自动生效),
 * 不新画任何 UI —— 少一套 UI 就少一个将来会漏馅的地方:
 *   - [managerNotRecognized] = true + [isRootAvailable] = false;
 *   - 清掉所有"其实认主了 / 其实有 root / 其实是 LKM"的字段,
 *     否则会漏出绿卡、「安装 / 更新内核」卡、更新卡、GKI 警告卡。
 *
 * ⚠️ **不动 [isManager]**:那是内核给的**真实**值(隐身时本来就是 false),
 *    底栏 / 导航 / 闸门 / 数据迁移都靠它,这里一个字都不许改。
 * ⚠️ 这里只做**内容侧**归一化,**外观侧一个字都不动** ——
 *    壁纸 / 透明度 / 动画 / 字体 / 配色 / 扁平化在隐身时全部照常(见 `security/Stealth.kt` 顶部注释)。
 */
fun HomeUiState.asStealthKernelNotReady(): HomeUiState = copy(
    ksuVersion = null,
    kernelUAPIVersion = null,
    lkmMode = null,
    isLkmBundled = false,
    managerNotRecognized = true,
    isManagerPrBuild = false,
    isKernelPrBuild = false,
    requiresNewKernel = false,
    requiresNewManager = false,
    isRootAvailable = false,
    sdkRootAvailable = false,
    rootReadiness = null,
    isSafeMode = false,
    isLateLoadMode = false,
    // 隐身时不检查更新:更新卡会写版本号 + 下载链接,还多一次联网(伪装期越安静越好)
    checkUpdateEnabled = false,
    latestVersionInfo = LatestVersionInfo(),
    // P0：Lite 的三个字段也必须一起归一化 —— 伪装成「未安装」时，多一行
    // 「MapleSU_Ultra模式启动失败！」就等于自曝。放在这里（而不是只靠调用方 copy）
    // 是为了让"隐身 ⇒ 不露 Lite 痕迹"成为**状态自身的**不变量，将来新调用方也不会漏。
    // 2026-10-30：新增 [litePending] 同样要清 —— 隐身时画 loading 占位等于告诉观察者
    // "这个 App 正在判定 Lite 状态"，与伪装目标冲突；隐身必须立刻就是原版「未安装」。
    liteInstalled = false,
    liteRootFailure = false,
    litePending = false,
    // 已确认隐藏 ⇒ 已经"确认完成"，必须直接呈「未安装」，不能再画确认提示。
    hiddenConfirming = false,
    environmentChecking = false,
    environmentFailure = null,
    environmentConfirmedAbsent = true,
    manualEnvironmentChecking = false,
    manualEnvironmentFailure = null,
    ultraBrandVisible = false,
    environmentMode = null,
    previousEnvironmentMode = null,
    environmentRuntimeReady = false,
    cachedEnvironmentReady = false,
    ultraObservationFailure = null,
    ultraObservationDetail = null,
    ultraObservationCode = null,
    ultraComponentDiagnostic = null,
)

/**
 * **A（Lite 隐藏）生效时**的首页伪装：与 KSU 隐身走**同一条**「未安装」渲染路径
 * （[asStealthKernelNotReady]），并额外把 [HomeUiState.isManager] 置 false。
 *
 * 为什么必须改 isManager：KSU 隐身时内核已经不再上报 MANAGER 标志，`isManager` 本来就是
 * 内核给的 false；Lite 隐藏是 **App 级**伪装，没有内核事实要保留，不置 false 就会继续
 * 露出"管理器才有"的卡片/入口，与「App 呈未安装」的目标冲突。
 *
 * ⚠️ 只用于**内容侧**（首页渲染）；底栏/导航等全局门禁不在本函数职责内。
 */
fun HomeUiState.asLiteHiddenNotInstalled(): HomeUiState =
    asStealthKernelNotReady().copy(isManager = false)

/** 确定隐藏和真实事务优先；普通未知仅保留安装历史，不授予管理能力。 */
internal fun HomeUiState.withHiddenFacts(hidden: HomeHiddenFacts): HomeUiState = when {
    hidden.masking -> asLiteHiddenNotInstalled()
    hidden.transitionPending -> asLiteHiddenNotInstalled().copy(hiddenConfirming = true)
    hidden.confirming -> asLiteHiddenNotInstalled().copy(
        hiddenConfirming = true,
        previousEnvironmentMode = displayEnvironmentMode,
        environmentConfirmedAbsent = environmentConfirmedAbsent,
        manualEnvironmentChecking = manualEnvironmentChecking && !hidden.transitionPending,
        manualEnvironmentFailure = manualEnvironmentFailure.takeUnless { hidden.transitionPending },
        environmentChecking = environmentChecking || litePending,
        environmentFailure = environmentFailure,
    )
    else -> copy(hiddenConfirming = false)
}

/** 检查期间保留已确认模式；没有上次模式时才显示检查进度。 */
internal fun HomeUiState.checkingAfterSuMissing(): HomeUiState = if (environmentMode != null) {
    copy(environmentChecking = true, environmentFailure = null)
} else copy(
    environmentMode = null, ksuVersion = null, ultraBrandVisible = false,
    liteInstalled = false, litePending = true,
    environmentChecking = true, environmentFailure = null,
)

@Immutable
data class HomeActions(
    val onInstallClick: () -> Unit,
    val onOpenUrl: (String) -> Unit,
    val onJailbreakClick: () -> Unit = {},
    val onEnvironmentRetry: () -> Unit = {},
    val onOpenEnvironmentSettings: () -> Unit = {},
    val onManageModules: () -> Unit = {},
    val onFeedbackClick: () -> Unit = {},
)
