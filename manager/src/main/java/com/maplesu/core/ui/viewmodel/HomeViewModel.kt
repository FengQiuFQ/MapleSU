package com.maplesu.core.ui.viewmodel

import android.os.Build
import android.os.SystemClock
import android.system.Os
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import com.maplesu.core.BuildConfig
import com.maplesu.core.KernelVersion
import com.maplesu.core.Natives
import com.maplesu.core.data.repository.SettingsRepository
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.getKernelVersion
import com.maplesu.core.ksuApp
import com.maplesu.core.ui.screen.home.HomeEntryFacts
import com.maplesu.core.ui.screen.home.HomeHiddenFacts
import com.maplesu.core.ui.screen.home.HomeUiState
import com.maplesu.core.ui.screen.home.HomeUltraComponentDiagnostic
import com.maplesu.core.ui.screen.home.HomeWorkModeSwitchRuntime
import com.maplesu.core.ui.screen.home.ManagerVersion
import com.maplesu.core.ui.screen.home.SystemInfo
import com.maplesu.core.ui.screen.home.asStealthKernelNotReady
import com.maplesu.core.ui.screen.home.getManagerVersion
import com.maplesu.core.ui.screen.home.homeEntryFacts
import com.maplesu.core.ui.screen.home.mergedOver
import com.maplesu.core.ui.screen.home.withUltraSafety
import com.maplesu.core.ui.screen.home.afterEnvironmentCheck
import com.maplesu.core.ui.screen.home.afterUltraEnvironmentHealth
import com.maplesu.core.ui.screen.home.afterFinalEnvironmentScopeCheck
import com.maplesu.core.ui.screen.home.asLiteHiddenNotInstalled
import com.maplesu.core.ui.security.HiddenFactsSignal
import com.maplesu.core.ui.security.HiddenStartupConfirm
import com.maplesu.core.ui.util.checkNewVersion
import com.maplesu.core.ui.util.getSELinuxStatusRaw
import com.maplesu.core.ui.util.module.LatestVersionInfo
import com.maplesu.core.ui.util.resolveDeviceName
import dev.maplesu.manager.litehidden.LiteStartupFacts
import dev.maplesu.manager.litehidden.LiteStartupStatusPolicy
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.EnvironmentProbeResult
import dev.maplesu.manager.workmode.EnvironmentProbeRunner
import dev.maplesu.manager.workmode.boot.ModeBootstrap
import dev.maplesu.manager.workmode.detect.EnvironmentCheckOutcome
import dev.maplesu.manager.workmode.detect.EnvironmentVerdict
import dev.maplesu.manager.workmode.detect.probes.BootIdSourceAdapter
import dev.maplesu.manager.workmode.detect.SuReadiness
import dev.maplesu.manager.workmode.detect.probes.EnvironmentCheckProduction
import com.maplesu.core.ui.screen.home.HomeEnvironmentFailure
import com.maplesu.core.ui.screen.settings.UltraComponentDiagnosticRequests
import com.maplesu.core.ui.screen.settings.currentUltraComponentDiagnosticSnapshot
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.PageReadDeadline

/*
 * P0（Lite 模式启动状态）两个时序常量：
 *  - 模式判定是**两段式**的（阶段二约 2.5s 后才 activate）。未判定窗口里 root 探测本身被
 *    启动门控挡住，这一次失败不能当"Lite 启动失败"，所以要等判定落定后再判；
 *  - 已在途的模式判定可以有界等待；新的观察只来自显式动作或真实模式变化。
 */
private const val LITE_MODE_SETTLE_TIMEOUT_MS = 8_000L

/** 等模式激活后重算一次入口事实的上限；超时后由回前台/切页继续兜底。 */
private const val ENTRY_FACTS_MODE_WAIT_MS = 15_000L
private const val HOME_ENVIRONMENT_PROBE_TIMEOUT_MS = 8_000L
private const val HOME_ENVIRONMENT_SESSION_TIMEOUT_MS = 10_000L
private val homeEnvironmentProbeRunner = EnvironmentProbeRunner("maplesu-home-environment")
private val homeDeviceNameProbeRunner = EnvironmentProbeRunner("maplesu-home-device-name")
private val homeSELinuxProbeRunner = EnvironmentProbeRunner("maplesu-home-selinux")

class HomeViewModel(
    private val settingsRepo: SettingsRepository = SettingsRepositoryImpl()
) : ViewModel() {

    // ⚠️ 2026-09-19 修(启动首帧:ANR + 闪退):
    //    这里以前是 `MutableStateFlow(buildState())`。HomeViewModel 是**在主线程上构造**的,
    //    而 buildState() 会同步去建 root shell(最多 2 个候选、每次探测超时 1.5s)
    //    和 SELinux shell → 首帧白屏甚至 ANR;里面任何一处抛异常还会直接闪退。
    //    现在:首帧只算**不碰 shell / JNI** 的本地快照,
    //    root 和普通信息分别在后台读取,各自完成后刷新现有 UI 字段。
    //    界面结构、字段、默认值展示方式都不变,只是「有没有 root / SELinux 状态」
    //    这两个字段先显示默认值(false / Unknown),后台算完自动刷新。
    //
    // 首帧只读取当前运行事实；历史安装记录不参与身份和未安装判断。
    // 整个观察会话结束前不发布各轮候选，避免主卡随探针的中间结果变化。
    private val _uiState = MutableStateFlow(
        buildState(probeRoot = false, modeSettled = ModeRuntime.active != null)
            .state
            .copy(environmentChecking = true),
    )
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    // 组合期不读 JNI / prefs / 文件：首页入口的事实都在这里。
    //
    // 首帧快照只含隐藏事实（内存 + 上面 buildState 已加载的中性 prefs 种子），入口一律不可见；
    // 隐藏优先，所以"还没读到事实"永远不会露出入口。
    private val _entryFacts = MutableStateFlow(HomeEntryFacts.beforeFirstRead(readHiddenFacts()))
    val entryFacts: StateFlow<HomeEntryFacts> = _entryFacts.asStateFlow()
    private val entryFactsTick = MutableStateFlow(0L)

    /** One flight owns the complete observation session; ordinary information stays independent. */
    private val environmentMutex = Mutex()
    private val publishMutex = Mutex()
    private val refreshFlight = HomeRefreshSingleFlight()
    // A completed Job also records that this Home has used its automatic session.
    private var environmentSessionJob: Job? = null
    private var environmentExplicitRequest = false
    private var installedKernelInspectionRequested = false
    private var restoredSdkRefreshRequested = false
    private var publishedDetectionRevision = -1L
    private var environmentOwner = 0L
    private var informationOwner = 0L
    private var deviceNameInformationJob: Job? = null
    private var selinuxInformationJob: Job? = null
    private var selinuxInformationOwner = 0L
    private var selinuxInformationBootId: String? = null
    private var informationContext: HomeInformationOwner? = null

    private data class HomeStateRead(
        val state: HomeUiState,
        val owner: HomeInformationOwner? = null,
        val evidence: EnvironmentCheckOutcome? = null,
        val evidenceActivation: ModeActivation? = null,
        val healthObservation: UltraEnvironmentProbe.Snapshot? = null,
    )
    private data class HomeInformationOwner(
        val id: Long,
        val revision: Long,
        val activation: WorkMode?,
        val bootId: String,
    )

    private fun HomeInformationOwner.isCurrent(currentOwner: Long): Boolean =
        id == currentOwner && revision == ModeRuntime.detectionRevision.value &&
            activation == ModeRuntime.active

    init {
        viewModelScope.launch {
            var previous = UltraEnvironmentProbe.current()
            UltraEnvironmentProbe.states.collect { state ->
                _uiState.update { it.withCurrentUltraSafety() }
                if (state == UltraEnvironmentProbe.State.Running && previous != state &&
                    ModeRuntime.active != WorkMode.KSU) startEnvironmentSession()
                previous = state
            }
        }
        // 隐藏信号要尽快生效：不走主线程调度，主线程忙时入口也能先收起。
        // collectLatest 保证新信号会作废正在进行的读取，迟到的"可见"结果写不进来。
        viewModelScope.launch(Dispatchers.Default) {
            merge(entryFactsTick, HiddenFactsSignal.revision, dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.pendingFlow.map { if (it) 1L else 0L }).collectLatest { publishEntryFacts() }
        }
        if (ModeRuntime.active == null) {
            viewModelScope.launch {
                ModeRuntime.awaitActivated(ENTRY_FACTS_MODE_WAIT_MS)
                refreshEntryFacts()
            }
        }
        viewModelScope.launch {
            ModeRuntime.detectionRevision.drop(1).collect {
                startEnvironmentSession()
            }
        }
        viewModelScope.launch {
            UltraComponentDiagnosticRequests.retries.collect { request ->
                val current = withContext(Dispatchers.IO) { currentUltraComponentDiagnosticSnapshot(ksuApp) }
                    ?: return@collect
                if (current.modeActivation !== request.modeActivation ||
                    current.managerOwnerIdentity != request.managerOwnerIdentity) return@collect
                startEnvironmentSession(explicit = true)
            }
        }
        // Ordinary system facts do not wait for backend activation.
        viewModelScope.launch {
            refreshInformation(forceSELinuxRead = true)
        }
        startEnvironmentSession()
    }

    /** A round collects a candidate; only the owning session publishes an identity. */
    private suspend fun collectEnvironment(
        rootProbeSettled: Boolean,
        modeSettled: Boolean = ModeRuntime.active != null,
        evidence: EnvironmentCheckOutcome? = null,
        evidenceActivation: ModeActivation? = null,
        owner: HomeInformationOwner,
        deadline: Long,
    ): HomeStateRead {
        return environmentMutex.withLock {
        val revision = owner.revision
        val budget = remainingEnvironmentTime(deadline)
        if (budget == 0L) return@withLock HomeStateRead(
            resolvedFailure(HomeEnvironmentFailure.TIMED_OUT, "home_health_session_deadline"),
            owner, evidence, evidenceActivation,
        )
        val checked = homeEnvironmentProbeRunner.run(minOf(HOME_ENVIRONMENT_PROBE_TIMEOUT_MS, budget)) {
            // 确认窗口：上次已知隐藏 ON 且本进程还没真实读过 → 先读一次（root 通道）。
            // 读完再构建状态，避免"先画正在运行、过一会翻未安装"的自曝窗口。
            runCatching { HiddenStartupConfirm.ensureConfirmedOnce(ksuApp) }
            val knownUltra = evidence?.verdict == EnvironmentVerdict.ULTRA
            val observation = if (knownUltra) UltraEnvironmentProbe.observeFresh(ksuApp) else null
            val observed = buildState(
                probeRoot = true,
                rootProbeSettled = rootProbeSettled,
                modeSettled = modeSettled,
                evidence = evidence,
                healthObservation = observation,
            ).state
            // Bootstrap diagnostics belong to a detection revision. A later Home
            // session must not reintroduce a failure already consumed by its final publication.
            val detectionFailure = ModeRuntime.detectionFailure.takeIf { revision != publishedDetectionRevision }
            val projected = observed.afterEnvironmentCheck(
                modeResolved = ModeRuntime.active != null,
                detectionComplete = knownUltra || ModeRuntime.detectionComplete,
                detectionFailure = detectionFailure,
                detectedState = ModeRuntime.latestDetection?.state.takeUnless { knownUltra },
                knownUltra = knownUltra,
                failureDetail = ModeRuntime.detectionFailureDetail.takeIf { detectionFailure != null } ?: detectionFailure,
            )
            val state = if (observation != null) projected.afterUltraEnvironmentHealth(
                observation = observation,
                expectedOwner = evidence?.ultraOwnerIdentity,
                scopeCurrent = evidenceActivation === ModeRuntime.activation &&
                    observation.modeActivation === evidenceActivation && ModeRuntime.active != WorkMode.KSU,
            ) else projected
            HomeStateRead(state, owner, evidence, evidenceActivation, observation)
        }
        currentCoroutineContext().ensureActive()
        // Activation can complete while the worker builds its old snapshot.
        // Use current local facts until the queued detection refresh observes Root again.
        val detectionChanged = revision != ModeRuntime.detectionRevision.value
        if (detectionChanged) return@withLock HomeStateRead(
            resolvedFailure(HomeEnvironmentFailure.BUSY, "detection_revision_changed"),
            owner, evidence, evidenceActivation,
        )
        val failure = when (checked) {
            is EnvironmentProbeResult.Completed -> return@withLock checked.value
            EnvironmentProbeResult.TimedOut -> resolvedFailure(HomeEnvironmentFailure.TIMED_OUT, "timeout")
            EnvironmentProbeResult.Busy -> resolvedFailure(HomeEnvironmentFailure.BUSY, "busy")
            is EnvironmentProbeResult.Failed -> {
                Log.w(TAG, "Home environment check failed", checked.cause)
                resolvedFailure(HomeEnvironmentFailure.FAILED,
                    checked.cause?.message ?: checked.cause?.javaClass?.simpleName ?: "failed")
            }
        }
        HomeStateRead(failure, owner, evidence, evidenceActivation)
    } }

    private suspend fun refreshInformation(forceSELinuxRead: Boolean = false) {
        val revision = ModeRuntime.detectionRevision.value
        val activation = ModeRuntime.active
        val bootId = runCatching { BootIdSourceAdapter.read() }.getOrDefault("")
        publishMutex.withLock {
            refreshSELinuxInformation(bootId, forceSELinuxRead)
            val currentOwner = informationContext
            val sameContext = currentOwner?.let {
                it.revision == revision && it.activation == activation && it.bootId == bootId
            } == true
            if (currentOwner != null && sameContext && deviceNameInformationJob?.isActive == true) return
            val owner = HomeInformationOwner(++informationOwner, revision, activation, bootId)
            informationContext = owner
            deviceNameInformationJob = viewModelScope.launch { readDeviceName(owner) }
        }
    }

    private fun refreshSELinuxInformation(bootId: String, forceRead: Boolean) {
        val previous = selinuxInformationJob
        val sameBoot = selinuxInformationBootId == bootId
        if (sameBoot && (previous?.isActive == true || (!forceRead && previous != null))) return
        val owner = ++selinuxInformationOwner
        selinuxInformationBootId = bootId
        if (!sameBoot) _uiState.update { it.copy(systemInfo = it.systemInfo.copy(selinuxStatus = "Unknown")) }
        selinuxInformationJob = viewModelScope.launch {
            previous?.join()
            if (owner != selinuxInformationOwner || bootId.isBlank()) return@launch
            readSELinux(bootId, owner)
        }
    }

    private suspend fun readDeviceName(owner: HomeInformationOwner) {
        val result = homeDeviceNameProbeRunner.run(HOME_ENVIRONMENT_PROBE_TIMEOUT_MS) { resolveDeviceName() }
        val name = (result as? EnvironmentProbeResult.Completed)?.value ?: Build.MODEL
        publishInformation(owner) { it.copy(deviceModel = name) }
    }

    private suspend fun readSELinux(bootId: String, owner: Long) {
        val result = homeSELinuxProbeRunner.run(HOME_ENVIRONMENT_PROBE_TIMEOUT_MS) {
            getSELinuxStatusRaw()
        }
        val status = (result as? EnvironmentProbeResult.Completed)?.value ?: return
        if (status !in setOf("Enforcing", "Permissive", "Disabled")) return
        publishSELinuxInformation(bootId, owner, status)
    }

    private suspend fun publishSELinuxInformation(bootId: String, owner: Long, status: String) {
        currentCoroutineContext().ensureActive()
        val sameBoot = runCatching { BootIdSourceAdapter.read() == bootId }.getOrDefault(false)
        publishMutex.withLock {
            if (sameBoot && owner == selinuxInformationOwner && bootId == selinuxInformationBootId) {
                _uiState.update { it.copy(systemInfo = it.systemInfo.copy(selinuxStatus = status)) }
            }
        }
    }

    private suspend fun publishInformation(
        owner: HomeInformationOwner,
        update: (SystemInfo) -> SystemInfo,
    ) {
        currentCoroutineContext().ensureActive()
        val sameBoot = runCatching { BootIdSourceAdapter.read() == owner.bootId }.getOrDefault(false)
        publishMutex.withLock {
            if (sameBoot && owner.isCurrent(informationOwner)) {
                _uiState.update { it.copy(systemInfo = update(it.systemInfo)) }
            }
        }
    }

    /** A failed observation keeps installation facts and exposes its actual failure. */
    private fun resolvedFailure(failure: HomeEnvironmentFailure, reason: String): HomeUiState {
        val mode = ModeRuntime.active
        Log.i(TAG, "home environment probe ${failure.name.lowercase()}/$reason: mode=${mode ?: "unresolved"}")
        return _uiState.value.copy(environmentFailure = failure, isLateLoadMode = false,
            environmentRuntimeReady = false, sdkRootAvailable = false, isRootAvailable = false, rootReadiness = null,
            cachedEnvironmentReady = false, ultraObservationFailure = failure, ultraObservationDetail = reason,
            ultraObservationCode = null, ultraComponentDiagnostic = null)
    }

    private suspend fun publishState(state: HomeUiState, owner: HomeInformationOwner, source: HomeStateRead?): Long? {
        val consumedRevision = publishMutex.withLock {
            if (!owner.isCurrent(environmentOwner)) return@withLock null
            val currentBootId = if (source?.owner?.bootId?.isNotBlank() == true)
                runCatching { BootIdSourceAdapter.read() }.getOrNull() else null
            val sourceCurrent = source?.evidenceActivation === ModeRuntime.activation &&
                source?.owner?.revision == ModeRuntime.detectionRevision.value &&
                (currentBootId.isNullOrBlank() || source.owner.bootId == currentBootId)
            val scoped = state.afterFinalEnvironmentScopeCheck(
                source?.evidenceActivation, source?.owner?.revision,
                ModeRuntime.activation, ModeRuntime.detectionRevision.value,
                currentBootId = currentBootId,
                currentObservation = if (state.ultraComponentDiagnostic != null)
                    UltraEnvironmentProbe.currentSnapshot(ksuApp) else null,
                observedBootId = source?.owner?.bootId,
            )
            val currentState = if (scoped.sdkRootAvailable && source?.hasCurrentSdkHealthScope() != true) scoped.copy(
                sdkRootAvailable = false, environmentRuntimeReady = false,
                ultraObservationFailure = HomeEnvironmentFailure.UNCONFIRMED,
                ultraObservationDetail = "SDK_IDENTITY_SCOPE_CHANGED",
                ultraObservationCode = null, ultraComponentDiagnostic = null,
            ) else scoped
            _uiState.update { previous ->
                currentState.copy(systemInfo = currentState.systemInfo.copy(
                    deviceModel = previous.systemInfo.deviceModel,
                    selinuxStatus = previous.systemInfo.selinuxStatus,
                )).mergedOver(previous).copy(
                    manualEnvironmentChecking = currentState.manualEnvironmentChecking,
                    manualEnvironmentFailure = currentState.manualEnvironmentFailure,
                ).withUltraSafety(previous.isSafeMode, currentState.environmentMode)
            }
            owner.revision.takeIf { sourceCurrent }
        }
        refreshEntryFacts()
        return consumedRevision
    }

    /** Pure cache/prefs reads only; keep KSU safety and the screen's existing hidden projection. */
    private fun HomeUiState.withCurrentUltraSafety(): HomeUiState = withUltraSafety(
        UltraEnvironmentProbe.isSafeMode(ksuApp), ModeRuntime.active ?: environmentMode,
    )

    /** 重算首页入口事实（回前台、切页、探测完成时调用；幂等、不阻塞调用方）。 */
    fun refreshEntryFacts() {
        entryFactsTick.update { it + 1 }
    }

    private fun readHiddenFacts(): HomeHiddenFacts = HomeHiddenFacts(
        masking = runCatching { HiddenStartupConfirm.masking(ksuApp) }.getOrDefault(true),
        confirming = runCatching { HiddenStartupConfirm.current(ksuApp) }.getOrDefault(true),
        transitionPending = runCatching { HiddenStartupConfirm.isPending(ksuApp) }.getOrDefault(true),
    )

    /**
     * 隐藏事实先行：收紧方向不等 IO，当场发布。放行方向要等 IO 读完，
     * 读完再核对一次隐藏事实，读取期间隐藏生效时不把"可见"写出去。
     */
    private suspend fun publishEntryFacts() {
        val hidden = readHiddenFacts()
        if (hidden.suppressEntries || _uiState.value.environmentMode == null) {
            _entryFacts.value = HomeEntryFacts.beforeFirstRead(hidden)
            return
        }
        val facts = withContext(Dispatchers.IO) {
            homeEntryFacts(
                hidden = hidden,
                entry = { dev.maplesu.manager.workmode.ui.currentWorkModeEntryPolicy() },
                switch = { HomeWorkModeSwitchRuntime.current() },
            )
        }
        val latest = readHiddenFacts()
        _entryFacts.value = if (latest.suppressEntries || _uiState.value.environmentMode == null) {
            HomeEntryFacts.beforeFirstRead(latest)
        } else {
            facts.copy(hidden = latest)
        }
    }

    /** Explicit restore joins the active session or starts a new bounded observation. */
    fun refreshAfterManagerRestore() {
        ModeBootstrap.retryEnvironmentDetection()
        startEnvironmentSession(explicit = true, refreshRestoredSdk = true)
    }

    /** Dialog completion does not resume the Activity; queue its refresh even during an older read. */
    fun refreshAfterJailbreak() {
        ModeBootstrap.retryEnvironmentDetection()
        ksuApp.requestUltraRecovery()
        startEnvironmentSession(explicit = true)
    }

    /** Repeated explicit actions merge into the complete session already in flight. */
    fun checkEnvironmentManually() {
        startEnvironmentSession(explicit = true, inspectInstalledKernel = true)
    }

    /** Foreground callbacks never restart an automatic session that already ended. */
    fun refreshOnForeground() {
        refreshEntryFacts()
        startEnvironmentSession()
    }

    fun refresh() {
        startEnvironmentSession(explicit = true)
    }

    private fun startEnvironmentSession(
        explicit: Boolean = false,
        inspectInstalledKernel: Boolean = false,
        refreshRestoredSdk: Boolean = false,
    ) {
        if (explicit) {
            environmentExplicitRequest = true
            installedKernelInspectionRequested = installedKernelInspectionRequested || inspectInstalledKernel
            restoredSdkRefreshRequested = restoredSdkRefreshRequested || refreshRestoredSdk
        }
        if (environmentSessionJob?.isActive == true || !explicit && environmentSessionJob != null) return
        environmentSessionJob = refreshFlight.launch(viewModelScope) {
            withContext(PageReadDeadline.context(HOME_ENVIRONMENT_SESSION_TIMEOUT_MS)) {
                _uiState.update { it.copy(environmentChecking = true, environmentFailure = null,
                    manualEnvironmentChecking = explicit, manualEnvironmentFailure = null) }
                var candidate: HomeStateRead? = null
                val deadline = SystemClock.elapsedRealtime() + HOME_ENVIRONMENT_SESSION_TIMEOUT_MS
                val completed = withTimeoutOrNull(HOME_ENVIRONMENT_SESSION_TIMEOUT_MS) {
                    do {
                        try {
                            prepareEnvironmentObservation(deadline)
                            candidate = observeEnvironment(deadline) { candidate = it }
                        } catch (cancelled: kotlinx.coroutines.CancellationException) {
                            currentCoroutineContext().ensureActive()
                            Log.w(TAG, "Environment observation cancelled", cancelled)
                        } catch (error: Exception) {
                            Log.w(TAG, "Environment observation failed", error)
                            val failed = resolvedFailure(HomeEnvironmentFailure.FAILED,
                                error.message ?: error.javaClass.simpleName)
                            candidate = candidate?.copy(state = failed) ?: HomeStateRead(failed)
                        }
                    } while (environmentExplicitRequest && remainingEnvironmentTime(deadline) > 0L)
                    true
                }
                currentCoroutineContext().ensureActive()
                finishEnvironmentSession(candidate, deadlineExceeded = completed != true)
            }
        }
    }

    private fun remainingEnvironmentTime(deadline: Long): Long =
        (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L)

    private suspend fun prepareEnvironmentObservation(deadline: Long) {
        if (!environmentExplicitRequest) return
        environmentExplicitRequest = false
        val inspectInstalledKernel = installedKernelInspectionRequested
        val refreshRestoredSdk = restoredSdkRefreshRequested
        installedKernelInspectionRequested = false
        restoredSdkRefreshRequested = false
        val budget = remainingEnvironmentTime(deadline)
        if (budget > 0L && (inspectInstalledKernel || refreshRestoredSdk)) {
            homeEnvironmentProbeRunner.run(minOf(HOME_ENVIRONMENT_PROBE_TIMEOUT_MS, budget)) {
                if (inspectInstalledKernel) {
                    dev.maplesu.manager.runtime.ultra.UltraEnvironmentUpgrade.checkInstalledKernel(ksuApp)
                }
                if (refreshRestoredSdk) UltraEnvironmentProbe.refresh(ksuApp, force = true)
            }
        }
    }

    private suspend fun observeEnvironment(
        deadline: Long,
        eventRecheckAllowed: Boolean = true,
        onIdentity: (HomeStateRead) -> Unit,
    ): HomeStateRead {
        val activation = ModeRuntime.activation
        val evidence = checkEnvironmentPresence(deadline)
        val owner = publishMutex.withLock {
            HomeInformationOwner(++environmentOwner, ModeRuntime.detectionRevision.value, ModeRuntime.active,
                evidence?.bootId.orEmpty())
        }
        val identity = HomeStateRead(_uiState.value.copy(isLateLoadMode = false,
            environmentRuntimeReady = false, sdkRootAvailable = false, isRootAvailable = false, rootReadiness = null,
            cachedEnvironmentReady = false,
            ultraObservationFailure = HomeEnvironmentFailure.UNCONFIRMED.takeIf { evidence?.verdict == EnvironmentVerdict.ULTRA },
            ultraObservationDetail = "home_health_pending".takeIf { evidence?.verdict == EnvironmentVerdict.ULTRA },
            ultraObservationCode = null, ultraComponentDiagnostic = null),
            owner, evidence, activation)
        if (identity.hasFreshIdentityEvidence()) onIdentity(identity)
        else if (ModeRuntime.active == null && remainingEnvironmentTime(deadline) > 0L) {
            withTimeoutOrNull(minOf(LITE_MODE_SETTLE_TIMEOUT_MS, remainingEnvironmentTime(deadline))) {
                ModeBootstrap.pendingEnvironmentDetection()?.await()
            }
        }
        val read = collectEnvironment(
            rootProbeSettled = ModeRuntime.detectionComplete,
            modeSettled = ModeRuntime.detectionComplete,
            evidence = evidence,
            evidenceActivation = activation,
            owner = owner,
            deadline = deadline,
        )
        // Activation or a completed detection invalidates the observation's actual
        // scope. Reconcile that event once within this session; never poll a failure.
        return if (eventRecheckAllowed && remainingEnvironmentTime(deadline) > 0L &&
            (activation !== ModeRuntime.activation || owner.revision != ModeRuntime.detectionRevision.value)) {
            observeEnvironment(deadline, eventRecheckAllowed = false, onIdentity = onIdentity)
        } else read
    }

    private fun HomeStateRead.hasFreshIdentityEvidence(): Boolean {
        val currentOwner = owner ?: return false
        val currentEvidence = evidence ?: return false
        val expectedUltraOwner = currentEvidence.ultraOwnerIdentity
        val observedUltraOwner = healthObservation?.managerOwnerIdentity
        if (expectedUltraOwner != null && observedUltraOwner != null && expectedUltraOwner != observedUltraOwner) return false
        return currentOwner.isCurrent(environmentOwner) && evidenceActivation === ModeRuntime.activation &&
            currentOwner.bootId.isNotBlank() && currentEvidence.bootId == currentOwner.bootId &&
            currentEvidence.verdict in setOf(
                EnvironmentVerdict.ULTRA, EnvironmentVerdict.KSU_NORMAL, EnvironmentVerdict.NOT_INSTALLED,
            )
    }

    /** Retained observations can revoke this fresh proof, but never supply a positive proof. */
    private fun HomeStateRead.hasCurrentSdkHealthScope(): Boolean {
        val health = healthObservation ?: return false
        if (evidenceActivation !== ModeRuntime.activation || health.modeActivation !== evidenceActivation ||
            ModeRuntime.active == WorkMode.KSU) return false
        val current = UltraEnvironmentProbe.currentSnapshot(ksuApp)
        return current.modeActivation === health.modeActivation && current.rootAvailable &&
            current.managerOwnerIdentity == health.managerOwnerIdentity &&
            (health.managerOwnerIdentity != null || health.legacyCredentialFingerprint != null &&
                current.legacyCredentialFingerprint == health.legacyCredentialFingerprint)
    }

    private suspend fun finishEnvironmentSession(candidate: HomeStateRead?, deadlineExceeded: Boolean) {
        val confirmed = candidate?.takeIf { it.hasFreshIdentityEvidence() }
        val observed = confirmed?.state ?: _uiState.value
        val settledState = observed.copy(
            environmentChecking = false, litePending = false,
            environmentFailure = null, manualEnvironmentChecking = false, manualEnvironmentFailure = null,
            previousEnvironmentMode = null, cachedEnvironmentReady = false,
        ).let { settled ->
            when (confirmed?.evidence?.verdict) {
                EnvironmentVerdict.ULTRA -> settled.copy(environmentMode = WorkMode.LITE,
                    environmentConfirmedAbsent = false, liteInstalled = true,
                    ultraObservationFailure = if (deadlineExceeded && settled.ultraObservationDetail == "home_health_pending")
                        HomeEnvironmentFailure.TIMED_OUT else settled.ultraObservationFailure,
                    ultraObservationDetail = if (deadlineExceeded && settled.ultraObservationDetail == "home_health_pending")
                        "home_health_session_deadline" else settled.ultraObservationDetail)
                EnvironmentVerdict.KSU_NORMAL -> settled.copy(environmentMode = WorkMode.KSU,
                    environmentConfirmedAbsent = false, liteInstalled = false,
                    sdkRootAvailable = false,
                    ultraBrandVisible = false, ultraObservationFailure = null, ultraObservationDetail = null,
                    ultraObservationCode = null, ultraComponentDiagnostic = null)
                EnvironmentVerdict.NOT_INSTALLED -> settled.asLiteHiddenNotInstalled()
                else -> settled.afterFinalEnvironmentScopeCheck(null, null,
                    ModeRuntime.activation, ModeRuntime.detectionRevision.value)
            }
        }
        val state = if (confirmed?.evidence?.verdict == EnvironmentVerdict.ULTRA) {
            val diagnostic = settledState.ultraObservationDetail?.takeIf {
                settledState.ultraObservationFailure != null && it.isNotBlank() && it != "home_health_pending"
            }?.let { detail ->
                HomeUltraComponentDiagnostic(
                    modeActivation = confirmed.evidenceActivation ?: ModeRuntime.activation,
                    detectionRevision = confirmed.owner?.revision ?: ModeRuntime.detectionRevision.value,
                    bootId = confirmed.owner?.bootId.orEmpty(),
                    managerOwnerIdentity = confirmed.evidence.ultraOwnerIdentity ?:
                        confirmed.healthObservation?.managerOwnerIdentity,
                    legacyCredentialFingerprint = confirmed.healthObservation?.legacyCredentialFingerprint,
                    failureCode = settledState.ultraObservationCode,
                    detail = detail,
                )
            }
            settledState.copy(ultraComponentDiagnostic = diagnostic)
        } else settledState
        val owner = publishMutex.withLock {
            HomeInformationOwner(++environmentOwner, ModeRuntime.detectionRevision.value, ModeRuntime.active,
                confirmed?.owner?.bootId.orEmpty())
        }
        publishState(state, owner, candidate)?.let { publishedDetectionRevision = it }
        refreshUpdate(_uiState.value.checkUpdateEnabled)
    }

    /** The fresh runner returns only evidence from this invocation; UNKNOWN history is ignored. */
    private suspend fun checkEnvironmentPresence(deadline: Long): EnvironmentCheckOutcome? = withContext(Dispatchers.IO) {
        val remaining = remainingEnvironmentTime(deadline)
        if (remaining == 0L) return@withContext null
        runCatching { withTimeoutOrNull(remaining) { EnvironmentCheckProduction.freshRunner(ksuApp).check(remaining) } }
            .onFailure { error ->
                if (error is kotlinx.coroutines.CancellationException) throw error
                if (error is InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw error
                }
                Log.w(TAG, "Silent environment check failed; retaining confirmed state", error)
            }.getOrNull()
    }

    private fun refreshUpdate(enabled: Boolean) {
        if (!enabled) return
        viewModelScope.launch {
            val latest = withContext(Dispatchers.IO) {
                runCatching { checkNewVersion() }.getOrNull()
            } ?: return@launch
            _uiState.update { if (it.checkUpdateEnabled) it.copy(latestVersionInfo = latest) else it }
        }
    }

    /**
     * @param probeRoot 是否读取 root 能力；设备名与 SELinux 由本轮独立读取。
     *                  主线程首帧传 false(绝不阻塞),IO 线程刷新传 true。
     * @param rootProbeSettled root 探测结论是否已经等到"模式判定落定"(见 [LiteStartupFacts])。
     *                  未判定窗口内传 false —— 那一次失败不作为 Lite 启动失败提示。
     * @param modeSettled 模式判定是否已经落定(activate 或 8s 超时)。
     *                    false = 判定中 → 保留历史或中性操作卡，不宣称「未安装」。
     */
    private fun buildState(
        probeRoot: Boolean,
        rootProbeSettled: Boolean = true,
        modeSettled: Boolean = ModeRuntime.active != null,
        evidence: EnvironmentCheckOutcome? = null,
        healthObservation: UltraEnvironmentProbe.Snapshot? = null,
    ): HomeStateRead {
        val absenceConfirmed = evidence?.verdict == EnvironmentVerdict.NOT_INSTALLED
        // Identity observation does not enumerate or invoke ordinary/third-party SU.
        // SDK Root remains a separate capability; standard SU has no proof in this session.
        val liveReadiness: SuReadiness? = null
        val ultraEnvironmentRunning = healthObservation?.state == UltraEnvironmentProbe.State.Running
        val ultraSafeMode = healthObservation?.state == UltraEnvironmentProbe.State.Fault
        val environmentMode = when (evidence?.verdict) {
            EnvironmentVerdict.ULTRA -> WorkMode.LITE
            EnvironmentVerdict.KSU_NORMAL -> WorkMode.KSU
            EnvironmentVerdict.NOT_INSTALLED -> null
            else -> null
        }
        val confirmedNotInstalled = absenceConfirmed
        // ⚠️ 2026-09-19 修:下面每一个 runCatching 都是"防闪退" ——
        //    Natives 是 JNI(可能 UnsatisfiedLinkError),读设置走磁盘,Os.uname 也可能抛。
        //    以前任何一个抛了,HomeViewModel 的构造 / 刷新协程就炸;现在各自兜底,
        //    最坏只是某个字段显示默认值,页面照样打开。
        val kernelVersion = runCatching { getKernelVersion() }
            .getOrElse { KernelVersion(-1, -1, -1) }
        val isManager = if (probeRoot && environmentMode != null) runCatching { Natives.isManager }.getOrDefault(false) else false
        // isManager 为 false 有两种原因,不能混着提示(详见 HomeUiState.managerNotRecognized 的注释):
        //   ① 隐身模式   → stealthState() 能读到 1(内核仍然认我们)
        //   ② 内核没认主 → 读不到(返回 -1)→ 只要重启一次设备即可,不要引导用户去刷机
        val observedStealth = if (probeRoot) runCatching { Natives.stealthState() }.getOrDefault(-1) else -1
        if (probeRoot && environmentMode == WorkMode.KSU) {
            HiddenStartupConfirm.rememberNormalState(ksuApp, observedStealth)
        }
        val stealthState = if (observedStealth in 0..1) observedStealth else if (environmentMode == WorkMode.KSU) {
            HiddenStartupConfirm.normalState(ksuApp)
        } else -1
        val ksuVersionRaw = if (probeRoot) runCatching { Natives.version }.getOrDefault(-1) else -1
        val managerNotRecognized = !isManager && ksuVersionRaw >= 0 && stealthState != 1
        // 隐身模式(内核 stealthState == 1):内核其实仍然认我们,只是不上报 MANAGER 标志。
        // 界面要把首页伪装成「未安装」那一支(详见 HomeUiState.asStealthKernelNotReady)。
        val stealthOn = stealthState == 1
        val kernelUapiRaw = if (probeRoot) runCatching { Natives.kernelUAPIVersion }.getOrDefault(0) else 0
        val managerUapiRaw = if (probeRoot) runCatching { Natives.managerUAPIVersion }.getOrDefault(0) else 0
        val ksuVersion = if (isManager) ksuVersionRaw else null
        val kernelUAPIVersion = if (isManager) kernelUapiRaw else null
        val managerUAPIVersion = managerUapiRaw
        // Lite patches the kernel binary; KSU's GKI/LKM installation modes do not describe it.
        val lkmMode: Boolean? = null
        // 下面这两个都要起 shell(最慢、最可能抛)→ 只在 probeRoot = true(IO 线程)时做
        // Only the actual standard-SU verdict proves Manager SU; SDK Root is a separate capability.
        val isRootAvailable = probeRoot && !confirmedNotInstalled && liveReadiness == SuReadiness.USABLE

        val managerVersion = runCatching { getManagerVersion(ksuApp) }
            .getOrElse { ManagerVersion("未知", 0L) }

        // Installation identity comes from the current runtime/owner/carrier, never credentials or history.
        val liteFacts = LiteStartupFacts(
            liteMode = environmentMode == WorkMode.LITE,
            liteEvidence = false,
            ultraEnvironmentRunning = ultraEnvironmentRunning,
            rootAvailable = isRootAvailable,
            probeRoot = probeRoot,
            stealthOn = stealthOn,
            ksuMode = environmentMode == WorkMode.KSU,
            rootProbeSettled = rootProbeSettled && liveReadiness != null && liveReadiness != SuReadiness.UNKNOWN,
            ultraPaired = ultraEnvironmentRunning,
            modeSettled = modeSettled,
            // 既有已安装通道（KSU 认主 / Ultra Running）→ 不需要 Lite 判定，也不该进 loading。
            nonLiteInstalled = ksuVersion != null || ultraEnvironmentRunning,
        )
        val liteStatus = LiteStartupStatusPolicy.evaluate(liteFacts)

        val state = HomeUiState(
            kernelVersion = kernelVersion,
            ksuVersion = ksuVersion,
            lkmMode = lkmMode,
            isLkmBundled = lkmMode == true &&
                runCatching { Natives.isLkmBundled }.getOrDefault(false),
            isManager = isManager,
            environmentRuntimeReady = if (environmentMode == WorkMode.LITE) ultraEnvironmentRunning
                else environmentMode == WorkMode.KSU && ksuVersion != null && isManager,
            managerNotRecognized = managerNotRecognized,
            isManagerPrBuild = BuildConfig.IS_PR_BUILD,
            isKernelPrBuild = probeRoot && runCatching { Natives.isPrBuild }.getOrDefault(false),
            requiresNewKernel = isManager && managerUapiRaw > kernelUapiRaw,
            // 内核 UAPI 比管理器新(5 -> 6)时不再报"需要更新管理器":
            // UAPI 升级是向后兼容的,旧管理器可以直接用;否则内核先行更新就会误报,
            // 还会顺带把界面降级(见 isFullFeatured)。
            requiresNewManager = false,
            kernelUAPIVersion = kernelUAPIVersion,
            managerUAPIVersion = managerUAPIVersion,
            isRootAvailable = isRootAvailable,
            rootReadiness = liveReadiness,
            isSafeMode = ultraSafeMode || probeRoot && runCatching { Natives.isSafeMode }.getOrDefault(false),
            isLateLoadMode = probeRoot && runCatching { Natives.isLateLoadMode }.getOrDefault(false),
            checkUpdateEnabled = runCatching { settingsRepo.checkUpdate }.getOrDefault(false),
            latestVersionInfo = LatestVersionInfo(),
            currentManagerVersionCode = managerVersion.versionCode,
            systemInfo = SystemInfo(
                kernelVersion = runCatching { Os.uname().release }.getOrDefault("未知"),
                managerVersion = "${managerVersion.versionName} (${managerVersion.versionCode})",
                deviceModel = Build.MODEL,
                fingerprint = Build.FINGERPRINT,
                selinuxStatus = "Unknown",
                seccompStatus = runCatching {
                    Os.prctl(21 /* PR_GET_SECCOMP */, 0, 0, 0, 0)
                }.getOrDefault(-1),
            ),
            liteInstalled = liteStatus.liteInstalled,
            environmentMode = environmentMode,
            environmentConfirmedAbsent = confirmedNotInstalled,
            liteRootFailure = liteStatus.liteRootFailure,
            // 仅记录后台未落定；自动检查不把主卡替换为等待页。
            litePending = if (!probeRoot && !liteStatus.liteInstalled) true else liteStatus.litePending,
            // 2026-10-31：隐藏/寄生的「确认窗口」——在寄生结果与运行环境都确认前，
            // 首页只保留安装历史，不先报「正在运行」。
            hiddenConfirming = runCatching {
                HiddenStartupConfirm.current(ksuApp)
            }.getOrDefault(true),
        )

        // P0：Lite 已安装 → 追加"已安装/正常"语义（首帧即可）；root 失败只置提示行，
        // **绝不**把已安装回退成未安装（KSU/未判定保持原判定）。
        val liteForced = if (liteStatus.liteInstalled) {
            state.copy(
                isManager = true,
                managerNotRecognized = false,
                ksuVersion = state.ksuVersion ?: if (probeRoot) runCatching { Natives.version }.getOrDefault(ksuVersionRaw) else ksuVersionRaw,
                liteInstalled = true,
                liteRootFailure = liteStatus.liteRootFailure,
                // 已安装 ⇒ 一定不在 loading（策略侧本来也不会同时给，这里再钉一次不变量）。
                litePending = false,
            )
        } else {
            state
        }

        // Ultra Running 补齐安装/管理器事实；root 能力仍只采用上面的实际命令探测结果。
        val effectiveState = if (ultraEnvironmentRunning || ultraSafeMode) {
            liteForced.copy(
                ksuVersion = if (probeRoot) runCatching { Natives.version }.getOrDefault(ksuVersionRaw) else ksuVersionRaw,
                isManager = true,
                managerNotRecognized = false,
                // Ultra Running 就是"已安装"的既有通道 → 不进 loading（否则会从绿卡退化成转圈）。
                litePending = false,
            )
        } else {
            liteForced
        }

        // 🔒 隐身:把整个状态归一化成「未安装」那一支(照抄没刷内核时首页的样子)。
        //    界面层一行不用改就会走进那条已存在的分支(见 HomeUiState.asStealthKernelNotReady)。
        //    顺手把"更新检查"也关掉 —— 状态里 checkUpdateEnabled 为 false 时
        //    refresh() 不会再联网查版本,伪装期少一条痕迹。
        val projected = if (confirmedNotInstalled) {
            // 后台已确认 SU 和 Ultra 都不存在，旧进程模式/种子不再参与首页展示。
            effectiveState.asLiteHiddenNotInstalled()
        } else if (stealthOn) {
            // 隐身伪装：不暴露 Lite 已安装/失败提示（与伪装目标一致）。
            // 同时把 isManager 还原成内核给的**原始**值：上面的 Lite 强制/Ultra 兜底都会把它改成
            // true，而 asStealthKernelNotReady() 按约定不动 isManager —— 不还原就会漏馅
            // （底栏 / 导航 / 闸门都以 isManager 为准）。
            // litePending 也一起清：隐身时画 loading 占位等于暴露"正在判定 Lite 状态"。
            effectiveState.asStealthKernelNotReady().copy(
                isManager = isManager,
                liteInstalled = false,
                liteRootFailure = false,
                litePending = false,
            )
        } else {
            effectiveState
        }
        return HomeStateRead(projected)
    }

}
