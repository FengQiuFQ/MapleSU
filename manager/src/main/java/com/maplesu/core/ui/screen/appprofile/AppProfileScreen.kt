package com.maplesu.core.ui.screen.appprofile

import android.content.Context
import android.util.Log
import android.widget.Toast
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import com.maplesu.core.Natives
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.dialog.rememberInfoDialog
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.util.forceStopApp
import com.maplesu.core.ui.util.launchApp
import com.maplesu.core.ui.util.restartApp
import com.maplesu.core.ui.viewmodel.SuperUserViewModel
import dev.maplesu.manager.runtime.State
import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.runtime.HookRootExecutor
import dev.maplesu.manager.runtime.HookSuCompatibility
import dev.maplesu.manager.runtime.managerSuState
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraSdkCredentials
import dev.maplesu.manager.runtime.ultra.UltraSdkLogging
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import dev.maplesu.manager.runtime.stateFor
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode

private const val PROFILE_OPERATION_TIMEOUT_MILLIS = 10_000L

private data class AppProfileObservation(
    val profile: Natives.Profile?,
    val state: State = State.NOT_AUTHORIZED,
    val deliveryConfirmed: Boolean? = null,
    val code: String? = null,
    val detail: String = "",
    val entryConfirmed: Boolean? = null,
)

/** One current source read; none of the display paths grant, deploy or replay a mutation. */
private fun readProfileObservation(
    context: Context,
    packageName: String,
    uid: Int,
    special: Boolean,
    mode: WorkMode?,
): AppProfileObservation {
    if (special) return AppProfileObservation(Natives.Profile(packageName, currentUid = uid), deliveryConfirmed = true)
    val read = Natives.getAppProfileFreshDetailed(packageName, uid)
    val current = read.profile?.takeIf { it.name == packageName && it.currentUid == uid }
        ?: return AppProfileObservation(null, code = read.code ?: "PROFILE_CURRENT_READ_FAILED", detail = read.detail)
    val profile = if (mode == WorkMode.KSU) loadKsuProfileRules(current) else current
    if (profile == null) return AppProfileObservation(null, code = "PROFILE_SEPOLICY_READ_FAILED", detail = read.detail)
    val granted = profile.allowSu
    val ultra = mode == WorkMode.LITE && UltraEnvironmentProbe.usesUltraBackend(context)
    val managerAuthority = mode == WorkMode.LITE && ManagerAuthorizations.usesManagerAuthority(context)
    val state = when {
        !granted && (mode == WorkMode.KSU || ultra || managerAuthority) -> State.NOT_AUTHORIZED
        mode == WorkMode.KSU -> if (read.deliveryConfirmed == true) ksuSuState(granted) else State.ENTRY_UNAVAILABLE
        read.deliveryConfirmed == false -> managerSuState(granted, stale = false, pending = true, entryReady = false)
        managerAuthority -> when (read.deliveryConfirmed) {
            true -> managerSuState(granted, stale = false, pending = false,
                entryReady = if (HookRootExecutor.production(context).available()) HookSuCompatibility.traditionalReady(context)
                    else read.entryConfirmed == true)
            else -> if (granted) State.ENTRY_UNAVAILABLE else State.NOT_AUTHORIZED
        }
        ultra -> managerSuState(granted, stale = false, pending = false,
            entryReady = read.deliveryConfirmed == true && read.entryConfirmed == true)
        else -> {
            val stale = !granted && DirectPolicy.grantedUids(context).orEmpty().contains(uid)
            stateFor(context, packageName, granted, stale)
        }
    }
    return AppProfileObservation(profile, state, read.deliveryConfirmed, read.code, read.detail, read.entryConfirmed)
}

private fun captureProfileScope(context: Context): () -> Boolean {
    val activation = ModeRuntime.activation
    val mode = ModeRuntime.active
    val ownerCurrent = if (mode == WorkMode.LITE) UltraSdkCredentials.captureOwnerMarker(context) else { { true } }
    return { ModeRuntime.activation === activation && ModeRuntime.active == mode && ownerCurrent() }
}

@Composable
fun AppProfileScreen(uid: Int) {
    val uiMode = LocalUiMode.current
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val snackbarHost = remember { SnackbarHostState() }
    val diagnosticDialog = rememberInfoDialog()
    val scope = rememberCoroutineScope()
    val viewModel: SuperUserViewModel = viewModel()
    val appGroupState = remember(uid) {
        derivedStateOf {
            viewModel.uiState.value.groupedApps.find { it.uid == uid } ?: SuperUserViewModel.getGroupedApp(uid)
        }
    }
    val appGroup = appGroupState.value
    val primaryAppInfo = appGroup?.primary
    if (primaryAppInfo == null) {
        LaunchedEffect(Unit) {
            navigator.pop()
        }
        return
    }

    val packageName = primaryAppInfo.profileKey
    val detectionRevision by ModeRuntime.detectionRevision.collectAsStateWithLifecycle()
    val sharedUserId = remember(uid) {
        primaryAppInfo.packageInfo.sharedUserId
            ?: appGroup.apps.firstOrNull { it.packageInfo.sharedUserId != null }?.packageInfo?.sharedUserId
            ?: ""
    }

    var profile by remember(uid, packageName, primaryAppInfo.special) {
        mutableStateOf<Natives.Profile?>(null)
    }
    var loading by remember(uid, packageName, primaryAppInfo.special) { mutableStateOf(true) }
    var loadAttempt by remember(uid, packageName, primaryAppInfo.special) { mutableStateOf(0) }
    var writePolicy by remember(uid, packageName, primaryAppInfo.special) {
        mutableStateOf<ProfileWritePolicy<Natives.Profile>?>(null)
    }
    val saveMutex = remember(uid, packageName, primaryAppInfo.special) { Mutex() }
    var saving by remember(uid, packageName, primaryAppInfo.special) { mutableStateOf(false) }
    var suState by remember(uid, packageName) { mutableStateOf(State.NOT_AUTHORIZED) }
    var diagnostic by remember(uid, packageName) { mutableStateOf<AppProfileDiagnostic?>(null) }
    var lastWrite by remember(uid, packageName) { mutableStateOf<Natives.ProfileWriteResult?>(null) }
    var lastSubmitted by remember(uid, packageName) { mutableStateOf<Natives.Profile?>(null) }
    var profileScope by remember(uid, packageName) { mutableStateOf<(() -> Boolean)?>(null) }
    val failToLoadAppProfile = stringResource(R.string.failed_to_load_app_profile).format(primaryAppInfo.label)
    val failToUpdateAppProfile = stringResource(R.string.failed_to_update_app_profile).format(primaryAppInfo.label)
    val deliveryIncompleteMessage = stringResource(R.string.su_grants_saved_delivery_incomplete)
    val suNotAllowed = stringResource(R.string.su_not_allowed).format(primaryAppInfo.label)
    val suDisabled = stringResource(R.string.maplesu_su_disabled_grant)
    LaunchedEffect(detectionRevision) {
        if (profileScope?.invoke() == false) {
            profile = null
            writePolicy = null
            suState = State.NOT_AUTHORIZED
            diagnostic = null
            diagnosticDialog.hide()
            lastWrite = null
            lastSubmitted = null
            loading = false
        }
    }
    LaunchedEffect(uid, packageName, primaryAppInfo.special, loadAttempt) {
        val current = captureProfileScope(context)
        val requestedMode = ModeRuntime.active
        profileScope = current
        loading = true
        val observed = try {
            withContext(Dispatchers.IO + PageReadDeadline.context(PROFILE_OPERATION_TIMEOUT_MILLIS)) {
                withTimeout(PROFILE_OPERATION_TIMEOUT_MILLIS) {
                    readProfileObservation(context, packageName, uid, primaryAppInfo.special, requestedMode)
                }
            }
        } catch (timeout: TimeoutCancellationException) {
            currentCoroutineContext().ensureActive()
            AppProfileObservation(null, code = "PROFILE_READ_TIMEOUT", detail = timeout.javaClass.simpleName)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            AppProfileObservation(null, code = "PROFILE_READ_EXCEPTION", detail = error.toString())
        }
        if (!current()) {
            profile = null
            writePolicy = null
            suState = State.NOT_AUTHORIZED
            diagnostic = null
            diagnosticDialog.hide()
            lastWrite = null
            lastSubmitted = null
            loading = false
            return@LaunchedEffect
        }
        if (observed.profile != null) {
            profile = observed.profile
            writePolicy = ProfileWritePolicy(observed.profile)
        }
        val observedState = if (observed.profile == null && profile?.allowSu == true)
            State.ENTRY_UNAVAILABLE else observed.state
        val recovered = profileWriteRecovered(lastWrite, lastSubmitted, observed.profile, observed.deliveryConfirmed)
        val currentDelivery = if (observed.deliveryConfirmed == true && lastWrite?.succeeded == false && !recovered)
            null else observed.deliveryConfirmed
        suState = profileDeliveryState(profile?.allowSu == true, observedState, lastWrite, currentDelivery)
        if (recovered) {
            diagnostic = null
            lastWrite = null
            lastSubmitted = null
        }
        val entryUnconfirmed = observed.profile?.allowSu == true && observed.state == State.ENTRY_UNAVAILABLE
        if (observed.profile == null || observed.deliveryConfirmed == false || observed.code != null || entryUnconfirmed) {
            val detail = UltraSdkLogging.redact("package=$packageName fullUID=$uid code=${observed.code}\n${observed.detail}")
            diagnostic = diagnostic?.let { if (detail in it.detail) it else it.copy(detail = it.detail + "\n\n" + detail) }
                ?: AppProfileDiagnostic(if (observed.profile != null && observed.deliveryConfirmed == false)
                    deliveryIncompleteMessage else if (entryUnconfirmed) context.getString(R.string.maplesu_state_entry_unavailable)
                    else failToLoadAppProfile, detail)
        }
        loading = false
    }
    fun showMessage(message: String) {
        scope.launch {
            if (uiMode == UiMode.Material) {
                snackbarHost.showSnackbar(message)
            } else {
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val state = AppProfileUiState(
        uid = uid,
        packageName = packageName,
        profile = profile ?: Natives.Profile(packageName, currentUid = uid),
        appGroup = appGroup,
        sharedUserId = sharedUserId,
        isLoading = loading,
        loadFailed = !loading && profile == null,
        isSaving = saving,
        suState = suState,
        diagnostic = diagnostic,
    )

    val actions = AppProfileActions(
        onBack = dropUnlessResumed { navigator.pop() },
        // 🔴（v2.19）这三个都是 **root shell 往返**（getRootShell + am/cmd package ...）。
        // 旧写法用函数引用直接挂在 onClick 上 ⇒ 在**主线程**同步跑 su，shell 没缓存时
        // 还要 fork/exec，最坏数秒 ⇒ 点一下白屏/ANR。现在挪到 IO 协程，主线程只负责发起。
        onLaunchApp = { pkg, userId -> scope.launch { withContext(Dispatchers.IO) { launchApp(pkg, userId) } } },
        onForceStopApp = { pkg, userId -> scope.launch { withContext(Dispatchers.IO) { forceStopApp(pkg, userId) } } },
        onRestartApp = { pkg, userId -> scope.launch { withContext(Dispatchers.IO) { restartApp(pkg, userId) } } },
        // 模板入口（2026-11-01 收尾）：以前是 `{}` 空实现 —— 点了没反应，等于功能缺失。
        // 现在走真实的模板链路：Normal 由 ksud `profile` 子命令提供（KSU 模板），
        // Ultra 走既有的 Lite 实现；"查看"打开对应模板编辑器，"管理"进入模板列表。
        onViewTemplate = { templateId ->
            scope.launch {
                val info = withContext(Dispatchers.IO) {
                    runCatching {
                        com.maplesu.core.data.repository.TemplateRepositoryImpl()
                            .getTemplate(templateId)
                            .getOrNull()
                    }.getOrNull()
                }
                if (info != null) {
                    navigator.push(Route.TemplateEditor(info, readOnly = !info.local))
                } else {
                    // 读不到就显式说"读不到"，不假装打开了模板。
                    showMessage(
                        context.getString(R.string.app_profile_template_not_found, templateId),
                    )
                }
            }
        },
        onManageTemplate = { navigator.push(Route.AppProfileTemplate) },
        onRetry = { if (!saving) loadAttempt++ },
        onShowDiagnostic = { diagnostic?.let { diagnosticDialog.show(it.title, it.detail) } },
        onProfileChange = change@{ updatedProfile ->
            if (saving || loading || profileScope?.invoke() != true) return@change
            val policy = writePolicy ?: return@change
            val profileToSave = updatedProfile.copy(name = packageName, currentUid = uid,
                allowSu = !primaryAppInfo.special && updatedProfile.allowSu)
            if (profileToSave.allowSu && uid < 2000 && uid != 1000) {
                showMessage(suNotAllowed)
            } else {
                val request = policy.request()
                val current = captureProfileScope(context)
                val requestedMode = ModeRuntime.active
                val deadline = PageReadDeadline.context(PROFILE_OPERATION_TIMEOUT_MILLIS)
                // React in this frame while keeping the last confirmed decision on the switch.
                saving = true
                scope.launch {
                    saveMutex.withLock {
                        var submitted = false
                        var written: Natives.ProfileWriteResult? = null
                        var observed: AppProfileObservation? = null
                        var enabled: Boolean? = null
                        try {
                            withContext(Dispatchers.IO + deadline) {
                                withTimeout(PROFILE_OPERATION_TIMEOUT_MILLIS) {
                                    if (!current()) return@withTimeout
                                    submitted = true
                                    written = if (requestedMode == WorkMode.KSU) saveKsuProfileWithRules(profileToSave)
                                        else Natives.setAppProfileDetailed(profileToSave)
                                    if (current()) {
                                        observed = readProfileObservation(context, packageName, uid, primaryAppInfo.special, requestedMode)
                                        if (written?.succeeded == true && profileToSave.allowSu) enabled = Natives.isSuEnabled()
                                    }
                                }
                            }
                        } catch (timeout: TimeoutCancellationException) {
                            currentCoroutineContext().ensureActive()
                            observed = observed?.copy(state = State.ENTRY_UNAVAILABLE, deliveryConfirmed = null,
                                code = "PROFILE_READ_TIMEOUT", detail = observed?.detail.orEmpty() + "\n" + timeout.javaClass.simpleName)
                                ?: AppProfileObservation(null, code = "PROFILE_READ_TIMEOUT", detail = timeout.javaClass.simpleName)
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (error: Exception) {
                            observed = observed?.copy(state = State.ENTRY_UNAVAILABLE, deliveryConfirmed = null,
                                code = "PROFILE_OPERATION_EXCEPTION", detail = observed?.detail.orEmpty() + "\n" + error.toString())
                                ?: AppProfileObservation(null, code = "PROFILE_OPERATION_EXCEPTION", detail = error.toString())
                        } finally {
                            if (policy.isLatest(request)) saving = false
                        }
                        val result = written ?: Natives.ProfileWriteResult(false,
                            pendingApply = submitted, commitUnknown = submitted,
                            code = observed?.code ?: "PROFILE_WRITE_CONTEXT_CHANGED", detail = observed?.detail.orEmpty())
                        if (!result.succeeded) {
                            Log.w("AppProfileScreen", UltraSdkLogging.redact(
                                "profile write code=${result.code} committed=${result.decisionCommitted} " +
                                    "pending=${result.pendingApply} unknown=${result.commitUnknown} package=$packageName fullUID=$uid ${result.detail}"))
                        }
                        if (!current()) {
                            profile = null
                            writePolicy = null
                            suState = State.NOT_AUTHORIZED
                            diagnostic = null
                            diagnosticDialog.hide()
                            lastWrite = null
                            lastSubmitted = null
                            return@withLock
                        }
                        val completion = policy.complete(request, profileToSave, result, observed?.profile)
                            ?: return@withLock
                        profile = completion.profile
                        lastWrite = result
                        lastSubmitted = profileToSave
                        val state = observed?.state ?: if (completion.profile.allowSu) State.ENTRY_UNAVAILABLE else State.NOT_AUTHORIZED
                        val recovered = profileWriteRecovered(result, profileToSave, observed?.profile, observed?.deliveryConfirmed)
                        val currentDelivery = if (observed?.deliveryConfirmed == true && !result.succeeded && !recovered)
                            null else observed?.deliveryConfirmed
                        suState = profileDeliveryState(completion.profile.allowSu,
                            if (enabled == false && completion.profile.allowSu) State.ENTRY_UNAVAILABLE else state,
                            result, currentDelivery)
                        val readFailed = observed?.profile == null
                        val entryUnconfirmed = completion.profile.allowSu && suState == State.ENTRY_UNAVAILABLE
                        if ((!result.succeeded && !recovered) || readFailed || observed?.deliveryConfirmed == false || entryUnconfirmed ||
                            (observed?.code != null && observed?.deliveryConfirmed != true)) {
                            val title = if (!recovered && result.decisionCommitted && result.pendingApply) deliveryIncompleteMessage
                                else if (entryUnconfirmed && (result.succeeded || recovered)) context.getString(R.string.maplesu_state_entry_unavailable)
                                else if (readFailed && result.succeeded) failToLoadAppProfile else failToUpdateAppProfile
                            val detail = UltraSdkLogging.redact(buildString {
                                append("package=$packageName fullUID=$uid\n")
                                append("code=${result.code} committed=${result.decisionCommitted} pending=${result.pendingApply} unknown=${result.commitUnknown}\n")
                                append(result.detail)
                                observed?.let {
                                    if (it.code != null || it.detail.isNotEmpty()) append("\n\nreadCode=${it.code}\n${it.detail}")
                                }
                            })
                            diagnostic = AppProfileDiagnostic(title, detail)
                            diagnosticDialog.show(title, detail)
                        } else {
                            diagnostic = null
                            lastWrite = null
                            lastSubmitted = null
                            if (enabled == false) showMessage(suDisabled)
                        }
                        // Both themes consume the same current decision and delivery snapshot.
                        viewModel.markNeedRefresh()
                        viewModel.loadAppList()
                    }
                }
            }
        },
    )

    when (uiMode) {
        UiMode.Miuix -> AppProfileScreenMiuix(
            state = state,
            actions = actions,
        )

        UiMode.Material -> AppProfileScreenMaterial(
            state = state,
            actions = actions,
            snackBarHost = snackbarHost,
        )
    }
}
