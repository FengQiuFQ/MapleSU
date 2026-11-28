package com.maplesu.core.ui.screen.settings

import android.content.Context
import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.RemoveModerator
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.Card as MaterialCard
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.maplesu.core.R
import com.maplesu.core.ui.component.dialog.rememberConfirmDialog
import com.maplesu.core.ui.component.material.SegmentedListItem
import com.maplesu.core.ui.component.statustag.StatusTag
import com.maplesu.core.ui.component.uninstalldialog.UninstallChoice
import com.maplesu.core.ui.component.uninstalldialog.UninstallChooser
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.runtime.HookRootExecutor
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentInstaller
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentAutoSetup
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentInstallReadiness
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentUninstaller
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentUpgrade
import dev.maplesu.manager.runtime.ultra.UltraInstalledIdentityProbe
import dev.maplesu.manager.runtime.ultra.UltraSdkCredentials
import dev.maplesu.manager.runtime.ultra.UltraSdkLogging
import dev.maplesu.manager.runtime.ultra.UltraSdkSession
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentVersion
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.Icon as MiuixIcon
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

private const val TAG = "MapleSUUltraEnvUi"

internal val ultraComponentDiagnosticObservations get() = UltraEnvironmentProbe.observations

/** Current installation facts only; this never starts an SDK, Root or version read. */
internal fun currentUltraComponentDiagnosticSnapshot(context: Context): UltraEnvironmentProbe.Snapshot? = runCatching {
    if (ModeRuntime.active != null) return@runCatching null
    val observation = UltraEnvironmentProbe.currentSnapshot(context)
    val owner = observation.managerOwnerIdentity ?: return@runCatching null
    if (owner.fullUid != android.os.Process.myUid() ||
        com.maplesu.core.ui.security.HiddenStartupConfirm.masks(
            com.maplesu.core.ui.security.LiteHiddenRuntime.currentState(),
            com.maplesu.core.ui.security.LiteHiddenRuntime.lastKnownOn(), ModeRuntime.active) ||
        com.maplesu.core.ui.security.HiddenStartupConfirm.isPending(context) ||
        dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.pending ||
        dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate.isBlocked() ||
        UltraRootKeyStore.isSuspended(context)) return@runCatching null
    observation.takeIf { ModeRuntime.active == null && it.modeActivation === ModeRuntime.activation &&
        it == UltraEnvironmentProbe.currentSnapshot(context) }
}.onFailure { if (it is kotlinx.coroutines.CancellationException) throw it }.getOrNull()

/** Read-only diagnostics retain the original component result and identify historical install failures. */
internal fun environmentDiagnosticDetail(
    rootProbeDetail: String?,
    detail: String? = null,
    persistedFailure: String? = null,
    componentFailureDetail: String? = null,
): String? = listOf(rootProbeDetail, detail, componentFailureDetail,
    persistedFailure?.takeIf(String::isNotBlank)?.let { "lastFailure=$it" })
    .filterNotNull().filter(String::isNotBlank).map(UltraSdkLogging::redact)
    .distinct().joinToString("\n").takeIf(String::isNotBlank)

internal enum class UltraEnvironmentRecoveryAction { NONE, RESTORE, REPAIR }

/** Fresh admission failures have no publication; they only retire unchanged cached UI evidence. */
internal fun environmentReadStillCurrent(
    observation: UltraEnvironmentProbe.Snapshot,
    publication: UltraEnvironmentProbe.Snapshot,
    latest: UltraEnvironmentProbe.Snapshot,
): Boolean = publication === latest && (observation.observedAtElapsedMs < 0 ||
    observation == publication.copy(managerSuFailureDetail = observation.managerSuFailureDetail))

internal fun environmentRepairEvidence(observation: UltraEnvironmentProbe.Snapshot): Boolean {
    val detail = observation.detail ?: return false
    val sdkError = detail.substringAfter("sdkError=", "").substringBefore(';')
    val sdkCode = detail.substringAfter("sdkErrorCode=", "").substringBefore(';').toIntOrNull()
    return observation.sdkChannelAvailable && sdkError in setOf("OK", "NONE") && sdkCode == 0 &&
        (observation.managerOwnerIdentity != null || observation.legacyCredentialFingerprint != null)
}

/** Missing reads offer manual recovery; only this page's current fault recommends repair. */
internal fun environmentRecoveryAction(
    state: UltraEnvironmentProbe.State,
    kernelRootVerified: Boolean,
    currentEvidence: Boolean,
    diagnosticsOnly: Boolean,
    hookEnvironment: Boolean,
): UltraEnvironmentRecoveryAction = when {
    diagnosticsOnly || hookEnvironment -> UltraEnvironmentRecoveryAction.NONE
    currentEvidence && (state == UltraEnvironmentProbe.State.Fault ||
        state == UltraEnvironmentProbe.State.NotInstalled && kernelRootVerified) -> UltraEnvironmentRecoveryAction.REPAIR
    state == UltraEnvironmentProbe.State.Unknown || state == UltraEnvironmentProbe.State.Fault ||
        state == UltraEnvironmentProbe.State.NotInstalled && kernelRootVerified -> UltraEnvironmentRecoveryAction.RESTORE
    else -> UltraEnvironmentRecoveryAction.NONE
}

/** A clicked Home result remains read-only, including when its failed read had no owner. */
@Composable
internal fun rememberHomeUltraComponentDiagnostic(enabled: Boolean): String? {
    if (!enabled) return null
    val request = UltraComponentDiagnosticRequests.clickedDiagnostic ?: return null
    val context = LocalContext.current.applicationContext
    val revision by ModeRuntime.detectionRevision.collectAsStateWithLifecycle()
    val observation by UltraEnvironmentProbe.observations.collectAsStateWithLifecycle(
        initialValue = UltraEnvironmentProbe.currentSnapshot())
    val activation = ModeRuntime.activation
    val superseded = request.isSupersededBy(activation, revision, null, observation)
    var detail by remember(request) { mutableStateOf<String?>(null) }
    LaunchedEffect(request, activation, revision, observation) {
        val current = withContext(Dispatchers.IO) {
            val snapshot = UltraEnvironmentProbe.currentSnapshot(context)
            val changed = request.isSupersededBy(ModeRuntime.activation,
                ModeRuntime.detectionRevision.value, UltraEnvironmentAutoSetup.currentBootId(), snapshot)
            val hidden = com.maplesu.core.ui.security.HiddenStartupConfirm.masks(
                com.maplesu.core.ui.security.LiteHiddenRuntime.currentState(),
                com.maplesu.core.ui.security.LiteHiddenRuntime.lastKnownOn(), ModeRuntime.active)
            val pending = com.maplesu.core.ui.security.HiddenStartupConfirm.isPending(context) ||
                dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.pending ||
                dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate.isBlocked() ||
                UltraRootKeyStore.isSuspended(context)
            changed to request.takeUnless { changed || hidden || pending || ModeRuntime.active == WorkMode.KSU }
        }
        if (UltraComponentDiagnosticRequests.clickedDiagnostic !== request) return@LaunchedEffect
        if (current.first) UltraComponentDiagnosticRequests.clear(request)
        detail = current.second?.let {
            environmentDiagnosticDetail(it.failureCode?.let { code -> "code=$code" }, it.detail)
        }
    }
    return detail.takeUnless { superseded }
}

@Composable
internal fun HomeUltraComponentDiagnosticMiuix(detail: String) {
    Column {
        BasicComponent(title = stringResource(R.string.work_mode_open_diagnosis))
        MiuixText(detail, color = colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
    }
}

@Composable
internal fun HomeUltraComponentDiagnosticMaterial(detail: String) {
    SegmentedListItem(
        headlineContent = { MaterialText(stringResource(R.string.work_mode_open_diagnosis)) },
        supportingContent = { MaterialText(detail) },
    )
}

/** History is a read-only result; no owner or runtime capability is inferred from it. */
internal fun savedUltraInstallFailureDiagnostic(
    enabled: Boolean,
    mode: WorkMode?,
    hidden: Boolean,
    pending: Boolean,
    readFailure: () -> String?,
): String? {
    if (!enabled || mode != null || hidden || pending) return null
    return environmentDiagnosticDetail(null, persistedFailure = readFailure())
}

@Composable
internal fun rememberSavedUltraInstallFailureDiagnostic(enabled: Boolean): String? {
    if (!enabled) return null
    val context = LocalContext.current.applicationContext
    val hiddenRevision by com.maplesu.core.ui.security.HiddenFactsSignal.revision.collectAsStateWithLifecycle()
    val switching by dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.pendingFlow.collectAsStateWithLifecycle()
    val mode = ModeRuntime.active
    val hidden = com.maplesu.core.ui.security.HiddenStartupConfirm.masks(
        com.maplesu.core.ui.security.LiteHiddenRuntime.currentState(),
        com.maplesu.core.ui.security.LiteHiddenRuntime.lastKnownOn(), mode)
    val pending = switching || com.maplesu.core.ui.security.HiddenStartupConfirm.isPending(context) ||
        dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate.isBlocked() || UltraRootKeyStore.isSuspended(context)
    val diagnosticKey = listOf(mode, hidden, pending, hiddenRevision)
    var detail by remember(context, diagnosticKey) { mutableStateOf(
        savedUltraInstallFailureDiagnostic(enabled, mode, hidden, pending) { UltraEnvironmentUpgrade.persistedFailure(context) }) }
    LifecycleResumeEffect(context, diagnosticKey) {
        detail = savedUltraInstallFailureDiagnostic(enabled, mode, hidden, pending) { UltraEnvironmentUpgrade.persistedFailure(context) }
        onPauseOrDispose { }
    }
    return detail
}

@Composable
internal fun SavedUltraInstallFailureDiagnosticMiuix(detail: String) {
    Column {
        BasicComponent(title = stringResource(R.string.ultra_sdk_install_title),
            summary = stringResource(R.string.ui_d_env_install_failed))
        MiuixText(detail, color = colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
    }
}

@Composable
internal fun SavedUltraInstallFailureDiagnosticMaterial(detail: String) {
    SegmentedListItem(
        headlineContent = { MaterialText(stringResource(R.string.ultra_sdk_install_title)) },
        supportingContent = {
            Column {
                MaterialText(stringResource(R.string.ui_d_env_install_failed))
                MaterialText(detail)
            }
        },
    )
}

private data class InstalledUltraUpgradeAction(val busy: Boolean, val onClick: () -> Unit)

@Composable
private fun rememberInstalledUltraUpgradeAction(): InstalledUltraUpgradeAction {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val title = stringResource(R.string.ultra_env_existing_upgrade_title)
    val content = stringResource(R.string.ultra_env_existing_upgrade_confirm)
    val confirm = stringResource(R.string.ultra_env_update_confirm)
    val dialog = rememberConfirmDialog(onConfirm = {
        if (!busy) {
            busy = true
            scope.launch {
                val result = withContext(Dispatchers.IO + NonCancellable) {
                    val visible = installedUltraUpgradeVisible(
                        ModeRuntime.active,
                        UltraEnvironmentUpgrade.installedKernelKnown(context),
                        UltraEnvironmentUpgrade.installedKernelUpdateRequired(context),
                        com.maplesu.core.ui.security.HiddenStartupConfirm.masking(context) ||
                            com.maplesu.core.ui.security.HiddenStartupConfirm.current(context) ||
                            com.maplesu.core.ui.security.HiddenStartupConfirm.isPending(context),
                        dev.maplesu.manager.workmode.ui.WorkModeSwitchSession.pending,
                    )
                    if (!visible) UltraEnvironmentUpgrade.Result.REFUSED
                    else runCatching { UltraEnvironmentUpgrade.upgrade(context) }
                        .getOrDefault(UltraEnvironmentUpgrade.Result.FAILED)
                }
                busy = false
                val message = when (result) {
                    UltraEnvironmentUpgrade.Result.SUBMITTED -> R.string.ui_d_env_repair_submitted
                    UltraEnvironmentUpgrade.Result.REFUSED -> R.string.ultra_env_update_refused
                    UltraEnvironmentUpgrade.Result.FAILED -> R.string.ultra_env_update_failed
                }
                Toast.makeText(context, message, Toast.LENGTH_LONG).show()
            }
        }
    })
    return InstalledUltraUpgradeAction(busy || UltraEnvironmentUpgrade.inProgress) {
        if (!busy) dialog.showConfirm(title = title, content = content, confirm = confirm)
    }
}

@Composable
internal fun InstalledUltraUpgradeRowMiuix() {
    val action = rememberInstalledUltraUpgradeAction()
    BasicComponent(
        title = stringResource(R.string.ultra_env_existing_upgrade_title),
        summary = stringResource(R.string.ultra_env_existing_upgrade_summary),
        endActions = {
            MiuixTextButton(text = stringResource(R.string.ultra_env_update_confirm),
                onClick = action.onClick, enabled = !action.busy)
        },
    )
}

@Composable
internal fun InstalledUltraUpgradeRowMaterial() {
    val action = rememberInstalledUltraUpgradeAction()
    SegmentedListItem(
        onClick = action.onClick,
        enabled = !action.busy,
        headlineContent = { MaterialText(stringResource(R.string.ultra_env_existing_upgrade_title)) },
        supportingContent = { MaterialText(stringResource(R.string.ultra_env_existing_upgrade_summary)) },
        leadingContent = { MaterialIcon(Icons.Rounded.Security, contentDescription = null) },
        trailingContent = {
            MaterialTextButton(onClick = action.onClick, enabled = !action.busy) {
                MaterialText(stringResource(R.string.ultra_env_update_confirm))
            }
        },
    )
}

/** Ultra environment settings. Permanent removal restores backed-up images or persists
 * disable. SDK calls use the current verified installation and run off the UI thread.
 */
@Stable
class UltraEnvironmentPanel internal constructor(
    private val context: Context,
    private val scope: CoroutineScope,
    initialSnapshot: UltraEnvironmentProbe.Snapshot,
    internal val diagnosticsOnly: Boolean = false,
) {
    private val seed = if (diagnosticsOnly) null else lastFacts?.takeIf { it.current() }
    private val diagnosticScope = initialSnapshot.takeIf { diagnosticsOnly }

    var state by mutableStateOf(seed?.state ?: initialSnapshot.state)
        private set
    private var observationDetail by mutableStateOf(environmentDiagnosticDetail(
        if (seed != null) seed.detail else environmentDiagnosticDetail(initialSnapshot.rootProbeDetail,
            initialSnapshot.detail, componentFailureDetail = initialSnapshot.managerSuFailureDetail),
        persistedFailure = UltraEnvironmentUpgrade.persistedFailure(context),
    ))
    private var homeDiagnosticDetail by mutableStateOf<String?>(null)
    private var currentRepairEvidence by mutableStateOf(false)
    private var repairEvidencePublication: UltraEnvironmentProbe.Snapshot? = null
    val detail: String? get() = environmentDiagnosticDetail(observationDetail, homeDiagnosticDetail)
    internal val recoveryAction: UltraEnvironmentRecoveryAction
        get() = environmentRecoveryAction(state, kernelRootVerified, currentRepairEvidence, diagnosticsOnly, hookEnvironment)

    internal fun updateHomeDiagnostic(detail: String?) {
        homeDiagnosticDetail = detail
    }
    var kernelRootVerified by mutableStateOf(seed?.kernelRootVerified ?: initialSnapshot.kernelRootVerified)
        private set
    var version by mutableStateOf(seed?.version)
        private set
    var observedAtWallClockMs by mutableStateOf(seed?.observedAt ?: initialSnapshot.observedAtWallClockMs)
        private set
    var busy by mutableStateOf(false)
        private set
    var hookEnvironment by mutableStateOf(seed?.hookEnvironment ?: false)
        private set

    fun loadInitialState() {
        if (diagnosticsOnly || busy) return
        busy = true
        scope.launch {
            try {
                applyFacts(readFacts())
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (error: Exception) {
                Log.w(TAG, "initial environment read failed", error)
            } finally {
                busy = false
            }
        }
    }

    /** 静默刷新：界面直接反映新状态，不弹 Toast。 */
    fun refresh() = runAction {
        if (diagnosticsOnly) {
            withContext(Dispatchers.IO) { currentDiagnosticObservation() }
                ?.let(UltraComponentDiagnosticRequests::retry)
        } else applyFacts(readFacts())
        ""
    }

    fun repairEnvironment() = runAction {
        if (diagnosticsOnly) return@runAction ""
        val result = withContext(Dispatchers.IO) { UltraEnvironmentUpgrade.repairEnvironment(context) }
        applyFacts(readFacts())
        when (result) {
            UltraEnvironmentUpgrade.Result.SUBMITTED -> context.getString(R.string.ui_d_env_repair_submitted)
            UltraEnvironmentUpgrade.Result.REFUSED -> context.getString(R.string.ui_d_env_repair_refused)
            UltraEnvironmentUpgrade.Result.FAILED -> context.getString(R.string.ui_d_env_repair_failed)
        }
    }

    /** Permanent removal marks the environment removed only after backed-up images are restored. */
    fun removeEnvironment() = uninstall(permanent = true)

    /** Temporary removal records explicit suspension after the SDK operation. */
    fun suspendLocal() = uninstall(permanent = false)

    private fun uninstall(permanent: Boolean) = runAction {
        if (diagnosticsOnly) return@runAction ""
        val result = withContext(Dispatchers.IO) { UltraEnvironmentUninstaller.uninstall(context, permanent) }
        if (!result.ok) {
            Log.w(TAG, UltraSdkLogging.redact(
                "uninstall failed sdkError=${result.sdkError} sdkErrorCode=${result.sdkErrorCode}"))
            context.getString(R.string.ui_d_env_remove_failed)
        } else {
            applyFacts(readFacts())
            context.getString(R.string.ui_d_env_remove_done)
        }
    }

    private fun currentDiagnosticObservation(): UltraEnvironmentProbe.Snapshot? =
        currentUltraComponentDiagnosticSnapshot(context)?.takeIf {
            it.modeActivation === diagnosticScope?.modeActivation &&
                it.managerOwnerIdentity == diagnosticScope?.managerOwnerIdentity
        }

    internal suspend fun observeDiagnostic() {
        val observation = withContext(Dispatchers.IO) {
            if (diagnosticsOnly) currentDiagnosticObservation() else UltraEnvironmentProbe.currentSnapshot(context)
        } ?: return
        if (UltraEnvironmentProbe.currentSnapshot() !== repairEvidencePublication) {
            currentRepairEvidence = false
        }
        observationDetail = environmentDiagnosticDetail(observation.rootProbeDetail, observation.detail,
            UltraEnvironmentUpgrade.persistedFailure(context), observation.managerSuFailureDetail)
        if (diagnosticsOnly) {
            state = observation.state
            kernelRootVerified = observation.kernelRootVerified
            observedAtWallClockMs = observation.observedAtWallClockMs
        }
    }

    private fun captureObservation(): () -> Boolean {
        val activation = ModeRuntime.activation
        val boot = UltraEnvironmentAutoSetup.currentBootId()
        val owner = UltraSdkCredentials.captureOwnerMarker(context)
        val session = UltraSdkSession.captureOwnerMarker(context)
        return {
            ModeRuntime.activation === activation && boot != null &&
                UltraEnvironmentAutoSetup.currentBootId() == boot && owner() && session()
        }
    }
    /** 一次读全：减少重组次数，也避免版本行和状态胶囊错开刷新。 */
    private suspend fun readFacts(): Facts = withContext(Dispatchers.IO) {
        val hook = HookRootExecutor.production(context)
        if (ModeRuntime.active == WorkMode.LITE && UltraSdkCredentials.hookWithoutSdk(context) && hook.available()) {
            val current = captureObservation()
            val result = hook.run("/system/bin/id -u")
            return@withContext Facts(
                state = if (result.ok && result.output.trim() == "0") UltraEnvironmentProbe.State.Running
                    else UltraEnvironmentProbe.State.Unknown,
                version = null,
                observedAt = System.currentTimeMillis(),
                hookEnvironment = true,
                current = current,
            )
        }
        val scopeCurrent = captureObservation()
        val observation = UltraEnvironmentProbe.observeFresh(context)
        val publication = UltraEnvironmentProbe.currentSnapshot()
        val current = {
            scopeCurrent() && environmentReadStillCurrent(observation, publication,
                UltraEnvironmentProbe.currentSnapshot())
        }
        val detailObservation = if (observation.observedAtElapsedMs >= 0 && current()) publication else observation
        Facts(
            state = observation.state,
            version = if (current()) readVersion(current) else null,
            observedAt = observation.observedAtWallClockMs,
            kernelRootVerified = observation.kernelRootVerified,
            repairEvidence = environmentRepairEvidence(observation),
            detail = environmentDiagnosticDetail(detailObservation.rootProbeDetail, detailObservation.detail,
                componentFailureDetail = detailObservation.managerSuFailureDetail),
            publication = publication,
            current = current,
        )
    }

    private fun readVersion(current: () -> Boolean): String? = runCatching {
        val client = UltraSdkCredentials.client(context, current)
        val raw = client
            .installedEnvironmentVersion()
            .takeIf { it.succeeded }
            ?.string("version")
        if (raw != null) return@runCatching UltraEnvironmentVersion.displayOf(raw)
        // Version fallback only: do not start a root hash read when the SDK answered.
        val buildId = runCatching { UltraInstalledIdentityProbe.read(context, client).buildId }
            .onFailure { if (it is kotlinx.coroutines.CancellationException) throw it }.getOrNull()
        UltraEnvironmentVersion.displayOf(raw, buildId)
    }.onFailure { if (it is kotlinx.coroutines.CancellationException) throw it }.getOrNull()

    private fun applyFacts(facts: Facts) {
        if (!facts.current()) return
        // 环境仍在运行但这次没读到版本：保留旧值，版本行不闪回「未知」。
        val previous = lastFacts?.takeIf { it.current() }
        val merged = if (!facts.hookEnvironment && previous?.hookEnvironment == false &&
            facts.version == null && facts.state == UltraEnvironmentProbe.State.Running) {
            facts.copy(version = previous.version)
        } else {
            facts
        }
        lastFacts = merged
        state = merged.state
        repairEvidencePublication = merged.publication
        currentRepairEvidence = merged.repairEvidence
        observationDetail = environmentDiagnosticDetail(merged.detail,
            persistedFailure = UltraEnvironmentUpgrade.persistedFailure(context))
        kernelRootVerified = merged.kernelRootVerified
        version = merged.version
        observedAtWallClockMs = merged.observedAt
        hookEnvironment = merged.hookEnvironment
    }

    private fun runAction(block: suspend () -> String) {
        if (busy) return
        busy = true
        scope.launch {
            val text = try {
                block()
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (error: Exception) {
                Log.w(TAG, "environment action failed", error)
                context.getString(R.string.ui_d_env_action_failed)
            } finally {
                busy = false
            }
            // 空字符串 = 静默动作（例如刷新）。结果只走 Toast，不往卡片里塞文字，卡片高度不变。
            if (text.isNotBlank()) {
                Toast.makeText(context, text, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private data class Facts(
        val state: UltraEnvironmentProbe.State,
        val version: String?,
        val observedAt: Long,
        val hookEnvironment: Boolean = false,
        val kernelRootVerified: Boolean = false,
        val repairEvidence: Boolean = false,
        val detail: String? = null,
        val publication: UltraEnvironmentProbe.Snapshot? = null,
        val current: () -> Boolean,
    )

    private companion object {
        /** 本进程上一次的结果：面板重建时做首帧。 */
        @Volatile
        var lastFacts: Facts? = null
    }
}

/**
 * 工作环境面板（**仅 Ultra**）。
 *
 * [enabled] = `SettingsModePolicy.shows(SettingsSection.ULTRA_ULTRA_ENV)` 且隐藏未生效：
 * 其余情况返回 null 且**不做任何 Ultra SDK / 环境探测**
 * （`UltraEnvironmentProbe.currentSnapshot()`、`UltraAutoPair.ensure` 都不会被调用）。
 */
@Composable
fun rememberUltraEnvironmentPanel(enabled: Boolean): UltraEnvironmentPanel? {
    if (!enabled) return null
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val observation by UltraEnvironmentProbe.observations.collectAsStateWithLifecycle(
        initialValue = UltraEnvironmentProbe.currentSnapshot(context.applicationContext))
    val panel = remember(observation.modeActivation, observation.managerOwnerIdentity, observation.legacyCredentialFingerprint) {
        UltraEnvironmentPanel(
            context = context.applicationContext,
            scope = scope,
            initialSnapshot = UltraEnvironmentProbe.currentSnapshot(context.applicationContext),
        )
    }
    LaunchedEffect(panel, observation.state, observation.kernelRootVerified,
        observation.managerOwnerIdentity, observation.sdkChannelAvailable, observation.detail) { panel.loadInitialState() }
    LaunchedEffect(panel, observation) {
        panel.observeDiagnostic()
    }
    return panel
}

/** Rendering consumes current observations; explicit retries belong to the shared check session. */
@Composable
internal fun rememberUltraComponentDiagnosticsPanel(observation: UltraEnvironmentProbe.Snapshot?): UltraEnvironmentPanel? {
    if (observation == null || ModeRuntime.active != null || observation.modeActivation !== ModeRuntime.activation) return null
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val panel = remember(observation.modeActivation, observation.managerOwnerIdentity) {
        UltraEnvironmentPanel(context, scope, observation, diagnosticsOnly = true)
    }
    LaunchedEffect(panel, observation) { panel.observeDiagnostic() }
    return panel
}

private fun envStateLabelRes(panel: UltraEnvironmentPanel): Int = when {
    else -> when (panel.state) {
        UltraEnvironmentProbe.State.Running -> R.string.ui_d_env_state_running
        UltraEnvironmentProbe.State.NotInstalled -> R.string.ui_d_env_state_not_installed
        UltraEnvironmentProbe.State.Fault -> R.string.ui_d_env_state_fault
        UltraEnvironmentProbe.State.NoKey -> R.string.ui_d_env_state_unknown
        UltraEnvironmentProbe.State.Unknown -> R.string.ui_d_env_state_unknown
    }
}

/** 版本 + 检查时间，一行写完；只有数值在变，行高不变。 */
@Composable
private fun envSummary(panel: UltraEnvironmentPanel): String {
    if (panel.diagnosticsOnly) return stringResource(R.string.ui_d_env_refresh)
    val checkedAt = panel.observedAtWallClockMs.takeIf { it > 0 }?.let { at ->
        remember(at) { SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(at)) }
    }
    val version = panel.version
    return when {
        checkedAt == null -> stringResource(R.string.ui_d_env_checking)
        panel.hookEnvironment -> stringResource(R.string.ui_d_env_hook_summary, checkedAt)
        version != null -> stringResource(R.string.ui_d_env_summary, ultraEnvironmentLabel(version), checkedAt)
        else -> stringResource(R.string.ui_d_env_summary_no_version, checkedAt)
    }
}

@Composable
private fun rememberUltraUninstallChoices(panel: UltraEnvironmentPanel): List<UninstallChoice> {
    // The SDK checks the current verified Manager identity.
    val removeBlocked = when {
        panel.hookEnvironment -> stringResource(R.string.ui_d_env_hook_removal)
        else -> null
    }
    val remove = UninstallChoice(
        icon = Icons.Rounded.DeleteForever,
        title = stringResource(R.string.ui_d_uninstall_remove),
        message = stringResource(R.string.ui_d_uninstall_remove_message),
        disabledReason = removeBlocked,
        onRun = panel::removeEnvironment,
    )
    val secondary = UninstallChoice(
        icon = Icons.Rounded.RemoveModerator,
        title = stringResource(R.string.ui_d_uninstall_suspend),
        message = stringResource(R.string.ui_d_uninstall_suspend_message),
        disabledReason = removeBlocked,
        onRun = panel::suspendLocal,
    )
    return listOf(remove, secondary)
}

/** Miuix：「MapleSU_Ultra工作环境」卡。 */
@Composable
fun UltraEnvironmentSectionMiuix(panel: UltraEnvironmentPanel, showInstalledKernelUpdate: Boolean = false) {
    val confirmRepair = rememberFaultRepairAction(panel)
    val repair = panel.recoveryAction == UltraEnvironmentRecoveryAction.REPAIR
    MiuixCard(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        val title = stringResource(R.string.ui_d_env_title)
        BasicComponent(
            title = title,
            summary = envSummary(panel),
            startAction = {
                MiuixIcon(
                    Icons.Rounded.Security,
                    contentDescription = title,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
            endActions = {
                val (bg, fg) = envTagColorsMiuix(panel)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    StatusTag(label = stringResource(envStateLabelRes(panel)), backgroundColor = bg, contentColor = fg)
                    if (panel.diagnosticsOnly) MiuixText(stringResource(R.string.network_retry))
                    MiuixIcon(
                        Icons.Rounded.Refresh,
                        contentDescription = stringResource(if (panel.diagnosticsOnly) R.string.network_retry else R.string.ui_d_env_refresh),
                        modifier = Modifier
                            .size(18.dp)
                            .graphicsLayer { alpha = if (panel.busy) 0.38f else 1f },
                        tint = colorScheme.onSurfaceVariantSummary,
                    )
                }
            },
            onClick = panel::refresh,
        )
        panel.detail?.takeIf(String::isNotBlank)?.let { detail ->
            MiuixText(text = detail, color = colorScheme.onSurfaceVariantSummary,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        }
        if (showInstalledKernelUpdate) InstalledUltraUpgradeRowMiuix()
        if (panel.canShowRepair) {
            BasicComponent(
                title = stringResource(if (repair) R.string.ui_d_env_repair_title else R.string.ui_d_env_restore_title),
                summary = stringResource(if (repair) R.string.ui_d_env_repair_summary else R.string.ui_d_env_restore_summary),
                endActions = {
                    MiuixTextButton(
                        text = stringResource(if (repair) R.string.ui_d_env_repair_action else R.string.ui_d_env_restore_action),
                        onClick = confirmRepair,
                        enabled = !panel.busy,
                        modifier = Modifier.heightIn(min = 48.dp),
                    )
                },
            )
        }
    }
}

@Composable
private fun envTagColorsMiuix(panel: UltraEnvironmentPanel): Pair<Color, Color> = when {
    panel.state == UltraEnvironmentProbe.State.Running -> colorScheme.primary to colorScheme.onPrimary
    panel.state == UltraEnvironmentProbe.State.Fault -> colorScheme.error to colorScheme.onError
    else -> colorScheme.secondaryContainer to colorScheme.onSecondaryContainer
}

/** Miuix：卸载行（设置页最后一组）。 */
@Composable
fun UltraUninstallRowMiuix(panel: UltraEnvironmentPanel) {
    var show by rememberSaveable { mutableStateOf(false) }
    val title = stringResource(R.string.uninstall)
    ArrowPreference(
        title = title,
        startAction = {
            MiuixIcon(
                Icons.Rounded.Delete,
                contentDescription = title,
                modifier = Modifier.padding(end = 6.dp),
                tint = colorScheme.onBackground,
            )
        },
        enabled = !panel.busy,
        onClick = { show = true },
    )
    UninstallChooser(
        show = show,
        title = title,
        choices = rememberUltraUninstallChoices(panel),
        onDismissRequest = { show = false },
    )
}

/**
 * Material：环境信息作为一个分段项。分段项由调用方放进 `SegmentedColumn`，
 * 这样与同组的行共用圆角，不再是一张风格不同的卡片。
 */
@Composable
fun UltraEnvironmentRowMaterial(panel: UltraEnvironmentPanel) {
    val confirmRepair = rememberFaultRepairAction(panel)
    val repair = panel.recoveryAction == UltraEnvironmentRecoveryAction.REPAIR
    val title = stringResource(R.string.ui_d_env_title)
    SegmentedListItem(
        onClick = panel::refresh,
        headlineContent = { MaterialText(title) },
        supportingContent = {
            Column {
                MaterialText(envSummary(panel))
                panel.detail?.takeIf(String::isNotBlank)?.let { MaterialText(it) }
            }
        },
        leadingContent = { MaterialIcon(Icons.Rounded.Security, contentDescription = title) },
        trailingContent = {
            val (bg, fg) = envTagColorsMaterial(panel)
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                StatusTag(label = stringResource(envStateLabelRes(panel)), backgroundColor = bg, contentColor = fg)
                if (panel.diagnosticsOnly) MaterialText(stringResource(R.string.network_retry))
                MaterialIcon(
                    Icons.Rounded.Refresh,
                    contentDescription = stringResource(if (panel.diagnosticsOnly) R.string.network_retry else R.string.ui_d_env_refresh),
                    modifier = Modifier
                        .size(18.dp)
                        .graphicsLayer { alpha = if (panel.busy) 0.38f else 1f },
                )
            }
        },
    )
    if (panel.canShowRepair) {
        SegmentedListItem(
            onClick = confirmRepair,
            enabled = !panel.busy,
            headlineContent = { MaterialText(stringResource(if (repair) R.string.ui_d_env_repair_title else R.string.ui_d_env_restore_title)) },
            supportingContent = { MaterialText(stringResource(if (repair) R.string.ui_d_env_repair_summary else R.string.ui_d_env_restore_summary)) },
            leadingContent = { MaterialIcon(Icons.Rounded.Security, contentDescription = null) },
            trailingContent = {
                MaterialTextButton(onClick = confirmRepair, enabled = !panel.busy, modifier = Modifier.heightIn(min = 48.dp)) {
                    MaterialText(stringResource(if (repair) R.string.ui_d_env_repair_action else R.string.ui_d_env_restore_action))
                }
            },
        )
    }
}

@Composable
private fun rememberFaultRepairAction(panel: UltraEnvironmentPanel): () -> Unit {
    val dialog = rememberConfirmDialog(onConfirm = { panel.repairEnvironment() })
    val repair = panel.recoveryAction == UltraEnvironmentRecoveryAction.REPAIR
    val title = stringResource(if (repair) R.string.ui_d_env_repair_title else R.string.ui_d_env_restore_title)
    val content = stringResource(if (repair) R.string.ui_d_env_repair_confirm else R.string.ui_d_env_restore_confirm)
    val confirm = stringResource(if (repair) R.string.ui_d_env_repair_action else R.string.ui_d_env_restore_action)
    return { if (!panel.busy) dialog.showConfirm(title = title, content = content, confirm = confirm) }
}

private val UltraEnvironmentPanel.canShowRepair: Boolean
    get() = recoveryAction != UltraEnvironmentRecoveryAction.NONE

@Composable
private fun envTagColorsMaterial(panel: UltraEnvironmentPanel): Pair<Color, Color> {
    val scheme = MaterialTheme.colorScheme
    return when {
        panel.state == UltraEnvironmentProbe.State.Running -> scheme.primaryContainer to scheme.onPrimaryContainer
        panel.state == UltraEnvironmentProbe.State.Fault -> scheme.errorContainer to scheme.onErrorContainer
        else -> scheme.secondaryContainer to scheme.onSecondaryContainer
    }
}

/** Material：卸载行（分段项）。 */
@Composable
fun UltraUninstallRowMaterial(panel: UltraEnvironmentPanel) {
    var show by rememberSaveable { mutableStateOf(false) }
    val title = stringResource(R.string.uninstall)
    SegmentedListItem(
        onClick = { show = true },
        enabled = !panel.busy,
        headlineContent = { MaterialText(title) },
        leadingContent = { MaterialIcon(Icons.Rounded.Delete, contentDescription = title) },
        trailingContent = { MaterialIcon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
    )
    UninstallChooser(
        show = show,
        title = title,
        choices = rememberUltraUninstallChoices(panel),
        onDismissRequest = { show = false },
    )
}

/** Explicit environment recovery delegates installation capability to the SDK operation. */
@Stable
class UltraEnvironmentInstallPanel internal constructor(
    private val context: Context,
    private val scope: CoroutineScope,
) {
    var visible by mutableStateOf(false)
        private set
    var busy by mutableStateOf(false)
        private set
    var message by mutableStateOf<String?>(null)
        private set
    var detail by mutableStateOf<String?>(null)
        private set
    var readiness by mutableStateOf(UltraEnvironmentInstallReadiness.NotChecked)
        private set
    var needsConfirmation by mutableStateOf(true)
        private set
    private var homeMode: WorkMode? = null
    private var homeConfirmedAbsent = false
    private var refreshJob: Job? = null

    private fun eligible(mode: WorkMode? = homeMode): Boolean =
        environmentInstallEligible(mode, ModeRuntime.active,
            com.maplesu.core.ui.security.HiddenStartupConfirm.masking(context),
            com.maplesu.core.ui.security.HiddenStartupConfirm.isPending(context))

    fun refresh(mode: WorkMode? = ModeRuntime.active, confirmedAbsent: Boolean = false) {
        homeMode = mode
        homeConfirmedAbsent = confirmedAbsent
        needsConfirmation = environmentInstallNeedsConfirmation(mode, confirmedAbsent)
        if (mode == WorkMode.KSU || ModeRuntime.active == WorkMode.KSU) visible = false
        if (busy) return
        refreshJob?.cancel()
        refreshJob = scope.launch {
            val eligible = withContext(Dispatchers.IO) { eligible(mode) }
            val observation = UltraEnvironmentProbe.currentSnapshot(context)
            visible = environmentInstallVisible(eligible, observation.state, observation.kernelChannelAbsent)
            if (visible && message == null) {
                (UltraEnvironmentUpgrade.lastFailureReason ?: UltraEnvironmentUpgrade.persistedFailure(context))
                    ?.takeIf(String::isNotBlank)?.let { reason ->
                        readiness = UltraEnvironmentInstallReadiness.Unavailable
                        message = context.getString(R.string.ui_d_env_install_failed)
                        detail = reason
                    }
            }
        }
    }

    fun install() {
        if (busy || !eligible()) return
        refreshJob?.cancel()
        busy = true
        message = null
        detail = null
        readiness = UltraEnvironmentInstallReadiness.NotChecked
        scope.launch {
            try {
                val (result, failureReason) = withContext(Dispatchers.IO + NonCancellable) {
                    val result = UltraEnvironmentUpgrade.installBundled(context)
                    result to UltraEnvironmentUpgrade.lastFailureReason
                }
                val summary = context.getString(when (result) {
                    UltraEnvironmentUpgrade.Result.SUBMITTED -> R.string.ultra_sdk_install_submitted
                    UltraEnvironmentUpgrade.Result.FAILED -> R.string.ui_d_env_install_failed
                    UltraEnvironmentUpgrade.Result.REFUSED -> R.string.ultra_env_update_refused
                })
                readiness = if (result == UltraEnvironmentUpgrade.Result.SUBMITTED)
                    UltraEnvironmentInstallReadiness.NotChecked else UltraEnvironmentInstallReadiness.Unavailable
                message = summary
                detail = failureReason.takeUnless { result == UltraEnvironmentUpgrade.Result.SUBMITTED }
                Toast.makeText(context, summary, Toast.LENGTH_LONG).show()
            } catch (error: Exception) {
                if (error is kotlinx.coroutines.CancellationException) throw error
                Log.w(TAG, "SDK installation failed", error)
                readiness = UltraEnvironmentInstallReadiness.Unavailable
                message = context.getString(R.string.ui_d_env_install_failed)
                detail = error.message ?: error.javaClass.simpleName
            } finally {
                busy = false
                refresh(homeMode, homeConfirmedAbsent)
            }
        }
    }
}

internal fun environmentInstallVisible(
    eligible: Boolean,
    state: UltraEnvironmentProbe.State,
    kernelChannelAbsent: Boolean,
): Boolean = eligible

internal fun environmentReadinessSummaryResId(readiness: UltraEnvironmentInstallReadiness): Int = when (readiness) {
    UltraEnvironmentInstallReadiness.NotChecked, UltraEnvironmentInstallReadiness.Ready -> R.string.ultra_sdk_install_summary
    UltraEnvironmentInstallReadiness.NeedsImage -> R.string.ui_d_env_install_kernel_channel
    UltraEnvironmentInstallReadiness.Unavailable -> R.string.ui_d_env_install_failed
}

internal fun environmentInstallFailureResId(sdkError: String): Int =
    when (sdkError) {
        "ERR_MODULE_NO_BOOT" -> R.string.ui_d_env_install_kernel_channel
        else -> R.string.ui_d_env_install_failed
    }

private fun environmentInstallFailure(context: Context, sdkError: String): String =
    context.getString(environmentInstallFailureResId(sdkError))

@Composable
fun rememberUltraEnvironmentInstallPanel(
    mode: WorkMode? = ModeRuntime.active,
    confirmedAbsent: Boolean = false,
): UltraEnvironmentInstallPanel {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val appContext = context.applicationContext
    val panel = remember { UltraEnvironmentInstallPanel(appContext, scope) }
    val observation by UltraEnvironmentProbe.observations.collectAsStateWithLifecycle(
        initialValue = UltraEnvironmentProbe.currentSnapshot(appContext))
    val hiddenRevision by com.maplesu.core.ui.security.HiddenFactsSignal.revision.collectAsStateWithLifecycle()
    LaunchedEffect(panel, mode, confirmedAbsent, observation.state, observation.kernelChannelAbsent, hiddenRevision) {
        panel.refresh(mode, confirmedAbsent)
    }
    return panel
}

@Composable
private fun installSummary(panel: UltraEnvironmentInstallPanel): String =
    panel.message ?: when {
        panel.busy -> stringResource(R.string.ui_d_env_install_busy)
        panel.needsConfirmation -> stringResource(R.string.home_environment_confirmation_summary) + "\n" +
            stringResource(R.string.ultra_sdk_install_summary)
        else -> stringResource(environmentReadinessSummaryResId(panel.readiness))
    }

@Composable
private fun installActionLabel(panel: UltraEnvironmentInstallPanel): String = stringResource(when {
    panel.readiness == UltraEnvironmentInstallReadiness.Unavailable -> R.string.network_retry
    else -> R.string.ultra_sdk_install_action
})

@Composable
fun UltraEnvironmentInstallCardMiuix(panel: UltraEnvironmentInstallPanel, onOpenDiagnostics: () -> Unit) {
    if (!panel.visible) return
    val title = stringResource(R.string.ultra_sdk_install_title)
    MiuixCard(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
        BasicComponent(
            title = title,
            summary = installSummary(panel),
            startAction = {
                MiuixIcon(
                    Icons.Rounded.Security,
                    contentDescription = title,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
        )
        FlowRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 16.dp, bottom = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (!panel.detail.isNullOrBlank()) {
                MiuixTextButton(text = stringResource(R.string.work_mode_open_diagnosis), onClick = onOpenDiagnostics,
                    modifier = Modifier.heightIn(min = 48.dp))
            }
            MiuixTextButton(
                text = installActionLabel(panel),
                onClick = { panel.install() },
                enabled = !panel.busy,
                modifier = Modifier.heightIn(min = 48.dp),
            )
        }
    }
}

@Composable
fun UltraEnvironmentInstallCardMaterial(panel: UltraEnvironmentInstallPanel, onOpenDiagnostics: () -> Unit) {
    if (!panel.visible) return
    MaterialCard(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            MaterialText(stringResource(R.string.ultra_sdk_install_title), style = MaterialTheme.typography.titleMedium)
            MaterialText(
                installSummary(panel),
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FlowRow(modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!panel.detail.isNullOrBlank()) {
                    MaterialTextButton(onClick = onOpenDiagnostics, modifier = Modifier.heightIn(min = 48.dp)) {
                        MaterialText(stringResource(R.string.work_mode_open_diagnosis))
                    }
                }
                MaterialTextButton(onClick = { panel.install() }, enabled = !panel.busy,
                    modifier = Modifier.heightIn(min = 48.dp)) {
                    MaterialText(installActionLabel(panel))
                }
            }
        }
    }
}
