package com.maplesu.core.ui.screen.settings

import android.content.Context
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.maplesu.core.R
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentUpgrade
import dev.maplesu.manager.runtime.ultra.UltraEnvFacts
import dev.maplesu.manager.runtime.ultra.UltraEnvUpgrade
import dev.maplesu.manager.runtime.ultra.UltraEnvObservation
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentVersion
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.runtime.ultra.UltraLegacyCredential
import dev.maplesu.manager.runtime.ultra.UltraInstalledIdentityProbe
import dev.maplesu.manager.runtime.ultra.InstalledIdentity
import dev.maplesu.manager.runtime.ultra.Source
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.runtime.BoundedPageRead
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicLong

/** A completed read updates display identity only within the same observation scope. */
internal fun mergeCompletedReadback(facts: UltraEnvFacts?, scope: String?, identity: InstalledIdentity?): UltraEnvFacts? {
    if (facts == null || scope == null || facts.observationScope != scope || identity?.source != Source.Readback) return null
    return facts.copy(installedBuildId = identity.buildId, installedHelperSha256 = identity.helperSha256,
        identityKnown = true)
}

/**
 * 首页的「MapleSU_Ultra 工作环境」状态：版本号与更新提示（一份状态，两套皮肤）。
 *
 * 事实全部在后台读（[UltraEnvironmentUpgrade.readFacts]），组合期只读 state。
 * 上一次的结果留在进程里，回到首页时首帧不闪。
 */
@Stable
class UltraEnvironmentUpdatePanel internal constructor(
    private val context: Context,
    private val scope: CoroutineScope,
) {
    private var observation = last?.takeIf { it.scope == UltraEnvironmentUpgrade.observationScope(context) }

    private var versionActivation = ModeRuntime.activation
    private var installedVersion by mutableStateOf(lastVersion
        ?.takeIf { it.first === versionActivation }?.second)

    /** The last actual SDK version is display data, independent of upgrade identity. */
    val version: String?
        get() = installedVersion.takeIf {
            ModeRuntime.active != WorkMode.KSU && versionActivation === ModeRuntime.activation &&
                UltraEnvironmentProbe.currentSnapshot().state != UltraEnvironmentProbe.State.NotInstalled
        }

    var busy by mutableStateOf(UltraEnvironmentUpgrade.inProgress)
        private set

    var checking by mutableStateOf(false)
        private set

    private var decided by mutableStateOf(observation?.upgrade ?: UltraEnvUpgrade.None)

    var readUnknown by mutableStateOf(true)
        private set

    /** 由首页按 §2.1 与切换事务给出；不允许时不提示更新、也不执行。 */
    internal var allowed by mutableStateOf(false)

    val upgrade: UltraEnvUpgrade
        get() = decided.let { decision ->
            if (observation?.scope != UltraEnvironmentUpgrade.observationScope(context)) return UltraEnvUpgrade.None
            // 「可升级」与「待确认（可重装）」都受首页裁决约束：不允许时一律不出现。
            if (!allowed && UltraEnvironmentUpgrade.upgradeAllowed(decision)) UltraEnvUpgrade.None else decision
        }

    private var reading: Job? = null
    private var upgrading: Job? = null
    private var foreground = false
    private var readGeneration = 0L
    private var latestFacts: UltraEnvFacts? = null
    private var operationRevision = UltraEnvironmentUpgrade.operationFlow.value.completedRevision

    internal fun environmentChanged() {
        if (ModeRuntime.active == WorkMode.KSU || versionActivation !== ModeRuntime.activation ||
            UltraEnvironmentProbe.currentSnapshot().state == UltraEnvironmentProbe.State.NotInstalled) {
            installedVersion = null
            lastVersion = null
            versionActivation = ModeRuntime.activation
        }
    }

    internal fun resume() { environmentChanged(); foreground = true; refresh() }

    internal fun operationChanged(operation: UltraEnvironmentUpgrade.OperationState) {
        val completed = operation.completedRevision != operationRevision
        if (operation.inProgress || completed) {
            readGeneration++
            readRequests.incrementAndGet()
            reading?.cancel()
            reading = null
        }
        if (completed) {
            observationRead.invalidate()
            latestFacts = null
            observation = null
            last = null
            decided = UltraEnvUpgrade.None
            readUnknown = true
        }
        operationRevision = operation.completedRevision
        busy = operation.inProgress || upgrading?.isActive == true
        if (!busy && foreground) refresh()
    }

    internal fun pause() {
        foreground = false
        readGeneration++
        reading?.cancel()
        reading = null
    }

    fun refresh() {
        environmentChanged()
        if (!foreground || checking || reading?.isActive == true || ModeRuntime.active == WorkMode.KSU) return
        busy = UltraEnvironmentUpgrade.inProgress || upgrading?.isActive == true
        if (busy) return
        val generation = ++readGeneration
        val request = readRequests.incrementAndGet()
        val activation = ModeRuntime.activation
        readUnknown = true
        reading = scope.launch {
            try {
                val (readVersion, facts) = readCurrentObservation()
                if (generation != readGeneration || request != readRequests.get() || !foreground ||
                    ModeRuntime.activation !== activation || ModeRuntime.active == WorkMode.KSU) return@launch
                environmentChanged()
                if (readVersion != null && UltraEnvironmentProbe.currentSnapshot().state != UltraEnvironmentProbe.State.NotInstalled) {
                    installedVersion = readVersion
                    lastVersion = activation to readVersion
                }
                if (facts != null) apply(facts) else readUnknown = true
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                readUnknown = true
                logReadFailure(error)
            }
        }
    }

    /** One bounded, shared read; lifecycle and operation events request subsequent observations. */
    private suspend fun readCurrentObservation(): Pair<String?, UltraEnvFacts?> =
        observationRead.read(ModeRuntime.activation to UltraEnvironmentUpgrade.observationScope(context)) {
            if (ModeRuntime.active == WorkMode.LITE) {
                val facts = UltraEnvironmentUpgrade.readFacts(context)
                facts.installedVersion to facts
            } else {
                readInstalledVersion() to null
            }
        }

    private fun logReadFailure(error: Exception) {
        android.util.Log.w("MapleSUUltraEnvironment", dev.maplesu.manager.runtime.ultra.UltraSdkLogging.redact(
            "environment observation failed: ${error.javaClass.simpleName}: ${error.message}"))
    }

    private fun readInstalledVersion(): String? {
        if (UltraEnvironmentProbe.currentSnapshot().state == UltraEnvironmentProbe.State.NotInstalled) return null
        return try {
            val base = UltraRuntimeClient()
            val legacy = if (UltraEnvironmentProbe.currentSnapshot().managerOwnerIdentity == null)
                UltraLegacyCredential.read(context) else null
            val client = if (legacy == null) base else base.withLegacyCredential(legacy)
            client.installedEnvironmentVersion().takeIf { it.succeeded }?.string("version")
                ?.let(UltraEnvironmentVersion::displayOf)
        } catch (error: Exception) {
            if (error is CancellationException) throw error
            null
        }
    }

    /** A manual check reads current facts before offering the existing upgrade confirmation. */
    fun checkForUpgrade(onChecked: (UltraEnvUpgrade) -> Unit) {
        if (!foreground || busy || UltraEnvironmentUpgrade.inProgress || checking || !allowed || ModeRuntime.active != WorkMode.LITE) return
        reading?.cancel()
        val generation = ++readGeneration
        val request = readRequests.incrementAndGet()
        val activation = ModeRuntime.activation
        checking = true
        readUnknown = true
        reading = scope.launch {
            try {
                val facts = try {
                    readCurrentObservation().second
                } catch (error: Exception) {
                    if (error is CancellationException) throw error
                    logReadFailure(error)
                    null
                }
                if (generation != readGeneration || request != readRequests.get() || !foreground ||
                    ModeRuntime.activation !== activation || ModeRuntime.active != WorkMode.LITE || !allowed) return@launch
                if (facts != null) apply(facts)
                val current = upgrade
                if (facts == null || facts.readUnknown || readUnknown) {
                    toast(R.string.ultra_env_update_check_failed)
                    return@launch
                }
                if (current is UltraEnvUpgrade.None) toast(R.string.ultra_env_update_check_none)
                onChecked(current)
            } finally {
                checking = false
            }
        }
    }

    internal fun readbackCompleted() {
        if (!foreground || busy || checking || readUnknown || reading?.isActive == true) return
        val facts = mergeCompletedReadback(latestFacts, UltraEnvironmentUpgrade.observationScope(context),
            UltraInstalledIdentityProbe.completedReadback(context)) ?: return
        apply(facts)
    }

    fun startUpgrade() {
        // Available（同版本新构建）与 Unverified（身份读不到 → 重装写身份）都能点；
        // 真正写不写由 UltraEnvironmentUpgrade 再核一次事实，这里只是入口。
        if (busy || !allowed) return
        reading?.cancel()
        reading = null
        readGeneration++
        readRequests.incrementAndGet()
        observation = null
        latestFacts = null
        last = null
        readUnknown = true
        busy = true
        upgrading = scope.launch {
            try {
                // 离开首页也要让结果落地：标记的撤回必须执行完。
                val result = withContext(Dispatchers.IO + NonCancellable) {
                    runCatching { UltraEnvironmentUpgrade.installBundled(context) }
                        .getOrDefault(UltraEnvironmentUpgrade.Result.FAILED)
                }
                when (result) {
                    UltraEnvironmentUpgrade.Result.SUBMITTED -> Unit
                    UltraEnvironmentUpgrade.Result.FAILED -> {
                        val reason = UltraEnvironmentUpgrade.persistedFailure(context)
                        if (!reason.isNullOrBlank()) android.util.Log.w("MapleSUUltraEnvironment",
                            dev.maplesu.manager.runtime.ultra.UltraSdkLogging.redact("upgrade failed: $reason"))
                        toast(R.string.ultra_env_update_failed)
                    }
                    UltraEnvironmentUpgrade.Result.REFUSED -> toast(R.string.ultra_env_update_refused)
                }
            } finally {
                busy = false
                upgrading = null
                operationChanged(UltraEnvironmentUpgrade.operationFlow.value)
            }
        }
    }

    private fun apply(facts: UltraEnvFacts) {
        val currentScope = UltraEnvironmentUpgrade.observationScope(context)
        // A later completed identity must survive an older full-facts worker finishing.
        val current = mergeCompletedReadback(facts, currentScope,
            UltraInstalledIdentityProbe.completedReadback(context)) ?: facts
        latestFacts = current.takeIf { currentScope != null && it.observationScope == currentScope }
        observation = UltraEnvObservation.observe(observation, current, currentScope)
        decided = observation?.upgrade ?: UltraEnvUpgrade.None
        readUnknown = observation?.readUnknown ?: true
        last = observation
    }

    private fun toast(@StringRes res: Int) {
        Toast.makeText(context, context.getString(res), Toast.LENGTH_SHORT).show()
    }

    private companion object {
        val observationRead = BoundedPageRead<Pair<String?, UltraEnvFacts?>>(10_000L)
        val readRequests = AtomicLong()
        @Volatile
        var last: UltraEnvObservation? = null
        @Volatile
        var lastVersion: Pair<ModeActivation, String>? = null
    }
}

/**
 * @param visible 首页按 §2.1 的裁决（Ultra、已安装、未隐藏/隐身/确认中）；false 时不读任何事实
 * @param upgradeAllowed 没有未收尾的模式切换
 */
@Composable
fun rememberUltraEnvironmentPanel(
    visible: Boolean,
    upgradeAllowed: Boolean,
    foreground: Boolean,
): UltraEnvironmentUpdatePanel {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val panel = remember { UltraEnvironmentUpdatePanel(context, scope) }
    val detectionRevision by ModeRuntime.detectionRevision.collectAsStateWithLifecycle()
    val rootAvailable by UltraEnvironmentProbe.rootAvailability.collectAsStateWithLifecycle(initialValue = false)
    val environment by UltraEnvironmentProbe.observations.collectAsStateWithLifecycle(
        initialValue = UltraEnvironmentProbe.currentSnapshot())
    val identityRevision by UltraInstalledIdentityProbe.readbackRevision.collectAsStateWithLifecycle()
    val upgradeOperation by UltraEnvironmentUpgrade.operationFlow.collectAsStateWithLifecycle()
    SideEffect { panel.allowed = visible && upgradeAllowed }
    // The Ultra brand may already be visible from saved local facts before the
    // live mode is active. Re-read when detection settles, without requiring a tab change.
    LifecycleResumeEffect(visible, foreground, Pair(detectionRevision, rootAvailable)) {
        if (visible && foreground) panel.resume()
        onPauseOrDispose { panel.pause() }
    }
    LaunchedEffect(panel, detectionRevision, environment.state) { panel.environmentChanged() }
    LaunchedEffect(panel, identityRevision) { panel.readbackCompleted() }
    LaunchedEffect(panel, upgradeOperation) { panel.operationChanged(upgradeOperation) }
    return panel
}

/** 环境版本的统一写法：`MapleSU_Ultra 5.0.5`；还没读到版本时只写名字。 */
@Composable
fun ultraEnvironmentLabel(version: String?): String {
    val name = stringResource(R.string.work_mode_lite)
    return if (version.isNullOrBlank()) name else "$name $version"
}

/** 更新卡的一行字：可升级 / 升级中 / 待重启 / 待确认。 */
@Composable
internal fun ultraUpdateMessage(upgrade: UltraEnvUpgrade?, busy: Boolean): String = when (upgrade) {
    is UltraEnvUpgrade.Available -> if (busy) {
        stringResource(R.string.ultra_env_update_busy, ultraEnvironmentLabel(upgrade.to))
    } else if (upgrade.isBuildUpdate) {
        stringResource(R.string.ultra_env_build_update_available, ultraEnvironmentLabel(upgrade.to))
    } else {
        stringResource(
            R.string.ultra_env_update_available_from_to,
            ultraEnvironmentLabel(upgrade.from),
            ultraEnvironmentLabel(upgrade.to),
        )
    }

    is UltraEnvUpgrade.Rebooting -> stringResource(
        if (busy) R.string.ultra_env_update_busy else R.string.ultra_env_update_rebooting,
        ultraEnvironmentLabel(upgrade.to),
    )

    // 身份读不到：不说已是最新，但给一条能走出来的路——重装即写入可验证身份。
    is UltraEnvUpgrade.Unverified -> stringResource(
        if (busy) R.string.ultra_env_update_busy else R.string.ultra_env_update_unverified,
        ultraEnvironmentLabel(upgrade.to),
    )

    else -> if (busy) stringResource(R.string.ultra_env_update_busy, ultraEnvironmentLabel(null)) else ""
}

/**
 * 确认框正文。可升级 → from→to；待确认 → 明说「重装以写入可验证身份」。
 * 其它状态（None/Rebooting）返回 null（卡片不可点）。
 */
@Composable
internal fun ultraUpdateConfirmMessage(upgrade: UltraEnvUpgrade?): String? = when (upgrade) {
    is UltraEnvUpgrade.Available -> if (upgrade.isBuildUpdate) {
        stringResource(R.string.ultra_env_build_update_confirm, ultraEnvironmentLabel(upgrade.to))
    } else {
        stringResource(R.string.ultra_env_update_confirm_message,
            ultraEnvironmentLabel(upgrade.from), ultraEnvironmentLabel(upgrade.to))
    }

    is UltraEnvUpgrade.Unverified -> stringResource(
        R.string.ultra_env_update_unverified_confirm,
        ultraEnvironmentLabel(upgrade.to),
    )

    else -> null
}
