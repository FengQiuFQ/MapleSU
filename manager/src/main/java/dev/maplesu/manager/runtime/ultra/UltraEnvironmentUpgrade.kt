// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.os.Looper
import android.util.Log
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.ui.WorkModeSwitchSession
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.CancellationException
import java.security.MessageDigest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 「MapleSU_Ultra 工作环境」升级：读事实、执行升级。
 *
 * 升级 = 在运行中的环境上再安装一次（上游参考管理器给出的升级方式也是"重新安装环境"）：
 *  - SDK 环境走唯一安装入口 [UltraEnvironmentInstaller]，**并且显式声明**
 *    [UltraEnvironmentInstaller.Intent.UpgradeToBundledBuild]：Running 不是跳过安装的理由，
 *    否则「同一个上游版本的新构建」永远提交不下去（5.0.5 修复的正是这个短路）；
 *  - 安装身份回读与授权同步照常执行；
 *  - **绝不先卸载**：卸载会清空授权列表并删除已安装的模块；
 *  - Boot 模式安装成功后设备会在几秒内自动重启，所以只能由用户确认后触发，从不自动执行；
 *  - 写之前在后台把事实重新核对一遍，过期的卡片不能写设备；
 *  - 旧载体先走现有认证 Root 镜像安装事务，提交前核验本次激活引用、boot 与生命周期；
 *  - 每次开机最多提交一次：先落标记；明确未提交或已取消时撤回，结果不确定时等待重启核对；
 *  - 安装回执成功还不够：必须回读到「设备上就是随包这一版」才算 SUBMITTED，回读失败或
 *    摘要不符一律 FAILED（失败原因留在 [lastFailureReason]，UI 可以显示）。
 *
 * SDK 环境显式修复走相同提交链路；Unknown 另需初始化收据过期或空闲未启动的只读证据。
 * 未决模式仅显式动作可用认证 Root 证明旧载体并更新；Normal 下不读 Lite。
 * 全部阻塞，必须在后台线程调用。
 */
object UltraEnvironmentUpgrade {

    private const val TAG = "MapleSUUltraUpgrade"
    private const val PREFS = "ultra-env-upgrade"
    private const val KEY_SUBMITTED_BOOT = "submittedBootId"
    private const val KEY_FULL_INSTALL_BOOT = "fullInstallCarrierBoot"
    private const val KEY_FULL_INSTALL_ENV_BOOT = "fullInstallEnvironmentBoot"

    enum class Result { SUBMITTED, FAILED, REFUSED }

    private val running = AtomicBoolean(false)
    internal data class OperationState(val inProgress: Boolean = false, val completedRevision: Long = 0L)
    private val _operation = MutableStateFlow(OperationState())
    internal val operationFlow = _operation.asStateFlow()
    private val installedKernel = UltraInstalledKernelObservation()
    val installedKernelRevision = installedKernel.revisions

    /** Local identity only: no SDK probe, credential migration, root command or writes. */
    fun observationScope(context: Context): String? = runCatching {
        if (ModeRuntime.active != WorkMode.LITE || UltraRootKeyStore.isSuspended(context) ||
            LiteImplantQuiesceGate.isBlocked() || WorkModeSwitchSession.executing) return null
        val owner = UltraEnvironmentProbe.currentSnapshot().managerOwnerIdentity
        val legacy = if (owner == null) UltraLegacyCredential.read(
            context.getSharedPreferences("maplesu-ultra", Context.MODE_PRIVATE)) else null
        val credential = observationIdentity(owner, legacy?.fingerprint) ?: return null
        val boot = UltraEnvironmentAutoSetup.currentBootId() ?: return null
        val submitted = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
            .all[KEY_SUBMITTED_BOOT] == boot || UltraIdleEnvironmentRecovery.submittedThisBoot(context)
        val identity = listOf(credential, boot, ModeRuntime.activation.toString(), UltraSdkBuild.BUILD_ID,
            UltraSdkBuild.HELPER_SHA256, UltraSdkBuild.APP_VERSION, submitted.toString(), installedKernel.revision.toString())
            .joinToString(":") { "${it.length}:$it" }
        MessageDigest.getInstance("SHA-256").digest(identity.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }.getOrNull()

    internal fun observationIdentity(owner: UltraRuntimeClient.ManagerOwnerIdentity?, legacyFingerprint: String? = null): String? =
        owner?.let { "owner:${it.fullUid}:${it.epoch}:${it.hostInstance}" }
            ?: legacyFingerprint?.let { "legacy:$it" }

    private class CapturedIdentity(val client: UltraRuntimeClient,
                                   val owner: UltraRuntimeClient.ManagerOwnerIdentity?,
                                   val ownerReceipt: NativeReceipt,
                                   val current: () -> Boolean,
                                   val confirmed: () -> Boolean)

    /** One identity owns the fact reads and install; a known Owner never falls back to Legacy. */
    private fun captureIdentity(context: Context, fullInstall: Boolean = false): CapturedIdentity {
        val marker = UltraSdkCredentials.captureOwnerMarker(context)
        val knownOwner = UltraEnvironmentProbe.currentSnapshot().managerOwnerIdentity
        val base = UltraRuntimeClient().scoped(marker)
        val observed = base.queryManagerOwnerIdentity()
        val owner = observed.identity
        val legacy = if (owner == null && knownOwner == null) UltraLegacyCredential.read(context) else null
        fun current() = marker() &&
            (ModeRuntime.active == WorkMode.LITE || fullInstall && ModeRuntime.active == null) &&
            !LiteImplantQuiesceGate.isBlocked() && !WorkModeSwitchSession.executing &&
            if (owner != null) owner == knownOwner || fullInstall && knownOwner == null
            else knownOwner == null && legacy?.isCurrent(context) == true
        val client = (if (legacy == null) base else base.withLegacyCredential(legacy)).scoped(::current)
        return CapturedIdentity(client, owner, observed.receipt, ::current, {
            current() && base.queryManagerOwnerIdentity().identity == owner && current()
        })
    }

    internal fun invalidateObservation() = installedKernel.invalidate()

    /** Only a visible user check opens the existing authenticated partition reader. */
    internal fun checkInstalledKernel(context: Context): Boolean {
        requireBackground()
        val app = context.applicationContext
        val activation = ModeRuntime.activation
        val boot = UltraEnvironmentAutoSetup.currentBootId() ?: return false
        val revision = installedKernel.revision
        val ownerCurrent = UltraSdkCredentials.captureOwnerMarker(app)
        fun current() = revision == installedKernel.revision && ownerCurrent() &&
            kernelUpdateScopeFailure(activation, ModeRuntime.activation, boot,
                UltraEnvironmentAutoSetup.currentBootId(),
                dev.maplesu.manager.runtime.HookRootExecutor.production(app).available(),
                LiteImplantQuiesceGate.isBlocked(), WorkModeSwitchSession.executing,
                UltraRootKeyStore.isSuspended(app)) == null
        if (!current()) return false
        val carrier = dev.maplesu.manager.installer.UltraKernelEnvironmentUpgrade.observeInstalled(app)
        if (carrier == null) {
            if (current()) installedKernel.discard(revision)
            return false
        }
        if (carrier.bootId != boot) return false
        return installedKernel.publish(revision, carrier, ::current)
    }

    /** Installed bytes are separate from a current SDK owner, Root, or module capability. */
    internal fun installedKernelKnown(context: Context): Boolean = currentInstalledKernel(context) != null

    internal fun installedKernelUpdateRequired(context: Context): Boolean =
        currentInstalledKernel(context)?.updateRequired == true

    private fun currentInstalledKernel(context: Context): dev.maplesu.manager.installer.InstalledUltraCarrier? =
        installedKernel.current()?.takeUnless { UltraRootKeyStore.isSuspended(context) }

    /** 进程内是否有升级正在执行（界面重建时据此恢复"升级中"）。 */
    val inProgress: Boolean get() = running.get()

    /** 上一次升级失败的原因（机器码 + 一段说明）；成功后清空。UI 用它解释 FAILED。 */
    @Volatile
    var lastFailureReason: String? = null
        private set

    /** Publish the installed version before the slower identity read; upgrade decisions still use all facts. */
    @JvmOverloads
    fun readFacts(context: Context, onInstalledVersion: (String?) -> Unit = {}): UltraEnvFacts =
        readObservation(context, onInstalledVersion).first

    private fun readObservation(context: Context, onInstalledVersion: (String?) -> Unit,
                                captured: CapturedIdentity? = null): Pair<UltraEnvFacts, InstalledIdentity?> {
        requireBackground()
        if (ModeRuntime.active != WorkMode.LITE) return UltraEnvFacts() to null
        val app = context.applicationContext
        runCatchingCancellable { UltraEnvironmentProbe.refresh(app, force = false) }
        val binding = captured ?: captureIdentity(app)
        val scope = observationScope(app)
        val client = binding.client
        // A concurrent refresh may return the cached snapshot. These facts use this identity's receipt.
        val stateReceipt = runCatchingCancellable { client.environmentState() }.getOrNull()
        val state = when (stateReceipt?.takeIf { it.succeeded }?.string("state")) {
            "Running" -> UltraEnvironmentProbe.State.Running
            "NotInstalled" -> UltraEnvironmentProbe.State.NotInstalled
            "Fault" -> UltraEnvironmentProbe.State.Fault
            else -> UltraEnvironmentProbe.State.Unknown
        }
        val installedReceipt = runCatchingCancellable { client.installedEnvironmentVersion() }.getOrNull()
        val installedVersion = versionOf(installedReceipt)
        onInstalledVersion(installedVersion)
        // 身份回读失败不是致命错误：Unknown 照样进 facts，由策略判「待确认」，不猜。
        val identity = runCatchingCancellable { UltraInstalledIdentityProbe.read(app, client) }
            .onFailure { Log.w(TAG, "identity read failed ${it.javaClass.simpleName}") }
            .getOrElse { InstalledIdentity.unknown() }
            .takeIf { it.source == Source.Readback }
        val bundledReceipt = runCatchingCancellable { client.sdkVersion() }.getOrNull()
        val versions = versionFacts(state.name, installedReceipt, bundledReceipt,
            kernelRootVerified = UltraEnvironmentProbe.isKernelRootVerified(app))
        val facts = versions.copy(
            running = state == UltraEnvironmentProbe.State.Running,
            // 读不到暂停标记时按"已暂停"处理：宁可不提示，也不在不确定时写环境。
            suspended = runCatching { UltraRootKeyStore.isSuspended(app) }.getOrDefault(true),
            quiescing = LiteImplantQuiesceGate.isBlocked() || WorkModeSwitchSession.executing,
            submittedThisBoot = submittedThisBoot(app),
            installedBuildId = identity?.buildId,
            bundledBuildId = UltraInstalledIdentityProbe.bundledBuildId(),
            installedHelperSha256 = identity?.helperSha256,
            bundledHelperSha256 = UltraInstalledIdentityProbe.bundledHelperSha256(),
            // 真实设备上身份是判定的一部分：缺哪一侧就报「待确认」，不会静默 None。
            identityKnown = true,
            installedAppVersion = UltraInstalledIdentityProbe.persistedAppVersion(app),
            bundledAppVersion = UltraSdkBuild.APP_VERSION,
            observationScope = scope,
            freshKernelInstall = versions.freshKernelInstall && identity?.known != true,
        )
        val checked = if (scope != null && scope == observationScope(app) && binding.confirmed()) facts
            else facts.copy(quiescing = true, readUnknown = true, observationScope = null)
        return checked to identity
    }

    fun upgrade(context: Context): Result = submit(context, repairFault = false)

    /** Explicit recovery shares the upgrade marker, preparation and readback. */
    fun repairEnvironment(context: Context): Result = submit(context, repairFault = true)

    /** Explicit full installation is independent of the update card and historical metadata. */
    fun installBundled(context: Context): Result = submit(context, repairFault = false, fullInstall = true)

    /** Resume only the user's selected operation; a lost reply never replays a submitted install. */
    internal fun resumeFullInstall(context: Context): Result? {
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        val boot = UltraEnvironmentAutoSetup.currentBootId() ?: return null
        val saved = prefs.all
        if (failedPreparationThisBoot(saved, boot) != null) return null
        val carrierBoot = saved[KEY_FULL_INSTALL_BOOT]
        val environmentBoot = saved[KEY_FULL_INSTALL_ENV_BOOT]
        return when (fullInstallContinuation(carrierBoot, environmentBoot, boot)) {
            "NONE", "WAIT" -> null
            "INSTALL" -> if (UltraRuntimeClient().queryManagerOwnerIdentity().identity != null)
                installBundled(context) else Result.FAILED
            else -> verifyCompletedFullInstall(context)
        }
    }

    /** A known pre-submission error waits for another explicit action, not another startup pass. */
    internal fun failedPreparationThisBoot(context: Context): String? {
        val boot = UltraEnvironmentAutoSetup.currentBootId() ?: return null
        return failedPreparationThisBoot(context.ultraPreferences(PREFS, Context.MODE_PRIVATE).all, boot)
    }

    internal fun failedPreparationThisBoot(saved: Map<String, *>, boot: String): String? =
        (saved["lastFailure"] as? String)?.takeIf {
            saved["lastBoot"] == boot && saved["lastPhase"] == "install" && isPreparationFailure(it)
        }

    internal fun isPreparationFailure(reason: String): Boolean =
        reason == "SDK:POLICY_BACKEND_PREPARATION_FAILED" ||
            reason.startsWith("SDK:POLICY_BACKEND_PREPARATION_FAILED:")

    internal fun fullInstallContinuation(carrierBoot: Any?, environmentBoot: Any?, boot: String): String {
        val carrier = (carrierBoot as? String)?.takeIf(String::isNotBlank)
        val environment = (environmentBoot as? String)?.takeIf(String::isNotBlank)
        return when {
            environment == boot || carrier == boot -> "WAIT"
            environment != null -> "VERIFY"
            carrier != null -> "INSTALL"
            else -> "NONE"
        }
    }

    internal fun fullInstallPendingThisBoot(context: Context): Boolean {
        val boot = UltraEnvironmentAutoSetup.currentBootId() ?: return false
        val saved = context.ultraPreferences(PREFS, Context.MODE_PRIVATE).all
        return listOf(KEY_SUBMITTED_BOOT, KEY_FULL_INSTALL_BOOT, KEY_FULL_INSTALL_ENV_BOOT)
            .any { saved[it] == boot }
    }

    /** Post-reboot observation completes a prior submission, without another install/reboot. */
    private fun verifyCompletedFullInstall(context: Context): Result = runCatchingCancellable {
        val owner = UltraRuntimeClient().queryManagerOwnerIdentity().identity
            ?: return Result.FAILED
        UltraEnvironmentProbe.refresh(context, force = true)
        val marker = UltraSdkCredentials.captureOwnerMarker(context)
        val client = UltraSdkCredentials.client(context)
        fun current() = marker() && client.queryManagerOwnerIdentity().identity == owner
        val observation = UltraInstalledIdentityProbe.readAndVerify(context, client)
        if (!observation.verification.verified || !current()) return Result.FAILED
        val scope = UltraAuthorization.Scope(client, ::current, ::current)
        val initialized = dev.maplesu.manager.runtime.authorization.SuperuserControl
            .initializeForInstallationIfAbsent(context, scope)
        if (!initialized.succeeded || !current()) return Result.FAILED
        val migrated = dev.maplesu.manager.runtime.authorization.SuperuserControl.migrate(context, scope)
        if (!migrated.succeeded || !current()) return Result.FAILED
        if (!UltraSelfWhitelist.onEnvironmentInstalled(context, client, ::current).succeeded || !current())
            return Result.FAILED
        val modules = client.moduleList()
        if (!modules.succeeded || modules.array("modules") == null || !current()) return Result.FAILED
        if (UltraSuChannel().rootUid() != 0 || !current()) return Result.FAILED
        if (!UltraInstalledIdentityProbe.persist(context, observation.identity)) return Result.FAILED
        finishFullInstall(context)
        recordStatus(context, "verified")
        Result.SUBMITTED
    }.getOrElse { error ->
        recordStatus(context, "verify", "SDK_UPGRADE_PENDING:${error.javaClass.simpleName}")
        Result.FAILED
    }

    private fun finishFullInstall(context: Context) {
        UltraRootKeyStore.clearLegacy(context)
        check(context.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .remove(KEY_FULL_INSTALL_BOOT).remove(KEY_FULL_INSTALL_ENV_BOOT).commit()) {
            "SDK_UPGRADE_CONTINUATION_STORE_FAILED"
        }
        UltraEnvironmentProbe.invalidateAvailability()
    }

    @Synchronized
    private fun submit(context: Context, repairFault: Boolean, fullInstall: Boolean = false): Result {
        try {
            requireBackground()
        } catch (error: IllegalStateException) {
            notePreflightRefusal("preflight", "PREFLIGHT_BACKGROUND_REQUIRED")
            throw error
        }
        if (!running.compareAndSet(false, true)) {
            // A concurrent request must not overwrite the active operation's status.
            notePreflightRefusal("preflight", "PREFLIGHT_IN_PROGRESS")
            return Result.REFUSED
        }
        _operation.value = _operation.value.copy(inProgress = true)
        invalidateObservation()
        val app = context.applicationContext
        var phase = "preflight"
        try {
            recordStatus(app, phase)
            val installActivation = ModeRuntime.activation
            val installMode = (installActivation as? ModeActivation.Active)?.mode
            if (installMode != null && installMode != WorkMode.LITE)
                return preflightRefused(app, phase, "PREFLIGHT_MODE_NOT_LITE")
            if (!fullInstall && dev.maplesu.manager.runtime.HookRootExecutor.production(app).available())
                return preflightRefused(app, phase, "PREFLIGHT_HOOK_ACTIVE")
            if (LiteImplantQuiesceGate.isBlocked())
                return preflightRefused(app, phase, "PREFLIGHT_QUIESCING")
            if (WorkModeSwitchSession.executing)
                return preflightRefused(app, phase, "PREFLIGHT_SWITCH_PENDING")
            if (fullInstall) UltraRootKeyStore.allowEnvironmentInstall(app)
            if (UltraRootKeyStore.isSuspended(app))
                return preflightRefused(app, phase, "PREFLIGHT_SUSPENDED")
            if (submittedThisBoot(app))
                return preflightRefused(app, phase, "PREFLIGHT_SUBMITTED_THIS_BOOT")
            val installBoot = UltraEnvironmentAutoSetup.currentBootId()
                ?: return preflightRefused(app, phase, "PREFLIGHT_BOOT_UNAVAILABLE")
            // A newer helper cannot repair a retired executor retained in boot. Check only
            // this explicit action, before another SDK call can execute through that kernel.
            if (fullInstall) {
                // The installed protocol selects the implementation, never access to installation.
                // Missing old versions, paths and receipts do not prevent replacing the carrier.
                if (dev.maplesu.manager.runtime.HookRootExecutor.production(app).available()) {
                    UltraSdkSession.bootstrap(app, installBoot)
                    UltraSdkSession.current(app)?.let { UltraSdkSession.ensure(app, it) { true } }
                }
                UltraEnvironmentProbe.refresh(app, force = true)
                if (UltraRuntimeClient().queryManagerOwnerIdentity().identity == null) {
                    check(app.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
                        .putString(KEY_FULL_INSTALL_BOOT, installBoot).commit()) { "SDK_UPGRADE_CONTINUATION_STORE_FAILED" }
                    phase = "kernel"
                    val result = submitKernelUpdate(app, installActivation, installBoot)
                    if (result != Result.SUBMITTED && !submittedThisBoot(app))
                        app.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY_FULL_INSTALL_BOOT).commit()
                    return result
                }
            }
            if (!fullInstall && installMode == null) {
                val refusal = unresolvedKernelPreflight(installMode, carrier = {
                    val observed = dev.maplesu.manager.installer.InstallerServiceClient.observeBootChain(app)
                    dev.maplesu.manager.installer.InstallerServiceClient.installedCarrierPartition(app, observed)
                }, required = {
                    dev.maplesu.manager.installer.UltraKernelEnvironmentUpgrade.required(app)
                })
                if (refusal != null) return preflightRefused(app, phase, refusal)
                phase = "kernel"
                return submitKernelUpdate(app, installActivation, installBoot)
            }
            if (!fullInstall && dev.maplesu.manager.installer.UltraKernelEnvironmentUpgrade.required(app)) {
                phase = "kernel"
                return submitKernelUpdate(app, installActivation, installBoot)
            }
            val binding = captureIdentity(app, fullInstall = fullInstall)
            val client = binding.client
            val installOwner = binding.owner
            if (!binding.current()) return preflightRefused(app, phase,
                "PREFLIGHT_OWNER_UNCONFIRMED:${binding.ownerReceipt.sdkError}:${binding.ownerReceipt.sdkErrorCode}")
            UltraInstalledIdentityProbe.invalidate()
            // Available（同版本新构建）与 Unverified（身份读不到，重装写身份）都允许提交；
            // quiescing / 暂停 / 未运行 / 管理器降级 一律拒绝，不产生任何写调用。
            if (!fullInstall && repairFault) {
                val state = UltraEnvironmentProbe.refresh(app, force = true)
                if (state != UltraEnvironmentProbe.State.Fault && state != UltraEnvironmentProbe.State.Unknown &&
                    state != UltraEnvironmentProbe.State.NotInstalled) {
                    recordStatus(app, phase, "REPAIR_STATE_${state.name}")
                    return Result.REFUSED
                }
                val (facts, identity) = readObservation(app, {}, binding)
                // Version/identity reads already used the captured installation identity. A diagnostic
                // kernel EXEC test is not an installation prerequisite; the installer owns
                // the actual operation and returns its failure without changing the state.
                val completedBoot = state == UltraEnvironmentProbe.State.Unknown &&
                    completedBootRepairEvidence(app, client)
                if (!faultRepairAllowed(state.name, facts, completedBoot,
                        identity, UltraInstalledIdentityProbe.installedHelperPath()
                            ?: identity?.helperPath?.takeIf { installOwner != null }, installBoot,
                        kernelRootVerified = UltraEnvironmentProbe.isKernelRootVerified(app))) {
                    val reason = "REPAIR_FACTS_STATE_${state.name}:running=${facts.running}" +
                        ";suspended=${facts.suspended};quiescing=${facts.quiescing}" +
                        ";submitted=${facts.submittedThisBoot};completedBoot=$completedBoot" +
                        ";installedVersion=${facts.installedVersion};bundledVersion=${facts.bundledVersion}" +
                        ";helperMatch=${facts.installedHelperSha256 != null && facts.installedHelperSha256 == facts.bundledHelperSha256}" +
                        ";installedApp=${facts.installedAppVersion};bundledApp=${facts.bundledAppVersion}"
                    recordStatus(app, phase, reason)
                    Log.w(TAG, reason)
                    return Result.REFUSED
                }
            } else if (!fullInstall && !upgradeAllowed(UltraEnvUpgradePolicy.decide(readObservation(app, {}, binding).first))) {
                return Result.REFUSED
            }
            // Fact reads can take time; do not submit if a switch/pause started meanwhile.
            if ((ModeRuntime.active != WorkMode.LITE && !(fullInstall && ModeRuntime.active == null)) ||
                ModeRuntime.activation !== installActivation || LiteImplantQuiesceGate.isBlocked() || WorkModeSwitchSession.executing || UltraRootKeyStore.isSuspended(app) ||
                UltraEnvironmentAutoSetup.currentBootId() != installBoot || !binding.confirmed()) {
                if (repairFault) recordStatus(app, phase, "REPAIR_SCOPE_CHANGED")
                return Result.REFUSED
            }
            val bootId = installBoot
            val prefs = app.ultraPreferences(PREFS, Context.MODE_PRIVATE)
            // 标记先于安装落盘：安装途中进程被杀，本次开机也不会再提交第二次。
            if (!prefs.edit().putString(KEY_SUBMITTED_BOOT, bootId).commit())
                return preflightRefused(app, phase, "PREFLIGHT_MARKER_COMMIT_FAILED")
            if (fullInstall) check(prefs.edit().putString(KEY_FULL_INSTALL_ENV_BOOT, bootId).commit()) {
                "SDK_UPGRADE_CONTINUATION_STORE_FAILED"
            }
            phase = "install"
            recordStatus(app, phase)
            val outcome = submitMarked(install = {
                UltraEnvironmentInstaller.install(
                    app,
                    client = client,
                    // This user-confirmed action promises activation, not a file-only refresh.
                    intent = UltraEnvironmentInstaller.Intent.UpgradeToBundledBuild,
                )
            }, clear = {
                val editor = prefs.edit().remove(KEY_SUBMITTED_BOOT)
                if (fullInstall) editor.remove(KEY_FULL_INSTALL_ENV_BOOT)
                editor.commit()
            })
            if (resultOf(outcome) != Result.SUBMITTED) {
                phase = if (outcome?.ok == true) "verify" else "install"
                val reason = diagnosticReasonOf(outcome)
                recordStatus(app, phase, reason)
                Log.w(TAG, "upgrade failed phase=$phase reason=$reason")
                return Result.FAILED
            }
            // Retire the local legacy secret only after the new installation and grants work.
            if (fullInstall) finishFullInstall(app)
            // Activation and uncertain writes retain the marker until a real new boot.
            recordStatus(app, "verified")
            Log.i(TAG, "upgrade submitted build=${outcome?.buildId}")
            return Result.SUBMITTED
        } catch (error: Exception) {
            rethrowCancellation(error)
            recordStatus(app, phase, "EXCEPTION:" + generateSequence(error as Throwable) { it.cause }
                .take(4).joinToString(" <- ") { it.toString() })
            return Result.FAILED
        } finally {
            running.set(false)
            // The revision survives StateFlow conflation of a short true/false operation.
            _operation.value = OperationState(completedRevision = _operation.value.completedRevision + 1)
        }
    }

    /** Diagnostics only: no new credential, SDK, Root or boot-id reads. */
    private fun preflightRefused(context: Context, phase: String, reason: String): Result {
        val diagnostic = diagnosticText(reason)
        lastFailureReason = diagnostic
        // Diagnostic storage failure must not change the original refusal result.
        runCatching {
            context.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("lastPhase", phase).putString("lastFailure", diagnostic).commit()
        }
        notePreflightRefusal(phase, diagnostic)
        return Result.REFUSED
    }

    private fun notePreflightRefusal(phase: String, reason: String) {
        runCatching { Log.w(TAG, "upgrade refused phase=$phase reason=$reason") }
    }

    /** Root/read failures propagate; an unproven carrier is never a fresh-install fallback. */
    internal fun unresolvedKernelPreflight(mode: WorkMode?, carrier: () -> String?, required: () -> Boolean): String? {
        if (mode != null) return "PREFLIGHT_MODE_NOT_UNRESOLVED"
        if (carrier() == null) return "PREFLIGHT_ULTRA_CARRIER_UNPROVEN"
        if (!required()) return "PREFLIGHT_KERNEL_CURRENT_OWNER_UNCONFIRMED"
        return null
    }

    internal fun kernelUpdateScopeFailure(expectedActivation: ModeActivation, activation: ModeActivation,
                                         expectedBoot: String, boot: String?, hookActive: Boolean,
                                         quiescing: Boolean, switching: Boolean, suspended: Boolean): String? = when {
        activation !== expectedActivation -> "KERNEL_PREFLIGHT_ACTIVATION_CHANGED"
        (activation as? ModeActivation.Active)?.mode?.let { it != WorkMode.LITE } == true -> "KERNEL_PREFLIGHT_MODE_NOT_LITE"
        boot == null -> "KERNEL_PREFLIGHT_BOOT_UNAVAILABLE"
        boot != expectedBoot -> "KERNEL_PREFLIGHT_BOOT_CHANGED"
        hookActive -> "KERNEL_PREFLIGHT_HOOK_ACTIVE"
        quiescing -> "KERNEL_PREFLIGHT_QUIESCING"
        switching -> "KERNEL_PREFLIGHT_SWITCH_PENDING"
        suspended -> "KERNEL_PREFLIGHT_SUSPENDED"
        else -> null
    }

    private fun submitKernelUpdate(context: Context, activation: ModeActivation, bootId: String): Result {
        fun scopeFailure(): String? = kernelUpdateScopeFailure(activation, ModeRuntime.activation,
            bootId, UltraEnvironmentAutoSetup.currentBootId(),
            dev.maplesu.manager.runtime.HookRootExecutor.production(context).available(),
            LiteImplantQuiesceGate.isBlocked(), WorkModeSwitchSession.executing, UltraRootKeyStore.isSuspended(context))
        scopeFailure()?.let { return preflightRefused(context, "kernel", it) }
        if (submittedThisBoot(context))
            return preflightRefused(context, "kernel", "KERNEL_PREFLIGHT_SUBMITTED_THIS_BOOT")
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.edit().putString(KEY_SUBMITTED_BOOT, bootId).commit())
            return preflightRefused(context, "kernel", "KERNEL_PREFLIGHT_MARKER_COMMIT_FAILED")
        val taskId = java.util.UUID.randomUUID().toString()
        var selectedTask = taskId
        recordStatus(context, "kernel")
        var scopeRefusal: String? = null
        val result = try {
            com.maplesu.core.ui.util.installUltraKernelUpdate(taskId, onTaskSelected = { selectedTask = it }, verifyScope = {
                scopeFailure()?.let { reason ->
                    scopeRefusal = reason
                    error(reason)
                }
            })
        } catch (error: Exception) {
            val refusal = scopeRefusal ?: throw error
            prefs.edit().remove(KEY_SUBMITTED_BOOT).commit()
            return preflightRefused(context, "kernel", refusal)
        }
        if (result.code != 0 || result.outcome != com.maplesu.core.ui.util.FlashOutcome.WRITTEN) {
            if (result.outcome != com.maplesu.core.ui.util.FlashOutcome.RECOVERY_REQUIRED &&
                result.outcome != com.maplesu.core.ui.util.FlashOutcome.WRITTEN) {
                prefs.edit().remove(KEY_SUBMITTED_BOOT).commit()
            }
            if (scopeRefusal != null && result.outcome != com.maplesu.core.ui.util.FlashOutcome.RECOVERY_REQUIRED &&
                result.outcome != com.maplesu.core.ui.util.FlashOutcome.WRITTEN)
                return preflightRefused(context, "kernel", requireNotNull(scopeRefusal))
            val reason = listOfNotNull(scopeRefusal, result.err.ifBlank { "ULTRA_KERNEL_UPGRADE_FAILED" })
                .joinToString(":")
            recordStatus(context, "kernel", reason)
            return Result.FAILED
        }
        recordStatus(context, "kernel_verified")
        val rebootRequested = runCatching {
            dev.maplesu.manager.installer.InstallerServiceClient.rebootAfterInstallation(context, selectedTask)
        }.getOrDefault(false)
        if (!rebootRequested) {
            recordStatus(context, "kernel_awaiting_reboot")
        }
        return Result.SUBMITTED
    }

    internal fun faultRepairAllowed(state: String?, facts: UltraEnvFacts,
                                    completedBoot: Boolean = false, identity: InstalledIdentity? = null,
                                    expectedHelperPath: String? = null, expectedBootId: String? = null,
                                    kernelRootVerified: Boolean = false): Boolean {
        // A fresh device whose boot already carries the Ultra kernel proves the channel is live
        // even though no helper has completed a boot yet: repair is the only way to install that
        // helper, so refusing it here would be a deadlock. The kernel proof replaces the
        // completed-boot receipt in exactly that case, and every later fact check still applies.
        if (state != "Fault" && !((state == "Unknown" || state == "NotInstalled") && kernelRootVerified) &&
            !(state == "Unknown" && completedBoot &&
                UltraInstalledIdentityProbe.normalizeSha(facts.installedHelperSha256) != null)) return false
        if (facts.running || facts.suspended ||
            facts.quiescing || facts.submittedThisBoot) return false
        val bundled = EnvVersion.parse(facts.bundledVersion) ?: return false
        val installed = EnvVersion.parse(facts.installedVersion)
        val freshKernelInstall = (state == "Unknown" || state == "NotInstalled") && kernelRootVerified &&
            facts.freshKernelInstall && !facts.readUnknown &&
            facts.installedVersion == null && facts.installedHelperSha256 == null && identity?.known != true &&
            UltraInstalledIdentityProbe.normalizeSha(facts.bundledHelperSha256) != null
        if (state == "NotInstalled" && !freshKernelInstall) return false
        if (installed == null && !freshKernelInstall) {
            val observed = UltraInstalledIdentityProbe.normalizeSha(facts.installedHelperSha256) ?: return false
            val expected = UltraInstalledIdentityProbe.normalizeSha(facts.bundledHelperSha256) ?: return false
            if (observed != expected && (identity == null || identity.source != Source.Readback ||
                    expectedHelperPath == null || expectedBootId == null ||
                    identity.helperPath != expectedHelperPath || identity.bootId != expectedBootId ||
                    identity.helperSize?.let { it > 0L } != true ||
                    UltraInstalledIdentityProbe.normalizeSha(identity.helperSha256) != observed)) return false
        } else if (installed != null && installed > bundled) return false
        val installedApp = EnvVersion.parse(facts.installedAppVersion)
        val bundledApp = EnvVersion.parse(facts.bundledAppVersion)
        if (facts.installedAppVersion != null && installedApp == null ||
            facts.bundledAppVersion != null && bundledApp == null) return false
        return installedApp == null || bundledApp == null || installedApp <= bundledApp
    }

    private fun completedBootRepairEvidence(context: Context, client: UltraRuntimeClient): Boolean {
        val bootId = UltraEnvironmentAutoSetup.currentBootId() ?: return false
        val helper = UltraInstalledIdentityProbe.installedHelperPath()
            ?: UltraInstalledIdentityProbe.read(context, client, force = true)
                .takeIf { it.source == Source.Readback && it.bootId == bootId }?.helperPath
            ?: return false
        val receipt = client.runRootCommand(completedBootRepairScript(helper, bootId))
        return receipt.succeeded && completedBootRepairConfirmed(bootId, client.decodeText(receipt.string("result"))) &&
            UltraEnvironmentAutoSetup.currentBootId() == bootId
    }

    /** Manual recovery accepts a stale completed helper or an idle, never-started installation. */
    internal fun completedBootRepairScript(helper: String, bootId: String): String {
        require(helper.matches(Regex("/data/[A-Za-z0-9]{16}/init")))
        require(bootId.matches(Regex("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")))
        return """
            [ "${'$'}(/system/bin/getprop sys.boot_completed)" = 1 ] || exit 0
            [ "${'$'}(head -c 65 /proc/sys/kernel/random/boot_id)" = '$bootId' ] || exit 0
            h='$helper'
            [ -f "${'$'}h" ] && [ ! -L "${'$'}h" ] || exit 0
            [ -f "${'$'}h.safe_flag" ] && [ ! -L "${'$'}h.safe_flag" ] || exit 0
            flag=${'$'}(head -c 65 "${'$'}h.safe_flag") || exit 0
            current_receipt() {
                [ -f "${'$'}1" ] && [ ! -L "${'$'}1" ] && [ -r "${'$'}1" ] &&
                    [ "${'$'}(wc -c < "${'$'}1")" -le 64 ] 2>/dev/null &&
                    [ "${'$'}(head -c 65 "${'$'}1")" = '$bootId' ]
            }
            if { [ "${'$'}flag" = 2 ] || { [ ! -s "${'$'}h.safe_flag" ] &&
                    current_receipt "${'$'}h.boot_session.completed"; }; } &&
                current_receipt "${'$'}h.boot_session.work" &&
                current_receipt "${'$'}h.boot_session.duplicate" &&
                [ "${'$'}(head -c 65 "${'$'}h.safe_flag")" = "${'$'}flag" ]; then
                echo 'MAPLESU_COMPLETED_BOOT:$bootId'
                exit 0
            fi
            if [ ! -s "${'$'}h.safe_flag" ]; then
                read up rest < /proc/uptime || exit 0
                [ "${'$'}{up%%.*}" -ge 120 ] 2>/dev/null || exit 0
                for suffix in boot_fail_protect enable boot_session.work boot_session.duplicate boot_session.completed; do
                    f="${'$'}h.${'$'}suffix"
                    if [ -e "${'$'}f" ] || [ -L "${'$'}f" ]; then
                        [ -f "${'$'}f" ] && [ ! -L "${'$'}f" ] && [ -r "${'$'}f" ] && [ ! -s "${'$'}f" ] || exit 0
                    fi
                done
                [ ! -s "${'$'}h.safe_flag" ] || exit 0
                echo 'MAPLESU_COMPLETED_BOOT:$bootId'
                exit 0
            fi
            [ "${'$'}(head -c 65 "${'$'}h.safe_flag")" = 2 ] || exit 0
            if [ -e "${'$'}h.boot_session.work" ]; then
                [ -f "${'$'}h.boot_session.work" ] && [ ! -L "${'$'}h.boot_session.work" ] || exit 0
                work=${'$'}(head -c 65 "${'$'}h.boot_session.work") || exit 0
                [ "${'$'}work" != '$bootId' ] || exit 0
            elif [ -L "${'$'}h.boot_session.work" ]; then
                exit 0
            fi
            echo 'MAPLESU_COMPLETED_BOOT:$bootId'
        """.trimIndent()
    }

    internal fun completedBootRepairConfirmed(bootId: String, output: String?): Boolean =
        output?.trim() == "MAPLESU_COMPLETED_BOOT:$bootId"

    /** Survives process death, and is included in bugreports even when root is down. */
    fun persistedFailure(context: Context): String? =
        context.ultraPreferences(PREFS, Context.MODE_PRIVATE).all["lastFailure"] as? String

    internal fun recordPreparationReceipt(context: Context, diagnostic: String) {
        context.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("lastPreparationReceipt", diagnostic).commit()
    }

    internal fun recordPreparationFailure(context: Context, outcome: UltraEnvironmentInstaller.Outcome) {
        recordStatus(context, "install", diagnosticReasonOf(outcome))
    }

    fun diagnostics(context: Context): String {
        val saved = context.ultraPreferences(PREFS, Context.MODE_PRIVATE).all
        return "phase=${saved["lastPhase"] as? String ?: "none"}\n" +
            "failure=${saved["lastFailure"] as? String ?: ""}\n" +
            "preparationReceipt=${saved["lastPreparationReceipt"] as? String ?: ""}\n" +
            "build=${saved["lastBuild"] as? String ?: ""}\n" +
            "boot=${saved["lastBoot"] as? String ?: ""}\n"
    }

    private fun recordStatus(context: Context, phase: String, reason: String? = null) {
        val diagnostic = reason?.let(::diagnosticText)
        lastFailureReason = diagnostic
        context.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("lastPhase", phase).putString("lastFailure", diagnostic)
            .putString("lastBuild", UltraSdkBuild.BUILD_ID)
            .putString("lastBoot", UltraEnvironmentAutoSetup.currentBootId()).commit()
    }

    internal fun diagnosticReasonOf(outcome: UltraEnvironmentInstaller.Outcome?): String =
        diagnosticText(failureReasonOf(outcome))

    private fun diagnosticText(reason: String?): String =
        UltraSdkLogging.redact(reason).replace(Regex("/data/[A-Za-z0-9]{16,17}(?=/|$)"), "/data/<private>")
            .replace('\n', ' ').replace('\r', ' ').take(512)

    /** Executes after the durable per-boot marker has been stored. */
    internal fun submitMarked(install: () -> UltraEnvironmentInstaller.Outcome,
                              clear: () -> Unit): UltraEnvironmentInstaller.Outcome? {
        val outcome = try {
            install()
        } catch (cancelled: UltraInstallPreparationCancelled) {
            clear()
            throw cancelled.cancellation
        } catch (error: Exception) {
            rethrowCancellation(error)
            UltraEnvironmentInstaller.Outcome(false, "EXCEPTION", reason = UltraSdkLogging.redact(error.toString()),
                submissionUnknown = true)
        }
        // Success without readback and transport exceptions may already have written the
        // helper. Keep the durable marker until another boot; never replay an uncertain write.
        if (!outcome.ok && !outcome.submissionUnknown && outcome.sdkError != "EXCEPTION") clear()
        return outcome
    }

    /**
     * 哪些判定允许真正写设备。
     *
     *  - [UltraEnvUpgrade.Available]：同上游版本的新构建；
     *  - [UltraEnvUpgrade.Unverified]：身份读不到（老环境没有身份记录）。用户口径是
     *    「点一次就能升级」，所以确认不了时**允许重装**——重装会写入可验证身份；只是
     *    成功仍必须过回读，绝不因为放宽入口而放宽「算成功」的标准。
     *
     * [UltraEnvUpgrade.None]（含 quiescing/暂停/未运行/降级）与
     * [UltraEnvUpgrade.Rebooting]（本 boot 已提交）都不允许再次写。
     */
    fun upgradeAllowed(decision: UltraEnvUpgrade): Boolean =
        decision is UltraEnvUpgrade.Available || decision is UltraEnvUpgrade.Unverified

    /**
     * 安装回执 → 升级结论。**只有 ok 且 verified 才算提交成功**：
     * 「SDK 说装完了」不等于「设备上已经是这一版」，后者只能靠回读摘要证明。
     */
    fun resultOf(outcome: UltraEnvironmentInstaller.Outcome?): Result = when {
        outcome == null -> Result.FAILED
        !outcome.ok -> Result.FAILED
        !outcome.verified -> Result.FAILED
        else -> Result.SUBMITTED
    }

    /** 失败原因（机器码 + 摘要），成功后为 null；不包含任何密文/密钥。 */
    fun failureReasonOf(outcome: UltraEnvironmentInstaller.Outcome?): String? = when {
        outcome == null -> "INSTALL_EXCEPTION"
        !outcome.ok -> "SDK:${outcome.sdkError}" + (outcome.reason?.let { ":$it" } ?: "") +
            (outcome.sdkErrorCode?.let { " code=$it" } ?: "") +
            (outcome.detail?.let { " $it" } ?: "")
        !outcome.verified -> outcome.detail ?: "UNVERIFIED:UNKNOWN"
        else -> null
    }

    private fun submittedThisBoot(context: Context): Boolean {
        if (UltraIdleEnvironmentRecovery.submittedThisBoot(context)) return true
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        val marker = prefs.all[KEY_SUBMITTED_BOOT] as? String ?: return false
        val bootId = UltraEnvironmentAutoSetup.currentBootId() ?: return false
        if (marker == bootId) return true
        // 已经重启过：标记作废，回到按版本判断。
        prefs.edit().remove(KEY_SUBMITTED_BOOT).apply()
        return false
    }

    /** Only the SDK's explicit absence result distinguishes a fresh helper from a failed version read. */
    internal fun versionFacts(state: String, installed: NativeReceipt?, bundled: NativeReceipt?,
                              kernelRootVerified: Boolean = false): UltraEnvFacts {
        val installedVersion = versionOf(installed)
        val bundledVersion = versionOf(bundled)
        val helperAbsent = installed?.operation == "get_installed_maplesu_environment_version" &&
            installed.schemaVersion == 1 && installed.bridgeVersion == 1 &&
            installed.backend == UltraRuntimeClient.BACKEND && !installed.ok &&
            installed.sdkError == "ERR_MAPLESU_ENV_UNPREPARED" && installed.sdkErrorCode == -19916
        val freshAbsence = (state == "Unknown" || state == "NotInstalled") && helperAbsent
        return UltraEnvFacts(installedVersion = installedVersion, bundledVersion = bundledVersion,
            readUnknown = state == "Unknown" && !freshAbsence ||
                installedVersion == null && !freshAbsence || bundledVersion == null,
            freshKernelInstall = freshAbsence && kernelRootVerified)
    }

    private fun versionOf(receipt: NativeReceipt?): String? =
        receipt?.takeIf { it.succeeded }
            ?.string("version")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }

    private inline fun <T> runCatchingCancellable(block: () -> T): kotlin.Result<T> =
        runCatching(block).onFailure { rethrowCancellation(it) }

    private fun rethrowCancellation(error: Throwable) {
        if (error is CancellationException) throw error
        if (error is InterruptedException) {
            Thread.currentThread().interrupt()
            throw error
        }
    }

    private fun requireBackground() {
        check(Looper.myLooper() != Looper.getMainLooper()) { "ULTRA_UPGRADE_BACKGROUND_THREAD_REQUIRED" }
    }
}
