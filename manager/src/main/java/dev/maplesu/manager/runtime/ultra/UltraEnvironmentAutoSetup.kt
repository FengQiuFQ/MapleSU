package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.os.Looper
import android.util.Log
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.service.ModeSwitchProgress
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.ModeState
import dev.maplesu.manager.workmode.superuser.LiteImplantCodes
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import dev.maplesu.manager.workmode.ui.WorkModeSwitchSession
import java.io.File

/**
 * Startup re-identifies the current signed installation before entering this setup.
 * A fresh SDK NotInstalled observation permits one durable helper submission per boot.
 * Only a confirmed pre-submission failure permits retry in the same boot.
 * Running is reused. Unknown can recover a verified idle helper or install through
 * the current verified kernel Root channel; Unknown alone never permits installation.
 */
object UltraEnvironmentAutoSetup {

    private const val TAG = "MapleSUUltraAutoSetup"
    private const val PREFS = "ultra-auto-setup"
    private const val KEY_LAST_BOOT = "lastBootId"
    private const val KEY_SUBMITTED_BOOT = "submittedBootId"

    @Volatile
    private var processBootId: String? = null

    data class Result(val attempted: Boolean, val installed: Boolean, val reason: String) {
        val installationFailed: Boolean get() = UltraEnvironmentUpgrade.isPreparationFailure(reason)
    }

    /** Startup and foreground requests reconcile the current environment; idempotent. */
    fun ensure(context: Context): Result = ensure(context) { true }

    internal fun ensure(context: Context, current: () -> Boolean): Result {
        if (!current()) return Result(false, false, "SDK_IDENTITY_SCOPE_CHANGED")
        val bootId = currentBootId()
        val result = ensureForBoot(context, bootId, current)
        // App-owned evidence survives loss of both the SDK and the standard SU channel.
        if (current()) runCatching {
            context.ultraPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("lastObservedBoot", bootId)
                .putLong("lastObservedAt", System.currentTimeMillis())
                .putString("lastResult", "attempted=${result.attempted} installed=${result.installed} reason=${result.reason}")
                .apply()
        }
        return if (current()) result else result.copy(
            installed = false,
            reason = if (result.installationFailed) "${result.reason};scope=SDK_IDENTITY_SCOPE_CHANGED"
                else if (result.reason == "AUTHORIZATION_SYNC_PENDING") result.reason
                else "SDK_IDENTITY_SCOPE_CHANGED",
        )
    }

    internal fun diagnostics(context: Context): String {
        val prefs = context.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        return "attemptedBoot=${prefs.getString(KEY_LAST_BOOT, null)}\n" +
            "observedBoot=${prefs.getString("lastObservedBoot", null)}\n" +
            "observedAtMs=${prefs.getLong("lastObservedAt", 0L)}\n" +
            "result=${prefs.getString("lastResult", "NOT_OBSERVED")}\n"
    }

    internal fun ensureForBoot(context: Context, bootId: String?): Result =
        ensureForBoot(context, bootId) { true }

    @Synchronized
    internal fun ensureForBoot(context: Context, bootId: String?, current: () -> Boolean): Result {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "ULTRA_AUTO_SETUP_BACKGROUND_THREAD_REQUIRED"
        }
        val appContext = context.applicationContext
        if (!current()) return Result(false, false, "SDK_IDENTITY_SCOPE_CHANGED")
        val hook = dev.maplesu.manager.runtime.HookRootExecutor.production(appContext).available()
        if (!current()) return Result(false, false, "SDK_IDENTITY_SCOPE_CHANGED")
        blockedReason(appContext, bootSession = hook || UltraSdkSession.current(appContext) != null)
            ?.let { return Result(false, false, it) }
        if (hook) {
            if (bootId.isNullOrBlank()) return Result(false, false, "BOOT_ID_UNAVAILABLE")
            val bootstrap = UltraSdkSession.bootstrap(appContext, bootId, current)
            if (!current()) return Result(bootstrap.submitted, false, "SDK_IDENTITY_SCOPE_CHANGED")
            if (!bootstrap.bound) return Result(bootstrap.submitted, false, bootstrap.reason)
        }
        if (!current()) return Result(false, false, "SDK_IDENTITY_SCOPE_CHANGED")
        resumedInstallResult(UltraEnvironmentUpgrade.resumeFullInstall(appContext),
            UltraEnvironmentUpgrade.fullInstallPendingThisBoot(appContext),
            UltraEnvironmentUpgrade.failedPreparationThisBoot(appContext))?.let { return it }
        val session = UltraSdkSession.current(appContext)
        if (session != null) {
            val result = UltraSdkSession.ensure(appContext, session, current)
            fun changed() = Result(result.submitted, false, "SDK_IDENTITY_SCOPE_CHANGED")
            if (!current()) return changed()
            if (result.ready) {
                val scope = UltraAuthorization.captureScope(appContext, session, current) ?: return changed()
                val imported = dev.maplesu.manager.runtime.authorization.SuperuserControl.migrate(appContext, scope)
                if (!scope.current()) return if (imported.ok && imported.pendingApply)
                    Result(result.submitted, false, "AUTHORIZATION_SYNC_PENDING") else changed()
                if (!imported.ok) return Result(result.submitted, false, "AUTHORIZATION_IMPORT_PENDING")
                val reconciled = dev.maplesu.manager.runtime.authorization.SuperuserControl
                    .reconcilePending(appContext, scope, force = true)
                if (!scope.current()) return changed()
                if (!reconciled) return Result(result.submitted, false, "AUTHORIZATION_SYNC_PENDING")
            }
            return Result(result.submitted, result.ready, result.reason)
        }
        if (!current()) return Result(false, false, "SDK_IDENTITY_SCOPE_CHANGED")
        if (!hasVerifiedUltraIdentity(appContext)) return Result(false, false, "INSTALL_IDENTITY_PENDING")
        if (bootId.isNullOrBlank()) return Result(false, false, "BOOT_ID_UNAVAILABLE")
        val prefs = appContext.ultraPreferences(PREFS, Context.MODE_PRIVATE)
        val marker = UltraSdkCredentials.captureOwnerMarker(appContext)
        fun scopeCurrent() = current() && marker()
        val client = UltraSdkCredentials.client(appContext, ::scopeCurrent)
        var installSkipped = false
        val result = UltraAutoSetupAttempt.run(
            object : UltraAutoSetupAttempt.Port {
                override fun blockedReason(): String? = when {
                    !scopeCurrent() -> "SDK_IDENTITY_SCOPE_CHANGED"
                    currentBootId() != bootId -> "BOOT_CHANGED"
                    else -> UltraEnvironmentAutoSetup.blockedReason(appContext)
                }
                override fun state() = UltraEnvironmentProbe.refresh(appContext)
                override fun kernelRootVerified() = scopeCurrent() &&
                    UltraEnvironmentProbe.hasCurrentRootProof(appContext) && scopeCurrent()
                override fun recordAttempt() {
                    if (current()) prefs.edit().putString(KEY_LAST_BOOT, bootId).apply()
                }
                override fun alreadySubmitted() = prefs.all[KEY_SUBMITTED_BOOT] == bootId
                override fun markSubmitted() = scopeCurrent() &&
                    prefs.edit().putString(KEY_SUBMITTED_BOOT, bootId).commit()
                override fun clearUnsubmitted() {
                    if (scopeCurrent()) prefs.edit().remove(KEY_SUBMITTED_BOOT).commit()
                }
                override fun install(): UltraEnvironmentInstaller.Outcome {
                    if (!scopeCurrent()) {
                        installSkipped = true
                        return UltraEnvironmentInstaller.Outcome(false, "SDK_IDENTITY_SCOPE_CHANGED")
                    }
                    return UltraEnvironmentInstaller.install(appContext, client,
                        UltraEnvironmentInstaller.Intent.InstallToBundledBuild)
                        .also {
                            if (scopeCurrent() && !it.ok && it.sdkError == "POLICY_BACKEND_PREPARATION_FAILED")
                                UltraEnvironmentUpgrade.recordPreparationFailure(appContext, it)
                            Log.i(TAG, "环境自动安装 ${it.summary}")
                        }
                }
                override fun refresh() { if (scopeCurrent()) UltraEnvironmentProbe.refresh(appContext) }
            }, recoverIdle = { UltraIdleEnvironmentRecovery.ensure(appContext, bootId, ::scopeCurrent) })
        return if (scopeCurrent()) result else result.copy(
            attempted = result.attempted && !installSkipped,
            reason = if (result.installationFailed) "${result.reason};scope=SDK_IDENTITY_SCOPE_CHANGED"
                else "SDK_IDENTITY_SCOPE_CHANGED",
        )
    }

    /** Verified installation identity never substitutes for live Root capability. */
    internal fun hasVerifiedUltraIdentity(context: Context): Boolean =
        UltraEnvironmentProbe.currentSnapshot(context).let {
            it.managerOwnerIdentity != null || it.legacyCredentialFingerprint != null
        }

    internal fun resumedInstallResult(resumed: UltraEnvironmentUpgrade.Result?, pendingThisBoot: Boolean,
                                     preparationFailure: String? = null): Result? = when {
        resumed == UltraEnvironmentUpgrade.Result.SUBMITTED -> Result(true, true, "SDK_UPGRADE_SUBMITTED")
        pendingThisBoot -> Result(false, false, "SDK_UPGRADE_PENDING")
        preparationFailure != null -> Result(resumed != null, false, preparationFailure)
        // A failed prior-boot continuation still owns the original submission.
        resumed != null -> Result(false, false, "SDK_UPGRADE_PENDING")
        else -> null
    }

    internal fun blockedReason(
        context: Context,
        bootSession: Boolean = UltraSdkSession.current(context) != null,
    ): String? = when {
        LiteImplantQuiesceGate.isBlocked() -> LiteImplantCodes.QUIESCING
        !bootSession && UltraRootKeyStore.isSuspended(context) -> "SUSPENDED"
        WorkModeSwitchSession.executing -> "SWITCH_PENDING"
        ModeRuntime.active == WorkMode.KSU -> "MODE_KSU"
        ModeRuntime.latestDetection?.state == ModeState.FOREIGN_SU ||
            ModeRuntime.latestDetection?.trace?.firstOrNull { it.id == "S1" }?.ok == true -> "ROOT_CONFLICT"
        else -> null
    }

    internal fun hasPostBootUltraSwitchRecovery(context: Context): Boolean = runCatching {
        if (WorkModeSwitchSession.executing) return@runCatching false
        val currentBoot = currentBootId() ?: return@runCatching false
        val identity = UltraInstallTransactions.fingerprint(context) ?: return@runCatching false
        val id = ModeSwitchProgress.postBootUltraRecovery(File(context.filesDir, "workmode/switch-work"),
            currentBoot, identity) ?: return@runCatching false
        UltraStartupWarmup.matchesPostBootSwitch(id, WorkModeSwitchSession.executing,
            WorkModeSwitchSession.pending, WorkModeSwitchSession.switchId)
    }.getOrDefault(false)

    internal fun currentBootId(): String? = processBootId ?: runCatching {
        File("/proc/sys/kernel/random/boot_id").readText().trim().takeIf { it.isNotEmpty() }
    }.getOrNull()?.also { processBootId = it }
}
