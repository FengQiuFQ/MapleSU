// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.util.Log
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import dev.maplesu.manager.workmode.ui.WorkModeSwitchSession
import java.util.concurrent.CancellationException

/** Preparation cancellation proves the SDK installation was never submitted. */
internal class UltraInstallPreparationCancelled(val cancellation: CancellationException) :
    CancellationException("INSTALL_PREPARATION_CANCELLED") {
    init { initCause(cancellation) }
}

object UltraEnvironmentInstaller {

    private const val TAG = "MapleSUUltraInstaller"

    /** 安装意图。默认值保持既有调用点的语义（复用运行中的环境）。 */
    enum class Intent {
        /** 已经 Running 就复用，不重复写设备。 */
        ReuseRunning,

        /** 显式安装：由 SDK 决定能否安装，不以前置状态探测代替提交。 */
        InstallToBundledBuild,

        /** 升级：无论当前是否 Running，都必须提交一次随包载荷。 */
        UpgradeToBundledBuild,

        /** Legacy 软件载荷刷新，保留当前启动状态，不重启或重刷底层镜像。 */
        RefreshToBundledBuild,
    }

    /** 安装结果。[ok] 只由 SDK 回执决定；[verified] 是「设备上真的是这一版」的独立结论。 */
    data class Outcome(
        val ok: Boolean,
        val sdkError: String,
        val reason: String? = null,
        val whitelist: String? = null,
        val detail: String? = null,
        /** 每次真正提交安装后核对；回读失败/摘要不符 → false（[ok] 仍可为 true）。 */
        val verified: Boolean = true,
        /** 回读到的（或随包的）构建号，供界面/日志显示。 */
        val buildId: String? = null,
        val sdkErrorCode: Int? = null,
        /** The installed state may have changed; replay requires reconciliation. */
        val submissionUnknown: Boolean = false,
    ) {
        val summary: String
            get() = "ok=$ok sdkError=$sdkError" +
                (sdkErrorCode?.let { " sdkErrorCode=$it" } ?: "") +
                (reason?.let { " reason=$it" } ?: "") +
                (whitelist?.let { " suAuth[$it]" } ?: "") +
                " verified=$verified" +
                " submissionUnknown=$submissionUnknown" +
                (buildId?.let { " buildId=$it" } ?: "") +
                (detail?.let { " detail=$it" } ?: "")
    }

    private fun failureOutcome(receipt: NativeReceipt, phase: String) = Outcome(
        false, receiptErrorName(receipt.succeeded, receipt.sdkError), receipt.reason,
        sdkErrorCode = receipt.sdkErrorCode,
        verified = false,
        detail = "phase=$phase operation=${receipt.operation} bridgeVersion=${receipt.bridgeVersion}",
        submissionUnknown = phase == "install" && (receipt.operationCompleted ||
            receipt.sdkError !in setOf("MAPLESU_SDK_BUSY", "MAPLESU_SDK_INTERRUPTED", "MAPLESU_SDK_DEADLINE_EXCEEDED",
                "MAPLESU_BRIDGE_UNAVAILABLE", "SDK_IDENTITY_SCOPE_CHANGED")),
    )

    /**
     * SDK 安装面（端口）。生产由 [UltraRuntimeClient] 支撑；主机测试用假实现数调用次数，
     * 从而能证明「升级真的调了安装，而不是被 Running 短路」。
     */
    interface InstallPort {
        fun environmentState(): NativeReceipt

        fun submitInstall(): NativeReceipt
    }

    /**
     * 安装之后的附带动作。主机测试传空实现；生产由 [install] 用真实 Context 装好。
     * 真正提交后先回读并保存身份，再做白名单与探针刷新。
     */
    class Attachments(
        val whitelist: () -> UltraSelfWhitelist.Result,
        /** 每次真正提交安装后调用；复用 Running 不重复回读。 */
        val verify: () -> IdentityObservation = {
            IdentityObservation(InstalledIdentity.unknown(), IdentityVerification.passed(null))
        },
        /** 只有核对通过才落盘（未经验证的身份不许写成「已装」）。 */
        val persist: (InstalledIdentity) -> Unit = {},
        val refreshProbe: () -> Unit = {},
        val prepareInstall: () -> String? = { null },
        val scopeFailure: () -> String? = { null },
        /** Explicit installation initializes only a genuinely absent durable authority. */
        val initializeAuthority: () -> String? = { null },
    )

    /** Authorization maintenance never changes a completed installation result. */
    fun afterInstall(
        succeeded: Boolean,
        sdkError: String,
        reason: String?,
        whitelist: () -> UltraSelfWhitelist.Result,
    ): Outcome {
        if (!succeeded) return Outcome(false, receiptErrorName(false, sdkError), reason)
        val white = try {
            whitelist()
        } catch (error: Throwable) {
            null
        }
        val whiteSummary = white?.summary ?: "EXCEPTION:WHITELIST"
        return Outcome(
            ok = true,
            sdkError = sdkError,
            reason = reason,
            whitelist = whiteSummary,
        )
    }

    /**
     * 生产适配：全仓唯一出现 `installEnvironment("Boot"` 的地方。
     *
     * 显式升级和软件刷新均提交真实 SDK 写入；Running 不代替写入。
     */
    fun portOf(client: UltraRuntimeClient, intent: Intent = Intent.ReuseRunning): InstallPort = object : InstallPort {
        override fun environmentState(): NativeReceipt = client.environmentState()

        override fun submitInstall(): NativeReceipt = client.installEnvironment(
            if (intent == Intent.RefreshToBundledBuild) "Refresh" else "Boot", "")
    }

    /**
     * 使用当前受验证安装身份安装环境，安装后核对真实回执与授权状态。
     *
     * <p>启动链路里 `UltraEnvironmentAutoSetup` 与 `UltraSelfHeal` 在不同
     * daemon 线程上可能同时判断出「需要补装」，锁内重新检查 Running，避免排队中的旧请求
     * 再次安装已激活的环境；自白名单仍在安装结果之后维护。
     *
     * @param intent 默认 [Intent.ReuseRunning]（保持既有调用点语义）；升级必须显式传
     *   [Intent.UpgradeToBundledBuild]，否则会被 Running 短路掉。
     * @param client 默认复用 [UltraSdkCredentials] 捕获的安装身份。
     */
    fun install(
        context: Context,
        client: UltraRuntimeClient = UltraSdkCredentials.client(context),
        intent: Intent = Intent.ReuseRunning,
    ): Outcome {
        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        val activation = ModeRuntime.activation
        val current = UltraSdkCredentials.captureOwnerMarker(context)
        val legacy = if (client.legacyCredentialFingerprint != null) UltraLegacyCredential.read(context)?.takeIf {
            it.fingerprint == client.legacyCredentialFingerprint
        } else null
        val owner = if (client.legacyCredentialFingerprint == null) client.queryManagerOwnerIdentity().identity else null
        fun checkScope(): String? = when {
            Thread.currentThread().isInterrupted -> "MAPLESU_SDK_INTERRUPTED"
            bootId == null || UltraEnvironmentAutoSetup.currentBootId() != bootId -> "INSTALL_BOOT_CHANGED"
            ModeRuntime.activation !== activation -> "INSTALL_MODE_CHANGED"
            LiteImplantQuiesceGate.isBlocked() || WorkModeSwitchSession.executing -> "INSTALL_SWITCH_PENDING"
            owner == null && legacy == null -> "INSTALL_IDENTITY_UNCONFIRMED"
            !current() || (legacy != null && !legacy.isCurrent(context)) ||
                (owner != null && client.queryManagerOwnerIdentity().identity != owner) -> "INSTALL_IDENTITY_CHANGED"
            else -> null
        }
        val scopedClient = client.scoped { checkScope() == null }
        return synchronized(this) {
            install(
                port = portOf(scopedClient, intent),
                intent = intent,
                attachments = Attachments(
                    whitelist = { UltraSelfWhitelist.onEnvironmentInstalled(context, scopedClient) { checkScope() == null } },
                    verify = {
                        UltraInstalledIdentityProbe.readAndVerify(
                            context,
                            scopedClient,
                        )
                    },
                    persist = { identity ->
                        check(checkScope() == null) { "INSTALL_CONTEXT_CHANGED" }
                        check(UltraInstalledIdentityProbe.persist(context, identity)) { "IDENTITY_PERSIST_FAILED" }
                    },
                    refreshProbe = {
                        runCatching { UltraEnvironmentProbe.refresh(context) }
                            .onFailure { Log.w(TAG, "probe refresh after install failed (ignored)") }
                    },
                    prepareInstall = { UltraPolicyBackendDeployment.prepare(context, scopedClient) },
                    scopeFailure = ::checkScope,
                    initializeAuthority = {
                        val current = { checkScope() == null }
                        val scope = UltraAuthorization.Scope(scopedClient, current, current)
                        val initialized = dev.maplesu.manager.runtime.authorization.SuperuserControl
                            .initializeForInstallationIfAbsent(context, scope)
                        val migrated = if (initialized.succeeded && current())
                            dev.maplesu.manager.runtime.authorization.SuperuserControl.migrate(context, scope)
                        else initialized
                        if (migrated.succeeded && current()) null else listOfNotNull(
                            migrated.code ?: "SU_AUTH_APPLY_PENDING",
                            migrated.detail.takeIf(String::isNotBlank),
                        ).joinToString(":")
                    },
                ),
            )
        }
    }

    private fun scopeFailure(attachments: Attachments): String? =
        runCatching { attachments.scopeFailure() }.getOrDefault("INSTALL_SCOPE_UNREADABLE")

    /**
     * 编排主体（不碰 Android）：提交/复用 → 回读身份 → 白名单 → 刷新探针。
     * 只有复用路径需要先读 Running；显式升级已在入口核对事实。
     */
    fun install(port: InstallPort, intent: Intent, attachments: Attachments): Outcome {
        fun pendingScopeFailure(): Outcome? = scopeFailure(attachments)?.let {
            Outcome(false, "INSTALL_CONTEXT_CHANGED", reason = it)
        }
        if (Thread.currentThread().isInterrupted) return Outcome(false, "MAPLESU_SDK_INTERRUPTED")
        pendingScopeFailure()?.let { return it }
        val existing = if (intent == Intent.ReuseRunning) {
            val observation = try {
                port.environmentState()
            } catch (error: Exception) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                return Outcome(false, "ENVIRONMENT_PROBE_FAILED", detail = error.javaClass.simpleName)
            }
            // A queued recovery may outlive its initial probe. A failed channel is
            // not evidence of absence, and must never fall through to a Boot write.
            if (!observation.succeeded) return failureOutcome(observation, "probe")
            val state = observation.string("state")
            if (state != "Running" && state != "NotInstalled") {
                return Outcome(false, if (state == "Fault") "ENVIRONMENT_FAULT" else "ENVIRONMENT_STATE_UNKNOWN")
            }
            observation.takeIf { state == "Running" }
        } else null
        // ReuseRunning：已有 Running 就不再写设备（自愈/启动补装的既有语义）。
        // UpgradeToBundledBuild：Running 不是复用理由，必须重新提交载荷。
        val reuse = intent == Intent.ReuseRunning && existing != null
        pendingScopeFailure()?.let { return it }
        if (!reuse) {
            val failure = try {
                attachments.prepareInstall()
            } catch (error: Exception) {
                if (error is CancellationException) throw UltraInstallPreparationCancelled(error)
                if (error is InterruptedException) Thread.currentThread().interrupt()
                "POLICY_BACKEND_PREPARATION_EXCEPTION"
            }
            if (failure != null) return Outcome(false, "POLICY_BACKEND_PREPARATION_FAILED", reason = failure)
            pendingScopeFailure()?.let { return it }
        }
        if (Thread.currentThread().isInterrupted) return Outcome(false, "MAPLESU_SDK_INTERRUPTED")
        pendingScopeFailure()?.let { return it }
        val receipt: NativeReceipt = try {
            existing ?: port.submitInstall()
        } catch (error: Throwable) {
            quietLog { Log.w(TAG, "install_maplesu_environment threw: ${error.javaClass.simpleName}") }
            return Outcome(false, "EXCEPTION", reason = UltraSdkLogging.redact(error.toString()),
                submissionUnknown = true)
        }
        quietLog {
            Log.i(
                TAG,
                "environment ready intent=$intent existing=${existing != null} reuse=$reuse " +
                    "ok=${receipt.succeeded} sdkError=${receipt.sdkError} reason=${receipt.reason.orEmpty()}",
            )
        }
        if (!receipt.succeeded) return failureOutcome(receipt, "install")
        fun submittedUnverified(reason: String, buildId: String? = null) = Outcome(
            true, receipt.sdkError, receipt.reason, detail = "UNVERIFIED:$reason", verified = false,
            buildId = buildId,
            sdkErrorCode = receipt.sdkErrorCode,
        )
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        // Persist readback before whitelist/identity deployment can consume the reboot window.
        val observation = if (!reuse) verifyAndPersist(attachments)
            else IdentityObservation(InstalledIdentity.unknown(), IdentityVerification.passed(null))
        val verified = observation.verification
        val verificationScopeFailure = scopeFailure(attachments)
        if (!verified.verified || verificationScopeFailure != null) {
            val reason = verificationScopeFailure ?: verified.reason ?: "UNKNOWN"
            return submittedUnverified(reason +
                (observation.readbackFailure?.let { " readback=$it" } ?: ""), verified.buildId)
        }
        val completeUpgrade = intent == Intent.UpgradeToBundledBuild
        val authorityFailure = if ((intent == Intent.InstallToBundledBuild || completeUpgrade) && verified.verified) {
            try { attachments.initializeAuthority() }
            catch (error: Exception) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                "AUTH_INITIALIZATION_EXCEPTION:${UltraSdkLogging.redact(error.toString())}"
            }
        } else null
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        var authorization: UltraSelfWhitelist.Result? = null
        val outcome = afterInstall(
            succeeded = true,
            sdkError = receipt.sdkError,
            reason = receipt.reason,
            whitelist = {
                check(scopeFailure(attachments) == null) { "INSTALL_CONTEXT_CHANGED" }
                (if (authorityFailure == null) attachments.whitelist()
                else UltraSelfWhitelist.Result(false, false, false, false, false, authorityFailure))
                    .also { authorization = it }
            },
        )
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        attachments.refreshProbe()
        scopeFailure(attachments)?.let { return submittedUnverified(it) }
        val authorizationFailure = if (completeUpgrade && authorization?.succeeded != true)
            authorization?.failure ?: "SU_AUTH_APPLY_PENDING" else null
        val result = outcome.copy(
            verified = verified.verified && authorityFailure == null && authorizationFailure == null,
            detail = when {
                authorityFailure != null -> "UNVERIFIED:AUTHORITY:$authorityFailure"
                authorizationFailure != null -> "UNVERIFIED:AUTHORIZATION:$authorizationFailure"
                else -> outcome.detail
            },
            buildId = verified.buildId,
            sdkErrorCode = receipt.sdkErrorCode,
        )
        quietLog { Log.i(TAG, "environment install outcome ${result.summary}") }
        return result
    }

    /**
     * 回读 + 核对；只有通过才落持久化身份。任何异常都收敛成「未验证」。
     *
     * 所有日志都用 [quietLog]：主机单测里 `android.util.Log` 是 stub 会抛，编排路径不能
     * 因为记一行日志就失败（与 [UltraSuChannel] 的既有纪律一致）。
     */
    private fun verifyAndPersist(attachments: Attachments): IdentityObservation {
        scopeFailure(attachments)?.let {
            return IdentityObservation(InstalledIdentity.unknown(), IdentityVerification(false, it, null))
        }
        val observation = try {
            attachments.verify()
        } catch (error: Throwable) {
            return IdentityObservation(InstalledIdentity.unknown(),
                IdentityVerification(false, "VERIFY_EXCEPTION:${error.javaClass.simpleName}", null))
        }
        scopeFailure(attachments)?.let {
            return observation.copy(verification = IdentityVerification(false, it, null))
        }
        if (!observation.verification.verified) {
            quietLog {
                Log.w(
                    TAG,
                    "install not verified: reason=${observation.verification.reason} " +
                        "source=${observation.identity.source}",
                )
            }
            return observation
        }
        // 校验通过 = 设备上的 helper 就是随包这一份：把随包构建号盖上去再落盘。
        // 不盖的话「摘要相同但构建号未知」会永远停在待确认，用户会每点一次都重装。
        val stamped = observation.identity.copy(
            buildId = observation.identity.buildId ?: observation.verification.buildId,
        )
        scopeFailure(attachments)?.let {
            return observation.copy(verification = IdentityVerification(false, it, null))
        }
        try {
            attachments.persist(stamped)
        } catch (error: Throwable) {
            quietLog { Log.w(TAG, "identity persist failed: ${error.javaClass.simpleName}") }
            return observation.copy(verification = IdentityVerification(false, "IDENTITY_PERSIST_FAILED", null))
        }
        scopeFailure(attachments)?.let {
            return observation.copy(verification = IdentityVerification(false, it, null))
        }
        return observation.copy(
            identity = stamped,
            verification = observation.verification.copy(buildId = stamped.buildId ?: observation.verification.buildId),
        )
    }

    /** 主机单测里 Log 是 stub：日志永远不允许把编排变成异常。 */
    private inline fun quietLog(block: () -> Unit) {
        runCatching(block)
    }

}
