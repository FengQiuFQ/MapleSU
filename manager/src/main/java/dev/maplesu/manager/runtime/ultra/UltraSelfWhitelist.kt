// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.util.Log

internal const val SU_DELIVERY_INCOMPLETE = "ERR_SU_DELIVERY_INCOMPLETE"

/** `KModErr::ERR_MODULE_STORAGE_NOT_FOUND`; a fresh environment has no uid-profile blob yet. */
internal const val ERR_MODULE_STORAGE_NOT_FOUND = -19964

/**
 * `su_auth` 读写的窄端口：生产实现是 [UltraRuntimeClient]，主机测试注入 fake。
 *
 * <p>刻意不用 `UltraRuntimeClient` 当依赖类型：那个类在类初始化时加载 JNI 库，
 * 主机 JVM 上根本构造不出来（`bridgeLoaded=false` 会让所有调用变成 bridge failure，
 * 测不出「白名单幂等」这类纯逻辑）。
 */
interface SuAuthPort {
    val supportsUidProfiles: Boolean get() = false
    fun uidProfiles(): List<SuUidProfile>? = null
    fun uidProfileReadError(): String? = null
    fun uidProfileReadReceipt(): NativeReceipt? = null
    fun setUidProfile(uid: Int, packageName: String, allow: Boolean): NativeReceipt =
        NativeReceipt.bridgeFailure("set_su_uid_profile", "SU_UID_PROFILE_UNSUPPORTED", null)

    /** 读当前列表；`null` = 读取失败（**不能**当空列表）。 */
    fun snapshot(): List<String>?

    /** 添加一个包名；保留本次 SDK 回执。 */
    fun add(packageName: String): NativeReceipt

    /** 移除一个包名；保留本次 SDK 回执。 */
    fun remove(packageName: String): NativeReceipt

    /** Rebuild delivery from the current persisted list without replaying a committed mutation. */
    fun refreshUidMapping(): NativeReceipt =
        NativeReceipt.bridgeFailure("refresh_su_auth_list", SU_DELIVERY_INCOMPLETE, null)
}

/**
 * Explicitly maintains the Manager's own SU decision in the existing authority.
 * Manager identity authenticates administration independently of this grant;
 * standard su access still requires an applied full-UID decision and readback.
 * Reads distinguish unavailable state from an empty list and never replay a
 * committed decision merely because a later delivery/readback is pending.
 */
object UltraSelfWhitelist {

    private const val TAG = "MapleSUUltraSelfWL"

    data class Result(
        /** 快照是否确认目标条目存在；不代表标准 su 已验证。 */
        val inList: Boolean,
        val added: Boolean,
        val alreadyPresent: Boolean,
        /** add 是否真的被调用过（快照可读且已在 → false）。 */
        val attempted: Boolean,
        /** 最终状态是否经过快照确认（写入时必须是写后快照）。 */
        val listVerified: Boolean,
        val failure: String? = null,
        /** Same add receipt, also retained when the later membership readback fails. */
        val receipt: NativeReceipt? = null,
        /** Original authority detail for failure consumers; excluded from log summaries. */
        val detail: String? = null,
        /** Independent current UID read; the original write receipt stays in [receipt]. */
        val readReceipt: NativeReceipt? = null,
    ) {
        val succeeded: Boolean get() = inList && listVerified && failure == null

        /** 单行可日志摘要（包名之外不含任何敏感信息）。 */
        val summary: String
            get() = "inList=$inList added=$added already=$alreadyPresent " +
                "attempted=$attempted verified=$listVerified" +
                (failure?.let { " failure=${suAuthLogCode(it)}" } ?: "") +
                (receipt?.let { " ${it.authorizationDiagnosticSummary()}" } ?: "") +
                (readReceipt?.takeUnless { it === receipt }?.let {
                    " readReceipt=[${it.authorizationDiagnosticSummary()}]"
                } ?: "")

        override fun toString(): String = "Result($summary)"
    }

    /**
     * 纯逻辑入口（主机可测）：[port] 之外的任何东西都不参与判定。
     *
     * @param force 已有条目也重新 add：SDK 的 add 会重建当前包名到 UID 的映射，
     *   不必先 remove，避免刷新失败时丢失已有授权。
     */
    fun ensure(port: SuAuthPort, packageName: String, force: Boolean = false): Result = synchronized(suAuthTransactionLock) {
        val target = packageName.trim()
        if (target.isEmpty()) {
            return Result(false, false, false, false, false, "EMPTY_PACKAGE")
        }
        val snapshot = port.snapshot()
        val listed = snapshot != null && snapshot.contains(target)
        if (listed && !force) {
            return Result(true, added = false, alreadyPresent = true, attempted = false, listVerified = true)
        }
        val receipt = port.add(target)
        val sdkError = receipt.suAuthWriteError()
        if (sdkError == SU_DELIVERY_INCOMPLETE) {
            val readback = port.snapshot()
            return Result(
                inList = readback?.contains(target) == true,
                added = false,
                alreadyPresent = listed,
                attempted = true,
                listVerified = readback != null,
                failure = sdkError,
                receipt = receipt,
            )
        }
        if (sdkError != "OK") {
            return Result(
                inList = false,
                added = false,
                alreadyPresent = listed,
                attempted = true,
                listVerified = false,
                failure = "ADD_FAILED:$sdkError",
                receipt = receipt,
            )
        }
        val readback = port.snapshot()
        if (readback == null || target !in readback) {
            return Result(
                inList = false,
                added = false,
                alreadyPresent = listed,
                attempted = true,
                listVerified = readback != null,
                failure = if (readback == null) "READBACK_FAILED" else "READBACK_MISMATCH",
                receipt = receipt,
            )
        }
        return Result(
            inList = true,
            added = true,
            alreadyPresent = false,
            attempted = true,
            listVerified = true,
            receipt = receipt,
        )
    }

    /** A listed package may retain its old UID; refresh once only after live SDK Root. */
    internal fun verifyExec(current: () -> Boolean, probe: () -> Boolean,
                            rootVerified: () -> Boolean, refresh: () -> Boolean): Boolean {
        if (!current()) return false
        if (probe()) return current()
        if (!current() || !rootVerified() || !current()) return false
        if (!refresh() || !current()) return false
        return probe() && current()
    }

    /**
     * Android 入口：用绑定当前安装身份的 [client] 保证本应用在 `su_auth` 里。
     * 阻塞（JNI），必须在后台线程调用。
     */
    fun ensure(
        context: Context,
        client: UltraRuntimeClient = UltraRuntimeClient(),
        packageName: String = context.packageName,
        force: Boolean = false,
    ): Result {
        val result = runCatching { ensure(clientPort(client), packageName, force) }.getOrElse { error ->
            Log.w(TAG, "self su_auth exception: ${error.javaClass.simpleName}")
            return Result(false, false, false, true, false, "EXCEPTION:${error.javaClass.simpleName}")
        }
        if (result.added || result.failure == SU_DELIVERY_INCOMPLETE) {
            // 进程内缓存跟着刷新（读快照一次；失败不影响结论）。
            runCatching { UltraAuthorization.refresh(context) }
                .onFailure { Log.w(TAG, "su_auth cache refresh failed (ignored)") }
        }
        when {
            result.failure != null -> Log.w(TAG, "self su_auth failed package=$packageName ${result.summary}")
            result.added -> Log.i(TAG, "self su_auth granted package=$packageName force=$force ${result.summary}")
            result.inList && result.alreadyPresent -> Log.i(TAG, "self su_auth already present package=$packageName")
            else -> Log.w(TAG, "self su_auth failed package=$packageName ${result.summary}")
        }
        return result
    }

    /** Signed Owner is a transport; the existing root-owned authority still owns the decision. */
    internal fun ensureOwner(context: Context, session: UltraRuntimeClient.ManagerOwnerIdentity,
                             current: () -> Boolean): Result {
        val scope = UltraAuthorization.captureOwnerScope(context, session, current)
            ?: return Result(false, false, false, false, false, "SU_AUTH_SCOPE_CHANGED")
        return ensureAuthority(context, scope)
    }

    private fun ensureAuthority(context: Context, scope: UltraAuthorization.Scope): Result {
        val authority = dev.maplesu.manager.runtime.authorization.SuperuserControl.ensureManagerGrant(context, scope)
        return ensureAuthority(context, scope, authority, clientPort(scope.client))
    }

    internal fun ensureAuthority(context: Context, scope: UltraAuthorization.Scope,
                                 authority: dev.maplesu.manager.runtime.authorization.SuperuserControl.Result,
                                 port: SuAuthPort): Result {
        if (!scope.current()) return Result(false, false, false, false, false, "SU_AUTH_SCOPE_CHANGED")
        if (!authority.succeeded) return Result(false, false, false, true, false,
            authority.code ?: "SU_AUTH_APPLY_PENDING", detail = authority.detail)
        val uid = context.applicationInfo.uid
        val profiles = port.uidProfiles()
        val readReceipt = port.uidProfileReadReceipt()
        if (!scope.current()) return Result(false, false, false, false, false, "SU_AUTH_SCOPE_CHANGED")
        if (profiles == null) return Result(false, false, false, false, false,
            port.uidProfileReadError() ?: "READ_FAILED", receipt = readReceipt, readReceipt = readReceipt)
        val present = profiles.any { it.uid == uid && it.allow }
        // Always synchronize this already-committed decision: list membership alone
        // does not establish the current installation's standard-su delivery.
        val attempt = UltraAuthorization.setUidGranted(context, uid, context.packageName, true, scope,
            durableDecisionCommitted = true)
        return Result(attempt.decisionVerified && attempt.succeeded, added = !present && attempt.succeeded,
            alreadyPresent = present, attempted = true, listVerified = attempt.decisionVerified,
            failure = attempt.error, receipt = attempt.receipt, readReceipt = attempt.readReceipt)
    }

    /** Reconfirm the sole authority before synchronizing standard-su delivery. */
    internal fun ensureCurrentAuthority(context: Context, client: UltraRuntimeClient,
                                        current: () -> Boolean = { true }): Result =
        runCatching {
            val scope = UltraAuthorization.captureClientScope(context, client, current)
                ?: return Result(false, false, false, false, false, "SU_AUTH_SCOPE_CHANGED")
            ensureAuthority(context, scope)
        }.getOrElse { error ->
            Log.w(TAG, "self su_auth exception: ${error.javaClass.simpleName}")
            Result(false, false, false, true, false, "EXCEPTION:${error.javaClass.simpleName}")
        }

    /** Existing installation completion consumer; no authority initialization occurs here. */
    fun onEnvironmentInstalled(context: Context, client: UltraRuntimeClient, current: () -> Boolean = { true }): Result =
        ensureCurrentAuthority(context, client, current)

    /** 把 [UltraRuntimeClient] 适配成 [SuAuthPort]（`snapshot()` 只在成功时返回列表）。 */
    fun clientPort(client: UltraRuntimeClient): SuAuthPort = clientPort(client) {}

    internal fun clientPort(client: UltraRuntimeClient,
                            onUidRead: (UltraRuntimeClient.SuUidProfilesSnapshot) -> Unit): SuAuthPort = object : SuAuthPort {
        override val supportsUidProfiles: Boolean = true
        private var profileReadError: String? = null
        private var profileReadReceipt: NativeReceipt? = null
        override fun uidProfileReadError(): String? = profileReadError
        override fun uidProfileReadReceipt(): NativeReceipt? = profileReadReceipt
        override fun uidProfiles(): List<SuUidProfile>? {
            val snapshot = client.suUidProfiles()
            profileReadReceipt = snapshot.receipt
            onUidRead(snapshot)
            if (snapshot.ok) {
                profileReadError = null
                return snapshot.profiles
            }
            // ERR_MODULE_STORAGE_NOT_FOUND (-19964) means the Ultra storage has no uid-profile
            // blob yet, which is the state of a freshly installed environment. Upstream treats it
            // as "nothing recorded" (runtime/ultra/authorization/su_allowlist_writer.cpp:57), so an
            // empty list is reported instead of failing the whole allowlist refresh.
            if (snapshot.receipt.sdkErrorCode == ERR_MODULE_STORAGE_NOT_FOUND) {
                profileReadError = null
                return emptyList()
            }
            profileReadError =
                "SDK_UID_READ:${suAuthLogCode(snapshot.receipt.sdkError)}:${snapshot.receipt.sdkErrorCode}"
            return null
        }
        override fun setUidProfile(uid: Int, packageName: String, allow: Boolean): NativeReceipt =
            client.setSuUidProfile(uid, packageName, allow)

        override fun snapshot(): List<String>? {
            val snapshot = client.suAuthSnapshot()
            return if (snapshot.ok) snapshot.packages else null
        }

        override fun add(packageName: String): NativeReceipt = client.addSuAuth(packageName)

        override fun remove(packageName: String): NativeReceipt = client.removeSuAuth(packageName)

        override fun refreshUidMapping(): NativeReceipt = client.refreshSuAuthList()
    }
}

/** All three receipt success fields must agree before acknowledging an authorization write. */
internal fun NativeReceipt.suAuthWriteError(): String =
    receiptErrorName(succeeded, sdkError)
