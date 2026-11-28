// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.maplesu.core.Natives.Profile

/**
 * KSU 模式的 `NativesBackend` 实现。
 *
 * 语义来源：
 * - 上游/7K `manager/app/src/main/cpp/jni.cc` 的返回值约定（`-1` = 无能力/失败）；
 * - 7K `Natives.kt` 的两条 `umount` 默认值实现：它们不是 JNI，而是
 *   「以 `$` / uid 9999 的 profile 为默认值载体」（7K `Natives.kt:122-144`）。
 *
 * 未加载 native 时**不是抛出**，而是构造 [unavailable]：所有读操作返回无能力默认值，
 * 写操作返回 false，并记录一条 `ksu.unavailable` 日志（03 §3.9）。
 */
class KsuNativesBackend private constructor(
    private val calls: KsuNativeCalls = KsuNativeCalls,
    private val availableFlag: Boolean,
    private val unavailableReason: String?,
) {

    val available: Boolean get() = availableFlag

    // ── 只读状态 ─────────────────────────────────────────────────────────
    val version: Int get() = if (availableFlag) calls.version else -1
    fun currentInfo(): IntArray? = if (availableFlag) calls.currentInfo() else null
    val isSafeMode: Boolean get() = availableFlag && calls.isSafeMode
    val isLkmMode: Boolean get() = availableFlag && calls.isLkmMode
    val isLkmBundled: Boolean get() = availableFlag && calls.isLkmBundled
    val isLateLoadMode: Boolean get() = availableFlag && calls.isLateLoadMode
    val isManager: Boolean get() = availableFlag && calls.isManager
    val isPrBuild: Boolean get() = availableFlag && calls.isPrBuild
    val kernelUAPIVersion: Int get() = if (availableFlag) calls.kernelUAPIVersion else -1
    val managerUAPIVersion: Int get() = if (availableFlag) calls.managerUAPIVersion else -1

    fun uidShouldUmount(uid: Int): Boolean = availableFlag && calls.uidShouldUmount(uid)

    // ── app lock（7K 内核侧是弃用桩：state 恒 2、auth 恒 true、set 恒 false）──
    fun appLockState(): Int = if (availableFlag) calls.appLockState() else -1
    fun appLockAuth(hash: ByteArray): Boolean = availableFlag && calls.appLockAuth(hash)
    fun appLockSet(hash: ByteArray, disable: Boolean): Boolean =
        availableFlag && calls.appLockSet(hash, disable)

    // ── stealth ─────────────────────────────────────────────────────────
    fun stealthState(): Int = if (availableFlag) calls.stealthState() else -1
    fun stealthSet(enabled: Boolean): Boolean = availableFlag && calls.stealthSet(enabled)

    // ── app profile ─────────────────────────────────────────────────────
    /** JNI 结构失败才 null；未认主时 JNI 返回「默认 profile」而不是 null（03 §3.9）。 */
    fun getAppProfile(key: String?, uid: Int): Profile? =
        if (availableFlag) calls.getAppProfile(key, uid) else null

    fun setAppProfile(profile: Profile?): Boolean =
        availableFlag && profile != null && calls.setAppProfile(profile)

    // ── su / feature 开关 ────────────────────────────────────────────────
    fun isSuEnabled(): Boolean = availableFlag && calls.isSuEnabled()
    fun setSuEnabled(enabled: Boolean): Boolean = availableFlag && calls.setSuEnabled(enabled)

    fun isKernelUmountEnabled(): Boolean = availableFlag && calls.isKernelUmountEnabled()
    fun setKernelUmountEnabled(enabled: Boolean): Boolean =
        availableFlag && calls.setKernelUmountEnabled(enabled)

    fun isSelinuxHideEnabled(): Boolean = availableFlag && calls.isSelinuxHideEnabled()

    /** 返回 0 = 成功；-1 = 不可用/失败（与 7K `setSelinuxHideEnabled` 一致）。 */
    fun setSelinuxHideEnabled(enabled: Boolean): Int =
        if (availableFlag) calls.setSelinuxHideEnabled(enabled) else -1

    fun getUserName(uid: Int): String? = if (availableFlag) calls.getUserName(uid) else null

    fun getSuperuserCount(): Int = if (availableFlag) calls.getSuperuserCount() else -1

    // ── umount 默认值（7K 用 `$`/9999 的 profile 承载，不新增 JNI）──────────
    fun setDefaultUmountModules(enabled: Boolean): Boolean =
        setAppProfile(Profile("$", 9999, false, umountModules = enabled))

    fun isDefaultUmountModules(): Boolean =
        getAppProfile("$", 9999)?.umountModules ?: true

    /**
     * 「功能齐全」判据：认主 + 内核 UAPI >= 管理器编译期 UAPI。
     * **不含** `rootAvailable()`（该调用会启动 shell；此处与 7K 有意保持差异）。
     */
    fun isFullFeatured(): Boolean {
        if (!availableFlag || !calls.isManager) return false
        val kernel = calls.kernelUAPIVersion
        val manager = calls.managerUAPIVersion
        return kernel > 0 && manager > 0 && kernel >= manager
    }

    companion object {
        /** native 已加载时使用。 */
        fun available(): KsuNativesBackend {
            KsuNativeLoader.ensureLoaded()
            return KsuNativesBackend(availableFlag = KsuNativeLoader.state ==
                KsuNativeLoader.State.LOADED, unavailableReason = KsuNativeLoader.lastError)
        }

        /** native 不可用：返回全默认值的安全替身（并记录原因）。 */
        fun unavailable(reason: String): KsuNativesBackend {
            KsuLog.unavailable("KsuNativesBackend", reason)
            return KsuNativesBackend(availableFlag = false, unavailableReason = reason)
        }

        /**
         * 集成入口：按 native 实际状态返回可用/降级替身。
         * 未加载 native 时**不会**尝试 load（`KsuNativeCalls.available` 才会），
         * 调用方若处于 LITE 模式请直接用 `unavailable(...)`。
         */
        fun current(): KsuNativesBackend = if (KsuNativeLoader.ensureLoaded()) {
            KsuNativesBackend.available()
        } else {
            KsuNativesBackend.unavailable(KsuNativeLoader.lastError ?: "native not loaded")
        }
    }
}
