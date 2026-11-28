// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.maplesu.core.Natives.Profile

/**
 * KSU JNI 门面，保持上游适配的符号签名。
 *
 * ⚠️ **符号名契约**：C++ 侧（`applied/manager/app/src/main/cpp/jni.cc`）导出的符号是
 * `Java_dev_maplesu_manager_ksu_KsuNatives_getVersion` 这一类，由「包名 + 类名 + 方法名」
 * 机械决定。因此：
 *  - 本类的包/类名/方法名**不能改**（改名 = 换 ABI，必须同步改 C++ 导出）；
 *  - 成员必须是 **public**：Kotlin 的 `internal` 成员会被 name-mangle 成
 *    `getVersion$manager_debug`，JNI 就找不到符号；因此使用 public，并限制调用方经过后端门面；
 *  - 常量用 `external fun getVersion(): Int` 而不是 `external val version: Int`：
 *    Kotlin 2.4 不再允许 `external` 修饰属性（编译错误 `Modifier 'external' is not
 *    applicable to 'property'`），而属性 getter 编出来的 JVM 方法名本来就是 `getVersion`，
 *    两种写法产生**完全相同**的 JNI 符号。
 *
 * 加载必须懒：LITE 模式一次都不能触碰到它（R5）。所有外部调用都必须经过
 * [KsuNativeCalls]（native 缺失时安全降级为 unavailable，不 crash）。
 */
object KsuNatives {
    /** APK `lib/arm64-v8a/libmaplesu_ksu.so` 的库名（不带 lib/.so）。 */
    const val LIBRARY_NAME = "maplesu_ksu"

    // ── 版本 / 状态（JNI getter；7K jni.cc 的 getVersion/getKernelUAPIVersion/...）──
    external fun getVersion(): Int
    /** One current GET_INFO receipt: status, version, flags, kernel UAPI. */
    external fun getCurrentInfo(): IntArray?
    external fun isSafeMode(): Boolean
    external fun isLkmMode(): Boolean
    external fun isLkmBundled(): Boolean
    external fun isLateLoadMode(): Boolean
    external fun isManager(): Boolean
    external fun isPrBuild(): Boolean
    external fun getKernelUAPIVersion(): Int
    external fun getManagerUAPIVersion(): Int

    // ── 行为（与 7K jni.cc 的方法名/签名逐字一致）────────────────────────
    external fun uidShouldUmount(uid: Int): Boolean
    external fun appLockState(): Int
    external fun appLockAuth(hash: ByteArray): Boolean
    external fun appLockSet(hash: ByteArray, disable: Boolean): Boolean
    external fun stealthState(): Int
    external fun stealthSet(enabled: Boolean): Boolean
    external fun getAppProfile(key: String?, uid: Int): Profile?
    external fun setAppProfile(profile: Profile?): Boolean
    external fun isSuEnabled(): Boolean
    external fun setSuEnabled(enabled: Boolean): Boolean
    external fun isKernelUmountEnabled(): Boolean
    external fun setKernelUmountEnabled(enabled: Boolean): Boolean
    external fun isSelinuxHideEnabled(): Boolean
    external fun setSelinuxHideEnabled(enabled: Boolean): Int
    external fun getUserName(uid: Int): String?
    external fun getSuperuserCount(): Int
}

/**
 * native 加载器：可注入 delegate，供单测证明「加载失败 → 安全降级」。
 *
 * 只加载一次；加载失败后状态固定为 [State.UNAVAILABLE]，后续调用直接走默认值，
 * 不会每次抛 `UnsatisfiedLinkError`（生产上反复抛会刷日志/拖慢首帧）。
 */
internal object KsuNativeLoader {
    enum class State { NOT_ATTEMPTED, LOADED, UNAVAILABLE }

    fun interface Delegate {
        fun load(libraryName: String)
    }

    @Volatile
    private var delegate: Delegate = Delegate { name -> System.loadLibrary(name) }

    @Volatile
    var state: State = State.NOT_ATTEMPTED
        private set

    @Volatile
    var lastError: String? = null
        private set

    fun ensureLoaded(): Boolean {
        if (state == State.LOADED) return true
        if (state == State.UNAVAILABLE) return false
        synchronized(this) {
            if (state == State.LOADED) return true
            if (state == State.UNAVAILABLE) return false
            return try {
                delegate.load(KsuNatives.LIBRARY_NAME)
                state = State.LOADED
                true
            } catch (t: Throwable) {
                // UnsatisfiedLinkError / SecurityException / 空 so 都归到这里
                state = State.UNAVAILABLE
                lastError = "${t.javaClass.simpleName}: ${t.message}"
                KsuLog.unavailable("KsuNatives", lastError ?: "load failed")
                false
            }
        }
    }

    /** 仅供单测：注入替身并清状态。 */
    fun installForTest(newDelegate: Delegate?) {
        synchronized(this) {
            delegate = newDelegate ?: Delegate { name -> System.loadLibrary(name) }
            state = State.NOT_ATTEMPTED
            lastError = null
        }
    }
}

/**
 * JNI 的安全调用层：native 未加载 / 符号缺失 / 结构失败一律返回无能力默认值。
 *
 * 与 7K `jni.cc` 的语义对齐：
 * - `getAppProfile` 结构失败 → null（不伪造 Profile）；
 * - `setSelinuxHideEnabled` 不可用 → -1；`appLockState` → -1（LITE 同款无能力值）；
 * - 其余布尔 → false、计数 → -1。
 */
object KsuNativeCalls {
    val available: Boolean get() = KsuNativeLoader.ensureLoaded()

    val loadError: String? get() = KsuNativeLoader.lastError

    private inline fun <T> call(default: T, block: () -> T): T {
        if (!available) return default
        return try {
            block()
        } catch (t: Throwable) {
            // 连 OutOfMemory 之类 Error 也按「不可用」处理：native 侧崩溃不应拖死 UI。
            KsuLog.record("native-error", "${t.javaClass.simpleName}: ${t.message}")
            default
        }
    }

    val version: Int get() = call(-1) { KsuNatives.getVersion() }
    fun currentInfo(): IntArray? = call<IntArray?>(null) { KsuNatives.getCurrentInfo() }
    val isSafeMode: Boolean get() = call(false) { KsuNatives.isSafeMode() }
    val isLkmMode: Boolean get() = call(false) { KsuNatives.isLkmMode() }
    val isLkmBundled: Boolean get() = call(false) { KsuNatives.isLkmBundled() }
    val isLateLoadMode: Boolean get() = call(false) { KsuNatives.isLateLoadMode() }
    val isManager: Boolean get() = call(false) { KsuNatives.isManager() }
    val isPrBuild: Boolean get() = call(false) { KsuNatives.isPrBuild() }
    val kernelUAPIVersion: Int get() = call(-1) { KsuNatives.getKernelUAPIVersion() }
    val managerUAPIVersion: Int get() = call(-1) { KsuNatives.getManagerUAPIVersion() }

    fun uidShouldUmount(uid: Int): Boolean = call(false) { KsuNatives.uidShouldUmount(uid) }

    fun appLockState(): Int = call(-1) { KsuNatives.appLockState() }
    fun appLockAuth(hash: ByteArray): Boolean = call(false) { KsuNatives.appLockAuth(hash) }
    fun appLockSet(hash: ByteArray, disable: Boolean): Boolean =
        call(false) { KsuNatives.appLockSet(hash, disable) }

    fun stealthState(): Int = call(-1) { KsuNatives.stealthState() }
    fun stealthSet(enabled: Boolean): Boolean = call(false) { KsuNatives.stealthSet(enabled) }

    fun getAppProfile(key: String?, uid: Int): Profile? =
        call<Profile?>(null) { KsuNatives.getAppProfile(key, uid) }

    fun setAppProfile(profile: Profile?): Boolean = call(false) { KsuNatives.setAppProfile(profile) }

    fun isSuEnabled(): Boolean = call(false) { KsuNatives.isSuEnabled() }
    fun setSuEnabled(enabled: Boolean): Boolean = call(false) { KsuNatives.setSuEnabled(enabled) }

    fun isKernelUmountEnabled(): Boolean = call(false) { KsuNatives.isKernelUmountEnabled() }
    fun setKernelUmountEnabled(enabled: Boolean): Boolean =
        call(false) { KsuNatives.setKernelUmountEnabled(enabled) }

    fun isSelinuxHideEnabled(): Boolean = call(false) { KsuNatives.isSelinuxHideEnabled() }
    fun setSelinuxHideEnabled(enabled: Boolean): Int =
        call(-1) { KsuNatives.setSelinuxHideEnabled(enabled) }

    fun getUserName(uid: Int): String? = call<String?>(null) { KsuNatives.getUserName(uid) }
    fun getSuperuserCount(): Int = call(-1) { KsuNatives.getSuperuserCount() }

    /** 单测/集成测试用：重置加载状态。 */
    fun resetForTest() = KsuNativeLoader.installForTest(null)
}
