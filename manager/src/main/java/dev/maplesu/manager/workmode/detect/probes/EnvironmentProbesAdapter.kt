// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.content.pm.ApplicationInfo
import dev.maplesu.manager.runtime.HookRootExecutor
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.workmode.detect.EnvDiag
import dev.maplesu.manager.workmode.detect.EnvironmentCheckRunner
import dev.maplesu.manager.workmode.detect.EnvironmentInvalidation
import dev.maplesu.manager.workmode.detect.EnvironmentProbes
import dev.maplesu.manager.workmode.detect.EnvironmentResolver
import dev.maplesu.manager.workmode.detect.EnvironmentSnapshot
import dev.maplesu.manager.workmode.detect.EnvironmentSnapshotCodec
import dev.maplesu.manager.workmode.detect.EnvironmentStatePersistence
import dev.maplesu.manager.workmode.detect.EnvironmentStateStore
import dev.maplesu.manager.workmode.detect.SuReadiness
import java.io.File
import java.util.concurrent.CancellationException

/**
 * T14 生产探针：先读当前 Ultra 通道，再执行未确认身份的恢复链。
 *
 * 1. [suReadiness]/[suPresent]：**真实子进程探针**（§5 C6）。枚举 MapleSU 自有 su
 *    （`/data/<16hex>/su`、`/dev/maplesu/bin/su`）、KSU su 与 `libksud_ksu.so debug su`、
 *    以及绑定本 boot 的 L3 gate，逐个执行 `sh -c 'id -u'`；只有 exit 0 + stdout uid=0
 *    才算 USABLE。`File.exists` 只用于枚举候选，**任何结论都不来自文件存在**。
 *    读不到/超时 = UNKNOWN，绝不折叠成 false（旧实现就是这样把"重启后"误判成未安装的）。
 *    默认预算 ≤1500ms（[SuReadinessProbeAdapter.DEFAULT_TIMEOUT_MILLIS]）。
 *    绝不调用 `KsuCli.rootAvailable()`（那会走 `RootManagement`，在没装 Ultra 的设备上
 *    直接 `MANAGEMENT_CREDENTIAL_UNAVAILABLE`）。
 * 2. [currentUltraFingerprint]：先核对当前 Ultra / 本 boot 已就绪的 Hook 通道。
 *    [ultraFingerprint] 仅在未确认身份时恢复凭据并重读通道。
 *    凭据和历史配对仅用于安装、恢复；从 Ultra 迁到 Normal 后仍会保留，不是运行证据。
 * 3. [ksuNormal]：JNI `KsuBackends.natives()` 的只读快照（经 [KsuKernelProbeAdapter]，
 *    不在本文件直接 import `dev.maplesu.manager.ksu.*`）。这是解除"判不出模式 → 不装
 *    KSU 通道 → 拿不到 root → 判不出模式"互锁的唯一例外：**只读探针**，
 *    不放宽 `RootManagement` 的路由语义，也不注册任何 root 通道。
 */
class EnvironmentProbesAdapter(private val context: Context) : EnvironmentProbes {

    private val readinessProbe = SuReadinessProbeAdapter(context)

    /** 「有内核在响应」的只读探针（APK 自带 ksud `debug info`，不解互锁的 root 通道）。 */
    private val foreignKsuProbe = ForeignKsuProbe(context)

    init {
        // 调试版才落盘诊断；正式包不安装 = 不产生任何文件。
        val debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (debuggable) {
            EnvDiag.install(File(context.cacheDir, "env-diag.log"), System.currentTimeMillis())
        }
    }

    /** 真子进程探针（默认 ≤1500ms；进程级缓存 2s，一次刷新只跑一轮）。 */
    override fun suReadiness(): SuReadiness {
        val readiness = readinessProbe.probe().readiness
        EnvDiag.log("suReadiness=$readiness")
        return readiness
    }

    /**
     * 旧布尔端口：`suReadiness() == USABLE`。
     *
     * ⚠️ 不再用 `File.exists()/canExecute()` 当实现（§5 C6）。读不到 = false，但调用方
     * （resolver）用 [suReadiness] 区分 UNKNOWN，不会把它落成"未安装"。
     */
    override fun suPresent(): Boolean = suReadiness() == SuReadiness.USABLE

    override fun currentUltraFingerprint(): String? {
        val result = runCatching { computeCurrentUltraFingerprint() }
        EnvDiag.log("currentUltra=${result.getOrNull()} err=${result.exceptionOrNull()?.message}")
        return result.getOrThrow()
    }

    private fun computeCurrentUltraFingerprint(): String? {
        // 与完整判定一致：当前认主的 Normal 内核优先于另一模式留下的缓存。
        if (ksuNormal() == true) return null
        // A live Hook supersedes cached SDK identity without starting competing IPC.
        if (HookRootExecutor.production(context.applicationContext).available()) return "hook:ready"
        // Otherwise revalidate the SDK TTL before inheriting a same-boot fingerprint.
        UltraEnvironmentProbe.refresh(context.applicationContext, force = false)
        val failures = mutableListOf<String>()
        for ((name, judge) in ultraJudges()) {
            val hit = try {
                judge()
            } catch (error: Throwable) {
                if (error is CancellationException) throw error
                if (error is InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw error
                }
                if (error is Error) throw error
                failures += name
                continue
            }
            if (hit) return name
        }
        // 有判据读失败 ⇒ 不能断言"没有 Ultra 环境"（UNKNOWN ≠ 没有）。
        if (failures.isNotEmpty()) {
            throw IllegalStateException("ULTRA_PROBE_PARTIAL:" + failures.joinToString(","))
        }
        return null
    }

    override fun ultraFingerprint(): String? {
        val result = runCatching { computeUltraFingerprint() }
        EnvDiag.log("ultraFingerprint=${result.getOrNull()} err=${result.exceptionOrNull()?.message}")
        return result.getOrThrow()
    }

    private fun computeUltraFingerprint(): String? {
        if (ksuNormal() == true) return null
        if (HookRootExecutor.production(context.applicationContext).available()) return "hook:ready"
        // Last chance before the resolver publishes NotInstalled. A reinstall may
        // have lost all app preferences while the environment/key backup survives.
        // The current channel was already read before SU; avoid repeating Unknown
        // observations here before recovery changes the credentials.
        // Recovery checks the current key, saved image candidates, then broker/backup, and
        // refreshes the live SDK state. Neither a saved key nor Root alone is a mode.
        dev.maplesu.manager.runtime.ultra.UltraIdentityRecovery.recover(context.applicationContext)
        UltraEnvironmentProbe.refresh(context.applicationContext, force = false)
        val observed = UltraEnvironmentProbe.currentSnapshot(context)
        return ultraRecoveryFingerprint(
            state = observed.state,
            safeMode = UltraEnvironmentProbe.isSafeMode(context),
            kernelRootVerified = observed.kernelRootVerified,
            kernelChannelAbsent = observed.kernelChannelAbsent,
            sdkChannelAvailable = observed.sdkChannelAvailable,
        )
    }

    override fun ksuNormal(): Boolean? {
        val snapshot = KsuKernelProbeAdapter.currentSnapshot()
        // native 没加载 = 这次读不到（unknown），不是"没有 KSU"。
        val normal = KsuProbeMapping.normalStatus(snapshot)
        EnvDiag.log(
            "ksuNormal=$normal available=${snapshot.available} version=${snapshot.version} " +
                "isManager=${snapshot.isManager} isLkm=${snapshot.isLkm}",
        )
        return normal
    }

    /**
     * 只读地确认"有没有内核在响应"。
     *
     * 与 [ksuNormal] 互补：后者回答"是不是 MapleSU_Normal"，依赖 JNI；本端口回答
     * "这台机器上有没有 KSU 内核"，走 APK 自带 ksud。二者都为 null 才允许落到 UNKNOWN。
     */
    override fun foreignKsuKernel(): Boolean? {
        val answer = foreignKsuProbe.kernelResponds()
        EnvDiag.log("foreignKsu=$answer")
        return answer
    }

    private fun ultraJudges(): List<Pair<String, () -> Boolean>> = listOf(
        "ultra:running" to {
            val observation = UltraEnvironmentProbe.currentSnapshot(context)
            observation.state == UltraEnvironmentProbe.State.Running &&
                UltraEnvironmentProbe.kernelChannelObserved(observation)
        },
        "ultra:fault" to { UltraEnvironmentProbe.isSafeMode(context) },
        "ultra:kernel" to { UltraEnvironmentProbe.isKernelRootVerified(context) },
        "hook:ready" to { HookRootExecutor.production(context.applicationContext).available() },
    )

    companion object {
        /**
         * su 的既有落点（KernelSU/Magisk 都挂到 `/system/bin/su`；另两个是历史路径）。
         *
         * **仅用于枚举候选**：是否可用由 [SuReadinessProbeAdapter] 的真实子进程回答。
         */
        val SU_BINARY_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su")

        /** `UltraEnvironmentProbe.recoveryFingerprint` 在"读不到 Ultra 环境"时抛出的消息。 */
        private const val ULTRA_RECOVERY_PROBE_UNKNOWN = "ULTRA_RECOVERY_PROBE_UNKNOWN"
    }
}

/** 上次环境状态的 prefs 持久化（单进程：管理器进程；root 服务进程不写这里）。 */
class EnvironmentStatePrefsPersistence(context: Context) : EnvironmentStatePersistence {

    private val prefs = context.applicationContext
        .ultraPreferences(EnvironmentCheckProduction.PREFS_NAME, Context.MODE_PRIVATE)

    override fun read(): EnvironmentSnapshot? {
        val values = prefs.all.mapValues { (_, value) -> value as? String }
        val snapshot = EnvironmentSnapshotCodec.decode(values)
        // One-time cleanup of the removed unresolved-SU state; preserve confirmed modes.
        if ("env.suTemp" in values) {
            val editor = prefs.edit()
            if (snapshot == null) editor.clear() else editor.remove("env.suTemp")
            editor.apply()
        }
        return snapshot
    }

    override fun write(snapshot: EnvironmentSnapshot) {
        val values = EnvironmentSnapshotCodec.encode(snapshot)
        val editor = prefs.edit()
        prefs.all.keys.filter { it !in values }.forEach { editor.remove(it) }
        values.forEach { (key, value) -> editor.putString(key, value) }
        editor.apply()
    }

    override fun clear() {
        prefs.edit().clear().apply()
    }
}

/**
 * 生产装配点（**唯一**）：环境检查的执行器、上次状态仓库、以及"置脏"入口。
 *
 * 执行器是**进程级单例**：单飞（single-flight）必须跨调用点生效，否则首页重试与
 * 启动判定各建一个执行器就会各跑一次探测（用户看到的"乱跳"就是这类并发）。
 */
object EnvironmentCheckProduction {

    /** 中性 prefs 名（不含包名/凭据/路径）。 */
    const val PREFS_NAME = "maplesu_environment_state"

    @Volatile
    private var sharedRunner: EnvironmentCheckRunner? = null

    fun store(context: Context): EnvironmentStateStore =
        EnvironmentStateStore(EnvironmentStatePrefsPersistence(context))

    fun runner(context: Context): EnvironmentCheckRunner {
        sharedRunner?.let { return it }
        return synchronized(this) {
            sharedRunner ?: run {
                val appContext = context.applicationContext
                val store = store(appContext)
                EnvironmentCheckRunner(
                    resolver = EnvironmentResolver(EnvironmentProbesAdapter(appContext), store),
                    store = store,
                    bootIdSource = BootIdSourceAdapter,
                ).also { sharedRunner = it }
            }
        }
    }

    /**
     * 让上次状态失效（模式切换 / 刷写 / 越狱完成 / 用户强制重试）。
     *
     * 只打开 `dirty` 位，`mode` 等字段保留：下次检查前仍能显示"上次状态"，且 UNKNOWN
     * 时不会把上次结论清成"未安装"。
     *
     * @return 更新后的快照；null = 本来就没有状态（不需要置脏）。
     */
    fun markDirty(context: Context, reason: EnvironmentInvalidation): EnvironmentSnapshot? =
        runCatching { store(context).markDirty(reason) }.getOrNull()

    /** 仅供测试替换（生产不调用）。 */
    internal fun resetForTest() {
        synchronized(this) { sharedRunner = null }
    }
}

/**
 * Ultra 恢复阶段的指纹判定。
 *
 * `recoveryFingerprint` 在 `Unknown` 且内核通道缺席时返回 null，其余 `Unknown`
 * 情况抛 `ULTRA_RECOVERY_PROBE_UNKNOWN`——resolver 会把它当成"探针失败"并停在
 * UNKNOWN（这是对的：读不到不等于没有）。
 *
 * 但"整条 SDK 通道一次都没有应答过"（`sdkChannelAvailable == false`）不是读取失败，
 * 而是这台机器上没有可读的 MapleSU 环境：帮助进程没装、内核也没有 MapleSU 桥。
 * 这种情况继续抛会让装了第三方 KernelSU 的机器永久停在「环境检查未完成」
 * （issue #11）。此时无 Ultra 指纹，判定继续走 KSU / 外来内核分支，得到诚实的
 * 「未安装」结论。
 */
internal fun ultraRecoveryFingerprint(
    state: UltraEnvironmentProbe.State,
    safeMode: Boolean,
    kernelRootVerified: Boolean,
    kernelChannelAbsent: Boolean,
    sdkChannelAvailable: Boolean,
): String? {
    val attempt = runCatching {
        UltraEnvironmentProbe.recoveryFingerprint(state, safeMode, kernelRootVerified, kernelChannelAbsent)
    }
    val error = attempt.exceptionOrNull() ?: return attempt.getOrNull()
    if (error.message == ULTRA_RECOVERY_PROBE_UNKNOWN && !sdkChannelAvailable) return null
    throw error
}

/** `UltraEnvironmentProbe.recoveryFingerprint` 在"读不到 Ultra 环境"时抛出的消息。 */
private const val ULTRA_RECOVERY_PROBE_UNKNOWN = "ULTRA_RECOVERY_PROBE_UNKNOWN"
