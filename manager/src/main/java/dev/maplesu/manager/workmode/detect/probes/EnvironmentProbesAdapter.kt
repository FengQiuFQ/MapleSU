// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.content.pm.ApplicationInfo
import dev.maplesu.manager.runtime.HookRootExecutor
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraIdentityRecovery
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.workmode.EnvironmentProbeRunner
import dev.maplesu.manager.workmode.ModeRuntime
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
import dev.maplesu.manager.workmode.detect.UltraIdentityObservation
import java.io.File

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
class EnvironmentProbesAdapter(
    private val context: Context,
    private val freshIdentity: Boolean = false,
) : EnvironmentProbes {

    private val readinessProbe = SuReadinessProbeAdapter(context)

    /** 当前明确外来分支的只读探针（APK 自带 ksud `debug info`）。 */
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
        val readiness = (if (freshIdentity) readinessProbe.probeFresh() else readinessProbe.probe()).readiness
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

    override fun currentUltraFingerprint(): String? = currentUltraIdentity().fingerprint

    override fun currentUltraIdentity(): UltraIdentityObservation {
        val result = runCatching { computeCurrentUltraIdentity() }
        EnvDiag.log("currentUltra=${result.getOrNull()} err=${result.exceptionOrNull()?.message}")
        return result.getOrThrow()
    }

    private fun computeCurrentUltraIdentity(): UltraIdentityObservation {
        if (freshIdentity) return freshUltraIdentity()
        // 与完整判定一致：当前认主的 Normal 内核优先于另一模式留下的缓存。
        if (ksuNormal() == true) return UltraIdentityObservation(null)
        // A live Hook supersedes cached SDK identity without starting competing IPC.
        if (HookRootExecutor.production(context.applicationContext).available()) return UltraIdentityObservation("hook:ready")
        val observed = UltraEnvironmentProbe.observeFreshIdentity(context.applicationContext)
        return UltraIdentityObservation("ultra:owner".takeIf { observed.managerOwnerIdentity != null },
            observed.managerOwnerIdentity)
    }

    override fun ultraFingerprint(): String? = ultraIdentity().fingerprint

    override fun ultraIdentity(): UltraIdentityObservation {
        val result = runCatching { computeUltraIdentity() }
        EnvDiag.log("ultraFingerprint=${result.getOrNull()} err=${result.exceptionOrNull()?.message}")
        return result.getOrThrow()
    }

    private fun computeUltraIdentity(): UltraIdentityObservation {
        if (freshIdentity) return freshUltraIdentity()
        if (ksuNormal() == true) return UltraIdentityObservation(null)
        if (HookRootExecutor.production(context.applicationContext).available()) return UltraIdentityObservation("hook:ready")
        // Reconcile the current signed installation before the resolver decides absence.
        // Recovery rechecks the live identity and state; preferences never authorize a mode.
        dev.maplesu.manager.runtime.ultra.UltraIdentityRecovery.recover(context.applicationContext)
        val observed = UltraEnvironmentProbe.observeFresh(context.applicationContext)
        return UltraIdentityObservation(UltraEnvironmentProbe.recoveryFingerprint(observed.state,
            observed.state == UltraEnvironmentProbe.State.Fault, observed.kernelRootVerified,
            observed.kernelChannelAbsent, observed.detail, observed.managerOwnerIdentity != null), observed.managerOwnerIdentity)
    }

    private fun freshUltraIdentity(): UltraIdentityObservation {
        if (ksuNormal() == true) return UltraIdentityObservation(null)
        val app = context.applicationContext
        val activation = ModeRuntime.activation
        val boot = dev.maplesu.manager.runtime.ultra.UltraEnvironmentAutoSetup.currentBootId()
            ?: throw IllegalStateException("ULTRA_PROBE_BOOT_UNAVAILABLE")
        val ownerCurrent = UltraRootKeyStore.captureOwnerMarker(app)
        fun current() = !UltraIdentityRecovery.blocked(app, freshIdentity = true) &&
            ModeRuntime.activation === activation && ownerCurrent() &&
            dev.maplesu.manager.runtime.ultra.UltraEnvironmentAutoSetup.currentBootId() == boot
        check(current()) { "ULTRA_PROBE_SCOPE_CHANGED" }
        val hook = HookRootExecutor.production(app, SuReadinessProbeAdapter.DEFAULT_TIMEOUT_MILLIS.toInt())
        if (hook.available()) {
            val result = hook.run("id -u")
            check(current()) { "ULTRA_PROBE_SCOPE_CHANGED" }
            check(result.ok && result.output.trim() == "0") {
                "ULTRA_HOOK_PROBE_UNKNOWN:${result.code}:${result.detail}"
            }
            return UltraIdentityObservation("hook:ready")
        }
        check(current()) { "ULTRA_PROBE_SCOPE_CHANGED" }
        val observed = UltraEnvironmentProbe.observeFreshIdentity(app)
        check(current()) { "ULTRA_PROBE_SCOPE_CHANGED" }
        return UltraIdentityObservation(UltraEnvironmentProbe.recoveryFingerprint(observed.state,
            observed.state == UltraEnvironmentProbe.State.Fault, observed.kernelRootVerified,
            observed.kernelChannelAbsent, observed.detail, observed.managerOwnerIdentity != null), observed.managerOwnerIdentity)
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
     * 只读地确认当前内核是否明确属于本项目模式以外的分支。
     *
     * 与 [ksuNormal] 互补：本端口使用 APK 自带 ksud 的内核 UAPI 与认主字段，
     * 同分支未认主或 legacy 回执不构成外来证据，保持 UNKNOWN。
     */
    override fun foreignKsuKernel(): Boolean? {
        val answer = foreignKsuProbe.kernelResponds(fresh = freshIdentity)
        EnvDiag.log("foreignKsu=$answer")
        return answer
    }

    companion object {
        /**
         * su 的既有落点（KernelSU/Magisk 都挂到 `/system/bin/su`；另两个是历史路径）。
         *
         * **仅用于枚举候选**：是否可用由 [SuReadinessProbeAdapter] 的真实子进程回答。
         */
        val SU_BINARY_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su")
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

    @Volatile
    private var sharedFreshRunner: EnvironmentCheckRunner? = null

    private var sharedProbeRunner = EnvironmentProbeRunner("maplesu-env-check")

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
                    probeRunner = sharedProbeRunner,
                ).also { sharedRunner = it }
            }
        }
    }

    /** Independent followers share one worker gate with the ordinary checker, never its results. */
    fun freshRunner(context: Context): EnvironmentCheckRunner {
        sharedFreshRunner?.let { return it }
        return synchronized(this) {
            sharedFreshRunner ?: run {
                val appContext = context.applicationContext
                val store = store(appContext)
                EnvironmentCheckRunner(
                    resolver = EnvironmentResolver(EnvironmentProbesAdapter(appContext, freshIdentity = true),
                        store, allowInheritance = false),
                    store = store,
                    bootIdSource = BootIdSourceAdapter,
                    probeRunner = sharedProbeRunner,
                ).also { sharedFreshRunner = it }
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
        synchronized(this) {
            sharedRunner = null
            sharedFreshRunner = null
            sharedProbeRunner = EnvironmentProbeRunner("maplesu-env-check")
        }
    }
}
