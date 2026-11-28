// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect

import dev.maplesu.manager.workmode.EnvironmentProbeResult
import dev.maplesu.manager.workmode.EnvironmentProbeRunner
import dev.maplesu.manager.runtime.PageReadDeadline
import kotlinx.coroutines.CompletableDeferred

/**
 * T14：环境检查的**单次执行器** —— 8000 ms 总超时 + 单飞（single-flight）。
 *
 * 用户要求：
 * - 单次探测总超时 **8000 ms**；拿不到结论就如实 [EnvironmentVerdict.UNKNOWN] 并**保留上次状态**
 *   （绝不把 UNKNOWN 写成"未安装"）。
 * - 重试必须单飞：并发/连点复用**同一个**进行中的探测，UI 不得在两种状态之间抖动。
 * - 超时后允许用户手动重试，但**不自动无限重试**（本类不含任何定时器/轮询）。
 *
 * 实现纪律：
 * - 只有一个 `CompletableDeferred` 作为"进行中的那一次"；leader 真正跑探测，follower 直接
 *   等它，因此 N 次点击 = 1 次探测、1 个结论。
 * - 超时/异常都不写磁盘（`EnvironmentResolver` 只在给出终态时落盘），上次状态原样保留。
 * - 超时的底层线程可能还在跑；[EnvironmentProbeRunner] 的 `running` 闸门保证在它退出之前
 *   不会另起第二个 worker（次要调用得到 Busy → UNKNOWN）。
 */
class EnvironmentCheckRunner(
    private val resolver: EnvironmentResolver,
    private val store: EnvironmentStateStore,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
    private val clock: Clock = WallClock,
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
    private val probeRunner: EnvironmentProbeRunner = EnvironmentProbeRunner("maplesu-env-check"),
) {

    private val lock = Any()

    /** 进行中的那一次（null = 空闲）。 */
    private var inflight: CompletableDeferred<EnvironmentCheckOutcome>? = null

    /** 生产/测试共用的预算（用户明确要求 8 s）。 */
    val timeout: Long get() = timeoutMillis

    /** 当前是否有一次探测在进行（诊断用；不触发任何事）。 */
    val busy: Boolean
        get() = synchronized(lock) { inflight != null }

    suspend fun check(): EnvironmentCheckOutcome = check(timeoutMillis)

    suspend fun check(maxBudgetMillis: Long): EnvironmentCheckOutcome {
        val budget = minOf(timeoutMillis, maxBudgetMillis)
        if (budget <= 0L) return execute(budget)
        var leader = false
        val deferred = synchronized(lock) {
            inflight ?: CompletableDeferred<EnvironmentCheckOutcome>().also { created ->
                inflight = created
                leader = true
            }
        }
        if (!leader) return deferred.await()

        try {
            val outcome = execute(budget)
            // 先发布再关窗口：这期间到达的 follower 拿到的是已完成的同一份结论（不重复探测）。
            deferred.complete(outcome)
            synchronized(lock) { if (inflight === deferred) inflight = null }
            return outcome
        } catch (error: Throwable) {
            deferred.completeExceptionally(error)
            synchronized(lock) { if (inflight === deferred) inflight = null }
            throw error
        }
    }

    private suspend fun execute(budget: Long): EnvironmentCheckOutcome {
        val startedAt = clock.nowMillis()
        val bootId = runCatching { bootIdSource.read() }.getOrDefault("")
        if (budget <= 0L) {
            return unknown(bootId, EnvironmentCheckDetail.DEADLINE_EXCEEDED, startedAt)
        }
        // 预算即"落盘许可"的边界：跑到超时之后才出结果的探测不得覆盖上次状态。
        val deadlineNanos = PageReadDeadline.limitNanos(budget)
        val ran = probeRunner.run(budget) {
            resolver.resolve(bootId) {
                !Thread.currentThread().isInterrupted && System.nanoTime() < deadlineNanos
            }
        }
        return when (ran) {
            is EnvironmentProbeResult.Completed -> ran.value
            EnvironmentProbeResult.TimedOut ->
                unknown(bootId, EnvironmentCheckDetail.DEADLINE_EXCEEDED, startedAt)
            EnvironmentProbeResult.Busy ->
                unknown(bootId, EnvironmentCheckDetail.PROBE_STILL_RUNNING, startedAt)
            is EnvironmentProbeResult.Failed ->
                unknown(
                    bootId,
                    EnvironmentCheckDetail.PROBE_FAILED + ":" +
                        (ran.cause.message ?: ran.cause.javaClass.simpleName),
                    startedAt,
                )
        }
    }

    /** UNKNOWN：**保留**上次状态（[EnvironmentStateStore] 一个字节都不写）。 */
    private fun unknown(bootId: String, detail: String, startedAt: Long): EnvironmentCheckOutcome {
        val previous = store.snapshot()
        return EnvironmentCheckOutcome(
            verdict = EnvironmentVerdict.UNKNOWN,
            mode = previous?.mode,
            snapshot = previous,
            trigger = null,
            detail = detail,
            bootId = bootId,
            elapsedMillis = (clock.nowMillis() - startedAt).coerceAtLeast(0L),
        )
    }

    companion object {
        /** 用户明确要求的单次探测总超时。 */
        const val DEFAULT_TIMEOUT_MILLIS: Long = 8_000L
    }
}
