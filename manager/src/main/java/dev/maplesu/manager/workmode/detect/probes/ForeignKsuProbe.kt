// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect.probes

import android.content.Context
import android.util.Log
import dev.maplesu.manager.runtime.PageReadDeadline
import java.io.File
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit

/**
 * 只读探针：当前回执是否明确属于本项目模式以外的 KernelSU 分支。
 *
 * 为什么需要它：环境检查的 [dev.maplesu.manager.workmode.detect.EnvironmentProbes.ksuNormal]
 * 走 JNI 快照，只有「内核认本管理器为主」时才会答 true，JNI 读不到时答 null。于是
 * 只有正版本、未认主及明确不同的内核 UAPI 才能补充外来分支证据。
 *
 * 同分支未认主、缺失 UAPI 与 Ultra 自身的 UAPI 0 兼容接口均保持未知；
 * 版本响应本身不排除本项目，userspace UAPI 也不代表当前内核。
 *
 * 约束（与 [SuReadinessProbeAdapter] 同规格）：
 * - 只执行 APK 自带的 `<nativeLibraryDir>/libksud_ksu.so debug info`，不写文件、不碰分区；
 * - 内核拒绝 / 被 seccomp 拦 / 进程起不来 / 超时 ⇒ null（读不到），**绝不**折叠成 false；
 * - 结果进程内缓存 [CACHE_MILLIS]，一次环境检查只跑一轮。
 */
internal class ForeignKsuProbe(
    context: Context,
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
    private val nanoTime: () -> Long = { System.nanoTime() / 1_000_000L },
) {

    private val daemon = File(context.applicationInfo.nativeLibraryDir, DAEMON_LIB_NAME)

    @Volatile
    private var cachedAtMillis: Long = Long.MIN_VALUE

    @Volatile
    private var cached: Boolean? = null

    /** true = 当前明确外来分支；null = 未确认归属或本次读不到。 */
    fun kernelResponds(fresh: Boolean = false): Boolean? {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("FOREIGN_KSU_PROBE_INTERRUPTED")
        val now = nanoTime()
        if (!fresh && cachedAtMillis != Long.MIN_VALUE && now - cachedAtMillis in 0 until CACHE_MILLIS) {
            Log.i(TAG, "foreign ksu probe cached=$cached")
            return cached
        }
        val startedAt = now
        val answer = try {
            probe()
        } catch (error: CancellationException) {
            throw error
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw error
        } catch (_: Throwable) {
            null
        }
        if (!fresh) {
            cached = answer
            cachedAtMillis = now
        }
        Log.i(TAG, "foreign ksu probe answer=$answer took=${nanoTime() - startedAt}ms")
        return answer
    }

    private fun probe(): Boolean? {
        val deadline = PageReadDeadline.limitNanos(timeoutMillis)
        if (deadline - System.nanoTime() <= 0) return null
        if (!daemon.isFile) {
            Log.i(TAG, "foreign ksu probe missing daemon=${daemon.absolutePath}")
            return null
        }
        val process = ProcessBuilder(daemon.absolutePath, "debug", "info")
            .redirectErrorStream(true)
            .start()
        return try {
            // ksud 的 `debug info` 不读 stdin；立刻关掉，避免子进程阻塞在管道上。
            runCatching { process.outputStream.close() }
            val output = StringBuilder()
            val reader = Thread {
                runCatching {
                    process.inputStream.bufferedReader().use { stream ->
                        stream.forEachLine { line ->
                            synchronized(output) {
                                if (output.length < MAX_OUTPUT_CHARS) output.append(line).append('\n')
                            }
                        }
                    }
                }
            }.apply {
                isDaemon = true
                name = "MapleSUForeignKsuProbe"
                start()
            }
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0 || !process.waitFor(remaining, TimeUnit.NANOSECONDS)) {
                process.destroyForcibly()
                Log.i(TAG, "foreign ksu probe timeout after ${timeoutMillis}ms")
                return null
            }
            val readerBudget = minOf(deadline - System.nanoTime(),
                TimeUnit.MILLISECONDS.toNanos(READER_JOIN_MILLIS))
            if (readerBudget > 0) TimeUnit.NANOSECONDS.timedJoin(reader, readerBudget)
            val code = process.exitValue()
            if (code != 0) {
                Log.i(TAG, "foreign ksu probe exit=$code")
                return null
            }
            if (reader.isAlive || deadline - System.nanoTime() <= 0) return null
            return synchronized(output) { parseResponse(output.toString()) }
        } finally {
            runCatching { if (process.isAlive) process.destroyForcibly() else process.destroy() }
        }
    }

    companion object {
        const val TAG = "MapleSUSuProbe"
        /** 与 `KsuCommands.DAEMON_LIB_NAME` 同名；此处不 import ksu 包（探测层不得依赖控制面）。 */
        const val DAEMON_LIB_NAME = "libksud_ksu.so"
        const val DEFAULT_TIMEOUT_MILLIS = 1_200L
        const val CACHE_MILLIS = 2_000L
        const val READER_JOIN_MILLIS = 200L
        const val MAX_OUTPUT_CHARS = 8_192

        /**
         * `ksud debug info` 的 `version: <n>`（内核驱动版本），区别于 `userspace_version:`。
         * 行首锚定保证不会把 `userspace_version` 当成内核版本。
         */
        private val VERSION_LINE = Regex("(?m)^\\s*version:\\s*(\\d+)\\s*$")
        private val FLAGS_LINE = Regex("(?m)^\\s*flags:\\s*0x([0-9a-fA-F]+)\\s*$")
        private val UAPI_LINE = Regex("(?m)^\\s*uapi_version:\\s*(\\d+)\\s*$")

        internal fun parseResponse(output: String): Boolean? {
            val version = VERSION_LINE.find(output)?.groupValues?.get(1)?.toLongOrNull() ?: return null
            if (version <= 0L) return null
            val flags = FLAGS_LINE.find(output)?.groupValues?.get(1)?.toLongOrNull(16) ?: return null
            val uapi = UAPI_LINE.find(output)?.groupValues?.get(1)?.toLongOrNull() ?: return null
            // Fixed KernelSU UAPI: KSU_GET_INFO_FLAG_MANAGER = (1U << 1).
            // A version alone does not exclude this app being the recognized manager.
            return if (flags and 2L == 0L && uapi > 0L && uapi != 7L) true else null
        }
    }
}
