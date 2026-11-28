// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import android.util.Log
import dev.maplesu.manager.runtime.PageReadDeadline
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock

class UltraSuChannel(
    private val exec: SuExec = ProcessSuExec,
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
) {

    @Volatile
    private var discoveredPath: String? = null

    private val probeLock = ReentrantLock()
    private class RootObservation(val uid: Int?)
    @Volatile private var lastObservation: RootObservation? = null

    /**
     * 依次尝试 [SuCommands.probeCandidates]，返回 `id -u` 的数值（仅 0 视为根可用）；
     * 全失败返回 null。[lastFailure] 记录最后一次失败原因（不含敏感内容）。
     */
    @Volatile
    var lastFailure: String? = null
        private set

    fun rootUid(): Int? {
        val before = lastObservation
        val deadline = PageReadDeadline.limitNanos(timeoutMillis)
        val remaining = (deadline - System.nanoTime()).coerceAtLeast(0L)
        val acquired = try {
            remaining > 0L && probeLock.tryLock(remaining, TimeUnit.NANOSECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            lastFailure = "EXEC_INTERRUPTED"
            return null
        }
        if (!acquired) { lastFailure = "SU_TIMEOUT"; return null }
        return try {
            if (System.nanoTime() >= deadline) { lastFailure = "SU_TIMEOUT"; return null }
            val completed = lastObservation
            if (completed != null && completed !== before) completed.uid
            else PageReadDeadline.onWorker(deadline) { probeRootUid() }.also { lastObservation = RootObservation(it) }
        } finally { probeLock.unlock() }
    }

    private fun probeRootUid(): Int? {
        val started = System.nanoTime()
        val budget = TimeUnit.MILLISECONDS.toNanos(timeoutMillis.coerceAtLeast(1L))
        for (candidate in SuCommands.probeCandidates(discoveredPath)) {
            val remaining = budget - (System.nanoTime() - started)
            if (remaining <= 0L) {
                lastFailure = "SU_TIMEOUT"
                break
            }
            val result = runSafely(candidate, TimeUnit.NANOSECONDS.toMillis(remaining).coerceAtLeast(1L))
            if (result == null) {
                lastFailure = "SU_EXEC_EXCEPTION:${candidate.firstOrNull() ?: "?"}"
                continue
            }
            if (result.timedOut) {
                lastFailure = "SU_TIMEOUT"
                continue
            }
            if (result.failure != null || result.cleanupPending || result.cleanupFailure != null) {
                lastFailure = result.failure ?: result.cleanupFailure ?: "PROCESS_CLEANUP_PENDING"
                continue
            }
            val uid = SuCommands.parseUid(result.output)
            if (uid == 0 && result.exitCode == 0) {
                discoveredPath = candidate.firstOrNull()
                lastFailure = null
                return 0
            }
            lastFailure = "SU_NOT_ROOT:exit=${result.exitCode}:uid=$uid"
        }
        discoveredPath = null
        return null
    }

    fun isRootAvailable(): Boolean = rootUid() != null

    /**
     * 用 root 执行一段脚本（`su -c <script>`）；[stdin] 非空时写入子进程标准输入。
     * 返回 null 表示通道不可用/异常（不是「命令失败」，命令失败在 [SuExecResult] 里）。
     */
    fun runRoot(script: String, stdin: String? = null, timeout: Long = timeoutMillis): SuExecResult? {
        val path = discoveredPath ?: run {
            if (rootUid() == null) return null
            discoveredPath ?: DEFAULT_SU_PATH
        }
        val result = runSafely(SuCommands.rootArgv(path, script), timeout, stdin)
        if (result == null || !result.ok) if (discoveredPath == path) discoveredPath = null
        return result
    }

    private fun runSafely(
        argv: List<String>,
        timeout: Long,
        stdin: String? = null,
    ): SuExecResult? = try {
        val deadline = PageReadDeadline.limitNanos(timeout)
        val remaining = (deadline - System.nanoTime()).coerceAtLeast(0L)
        if (remaining == 0L) SuExecResult(-1, "", timedOut = true)
        else PageReadDeadline.onWorker(deadline) {
            exec.exec(argv, TimeUnit.NANOSECONDS.toMillis(remaining).coerceAtLeast(1L), stdin)
        }
    } catch (error: Throwable) {
        // 日志本身绝不允许把「su 探测」变成异常（主机单测里 Log 是 stub，会抛）。
        runCatching { Log.w(TAG, "su exec failed: ${error.javaClass.simpleName}") }
        null
    }

    companion object {
        private const val TAG = "MapleSUUltraSu"
        const val DEFAULT_TIMEOUT_MILLIS = 5_000L

        /** 内核重定向只看「文件名是 su」，所以固定一个系统路径即可（文件不需要真的存在）。 */
        const val DEFAULT_SU_PATH = "/system/bin/su"
    }
}

/** 一次 `su` 进程执行的结果。 */
data class SuExecResult(
    val exitCode: Int,
    val output: String,
    val timedOut: Boolean = false,
    val failure: String? = null,
    val cleanupPending: Boolean = false,
    val cleanupFailure: String? = null,
) {
    val ok: Boolean get() = failure == null && !timedOut && exitCode == 0 && !cleanupPending && cleanupFailure == null
}

/** 可注入的 su 进程执行器（主机测试造假；生产用 [ProcessSuExec]）。 */
fun interface SuExec {
    fun exec(argv: List<String>, timeoutMillis: Long, stdin: String?): SuExecResult
}

/** 真实进程执行（`ProcessBuilder` + 合并 stderr + 超时强杀）。 */
object ProcessSuExec : SuExec {
    private val processSlot = Semaphore(1, true)
    private val pendingCleanup = AtomicReference<OwnedProcess?>()

    override fun exec(argv: List<String>, timeoutMillis: Long, stdin: String?): SuExecResult =
        exec(argv, timeoutMillis, stdin) { ProcessBuilder(argv).redirectErrorStream(true).start() }

    internal fun exec(argv: List<String>, timeoutMillis: Long, stdin: String?, startProcess: () -> Process): SuExecResult {
        if (argv.isEmpty()) return SuExecResult(-1, "", failure = "EMPTY_ARGV")
        val deadline = PageReadDeadline.limitNanos(timeoutMillis)
        if (remaining(deadline) == 0L) return SuExecResult(-1, "", timedOut = true)
        pendingCleanup.get()?.resume(deadline)
        val acquired = try {
            processSlot.tryAcquire(remaining(deadline), TimeUnit.NANOSECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return SuExecResult(-1, "", failure = "EXEC_INTERRUPTED")
        }
        if (!acquired) return SuExecResult(-1, "", timedOut = true)
        var owner: OwnedProcess? = null
        return try {
            if (remaining(deadline) == 0L) return SuExecResult(-1, "", timedOut = true)
            val process = try {
                startProcess()
            } catch (error: Throwable) {
                val errno = Regex("\\berror=([0-9]{1,4})\\b").find(error.message.orEmpty())?.groupValues?.get(1)
                return SuExecResult(-1, "", failure = "START_FAILED:${error.javaClass.simpleName}" +
                    (errno?.let { ":errno=$it" } ?: ""))
            }
            val owned = OwnedProcess(process)
            owner = owned
            executeOwned(owned, stdin, deadline)
        } finally {
            if (owner == null) processSlot.release()
        }
    }

    private fun executeOwned(owner: OwnedProcess, stdin: String?, deadline: Long): SuExecResult {
        val process = owner.process
        val buffer = ByteArrayOutputStream()
        val inputFailure = AtomicReference<Throwable?>()
        val outputFailure = AtomicReference<Throwable?>()
        var reader: Thread? = null
        var writer: Thread? = null
        val result = try {
            val readerThread = Thread {
                try {
                    owner.output.stream.copyTo(buffer)
                } catch (error: Throwable) {
                    outputFailure.set(error)
                } finally {
                    owner.output.close(owner.failure)
                    owner.reading.set(false)
                    owner.complete()
                }
            }.apply {
                name = "maplesu-ultra-su-reader"
                isDaemon = true
            }.also { reader = it }
            val writerThread = Thread {
                try {
                    if (stdin != null) owner.input.stream.write(stdin.toByteArray(Charsets.UTF_8))
                } catch (error: Throwable) {
                    inputFailure.set(error)
                } finally {
                    owner.input.close(owner.failure)
                    owner.writing.set(false)
                    owner.complete()
                }
            }.apply {
                name = "maplesu-ultra-su-writer"
                isDaemon = true
            }.also { writer = it }
            startIo(readerThread, owner.reading)
            startIo(writerThread, owner.writing)
            val finished = process.waitFor(remaining(deadline), TimeUnit.NANOSECONDS)
            if (!finished) {
                SuExecResult(-1, buffer.toString(Charsets.UTF_8.name()), timedOut = true)
            } else {
                joinUntil(writerThread, deadline)
                joinUntil(readerThread, deadline)
                val failure = when {
                    writerThread.isAlive || readerThread.isAlive -> "PROCESS_IO_INCOMPLETE"
                    inputFailure.get() != null -> "STDIN_FAILED:${inputFailure.get()!!.javaClass.simpleName}"
                    outputFailure.get() != null -> "STDOUT_FAILED:${outputFailure.get()!!.javaClass.simpleName}"
                    else -> null
                }
                SuExecResult(process.exitValue(), buffer.toString(Charsets.UTF_8.name()), failure = failure)
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            SuExecResult(-1, "", failure = "EXEC_INTERRUPTED")
        } catch (error: Throwable) {
            SuExecResult(-1, "", failure = "EXEC_FAILED:${error.javaClass.simpleName}")
        } finally {
            owner.beginCleanup(deadline)
            var interrupted = Thread.interrupted()
            try {
                owner.worker?.let { joinUntil(it, deadline) }
                writer?.let { joinUntil(it, deadline) }
                reader?.let { joinUntil(it, deadline) }
            } catch (_: InterruptedException) {
                interrupted = true
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }
        owner.complete()
        val cleanupPending = !owner.released.get()
        val cleanupFailure = owner.failure.get()
        return result.copy(failure = result.failure ?: when {
            cleanupFailure != null -> "PROCESS_CLEANUP_FAILED"
            cleanupPending -> "PROCESS_CLEANUP_PENDING"
            else -> null
        }, cleanupPending = cleanupPending, cleanupFailure = cleanupFailure)
    }

    private fun remaining(deadline: Long): Long = (deadline - System.nanoTime()).coerceAtLeast(0L)

    private fun joinUntil(thread: Thread, deadline: Long) {
        val nanos = remaining(deadline)
        if (nanos > 0L) thread.join(TimeUnit.NANOSECONDS.toMillis(nanos), (nanos % 1_000_000L).toInt())
    }

    private fun startIo(thread: Thread, running: AtomicBoolean) {
        running.set(true)
        try { thread.start() } catch (error: Throwable) { running.set(false); throw error }
    }

    private class PipeClose<T : Closeable>(val stream: T, private val name: String) {
        private val closing = AtomicBoolean(false)
        @Volatile var closed = false
        fun close(failure: AtomicReference<String?>) {
            if (closed || !closing.compareAndSet(false, true)) return
            try { stream.close(); closed = true }
            catch (error: Throwable) { failure.compareAndSet(null, "${name}_CLOSE_FAILED:${error.javaClass.simpleName}") }
            finally { closing.set(false) }
        }
    }

    /** A pending close keeps the one process slot until its actual resources are released. */
    private class OwnedProcess(val process: Process) {
        val input = PipeClose(process.outputStream, "STDIN")
        val output = PipeClose(process.inputStream, "STDOUT")
        private val error = PipeClose(process.errorStream, "STDERR")
        val reading = AtomicBoolean(false)
        val writing = AtomicBoolean(false)
        val failure = AtomicReference<String?>()
        val released = AtomicBoolean(false)
        private val cleaning = AtomicBoolean(false)
        @Volatile var worker: Thread? = null

        fun complete() {
            if (input.closed && output.closed && error.closed && !reading.get() && !writing.get() &&
                !process.isAlive && released.compareAndSet(false, true)) {
                pendingCleanup.compareAndSet(this, null)
                processSlot.release()
            }
        }

        fun beginCleanup(deadline: Long) {
            pendingCleanup.set(this)
            resume(deadline)
        }

        fun resume(deadline: Long) {
            complete()
            if (released.get() || !cleaning.compareAndSet(false, true)) return
            try {
                worker = Thread {
                    try {
                        try { if (process.isAlive) process.destroyForcibly() }
                        catch (error: Throwable) { failure.compareAndSet(null, "DESTROY_FAILED:${error.javaClass.simpleName}") }
                        try { process.waitFor(remaining(deadline), TimeUnit.NANOSECONDS) }
                        catch (error: Throwable) { failure.compareAndSet(null, "WAIT_FAILED:${error.javaClass.simpleName}") }
                        input.close(failure)
                        output.close(failure)
                        error.close(failure)
                    } finally { cleaning.set(false); complete() }
                }.apply { name = "maplesu-ultra-su-cleanup"; isDaemon = true; start() }
            } catch (error: Throwable) {
                cleaning.set(false)
                failure.compareAndSet(null, "CLEANUP_START_FAILED:${error.javaClass.simpleName}")
            }
        }
    }
}

/**
 * su 命令行与输出解析（纯函数，禁止 Android/IO）。单独放出来是为了让「哪一步失败」
 * 在主机测试里可枚举：候选顺序、uid 解析、脚本引用都必须能脱离真机验证。
 */
object SuCommands {

    fun probeCandidates(discovered: String? = null): List<List<String>> {
        val primary = discovered ?: UltraSuChannel.DEFAULT_SU_PATH
        return buildList {
            add(listOf(primary, "-c", "id -u"))
            add(listOf(primary, "0", "id", "-u"))
            add(listOf(primary, "-c", "id"))
            for (path in listOf("/system/xbin/su", "su")) {
                if (path != primary) add(listOf(path, "-c", "id -u"))
            }
        }
    }

    fun rootArgv(path: String, script: String): List<String> = listOf(path, "-c", script)

    /**
     * 解析 `id -u` / `id` 输出：
     *  - 任意一行 trim 后恰为 `0` → 0；
     *  - 出现 `uid=0(` / `uid=0 ` → 0（`id` 的整段输出）；
     *  - 否则返回最后一行里的十进制数（便于日志），没有数字返回 null。
     */
    fun parseUid(output: String?): Int? {
        val text = output.orEmpty()
        if (text.isBlank()) return null
        val lines = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        for (line in lines) {
            if (line == "0") return 0
        }
        if (UID_ZERO.containsMatchIn(text)) return 0
        val last = lines.lastOrNull() ?: return null
        val match = DECIMAL.find(last) ?: return null
        return match.value.toIntOrNull()
    }

    private val UID_ZERO = Regex("""\buid=0(?:\(|\s|$)""")
    private val DECIMAL = Regex("""\d{1,10}""")
}
