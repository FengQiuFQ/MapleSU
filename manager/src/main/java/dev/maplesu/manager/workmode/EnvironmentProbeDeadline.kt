package dev.maplesu.manager.workmode

import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import dev.maplesu.manager.runtime.PageReadDeadline
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext

sealed interface EnvironmentProbeResult<out T> {
    data class Completed<T>(val value: T) : EnvironmentProbeResult<T>
    data object TimedOut : EnvironmentProbeResult<Nothing>
    data object Busy : EnvironmentProbeResult<Nothing>
    data class Failed(val cause: Throwable) : EnvironmentProbeResult<Nothing>
}

/** A timed-out native call may keep running; retries never create another worker until it exits. */
class EnvironmentProbeRunner(
    private val threadName: String = "maplesu-environment-probe",
    private val startWorker: (Thread) -> Unit = { it.start() },
) {
    private val running = AtomicBoolean(false)

    suspend fun <T> run(timeoutMillis: Long, probe: () -> T): EnvironmentProbeResult<T> {
        val deadline = PageReadDeadline.limitNanos(timeoutMillis)
        if (deadline - System.nanoTime() <= 0) return EnvironmentProbeResult.TimedOut
        return withContext(Dispatchers.IO) {
            val task = FutureTask(Callable {
                PageReadDeadline.onWorker(deadline) {
                    if (deadline - System.nanoTime() <= 0) throw TimeoutException("ENVIRONMENT_PROBE_DEADLINE")
                    probe()
                }
            })
            if (deadline - System.nanoTime() <= 0) return@withContext EnvironmentProbeResult.TimedOut
            if (!running.compareAndSet(false, true)) return@withContext EnvironmentProbeResult.Busy
            try {
                startWorker(Thread({
                    try { task.run() } finally { running.set(false) }
                }, threadName).apply { isDaemon = true })
            } catch (error: Throwable) {
                running.set(false)
                task.cancel(true)
                if (error is CancellationException) throw error
                return@withContext EnvironmentProbeResult.Failed(error)
            }
            try {
                runInterruptible {
                    // Unwrap before a coroutine boundary can recover/copy ExecutionException.
                    try {
                        val remaining = deadline - System.nanoTime()
                        if (remaining <= 0) EnvironmentProbeResult.TimedOut
                        else EnvironmentProbeResult.Completed(task.get(remaining, TimeUnit.NANOSECONDS))
                    } catch (_: TimeoutException) {
                        EnvironmentProbeResult.TimedOut
                    } catch (error: ExecutionException) {
                        val cause = error.cause ?: error
                        if (cause is CancellationException) throw cause
                        if (cause is TimeoutException) return@runInterruptible EnvironmentProbeResult.TimedOut
                        EnvironmentProbeResult.Failed(cause)
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                EnvironmentProbeResult.Failed(error)
            } finally {
                task.cancel(true)
            }
        }
    }
}
