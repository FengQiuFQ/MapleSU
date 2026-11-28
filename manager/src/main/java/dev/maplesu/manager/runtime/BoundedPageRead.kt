package dev.maplesu.manager.runtime

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.coroutines.CoroutineContext

/** Propagates one page deadline through IO children without changing SDK concurrency. */
internal object PageReadDeadline {
    private val deadline = ThreadLocal<Long?>()

    fun currentNanos(): Long? = deadline.get()

    fun limitNanos(timeoutMillis: Long): Long {
        val next = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis.coerceAtLeast(0))
        return deadline.get()?.let { minOf(it, next) } ?: next
    }

    fun context(timeoutMillis: Long): CoroutineContext = deadline.asContextElement(limitNanos(timeoutMillis))

    fun <T> onWorker(limitNanos: Long, block: () -> T): T {
        val previous = deadline.get()
        deadline.set(previous?.let { minOf(it, limitNanos) } ?: limitNanos)
        return try { block() } finally {
            if (previous == null) deadline.remove() else deadline.set(previous)
        }
    }
}

/** One process-wide read per page, even when a caller times out inside non-interruptible JNI. */
internal class BoundedPageRead<T>(private val timeoutMillis: Long = 5_000L) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Any()
    private var inFlight: Deferred<T>? = null
    private var activeKey: Any? = null
    private var generation = 0L
    private var inFlightGeneration = 0L

    fun invalidate() { synchronized(lock) { generation++ } }

    suspend fun read(key: Any?, query: suspend () -> T): T {
        return try {
            withContext(PageReadDeadline.context(timeoutMillis)) {
                withTimeout(timeoutMillis) { readFresh(key, query) }
            }
        } catch (error: TimeoutCancellationException) {
            // An external cancellation remains cancellation, not a visible backend error.
            currentCoroutineContext().ensureActive()
            throw TimeoutException("PAGE_QUERY_TIMEOUT:${timeoutMillis}ms")
        }
    }

    private suspend fun readFresh(key: Any?, query: suspend () -> T): T {
        while (true) {
            val (pending, version) = synchronized(lock) {
                val task = inFlight?.takeUnless { it.isCompleted }?.also {
                    check(activeKey == key) { "PAGE_QUERY_CONTEXT_CHANGED" }
                } ?: scope.async(PageReadDeadline.context(timeoutMillis), start = CoroutineStart.LAZY) { query() }.also {
                    activeKey = key
                    inFlight = it
                    inFlightGeneration = generation
                }
                task to inFlightGeneration
            }
            val result = pending.await()
            if (synchronized(lock) { version == generation }) return result
            // A completed write invalidated this observation. Reread within the same
            // page budget, after the old worker has finished, without replaying a write.
        }
    }
}

/** Repository failures remain Result failures; lifecycle cancellation keeps its meaning. */
internal suspend fun <T> BoundedPageRead<Result<T>>.readResult(
    key: Any?,
    query: suspend () -> Result<T>,
): Result<T> = try {
    read(key, query)
} catch (cancelled: CancellationException) {
    throw cancelled
} catch (error: Exception) {
    Result.failure(error)
}
