package dev.maplesu.manager.workmode.boot

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred

/** Keep a retry requested by startup warmup until the current attempt releases execution. */
internal class ModeBootstrapRetryState(
    private val maxAttempts: Int,
    private val retryDelayMillis: Long,
) {
    private var executing = false
    private var attempts = 0
    private var retryRequested = false
    private var completion: CompletableDeferred<Unit>? = null

    data class Request(val scheduleNow: Boolean, val completion: Deferred<Unit>)

    @Synchronized
    fun tryStart(): Int? {
        if (executing || attempts >= maxAttempts) return null
        executing = true
        if (completion?.isCompleted != false) completion = CompletableDeferred()
        return ++attempts
    }

    /** A request waits for the bounded series, including automatic or explicitly merged retries. */
    @Synchronized
    fun requestRetry(): Request {
        val pending = completion?.takeUnless { it.isCompleted } ?: CompletableDeferred<Unit>().also { completion = it }
        if (executing) {
            retryRequested = true
            return Request(false, pending)
        }
        attempts = 0
        return Request(true, pending)
    }

    @Synchronized
    fun pendingCompletion(): Deferred<Unit>? = completion?.takeUnless { it.isCompleted }

    /** Returns one next delay, or null when resolved / the automatic budget is exhausted. */
    @Synchronized
    fun finish(resolved: Boolean, retryAllowed: Boolean = true): Long? {
        executing = false
        val nextDelay = when {
            resolved || !retryAllowed -> {
                retryRequested = false
                null
            }
            retryRequested -> {
                retryRequested = false
                attempts = 0
                0L
            }
            attempts < maxAttempts -> retryDelayMillis * attempts
            else -> null
        }
        if (nextDelay == null) completion?.complete(Unit)
        return nextDelay
    }
}
