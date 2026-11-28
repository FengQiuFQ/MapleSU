package com.maplesu.core.ui.screen.appprofile

import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.State

/** Keep the saved decision separate from delivery; a read never resubmits a write. */
internal class ProfileWritePolicy<T>(initial: T) {
    private var confirmed = initial
    private var latestRequest = 0L

    data class Completion<T>(val profile: T, val result: Natives.ProfileWriteResult)

    fun request(): Long = ++latestRequest

    fun isLatest(request: Long): Boolean = request == latestRequest

    fun complete(
        request: Long,
        submitted: T,
        result: Natives.ProfileWriteResult,
        readback: T? = null,
    ): Completion<T>? {
        if (result.decisionCommitted) confirmed = submitted
        if (!isLatest(request)) return null
        if (readback != null) confirmed = readback
        return Completion(confirmed, result)
    }
}

/** A profile bit proves the durable decision; only a current applied read clears delivery failure. */
internal fun profileDeliveryState(
    granted: Boolean,
    observed: State,
    write: Natives.ProfileWriteResult?,
    deliveryConfirmed: Boolean?,
): State = when {
    observed == State.STALE -> State.STALE
    !granted -> State.NOT_AUTHORIZED
    deliveryConfirmed == true -> observed
    write?.pendingApply == true || deliveryConfirmed == false -> State.AUTHORIZATION_PENDING
    write?.commitUnknown == true -> State.ENTRY_UNAVAILABLE
    else -> observed
}

internal fun <T> profileWriteRecovered(
    write: Natives.ProfileWriteResult?,
    submitted: T?,
    readback: T?,
    deliveryConfirmed: Boolean?,
): Boolean = deliveryConfirmed == true && readback != null && (write == null || write.succeeded ||
    ((write.decisionCommitted || write.pendingApply || write.commitUnknown) && readback == submitted))
