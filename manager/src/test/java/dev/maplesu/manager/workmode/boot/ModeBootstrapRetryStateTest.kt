package dev.maplesu.manager.workmode.boot

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.*
import org.junit.Test

class ModeBootstrapRetryStateTest {
    private fun state() = ModeBootstrapRetryState(maxAttempts = 3, retryDelayMillis = 750)

    @Test fun aLateFallbackTimerCannotRestartAnExhaustedAttemptWithoutARealRequest() {
        val state = ModeBootstrapRetryState(maxAttempts = 1, retryDelayMillis = 0)
        assertEquals(1, state.tryStart())
        assertNull(state.finish(resolved = false))
        assertNull(state.tryStart())
        assertTrue(state.requestRetry().scheduleNow)
        assertEquals(1, state.tryStart())
        assertNull(state.finish(resolved = false))
    }

    @Test fun warmupRetryAfterFinalDetectionSignalSurvivesUntilExecutionIsReleased() {
        val state = state()
        repeat(2) { state.tryStart(); state.finish(resolved = false) }
        assertEquals(3, state.tryStart())
        // finishDetection() has woken SDK warmup, but the phase-two finally has not run yet.
        assertFalse(state.requestRetry().scheduleNow)
        assertNull(state.tryStart())
        assertEquals(0L, state.finish(resolved = false))
        assertEquals(1, state.tryStart())
    }

    @Test fun repeatedInFlightRequestsMergeIntoOneFreshBoundedRetrySeries() {
        val state = state()
        state.tryStart()
        repeat(16) { assertFalse(state.requestRetry().scheduleNow) }
        assertEquals(0L, state.finish(resolved = false))
        assertEquals(1, state.tryStart())
        assertEquals(750L, state.finish(resolved = false))
        assertEquals(2, state.tryStart())
        assertEquals(1_500L, state.finish(resolved = false))
        assertEquals(3, state.tryStart())
        assertNull(state.finish(resolved = false))
    }

    @Test fun automaticFailuresStopAfterThreeAttempts() {
        val state = state()
        assertEquals(1, state.tryStart())
        assertEquals(750L, state.finish(resolved = false))
        assertEquals(2, state.tryStart())
        assertEquals(1_500L, state.finish(resolved = false))
        assertEquals(3, state.tryStart())
        assertNull(state.finish(resolved = false))
    }

    @Test fun idleManualRequestStartsANewBudget() {
        val state = state()
        repeat(3) { state.tryStart(); state.finish(resolved = false) }
        assertTrue(state.requestRetry().scheduleNow)
        assertEquals(1, state.tryStart())
    }

    @Test fun resolvedModeDropsPendingRetry() {
        val state = state()
        state.tryStart()
        assertFalse(state.requestRetry().scheduleNow)
        assertNull(state.finish(resolved = true))
    }

    @Test fun concurrentStartIsRejectedUntilTheAttemptFinishes() {
        val state = state()
        assertEquals(1, state.tryStart())
        repeat(16) { assertNull(state.tryStart()) }
        state.finish(resolved = false)
        assertEquals(2, state.tryStart())
    }

    @Test fun aQueuedRetryDoesNotFinishBeforeItsScheduledAttemptStarts() = runBlocking {
        val state = state()
        repeat(3) { state.tryStart(); state.finish(resolved = false) }
        val requested = state.requestRetry()
        assertTrue(requested.scheduleNow)
        assertFalse(requested.completion.isCompleted)
        assertNull(withTimeoutOrNull(1) { requested.completion.await() })
        assertFalse("a timed-out page must not cancel the shared attempt", requested.completion.isCancelled)
        state.tryStart()
        assertFalse(requested.completion.isCompleted)
        state.finish(resolved = false)
        assertFalse("automatic retries still belong to the same request", requested.completion.isCompleted)
        repeat(2) { state.tryStart(); state.finish(resolved = false) }
        assertTrue(requested.completion.isCompleted)
    }

    @Test fun anInFlightCompletionCannotReleaseTheNextRequestedRetry() {
        val state = state()
        val current = state.requestRetry()
        state.tryStart()
        val next = state.requestRetry()
        assertFalse(next.scheduleNow)
        assertSame(current.completion, next.completion)
        assertEquals(0L, state.finish(resolved = false))
        assertFalse(current.completion.isCompleted)
        assertFalse(next.completion.isCompleted)
        repeat(3) { state.tryStart(); state.finish(resolved = false) }
        assertTrue(next.completion.isCompleted)
    }

    @Test fun multipleRequestsBeforeExecutionShareOneQueuedCompletion() {
        val state = state()
        val first = state.requestRetry()
        repeat(16) { assertSame(first.completion, state.requestRetry().completion) }
        repeat(3) { state.tryStart(); state.finish(resolved = false) }
        assertTrue(first.completion.isCompleted)
    }

    @Test fun activationReleasesAQueuedRetryWithoutAnExtraProbe() {
        val state = state()
        state.tryStart()
        val queued = state.requestRetry()
        assertFalse(queued.completion.isCompleted)
        assertNull(state.finish(resolved = true))
        assertTrue(queued.completion.isCompleted)
    }

    @Test fun automaticStartupAttemptsExposeOnePendingSeriesUntilTheirBudgetEnds() {
        val state = state()
        state.tryStart()
        val pending = state.pendingCompletion()!!
        repeat(2) {
            assertNotNull(state.finish(resolved = false))
            assertFalse(pending.isCompleted)
            state.tryStart()
            assertSame(pending, state.pendingCompletion())
        }
        assertNull(state.finish(resolved = false))
        assertTrue(pending.isCompleted)
        assertNull(state.pendingCompletion())
    }

    @Test fun aRejectedSchedulerEndsTheSeriesWithoutWaitingForUnscheduledWork() {
        val state = state()
        val request = state.requestRetry()
        state.tryStart()
        assertNull(state.finish(resolved = false, retryAllowed = false))
        assertTrue(request.completion.isCompleted)
        assertNull(state.pendingCompletion())
    }
}
