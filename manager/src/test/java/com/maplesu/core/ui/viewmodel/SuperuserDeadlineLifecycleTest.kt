package com.maplesu.core.ui.viewmodel

import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Executes the same real loader before/after; no Android, JNI, Root or timing sleeps. */
class SuperuserDeadlineLifecycleTest {
    @Test fun anExpiredQueuedRequestNeverEntersItsAlreadyResolvedBackend() = runBlocking {
        var loads = 0
        val loader = SuperuserStartupLoader({ WorkMode.LITE }, { error("already resolved") })
        val failure = withContext(PageReadDeadline.context(0L)) {
            runCatching { loader.load({}) { loads++ } }.exceptionOrNull()
        }
        assertEquals("An expired page must not submit even one backend read", 0, loads)
        assertTrue(failure is TimeoutCancellationException)
    }

    @Test fun anExpiredQueuedRequestDoesNotStartAnotherModeWait() = runBlocking {
        var waits = 0
        var loads = 0
        val loader = SuperuserStartupLoader({ null }, { waits++; WorkMode.KSU })
        val failure = withContext(PageReadDeadline.context(0L)) {
            runCatching { loader.load({}) { loads++ } }.exceptionOrNull()
        }
        assertEquals("Queue time belongs to the original page budget", 0, waits)
        assertEquals(0, loads)
        assertTrue(failure is TimeoutCancellationException)
    }

    @Test fun modeWaitListAndSettingsChildKeepTheSameEarlierAbsoluteDeadline() = runBlocking {
        withContext(PageReadDeadline.context(9_000L)) {
            val original = PageReadDeadline.currentNanos()
            assertNotNull(original)
            val seen = mutableListOf<Long?>()
            val loader = SuperuserStartupLoader({ null }, {
                seen += PageReadDeadline.currentNanos()
                WorkMode.LITE
            })
            assertTrue(loader.load({}) {
                seen += PageReadDeadline.currentNanos()
                withContext(Dispatchers.IO) { seen += PageReadDeadline.currentNanos() }
            })
            assertEquals(listOf(original, original, original), seen)
        }
    }

    @Test fun cancellingTheModeWaitKeepsCleanupInItsDeadlineAndSkipsTheBackend() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        var loads = 0
        var cleanup: Long? = null
        val inherited = PageReadDeadline.context(9_000L)
        var original: Long? = null
        val loader = SuperuserStartupLoader({ null }, {
            entered.complete(Unit)
            try { awaitCancellation() } finally { cleanup = PageReadDeadline.currentNanos() }
        })
        val job = launch(inherited) {
            original = PageReadDeadline.currentNanos()
            loader.load({}) { loads++ }
        }
        entered.await()
        job.cancelAndJoin()
        assertTrue(job.isCancelled)
        assertEquals(0, loads)
        assertEquals(original, cleanup)
    }

    @Test fun cancellingAnInFlightReadSkipsTheNextStageAndRetainsItsCleanupDeadline() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        var settingsReads = 0
        var original: Long? = null
        var cleanup: Long? = null
        val loader = SuperuserStartupLoader({ WorkMode.KSU }, { error("already resolved") })
        val job = launch(PageReadDeadline.context(9_000L)) {
            original = PageReadDeadline.currentNanos()
            loader.load({}) {
                try { entered.complete(Unit); awaitCancellation() }
                finally { cleanup = PageReadDeadline.currentNanos() }
                @Suppress("UNREACHABLE_CODE")
                settingsReads++
            }
        }
        entered.await()
        job.cancelAndJoin()
        assertTrue(job.isCancelled)
        assertEquals(0, settingsReads)
        assertEquals(original, cleanup)
    }

    @Test fun coalescedExplicitPassesUseTheOriginalDeadline() = runBlocking {
        withContext(PageReadDeadline.context(9_000L)) {
            val original = PageReadDeadline.currentNanos()
            val seen = mutableListOf<Long?>()
            val loader = SuperuserStartupLoader({ WorkMode.LITE }, { error("already resolved") })
            repeat(2) { assertTrue(loader.load({}) { seen += PageReadDeadline.currentNanos() }) }
            assertEquals(listOf(original, original), seen)
        }
    }

    @Test fun laterExplicitRetryCanRunAfterTheExpiredRequest() = runBlocking {
        var calls = 0
        val loader = SuperuserStartupLoader({ WorkMode.LITE }, { error("already resolved") })
        withContext(PageReadDeadline.context(0L)) { runCatching { loader.load({}) { calls++ } } }
        assertEquals(0, calls)
        assertTrue(loader.load({}) { calls++ })
        assertEquals(1, calls)
    }

    @Test fun aBackendFailureRetainsTheOriginalFailureAndNoSuccess() = runBlocking {
        val expected = IllegalStateException("SDK_UID_READ:ERR_MODULE_TEST_CHANNEL:-19999")
        val loader = SuperuserStartupLoader({ WorkMode.LITE }, { error("already resolved") })
        val failure = runCatching { loader.load({}) { throw expected } }.exceptionOrNull()
        assertSame(expected, failure)
    }
}
