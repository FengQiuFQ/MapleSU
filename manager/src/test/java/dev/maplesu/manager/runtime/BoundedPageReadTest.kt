package dev.maplesu.manager.runtime

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class BoundedPageReadTest {
    @Test fun mutationInvalidationDiscardsAnEarlierReadAndQueriesAgainBeforePublishing() = runBlocking {
        val queue = BoundedPageRead<String>(2_000)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var calls = 0
        val result = async(start = CoroutineStart.UNDISPATCHED) {
            queue.read("LITE") {
                if (++calls == 1) { entered.complete(Unit); release.await(); "before-mutation" }
                else "after-mutation"
            }
        }
        entered.await()
        queue.invalidate()
        release.complete(Unit)
        assertEquals("after-mutation", result.await())
        assertEquals(2, calls)
    }

    @Test fun aCancelledPageCannotPublishAnObservationFromBeforeTheUpgrade() = runBlocking {
        val queue = BoundedPageRead<String>(2_000)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var calls = 0
        val first = launch(start = CoroutineStart.UNDISPATCHED) {
            queue.read("LITE") { calls++; entered.complete(Unit); release.await(); "before-upgrade" }
        }
        entered.await()
        first.cancelAndJoin()
        queue.invalidate()
        val refreshed = async(start = CoroutineStart.UNDISPATCHED) {
            queue.read("LITE") { calls++; "after-upgrade" }
        }
        release.complete(Unit)
        assertEquals("after-upgrade", refreshed.await())
        assertEquals(2, calls)
    }

    @Test fun repositoryTimeoutRemainsAResultFailure() = runBlocking {
        val queue = BoundedPageRead<Result<String>>(50)
        val release = CompletableDeferred<Unit>()
        try {
            val result = queue.readResult("LITE") { release.await(); Result.success("late") }
            assertTrue(result.exceptionOrNull() is TimeoutException)
        } finally { release.complete(Unit) }
    }

    @Test fun repositoryWrapperPreservesCallerCancellation() = runBlocking {
        val queue = BoundedPageRead<Result<String>>()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val request = launch(start = CoroutineStart.UNDISPATCHED) {
            queue.readResult("LITE") { entered.complete(Unit); release.await(); Result.success("late") }
            fail("Cancelled caller must not receive a failure Result")
        }
        try { entered.await(); request.cancelAndJoin(); assertTrue(request.isCancelled) }
        finally { release.complete(Unit) }
    }

    @Test fun nativeReadDoesNotKeepThePageWaitingAndRetriesDoNotMultiplyWorkers() = runBlocking {
        val queue = BoundedPageRead<String>(100)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        try {
            repeat(3) {
                try {
                    queue.read("LITE") {
                        calls.incrementAndGet(); entered.countDown()
                        check(release.await(5, TimeUnit.SECONDS)); "result"
                    }
                    fail("A stuck backend must time out the page")
                } catch (_: TimeoutException) { }
            }
            assertEquals(1, calls.get())
            assertEquals(0L, entered.count)
        } finally { release.countDown() }
    }

    @Test fun concurrentReadersShareTheActualResultAndLaterRefreshReadsAgain() = runBlocking {
        val queue = BoundedPageRead<String>(2_000)
        val release = CompletableDeferred<Unit>()
        var calls = 0
        val first = async(start = CoroutineStart.UNDISPATCHED) { queue.read("LITE") { calls++; release.await(); "ready" } }
        val second = async(start = CoroutineStart.UNDISPATCHED) { queue.read("LITE") { error("duplicate") } }
        release.complete(Unit)
        assertEquals("ready", first.await())
        assertEquals("ready", second.await())
        assertEquals("fresh", queue.read("LITE") { calls++; "fresh" })
        assertEquals(2, calls)
    }

    @Test fun cancellationOfOnePageDoesNotCancelOrReplayTheSharedQuery() = runBlocking {
        val queue = BoundedPageRead<String>(2_000)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val first = launch(start = CoroutineStart.UNDISPATCHED) {
            queue.read("LITE") { entered.complete(Unit); release.await(); "ready" }
        }
        entered.await()
        first.cancelAndJoin()
        val second = async(start = CoroutineStart.UNDISPATCHED) { queue.read("LITE") { error("replayed") } }
        release.complete(Unit)
        assertEquals("ready", second.await())
        assertTrue(first.isCancelled)
    }

    @Test fun modeChangesNeverInheritAnotherBackendsPendingResult() = runBlocking {
        val queue = BoundedPageRead<String>(2_000)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val first = async { queue.read("LITE") { entered.complete(Unit); release.await(); "lite" } }
        entered.await()
        try {
            queue.read("KSU") { error("must not start concurrently") }
            fail("Mode mismatch")
        } catch (error: IllegalStateException) { assertEquals("PAGE_QUERY_CONTEXT_CHANGED", error.message) }
        release.complete(Unit)
        assertEquals("lite", first.await())
        assertEquals("ksu", queue.read("KSU") { "ksu" })
    }

    @Test fun failureDoesNotPoisonLaterRefreshes() = runBlocking {
        val queue = BoundedPageRead<String>()
        try { queue.read(null) { error("root temporarily unavailable") }; fail() }
        catch (_: IllegalStateException) { }
        assertEquals("retried", queue.read(null) { "retried" })
    }
}
