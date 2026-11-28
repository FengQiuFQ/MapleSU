package dev.maplesu.manager.workmode.boot

import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ModeBootstrapRuntimeControlFlowTest {
    @Before fun reset() {
        ModeRuntime.resetForTest()
        ModeRuntime.installBootIdProviderForTest { "control-flow-boot" }
    }
    @After fun cleanup() { ModeRuntime.resetForTest() }

    private fun detected() = DetectionResult(ModeState.MODE_B_KERNEL_ONLY, DetectionGroup.B_KERNEL_ONLY,
        DetectionRules.Rule.R2_KSU_KERNEL_ONLY, "control-flow-boot", 123, emptyList(), RecoveryReadiness.NONE, null)

    @Test fun aRealPipelineFailureKeepsItsOriginalDetailThroughTheBootstrapConsumer() = runBlocking {
        val detail = "root:pipe:EACCES:13:receipt=command10,status0,effects8"
        val pipeline = ModeBootstrapPipeline(object : ModeDetector {
            override suspend fun detect(request: DetectionRequest): DetectionResult = throw IllegalStateException(detail)
        })
        val coordinator = ModeBootstrapCoordinator({ pipeline })
        val outcome = coordinator.runPhaseTwo() as BootstrapOutcome.Failed
        assertEquals("MODE_DETECT_FAILED", ModeRuntime.detectionFailure)
        val getter = ModeRuntime::class.java.declaredMethods.firstOrNull { it.name == "getDetectionFailureDetail" }
        assertNotNull("The production runtime must keep the original stage/errno/receipt for Home details", getter)
        assertEquals(detail, getter!!.invoke(ModeRuntime))
        ModeBootstrap::class.java.getDeclaredMethod("recordGate", BootstrapPhase::class.java, BootstrapOutcome::class.java)
            .apply { isAccessible = true }.invoke(ModeBootstrap, BootstrapPhase.AFTER_ROOT_GRANTED, outcome)
        assertEquals("The bootstrap consumer must preserve the pipeline detail", detail, getter.invoke(ModeRuntime))
        assertNull(ModeRuntime.active)
        ModeRuntime.failBootstrap("LEGACY_FAILURE")
        assertNull("The original one-argument ABI must not attach an earlier failure's detail", getter.invoke(ModeRuntime))
        coordinator.runPhaseTwo()
        assertEquals(detail, getter.invoke(ModeRuntime))
        ModeRuntime.beginDetection()
        assertNull("A fresh observation must not inherit the preceding diagnostic", getter.invoke(ModeRuntime))
    }

    @Test fun localPrecheckCancellationPropagatesWithoutCompletingOrActivatingAndReleasesRetryClaim() = runBlocking {
        var cancelled = true
        var calls = 0
        val pipeline = ModeBootstrapPipeline(object: ModeDetector {
            override suspend fun detect(request: DetectionRequest): DetectionResult { calls++; return detected() }
        }, environmentOverride = { if (cancelled) throw CancellationException("checker cancelled") else null })
        val coordinator = ModeBootstrapCoordinator({ pipeline })
        ModeRuntime.beginDetection()
        try { coordinator.runPhaseTwo(); fail("Local cancellation must propagate") }
        catch (error: CancellationException) { assertEquals("checker cancelled", error.message) }
        assertTrue(currentCoroutineContext().isActive)
        assertEquals(0, calls)
        assertNull(ModeRuntime.latestDetection)
        assertNull(ModeRuntime.active)
        assertFalse(ModeRuntime.detectionComplete)
        assertEquals(0L, ModeRuntime.detectionRevision.value)
        assertNull(ModeRuntime.detectionFailure)
        cancelled = false
        assertTrue(coordinator.runPhaseTwo() is BootstrapOutcome.Activated)
        assertEquals(WorkMode.KSU, ModeRuntime.active)
        assertEquals(1, calls)
    }

    @Test fun ordinaryPrecheckFailureKeepsExistingFallbackAndActivatesTheRealRuntime() = runBlocking {
        var calls = 0
        val pipeline = ModeBootstrapPipeline(object: ModeDetector {
            override suspend fun detect(request: DetectionRequest): DetectionResult { calls++; return detected() }
        }, environmentOverride = { throw IllegalStateException("ordinary precheck unavailable") })
        val coordinator = ModeBootstrapCoordinator({ pipeline }, isResolved = { ModeRuntime.active != null })
        ModeRuntime.beginDetection()
        assertTrue(coordinator.runPhaseTwo() is BootstrapOutcome.Activated)
        assertEquals(1, calls)
        assertEquals(WorkMode.KSU, ModeRuntime.active)
        assertEquals(detected(), ModeRuntime.latestDetection)
        assertTrue(ModeRuntime.detectionComplete)
        assertNull(ModeRuntime.detectionFailure)
        assertEquals(1L, ModeRuntime.detectionRevision.value)
        assertNull(coordinator.runPhaseTwo())
        assertEquals(1, calls)
    }

    @Test fun cancellingAnInflightRequestInterruptsTheWorkerAndLeavesItsParentAndRetryUsable() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val exited = CountDownLatch(1)
        val interrupted = java.util.concurrent.atomic.AtomicBoolean(false)
        var block = true
        val pipeline = ModeBootstrapPipeline(object: ModeDetector {
            override suspend fun detect(request: DetectionRequest): DetectionResult {
                if (block) {
                    entered.countDown()
                    try { release.await(5, TimeUnit.SECONDS) }
                    catch (error: InterruptedException) { interrupted.set(true); throw error }
                    finally { exited.countDown() }
                }
                return detected()
            }
        })
        val coordinator = ModeBootstrapCoordinator({ pipeline })
        ModeRuntime.beginDetection()
        val child = async(Dispatchers.Default) { coordinator.runPhaseTwo() }
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            withTimeout(2_000) { child.cancelAndJoin() }
            assertTrue(child.isCancelled)
            assertTrue(currentCoroutineContext().isActive)
            assertTrue(exited.await(2, TimeUnit.SECONDS))
            assertTrue(interrupted.get())
            assertNull(ModeRuntime.latestDetection)
            assertNull(ModeRuntime.active)
            assertFalse(ModeRuntime.detectionComplete)
            assertEquals(0L, ModeRuntime.detectionRevision.value)
            block = false
            assertTrue(coordinator.runPhaseTwo() is BootstrapOutcome.Activated)
            assertEquals(WorkMode.KSU, ModeRuntime.active)
            assertTrue(ModeRuntime.detectionComplete)
        } finally { release.countDown(); child.cancelAndJoin() }
    }

    @Test fun anExistingSettledWaiterFollowsTheNewAttemptCompletionInsteadOfTheReplacedDeferred() = runBlocking {
        val waiter = async(start = CoroutineStart.UNDISPATCHED) { ModeRuntime.awaitDetectionSettled(1_000) }
        assertFalse(waiter.isCompleted)
        ModeRuntime.beginDetection()
        ModeRuntime.recordDetection(detected().copy(state = ModeState.INDETERMINATE, group = DetectionGroup.NONE,
            rule = DetectionRules.Rule.R12_INDETERMINATE))
        ModeRuntime.finishDetection()
        assertTrue(withTimeout(500) { waiter.await() })
        assertNull(ModeRuntime.active)
        assertTrue(ModeRuntime.detectionComplete)
        assertEquals(1L, ModeRuntime.detectionRevision.value)
    }
}
