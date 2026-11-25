package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraProbeRecoveryTest {
    private val probe = UltraEnvironmentProbe

    @Test fun helperReadFailureDoesNotSuppressIndependentKernelRootEvidence() {
        var commands = 0
        assertTrue(probe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, false) { commands++; 0 })
        assertEquals(1, commands)
        assertFalse(probe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, false) { 2000 })
        assertFalse(probe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, false) { null })
    }

    @Test fun aForeignSuDoesNotProveAMapleSuKernelWhenNoChannelAnswered() {
        // 通用 su（KernelSU/Magisk 都挂在 /system/bin/su）返回 0，但 MapleSU 通道
        // 一次都没有应答（无回执、无 owner 身份、无 ERR_MODULE_NO_BOOT）：
        // 这个 0 是"设备有 root"，不是"Ultra 内核在跑"。
        var commands = 0
        assertFalse(
            probe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, false, kernelChannelObserved = false) {
                commands++; 0
            },
        )
        assertEquals(1, commands)
        // 通道应答过（例如内核回 ERR_MODULE_NO_BOOT 却没有装 helper）时，同一个 0 才算内核证据。
        assertTrue(probe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, false, kernelChannelObserved = true) { 0 })
        // 回执成功本身就是通道证据，与额外观察无关。
        assertTrue(
            probe.verifyKernelRoot(UltraEnvironmentProbe.State.Running, true, kernelChannelObserved = false) { 0 },
        )
    }

    @Test fun rootProofExpiresAndNeverSubstitutesHelperOrStandardSuReadiness() {
        val root = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Unknown,
            observedAtElapsedMs = 100, kernelRootVerified = true)
        assertTrue(probe.rootProofCurrent(root, 100))
        assertTrue(probe.rootProofCurrent(root, 3099))
        assertFalse(probe.rootProofCurrent(root, 3100))
        assertFalse(probe.rootProofCurrent(root, 99))
        assertFalse(probe.rootProofCurrent(root.copy(observedAtElapsedMs = -1), 100))
        assertFalse(probe.rootProofCurrent(root.copy(kernelRootVerified = false), 100))
        assertFalse(probe.rootProofCurrent(root.copy(state = UltraEnvironmentProbe.State.Fault), 100))
        assertFalse(probe.rootProofCurrent(root.copy(state = UltraEnvironmentProbe.State.NoKey), 100))
        assertFalse(root.sdkChannelAvailable)
        assertEquals(UltraEnvironmentProbe.State.Unknown, root.state)
    }

    @Test fun aResolvedKernelChannelDoesNotWaitForAnUnrelatedHelperReceipt() {
        var reads = 0
        val result = probe.readUntilConfirmed(false,
            read = { reads++; UltraEnvironmentProbe.State.Unknown }, kernelResolved = { true },
            pause = { fail("a verified kernel or explicit NO_BOOT is already decisive") })
        assertEquals(UltraEnvironmentProbe.State.Unknown, result)
        assertEquals(1, reads)
    }

    @Test fun aResolvedKernelObservationIsReusedOnlyWithinItsShortTtl() {
        assertTrue(probe.canReuse(UltraEnvironmentProbe.State.Unknown, 0, kernelResolved = true))
        assertTrue(probe.canReuse(UltraEnvironmentProbe.State.Unknown, 2_999, kernelResolved = true))
        assertFalse(probe.canReuse(UltraEnvironmentProbe.State.Unknown, 3_000, kernelResolved = true))
        assertFalse(probe.canReuse(UltraEnvironmentProbe.State.Unknown, -1, kernelResolved = true))
    }

    @Test fun transientReadFailureRequeriesTheSdkAndReturnsRunning() {
        val reads = mutableListOf<Boolean>()
        val pauses = mutableListOf<Long>()
        val result = probe.readUntilConfirmed(false, read = { forced ->
            reads += forced
            if (reads.size == 1) UltraEnvironmentProbe.State.Unknown else UltraEnvironmentProbe.State.Running
        }, pause = { pauses += it })
        assertEquals(UltraEnvironmentProbe.State.Running, result)
        assertEquals(listOf(false, true), reads)
        assertEquals(listOf(250L), pauses)
    }

    @Test fun slowInitializationCanCompleteOnTheLastBoundedRead() {
        var reads = 0
        val pauses = mutableListOf<Long>()
        val result = probe.readUntilConfirmed(true, read = {
            if (++reads < 4) UltraEnvironmentProbe.State.Unknown else UltraEnvironmentProbe.State.Running
        }, pause = { pauses += it })
        assertEquals(UltraEnvironmentProbe.State.Running, result)
        assertEquals(4, reads)
        assertEquals(listOf(250L, 500L, 1_000L), pauses)
    }

    @Test fun persistentUncertaintyStopsWithoutInventingRunningOrFault() {
        var reads = 0
        var delays = 0
        val result = probe.readUntilConfirmed(false, read = {
            reads++
            UltraEnvironmentProbe.State.Unknown
        }, pause = { delays++ })
        assertEquals(UltraEnvironmentProbe.State.Unknown, result)
        assertEquals(4, reads)
        assertEquals(3, delays)
    }

    @Test fun everyConfirmedStateAndNoKeyReturnImmediately() {
        for (state in UltraEnvironmentProbe.State.entries.filter { it != UltraEnvironmentProbe.State.Unknown }) {
            var reads = 0
            val result = probe.readUntilConfirmed(false, read = { reads++; state },
                pause = { fail("$state must not retry") })
            assertEquals(state, result)
            assertEquals(1, reads)
        }
    }

    @Test fun explicitProtectionOnARequeryStopsImmediately() {
        var reads = 0
        val result = probe.readUntilConfirmed(true, read = {
            if (++reads == 1) UltraEnvironmentProbe.State.Unknown else UltraEnvironmentProbe.State.Fault
        }, pause = {})
        assertEquals(UltraEnvironmentProbe.State.Fault, result)
        assertEquals(2, reads)
    }

    @Test fun identityChangeOrSuspensionStopsBeforeAnotherSdkRead() {
        var reads = 0
        val result = probe.readUntilConfirmed(false, read = {
            reads++
            UltraEnvironmentProbe.State.Unknown
        }, sameIdentity = { false }, pause = { fail("stale identity must not wait") })
        assertEquals(UltraEnvironmentProbe.State.Unknown, result)
        assertEquals(1, reads)
    }

    @Test fun identityChangeWhileWaitingDiscardsTheRetry() {
        var eligible = true
        var reads = 0
        val result = probe.readUntilConfirmed(false, read = {
            reads++
            UltraEnvironmentProbe.State.Unknown
        }, sameIdentity = { eligible }, pause = { eligible = false })
        assertEquals(UltraEnvironmentProbe.State.Unknown, result)
        assertEquals(1, reads)
        assertFalse(eligible)
    }

    @Test fun cancellationPreservesTheInterruptAndDoesNotReadAgain() {
        var reads = 0
        try {
            val result = probe.readUntilConfirmed(false, read = {
                reads++
                UltraEnvironmentProbe.State.Unknown
            }, pause = { throw InterruptedException("fixture") })
            assertEquals(UltraEnvironmentProbe.State.Unknown, result)
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(1, reads)
        } finally { Thread.interrupted() }
    }

    @Test fun anAlreadyCancelledWorkerDoesNotScheduleMoreNativeWork() {
        var reads = 0
        try {
            Thread.currentThread().interrupt()
            val result = probe.readUntilConfirmed(false, read = {
                reads++
                UltraEnvironmentProbe.State.Unknown
            }, pause = { fail("cancelled worker must not wait") })
            assertEquals(UltraEnvironmentProbe.State.Unknown, result)
            assertEquals(1, reads)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun anUnknownObservationDoesNotHideACompletedInitializationBehindTheCache() {
        assertFalse(probe.canReuse(UltraEnvironmentProbe.State.Unknown, 0))
        assertFalse(probe.canReuse(UltraEnvironmentProbe.State.Unknown, 2_999))
        for (state in UltraEnvironmentProbe.State.entries.filter { it != UltraEnvironmentProbe.State.Unknown }) {
            assertTrue(probe.canReuse(state, 0))
            assertTrue(probe.canReuse(state, 2_999))
            assertFalse(probe.canReuse(state, 3_000))
            assertFalse(probe.canReuse(state, -1))
        }
    }
}
