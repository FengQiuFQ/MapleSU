package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CancellationException

class UltraAutoPairReadinessTest {
    @Test fun sdkRootWithoutActualManagerSuDoesNotPair() {
        var verified = 0
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { true }, 
            verifyManagerSu = { verified++; false }, maintain = {})
        assertFalse(result.paired)
        assertEquals("MANAGER_SU_UNVERIFIED", result.reason)
        assertEquals(1, verified)
    }

    @Test fun ownerSessionPairsWithoutWritingPermanentKeyOrRunningMaintenance() {
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { true }, 
            verifyManagerSu = { true }, maintain = {})
        assertTrue(result.paired)
    }

    @Test fun revocationDuringManagerSuVerificationDiscardsTheResult() {
        var current = true
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { current }, 
            verifyManagerSu = { current = false; true }, maintain = { fail("revoked session") })
        assertFalse(result.paired)
        assertEquals("SDK_IDENTITY_SCOPE_CHANGED", result.reason)
    }

    @Test fun runningHelperWithoutRootNeverStartsAuthorizationOrManagerSu() {
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running),
            current = { fail("no Root proof"); false }, 
            verifyManagerSu = { fail("no Root proof"); true }, maintain = { fail() })
        assertFalse(result.paired)
        assertEquals("SDK_ROOT_UNVERIFIED", result.reason)
    }

    @Test fun anOwnerWithoutRootRetainsTheActualProbeFailureBeforeAuthorization() {
        val detail = "{\"sdkError\":\"ERR_READ_CHILD_ERRCODE\",\"sdkErrorCode\":-19914," +
            "\"rootCommand\":{\"phase\":11,\"childStatus\":256,\"receiptComplete\":false}}"
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, rootProbeDetail = detail),
            current = { fail("Root is unverified before authorization capture"); false },
            verifyManagerSu = { fail("Root failure must not enumerate SU"); false }, maintain = { fail() })
        assertFalse(result.paired)
        assertTrue(result.reason.startsWith("SDK_ROOT_UNVERIFIED:"))
        assertTrue(result.reason.contains("ERR_READ_CHILD_ERRCODE"))
        assertTrue(result.reason.contains("-19914"))
        assertTrue(result.reason.contains("256"))
        assertFalse(result.reason.contains("SDK_IDENTITY_SCOPE_CHANGED"))
    }

    @Test fun managerSuFailureDoesNotPublishReadinessOrRunMaintenance() {
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { true }, verifyManagerSu = { error("SU failed") }, maintain = { fail() })
        assertFalse(result.paired)
        assertEquals("MANAGER_SU_UNVERIFIED", result.reason)
    }

    @Test fun managerSuExceptionRetainsItsTypeAndErrnoWithoutPrivateCommandText() {
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { true },
            verifyManagerSu = { throw java.io.IOException("error=13 private-command") },
            maintain = { fail("failed SU must not schedule maintenance") })
        assertFalse(result.paired)
        assertEquals("MANAGER_SU_UNVERIFIED", result.reason)
        assertTrue(result.detail.orEmpty().contains("IOException"))
        assertTrue(result.detail.orEmpty().contains("13"))
        assertFalse(result.detail.orEmpty().contains("private-command"))
    }

    @Test fun managerSuCancellationPropagatesWithoutMaintenance() {
        val cancelled = CancellationException("cancelled")
        val observed = assertThrows(CancellationException::class.java) {
            UltraAutoPair.complete(
                UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
                current = { true }, verifyManagerSu = { throw cancelled }, maintain = { fail() })
        }
        assertSame(cancelled, observed)
    }

    @Test fun managerSuInterruptionRetainsTheInterruptedState() {
        try {
            val result = UltraAutoPair.complete(
                UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
                current = { !Thread.currentThread().isInterrupted },
                verifyManagerSu = { throw InterruptedException() }, maintain = { fail() })
            assertFalse(result.paired)
            assertEquals("SDK_IDENTITY_SCOPE_CHANGED", result.reason)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test fun anInterruptedThreadNeverStartsManagerSu() {
        try {
            Thread.currentThread().interrupt()
            val result = UltraAutoPair.complete(
                UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
                current = { true }, verifyManagerSu = { fail("interrupted"); true }, maintain = { fail() })
            assertFalse(result.paired)
            assertEquals("MANAGER_SU_UNVERIFIED", result.reason)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
