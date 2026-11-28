package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraAutoSetupAttemptTest {
    @Test fun verifiedNeverStartedUnknownUsesRecoveryWithoutBootReinstallation() {
        val port = Port().apply { observed = UltraEnvironmentProbe.State.Unknown }
        var starts = 0
        val result = UltraAutoSetupAttempt.run(port) {
            starts++
            UltraEnvironmentAutoSetup.Result(true, true, "IDLE_RECOVERED")
        }
        assertTrue("verified idle boot must leave STATE_Unknown", result.installed)
        assertEquals(1, starts)
        assertEquals(0, port.installs)
    }

    @Test fun unknownWithoutIdleEvidenceAndProtectedStatesStayBlocked() {
        for (state in listOf(UltraEnvironmentProbe.State.Unknown, UltraEnvironmentProbe.State.Fault,
                             UltraEnvironmentProbe.State.NoKey)) {
            val port = Port().apply { observed = state }
            var checks = 0
            val result = UltraAutoSetupAttempt.run(port) { checks++; null }
            assertFalse(result.attempted)
            assertEquals(if (state == UltraEnvironmentProbe.State.Unknown) 1 else 0, checks)
            assertEquals(0, port.installs)
        }
    }

    private class Port : UltraAutoSetupAttempt.Port {
        var observed = UltraEnvironmentProbe.State.Running
        var blocked: String? = null
        var afterProbe: (() -> Unit)? = null
        var afterRecord: (() -> Unit)? = null
        var records = 0
        var diagnosticCrash = false
        var installs = 0
        var refreshes = 0
        var outcome = UltraEnvironmentInstaller.Outcome(true, "OK")
        var crash = false
        var cancellation: java.util.concurrent.CancellationException? = null
        var submitted = false
        var guardOk = true
        override fun alreadySubmitted() = submitted
        override fun markSubmitted(): Boolean { if (guardOk) submitted = true; return guardOk }
        override fun clearUnsubmitted() { submitted = false }
        override fun blockedReason() = blocked
        override fun state() = observed.also { afterProbe?.invoke() }
        override fun recordAttempt() {
            records++
            afterRecord?.invoke()
            if (diagnosticCrash) error("diagnostic storage unavailable")
        }
        override fun install(): UltraEnvironmentInstaller.Outcome {
            installs++
            cancellation?.let { throw it }
            if (crash) error("install transport lost")
            if (outcome.ok && outcome.verified) observed = UltraEnvironmentProbe.State.Running
            return outcome
        }
        override fun refresh() { refreshes++ }
        fun run() = UltraAutoSetupAttempt.run(this)
    }

    @Test fun healthyObservationDoesNotConsumeTheLaterRecoveryAttempt() {
        val port = Port()
        assertEquals("ALREADY_RUNNING", port.run().reason)
        assertEquals(0, port.records)
        port.observed = UltraEnvironmentProbe.State.NotInstalled
        assertTrue(port.run().installed)
        assertEquals("ALREADY_RUNNING", port.run().reason)
        assertEquals(1, port.installs)
        assertEquals(1, port.records)
    }

    @Test fun faultUnknownAndNoKeyNeverInstallOrRecordAnAttempt() {
        for (state in listOf(UltraEnvironmentProbe.State.Fault, UltraEnvironmentProbe.State.Unknown,
                             UltraEnvironmentProbe.State.NoKey)) {
            val port = Port().apply { observed = state }
            assertFalse(port.run().attempted)
            assertEquals(0, port.records)
            assertEquals(0, port.installs)
        }
    }

    @Test fun changesDuringProbeAbortBeforeDiagnosticsOrAnyWrite() {
        for (reason in listOf("OWNER_CHANGED", "BOOT_CHANGED", "SUSPENDED", "SWITCH_PENDING", "MODE_KSU")) {
            val port = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                afterProbe = { blocked = reason }
            }
            assertEquals(reason, port.run().reason)
            assertEquals(0, port.records)
            assertEquals(0, port.installs)
        }
    }

    @Test fun diagnosticStorageFailureDoesNotBlockAConfirmedMissingEnvironment() {
        val port = Port().apply { observed = UltraEnvironmentProbe.State.NotInstalled; diagnosticCrash = true }
        assertTrue(port.run().installed)
        assertEquals(1, port.installs)
    }

    @Test fun changesWhileWritingDiagnosticsStillAbortBeforeInstallation() {
        val port = Port().apply {
            observed = UltraEnvironmentProbe.State.NotInstalled
            afterRecord = { blocked = "OWNER_CHANGED" }
        }
        assertEquals("OWNER_CHANGED", port.run().reason)
        assertEquals(1, port.records)
        assertEquals(0, port.installs)
    }

    @Test fun cancelledPreparationClearsOnlyTheKnownUnsubmittedGuard() {
        val original = java.util.concurrent.CancellationException("preparation cancelled")
        val port = Port().apply {
            observed = UltraEnvironmentProbe.State.NotInstalled
            cancellation = UltraInstallPreparationCancelled(original)
        }
        assertSame(original, assertThrows(java.util.concurrent.CancellationException::class.java) { port.run() })
        assertFalse(port.submitted)
        port.cancellation = null
        assertTrue(port.run().installed)
        assertEquals(2, port.installs)
    }

    @Test fun cancellationWithUnknownSubmissionKeepsTheGuardAndPropagates() {
        val original = java.util.concurrent.CancellationException("transport cancelled")
        val port = Port().apply {
            observed = UltraEnvironmentProbe.State.NotInstalled
            cancellation = original
        }
        assertSame(original, assertThrows(java.util.concurrent.CancellationException::class.java) { port.run() })
        assertTrue(port.submitted)
        port.cancellation = null
        assertEquals("INSTALL_RECONCILIATION_REQUIRED", port.run().reason)
        assertEquals(1, port.installs)
    }

    @Test fun aConfirmedUnsubmittedFailureAllowsAFreshAttempt() {
        val port = Port().apply {
            observed = UltraEnvironmentProbe.State.NotInstalled
            outcome = UltraEnvironmentInstaller.Outcome(false, "MAPLESU_SDK_BUSY")
        }
        assertFalse(port.run().installed)
        assertFalse(port.submitted)
        port.outcome = UltraEnvironmentInstaller.Outcome(true, "OK")
        assertTrue(port.run().installed)
        assertEquals(2, port.installs)
    }

    @Test fun uncertainUnverifiedAndInterruptedSubmissionsAreNeverReplayed() {
        for (scenario in 0..2) {
            val port = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                when (scenario) {
                    0 -> outcome = UltraEnvironmentInstaller.Outcome(false, "HOTLOAD_REPLY_LOST",
                        sdkErrorCode = -21002, submissionUnknown = true)
                    1 -> outcome = UltraEnvironmentInstaller.Outcome(true, "OK", verified = false)
                    2 -> crash = true
                }
            }
            assertFalse(port.run().installed)
            assertTrue(port.submitted)
            port.outcome = UltraEnvironmentInstaller.Outcome(true, "OK")
            port.crash = false
            repeat(3) { assertEquals("INSTALL_RECONCILIATION_REQUIRED", port.run().reason) }
            assertEquals(1, port.installs)
            val reloaded = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                submitted = port.submitted
            }
            assertEquals("INSTALL_RECONCILIATION_REQUIRED", reloaded.run().reason)
            assertEquals(0, reloaded.installs)
        }
    }

    @Test fun aFailedDurableGuardNeverSubmits() {
        val port = Port().apply { observed = UltraEnvironmentProbe.State.NotInstalled; guardOk = false }
        assertEquals("INSTALL_GUARD_STORE_FAILED", port.run().reason)
        assertEquals(0, port.installs)
    }

    @Test fun onlyAVerifiedSuccessfulInstallStartsAnotherProbe() {
        for ((outcome, reason) in listOf(
            UltraEnvironmentInstaller.Outcome(true, "OK") to "INSTALLED",
            UltraEnvironmentInstaller.Outcome(true, "OK", verified = false) to "INSTALL_UNVERIFIED",
            UltraEnvironmentInstaller.Outcome(false, "MAPLESU_SDK_BUSY", sdkErrorCode = -1002) to "SDK_ERROR_MAPLESU_SDK_BUSY",
            UltraEnvironmentInstaller.Outcome(false, "HOTLOAD_REPLY_LOST", sdkErrorCode = -21002,
                verified = false, submissionUnknown = true) to "INSTALL_RECONCILIATION_REQUIRED",
        )) {
            val port = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                this.outcome = outcome
            }
            val result = port.run()
            assertEquals(reason, result.reason)
            assertEquals(outcome.ok && outcome.verified, result.installed)
            assertEquals(1, port.installs)
            assertEquals("Failed, unverified and uncertain outcomes keep their original observation",
                if (outcome.ok && outcome.verified) 1 else 0, port.refreshes)
        }
    }

    @Test fun aLostInstallReplyIsReconciledBeforeAnyLaterSubmission() {
        for (later in listOf(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.Unknown,
                             UltraEnvironmentProbe.State.Fault, UltraEnvironmentProbe.State.NoKey)) {
            val port = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                crash = true
            }
            assertFalse(port.run().installed)
            port.observed = later
            assertFalse(port.run().attempted)
            assertEquals("observations preserve the original submission", 1, port.installs)
        }
    }
}
