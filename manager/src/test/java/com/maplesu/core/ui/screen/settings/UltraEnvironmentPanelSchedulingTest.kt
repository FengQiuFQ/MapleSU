package com.maplesu.core.ui.screen.settings

import dev.maplesu.manager.runtime.ultra.InstalledIdentity
import dev.maplesu.manager.runtime.ultra.Source
import dev.maplesu.manager.runtime.ultra.UltraEnvFacts
import dev.maplesu.manager.runtime.ultra.UltraEnvObservation
import dev.maplesu.manager.runtime.ultra.UltraEnvUpgrade
import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraEnvironmentPanelSchedulingTest {
    private val facts = UltraEnvFacts(running = true, installedVersion = "5.0.5", bundledVersion = "5.0.5",
        installedBuildId = "old", installedHelperSha256 = "a".repeat(64), bundledHelperSha256 = "b".repeat(64),
        identityKnown = true, observationScope = "scope")
    private val identity = InstalledIdentity("b".repeat(64), "/data/example/init", 123L,
        "current", "boot", Source.Readback)

    @Test fun completedReadbackReplacesOnlyInstalledIdentityFields() {
        assertEquals(facts.copy(installedBuildId = "current", installedHelperSha256 = "b".repeat(64)),
            mergeCompletedReadback(facts, "scope", identity))
    }

    @Test fun absentPersistedAndUnknownEvidenceDoesNotChangeTheDisplay() {
        assertNull(mergeCompletedReadback(facts, "scope", null))
        for (source in listOf(Source.Persisted, Source.Unknown)) {
            assertNull(mergeCompletedReadback(facts, "scope", identity.copy(source = source)))
        }
    }

    @Test fun anotherActivationOrCredentialScopeRejectsTheCompletion() {
        assertNull(mergeCompletedReadback(facts, "next-activation", identity))
        assertNull(mergeCompletedReadback(facts, null, identity))
        assertNull(mergeCompletedReadback(null, "scope", identity))
        assertNull(mergeCompletedReadback(facts.copy(observationScope = null), "scope", identity))
    }

    @Test fun completedReadbackPreservesIndependentFailureAndTransactionFacts() {
        val uncertain = facts.copy(running = false, suspended = true, quiescing = true,
            submittedThisBoot = true, readUnknown = true)
        assertEquals(uncertain.copy(installedBuildId = "current", installedHelperSha256 = "b".repeat(64)),
            mergeCompletedReadback(uncertain, "scope", identity))
    }

    @Test fun aFreshIdentityChangesTheRealUpgradeDecisionWithoutReadingFactsAgain() {
        val before = UltraEnvObservation.observe(null, facts, "scope")!!
        assertTrue(before.upgrade is UltraEnvUpgrade.Available)
        val after = mergeCompletedReadback(facts, "scope", identity)!!
        assertEquals(UltraEnvUpgrade.None, UltraEnvObservation.observe(before, after, "scope")!!.upgrade)
        assertEquals("5.0.5", after.installedVersion)
    }

    @Test fun aLateFullReadCanMergeTheNewestCompletedIdentity() {
        val oldFullRead = facts.copy(installedBuildId = "older", installedHelperSha256 = "c".repeat(64))
        val merged = mergeCompletedReadback(oldFullRead, "scope", identity)!!
        assertEquals("current", merged.installedBuildId)
        assertEquals("b".repeat(64), merged.installedHelperSha256)
    }

    private fun source(): String {
        val cwd = File(System.getProperty("user.dir") ?: ".").absoluteFile
        val manager = if (File(cwd, "src/main/java").isDirectory) cwd else File(cwd, "manager")
        return File(manager, "src/main/java/com/maplesu/core/ui/screen/settings/UltraEnvironmentPanel.kt").readText()
    }

    @Test fun completionEventsDoNotRetireTheLifecycleReadOrStartAnotherSdkRead() {
        val text = source()
        assertFalse(text.contains("Triple(detectionRevision, rootAvailable, identityRevision)"))
        assertTrue(text.contains("LaunchedEffect(panel, identityRevision) { panel.readbackCompleted() }"))
        val body = text.substringAfter("internal fun readbackCompleted()").substringBefore("fun startUpgrade()")
        assertTrue(body.contains("UltraInstalledIdentityProbe.completedReadback(context)"))
        assertFalse(body.contains("refresh()"))
        assertFalse(body.contains("readFacts("))
        assertFalse(body.contains("cancel()"))
    }

    @Test fun fullReadPublicationMergesLocalIdentityAndKeepsTheExistingCancellationGuard() {
        val text = source()
        val body = text.substringAfter("private fun apply(facts: UltraEnvFacts)").substringBefore("private fun toast")
        assertTrue(body.contains("mergeCompletedReadback(facts, currentScope"))
        assertTrue(text.contains("generation != readGeneration || request != readRequests.get() || !foreground"))
        val refreshGate = text.substringAfter("fun refresh()").substringBefore("val generation")
        assertTrue(refreshGate.contains("!foreground"))
        assertTrue(refreshGate.contains("reading?.isActive == true"))
        assertTrue(refreshGate.contains("ModeRuntime.active == WorkMode.KSU"))
        assertTrue(text.contains("if (visible && foreground) panel.resume()"))
    }

    @Test fun completedOperationsRetirePendingReadsBeforeRefreshingThePage() {
        val body = source().substringAfter("internal fun operationChanged(").substringBefore("internal fun pause()")
        assertTrue(body.contains("operation.completedRevision != operationRevision"))
        assertTrue(body.contains("reading?.cancel()"))
        assertTrue(body.contains("readGeneration++"))
        assertTrue(body.contains("observationRead.invalidate()"))
        assertTrue(body.indexOf("observationRead.invalidate()") < body.indexOf("refresh()"))
        val completion = source().substringAfter("fun startUpgrade()").substringBefore("private fun apply(")
        assertTrue(completion.contains("operationChanged(UltraEnvironmentUpgrade.operationFlow.value)"))
    }

    @Test fun factsAreReadOnceWithinOneBudgetAndSubsequentReadsNeedRealEvents() {
        val refresh = source().substringAfter("fun refresh()").substringBefore("private fun readInstalledVersion")
        assertTrue(refresh.contains("readCurrentObservation()"))
        assertTrue(refresh.contains("observationRead.read("))
        assertFalse(refresh.contains("generateSequence"))
        assertFalse(refresh.contains("delay("))
        assertFalse(refresh.contains("toast("))
        assertTrue(source().contains("BoundedPageRead<Pair<String?, UltraEnvFacts?>>(10_000L)"))
        assertTrue(source().contains("LaunchedEffect(panel, upgradeOperation) { panel.operationChanged(upgradeOperation) }"))
        assertTrue(source().contains("fun checkForUpgrade(onChecked: (UltraEnvUpgrade) -> Unit)"))
    }
}
