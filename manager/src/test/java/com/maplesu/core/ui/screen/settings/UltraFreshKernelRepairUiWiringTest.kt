package com.maplesu.core.ui.screen.settings

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraFreshKernelRepairUiWiringTest {
    private fun source(path: String): String = listOf(File("src/main/java/$path"), File("manager/src/main/java/$path"))
        .first { it.isFile }.readText()

    private fun settings() = source("com/maplesu/core/ui/screen/settings/UltraEnvironmentSettings.kt")

    @Test fun freshRepairVisibilityUsesTheObservedKernelProof() {
        val text = settings()
        val panel = text.substringAfter("class UltraEnvironmentPanel").substringBefore("fun rememberUltraEnvironmentPanel")
        assertTrue(panel.contains("seed?.kernelRootVerified ?: initialSnapshot.kernelRootVerified"))
        assertTrue(panel.contains("val observation = UltraEnvironmentProbe.observeFresh(context)"))
        assertTrue(panel.contains("kernelRootVerified = observation.kernelRootVerified"))
        assertTrue(panel.contains("kernelRootVerified = merged.kernelRootVerified"))
        val recovery = text.substringAfter("internal fun environmentRecoveryAction(")
            .substringBefore("/** A clicked Home result")
        assertTrue(recovery.contains("diagnosticsOnly || hookEnvironment -> UltraEnvironmentRecoveryAction.NONE"))
        assertTrue(recovery.contains("state == UltraEnvironmentProbe.State.NotInstalled && kernelRootVerified"))
        assertTrue(recovery.contains("currentEvidence && (state == UltraEnvironmentProbe.State.Fault"))
        assertTrue(panel.contains("private var currentRepairEvidence by mutableStateOf(false)"))
        assertTrue(panel.contains("currentRepairEvidence = merged.repairEvidence"))
        assertTrue(panel.contains("repairEvidence = environmentRepairEvidence(observation)"))
        assertTrue(panel.contains("scopeCurrent() && environmentReadStillCurrent(observation, publication,"))
        assertTrue(panel.contains("if (UltraEnvironmentProbe.currentSnapshot() !== repairEvidencePublication)"))
        assertFalse(panel.contains("UltraEnvironmentProbe.refresh(context"))
        assertTrue(text.contains("LaunchedEffect(panel, observation) {\n        panel.observeDiagnostic()"))
        assertTrue(panel.indexOf("val scopeCurrent = captureObservation()") <
            panel.indexOf("val observation = UltraEnvironmentProbe.observeFresh(context)"))
    }

    @Test fun bothThemesConfirmTheSameProductionRepairAction() {
        val text = settings()
        for (name in listOf("UltraEnvironmentSectionMiuix", "UltraEnvironmentRowMaterial")) {
            val row = text.substringAfter("fun $name(").substringBefore("\n@Composable")
            assertTrue("$name must use shared visibility", row.contains("if (panel.canShowRepair)"))
            assertTrue("$name must use shared confirmation", row.contains("rememberFaultRepairAction(panel)"))
            assertTrue("$name keeps a neutral manual recovery entry", row.contains("R.string.ui_d_env_restore_title"))
            assertTrue("$name keeps the recovery action", row.contains("R.string.ui_d_env_restore_action"))
        }
        assertTrue(text.contains("rememberConfirmDialog(onConfirm = { panel.repairEnvironment() })"))
        assertTrue(text.contains("withContext(Dispatchers.IO) { UltraEnvironmentUpgrade.repairEnvironment(context) }"))
    }

    @Test fun precomposedSettingsOnlyClearsTheDiagnosticItActuallyHeld() {
        val screen = source("com/maplesu/core/ui/screen/settings/SettingsScreen.kt")
        assertTrue(screen.contains("val heldDiagnostic = if (isCurrentPage && !appearanceOnly)"))
        assertTrue(screen.contains("DisposableEffect(heldDiagnostic)"))
        assertTrue(screen.contains("UltraComponentDiagnosticRequests.clear(heldDiagnostic)"))
        assertFalse(screen.contains("UltraComponentDiagnosticRequests.clear()"))
    }

    @Test fun unknownCarrierAndExplicitRepatchStillReachTheImagePath() {
        val caller = source("com/maplesu/core/ui/util/KsuCli.kt")
        val condition = caller.substringAfter("val changesUltraCarrier =").substringBefore("var directRequest =")
        assertTrue(condition.contains("installedCarrier != resolvedPartition"))
        assertFalse(condition.contains("installedCarrier != null"))
        assertTrue(caller.contains("forceRepatch = forceRepatch || changesUltraCarrier"))
    }
}
