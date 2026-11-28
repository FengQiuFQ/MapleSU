package com.maplesu.core.ui.screen.home

import java.io.File
import org.junit.Assert.*
import org.junit.Test

/** UI wiring checks; device rendering is verified separately. */
class HomeReadinessDisplayContractTest {
    private fun source(name: String) = listOf(File("src/main/java/$name"), File("manager/src/main/java/$name"))
        .first { it.isFile }.readText().replace("\r\n", "\n")

    @Test fun everyInstalledCardUsesCurrentReadinessRatherThanInstallationForItsCheckIcon() {
        for (name in listOf("HomeMaterial", "HomeMiuix", "HomeThemeLayouts")) {
            val code = source("com/maplesu/core/ui/screen/home/$name.kt")
            assertTrue("$name must distinguish readiness", code.contains("state.showEnvironmentReady"))
            assertTrue("$name must share installation/runtime wording", code.contains("homeInstalledStatusSummary(state"))
        }
    }

    @Test fun installedVersionLinesUseObservedValuesRatherThanAnInventedFallback() {
        val summary = source("com/maplesu/core/ui/screen/home/HomeThemeLayouts.kt")
            .substringAfter("internal fun homeInstalledStatusSummary(")
            .substringBefore("internal fun rememberThemeHomeLayout()")
        assertTrue(summary.contains("kernelUAPIVersion?.let"))
        assertFalse(summary.contains("kernelUAPIVersion ?:"))
        assertFalse(summary.contains("ultraEnvironmentLabel(null)"))
        assertTrue(summary.contains("ultraVersionLabel?.trim()?.takeIf"))
        assertTrue(summary.contains("it.isNotEmpty() && it != ultraName"))
        assertTrue(summary.contains("R.string.home_environment_cached_title"))
        for (skin in listOf("HomeMaterial", "HomeMiuix")) {
            val code = source("com/maplesu/core/ui/screen/home/$skin.kt")
            assertTrue(code.contains("ultraVersionLabel = if (state.ultraBrandVisible) ultraEnvironment?.version else null"))
            assertFalse(code.contains("ultraEnvironmentLabel(ultraEnvironment?.version)"))
        }
    }

    @Test fun bothSkinsKeepTheirTitleAndSummaryAsSeparateTextConsumers() {
        val material = source("com/maplesu/core/ui/screen/home/HomeMaterial.kt")
            .substringAfter("internal fun MaterialStatusCard(", missingDelimiterValue = "")
            .substringBefore("\n@Composable", missingDelimiterValue = "")
        assertTrue(material.contains("ksuActive -> homeInstalledStatusTitle(state)"))
        assertTrue(material.contains("ksuActive -> homeInstalledStatusSummary(state, ultraVersionLabel)"))
        assertTrue(material.contains("text = statusTitle"))
        assertTrue(material.contains("text = statusSummary"))
        val miuix = source("com/maplesu/core/ui/screen/home/HomeMiuix.kt")
            .substringAfter("internal fun StatusCard(", missingDelimiterValue = "")
            .substringBefore("\n@Composable", missingDelimiterValue = "")
        assertTrue(miuix.contains("val customStatusTitle = homeInstalledStatusTitle(state)"))
        assertTrue(miuix.contains("text = workingText"))
        assertTrue(miuix.contains("text = homeInstalledStatusSummary(state, ultraVersionLabel)"))
    }

    @Test fun threeCardHistoryRetainsItsIdentityAndDoesNotChangeLayoutDuringRetry() {
        val code = source("com/maplesu/core/ui/screen/home/HomeThemeLayouts.kt")
        assertTrue(code.contains("state.showInstalledUnready"))
        assertTrue(code.contains("R.string.home_environment_cached_title"))
        assertFalse(code.contains("|| state.showEnvironmentStatusCard"))
    }

    @Test fun homeProjectsAlreadyObservedRuntimeWithoutStartingAnotherDetector() {
        val code = source("com/maplesu/core/ui/viewmodel/HomeViewModel.kt")
        assertTrue(code.contains("environmentRuntimeReady ="))
        assertTrue(code.substringAfter("environmentRuntimeReady =").substringBefore("managerNotRecognized")
            .contains("ultraEnvironmentRunning"))
    }

    @Test fun completeInstallationRemainsAnActionForUnresolvedModesAndUnknownHiddenReads() {
        val code = source("com/maplesu/core/ui/screen/settings/UltraEnvironmentSettings.kt")
        val eligible = code.substringAfter("private fun eligible(").substringBefore("fun refresh(")
        assertFalse(eligible.contains("== WorkMode.LITE"))
        assertTrue(eligible.contains("environmentInstallEligible("))
        assertTrue(eligible.contains("HiddenStartupConfirm.masking(context)"))
        assertTrue(eligible.contains("HiddenStartupConfirm.isPending(context)"))
        assertFalse(eligible.contains("HiddenStartupConfirm.current("))
        assertTrue(code.contains("HiddenFactsSignal.revision.collectAsStateWithLifecycle()"))
    }

    @Test fun bothSkinsKeepUnknownDetectionAndExposeTheExistingSettingsForUltraIssues() {
        for (name in listOf("HomeMaterial", "HomeMiuix")) {
            val code = source("com/maplesu/core/ui/screen/home/$name.kt")
            assertTrue(code.contains("state.environmentUnknown -> actions.onEnvironmentRetry()"))
            assertTrue(code.contains("state.showUltraObservationFailure"))
            assertTrue(code.contains("state.environmentNeedsConfirmation"))
            assertTrue(code.contains("R.string.home_environment_confirmation_title"))
            assertTrue(code.contains("R.string.home_environment_confirmation_summary"))
            assertTrue(code.contains("onClick = actions.onEnvironmentRetry"))
            assertTrue(code.contains("homeInstalledStatusTitle(state)"))
            val componentBanner = code.substringAfter("if (state.showUltraObservationFailure)")
                .substringBefore("if (state.showEnvironmentRefreshWarning)")
            assertTrue(componentBanner.contains("message = summary"))
            assertFalse(componentBanner.contains("state.ultraObservationDetail"))
            assertFalse(componentBanner.contains("R.string.home_ultra_observation_detail"))
            assertTrue(code.contains("onClick = actions.onOpenEnvironmentSettings"))
        }
        assertTrue(source("com/maplesu/core/ui/screen/home/HomeMiuix.kt")
            .contains("state.environmentUnknown || state.kernelVersion.isGKI()"))
        val screen = source("com/maplesu/core/ui/screen/home/HomeScreen.kt")
        assertTrue(screen.contains("if (Route.Settings in navigator.backStack) navigator.popUntil { it == Route.Settings }"))
        assertTrue(screen.contains("else navigator.push(Route.Settings)"))
        assertTrue(screen.contains("active = displayState.displayEnvironmentMode"))
        assertTrue(screen.contains("installed = if (displayState.showInstalledStatus)"))
        assertFalse(screen.contains("UltraEnvironmentProbe.observations"))
        assertFalse(screen.contains("ModeRuntime.active"))
        val shared = source("com/maplesu/core/ui/screen/home/HomeThemeLayouts.kt")
        assertTrue(shared.contains("val title = homeInstalledStatusTitle(state)"))
        assertTrue(shared.contains("state.isLateLoadMode && state.environmentMode != null"))
    }

    @Test fun identityDetectionResourcesRemainInProgressAndUpdateErrorsNameTheirComponent() {
        for ((locale, checking) in listOf("values" to "Detecting environment", "values-zh-rCN" to "正在探测环境")) {
            val resRoot = listOf(File("src/main/res/$locale"), File("manager/src/main/res/$locale"))
                .first { it.isDirectory }
            val document = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(File(resRoot, "home_environment_check.xml"))
            val nodes = document.getElementsByTagName("string")
            val values = (0 until nodes.length).associate { index ->
                val node = nodes.item(index)
                node.attributes.getNamedItem("name").nodeValue to node.textContent
            }
            for (key in listOf("home_environment_unknown_title", "home_environment_check_failed")) {
                assertTrue("$locale/$key", values.getValue(key).startsWith(checking))
            }
            assertEquals(if (locale == "values") "Confirm again" else "重新确认",
                values.getValue("home_environment_check_retry"))
            assertTrue(values.containsKey("home_environment_confirmation_title"))
            assertTrue(values.containsKey("home_environment_confirmation_summary"))
            assertFalse(values.getValue("home_environment_unknown_summary").contains("automatically"))
            assertFalse(values.getValue("home_environment_unknown_summary").contains("自动"))
            val strings = File(resRoot, "strings.xml").readText()
            val update = strings.substringAfter("name=\"ultra_env_update_check_failed\">").substringBefore("</string>")
            assertTrue("$locale update component", update.contains("Ultra"))
            assertTrue("$locale update reason", update.contains(if (locale == "values") "error" else "异常"))
        }
    }

    @Test fun eachStatusLayoutKeepsConfirmationOutsideItsArtwork() {
        val material = source("com/maplesu/core/ui/screen/home/HomeMaterial.kt")
        val miuix = source("com/maplesu/core/ui/screen/home/HomeMiuix.kt")
        val shared = source("com/maplesu/core/ui/screen/home/HomeThemeLayouts.kt")
        assertFalse(material.contains("EnvironmentRefreshAction("))
        assertFalse(miuix.contains("EnvironmentRefreshAction("))
        assertEquals(2, shared.split("EnvironmentRefreshAction(state.environmentChecking").size - 1)
        assertFalse(material.contains("private fun EnvironmentRefreshAction("))
        assertFalse(miuix.contains("private fun EnvironmentRefreshAction("))
        val footer = shared.substringAfter("internal fun EnvironmentRefreshAction(")
            .substringBefore("private fun ThemeCountTile(")
        assertTrue(footer.contains("home-environment-footer"))
        assertTrue(footer.contains("enabled = !checking"))
        assertTrue(footer.contains("R.string.home_environment_check_retry"))
        assertTrue(footer.contains("UiMode.Material"))
        assertTrue(footer.contains("UiMode.Miuix"))
        for ((skin, signature) in listOf(material to "internal fun MaterialStatusCard(", miuix to "internal fun StatusCard(")) {
            val page = skin.substringBefore(signature)
            val card = skin.substringAfter(signature).substringBefore("\n@Composable")
            assertFalse(page.contains("EnvironmentRefreshAction("))
            assertFalse(card.contains("EnvironmentRefreshAction("))
            assertFalse(card.contains("onClick = actions.onEnvironmentRetry,"))
            assertTrue(page.indexOf("if (state.showUltraObservationFailure)") > page.indexOf("ThemeHomeStatus(state, actions"))
        }
        val original = shared.substringAfter("if (layout != ThemeHomeLayout.Three || !state.showInstalledStatus)")
            .substringBefore("} else {")
        assertTrue(original.contains("status()"))
        assertTrue(original.indexOf("EnvironmentRefreshAction(") > original.indexOf("status()"))
    }

    @Test fun footerAddsFlowHeightAndThreeTilesCanGrowForLargerText() {
        val miuix = source("com/maplesu/core/ui/screen/home/HomeMiuix.kt")
        assertTrue(miuix.contains("BoxWithConstraints(Modifier.fillMaxWidth())"))
        assertTrue(miuix.contains("homeStatusCardMinHeight(maxWidth, decorPrefs.largeCard)"))
        assertTrue(miuix.contains("Modifier.fillMaxWidth().heightIn(min = cardMinHeight)"))
        assertFalse(miuix.contains("Modifier.aspectRatio(StatusDecoration.CARD_ASPECT_RATIO)"))
        assertTrue(miuix.contains("StatusThemeBackdrop(themeArt)"))
        val material = source("com/maplesu/core/ui/screen/home/HomeMaterial.kt")
        assertTrue(material.contains("homeStatusCardMinHeight(maxWidth, decorationPrefs.homeLargeCard)"))
        assertTrue(material.contains("modifier = Modifier.heightIn(min = cardMinHeight)"))
        val shared = source("com/maplesu/core/ui/screen/home/HomeThemeLayouts.kt")
        val height = shared.substringAfter("internal fun homeStatusCardMinHeight(").substringBefore("@Composable")
        assertTrue(height.contains("width / com.maplesu.core.ui.util.StatusDecoration.CARD_ASPECT_RATIO"))
        assertTrue(height.contains("else 112.dp"))
        assertFalse(height.contains("coerceIn("))
        val three = shared
            .substringAfter("BoxWithConstraints(modifier.fillMaxWidth().testTag(\"home-three\"))")
            .substringBefore("/** Confirmation belongs")
        assertTrue(three.contains("Row(Modifier.fillMaxWidth().heightIn(min=(this@BoxWithConstraints.maxWidth-12.dp)/2)"))
        assertTrue(three.contains(".height(IntrinsicSize.Min)"))
        assertFalse(three.contains(".height((this@BoxWithConstraints.maxWidth-12.dp)/2)"))
        assertTrue(three.contains("ThemeThreeStatus(state,actions,Modifier.weight(1f).fillMaxHeight())"))
        assertTrue(three.contains("Column(Modifier.weight(1f).fillMaxHeight()"))
        assertTrue(three.indexOf("EnvironmentRefreshAction(") > three.indexOf("home-counter-module"))
    }

    @Test fun bothScrollableViewportsReserveTheProvidedBottomBarSpaceExactlyOnce() {
        val material = source("com/maplesu/core/ui/screen/home/HomeMaterial.kt")
        val miuix = source("com/maplesu/core/ui/screen/home/HomeMiuix.kt")
        for (skin in listOf(material, miuix)) {
            assertEquals(1, skin.split("padding(bottom = bottomInnerPadding)").size - 1)
            assertFalse(skin.contains("Spacer(Modifier.height(bottomInnerPadding))"))
        }
        assertTrue(material.indexOf(".padding(bottom = bottomInnerPadding)") < material.indexOf(".verticalScroll("))
        val viewport = miuix.substringAfter("LazyColumn(").substringBefore("contentPadding = innerPadding")
        assertTrue(viewport.contains(".padding(bottom = bottomInnerPadding)"))
        assertTrue(viewport.indexOf(".padding(bottom = bottomInnerPadding)") < viewport.indexOf(".scrollEndHaptic()"))
    }
}
