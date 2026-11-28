package com.maplesu.core.ui.viewmodel

import java.io.File
import org.junit.Assert.*
import org.junit.Test

/** Page and explicit refresh share one bounded observation session and its final publication. */
class HomeRecoveryRefreshContractTest {
    private fun source(path: String): String = listOf(File("src/main/java/$path"), File("manager/src/main/java/$path"))
        .first { it.isFile }.readText().replace("\r\n", "\n")

    @Test fun theCurrentBootstrapFailureKeepsItsFullDetailForTheHomeConsumer() {
        val viewModel = source("com/maplesu/core/ui/viewmodel/HomeViewModel.kt")
        val collection = viewModel.substringAfter("private suspend fun collectEnvironment(")
            .substringBefore("private suspend fun refreshInformation(")
        assertTrue(collection.contains("val detectionFailure = ModeRuntime.detectionFailure.takeIf { revision != publishedDetectionRevision }"))
        assertTrue(collection.contains("failureDetail = ModeRuntime.detectionFailureDetail.takeIf { detectionFailure != null } ?: detectionFailure"))
        assertTrue(collection.contains("detectionFailure = detectionFailure,"))
        val completion = viewModel.substringAfter("private suspend fun finishEnvironmentSession(")
            .substringBefore("private suspend fun checkEnvironmentPresence(")
        assertTrue(completion.contains("publishState(state, owner, candidate)?.let { publishedDetectionRevision = it }"))
    }

    @Test fun theFinalFailureDiagnosticChecksItsScopeWithoutDemandingARootSuccess() {
        val viewModel = source("com/maplesu/core/ui/viewmodel/HomeViewModel.kt")
        val completion = viewModel.substringAfter("private suspend fun finishEnvironmentSession(")
            .substringBefore("private suspend fun checkEnvironmentPresence(")
        val diagnostic = completion.substringAfter("val diagnostic = settledState.ultraObservationDetail")
        assertTrue(diagnostic.contains("failureCode = settledState.ultraObservationCode"))
        assertTrue(diagnostic.contains("detail = detail"))
        val publication = viewModel.substringAfter("private suspend fun publishState(")
            .substringBefore("fun refreshEntryFacts()")
        assertTrue(publication.contains("state.afterFinalEnvironmentScopeCheck("))
        assertTrue(publication.contains("BootIdSourceAdapter.read()"))
        assertTrue(publication.contains("UltraEnvironmentProbe.currentSnapshot(ksuApp)"))
        assertFalse(publication.contains("current.rootAvailable"))
        assertFalse(publication.contains("observeFresh("))
        assertTrue(publication.indexOf("publishMutex.withLock") < publication.indexOf("state.afterFinalEnvironmentScopeCheck("))
        assertTrue(publication.indexOf("state.afterFinalEnvironmentScopeCheck(") < publication.indexOf("_uiState.update"))
    }

    @Test fun aClaimedRefreshObservesExistingDetectionWithoutStartingRecovery() {
        val viewModel = source("com/maplesu/core/ui/viewmodel/HomeViewModel.kt")
        val refresh = viewModel.substringAfter("fun refresh() {")
            .substringBefore("private fun startEnvironmentSession(")
        assertTrue(refresh.contains("startEnvironmentSession(explicit = true)"))
        val session = viewModel.substringAfter("fun checkEnvironmentManually() {")
            .substringBefore("private fun HomeStateRead.hasFreshIdentityEvidence()")
        assertFalse(session.contains("ksuApp.requestUltraRecovery("))
        assertFalse(session.contains("ModeBootstrap.retryEnvironmentDetection("))
        val observation = session.substringAfter("private suspend fun observeEnvironment(")
        val check = observation.indexOf("checkEnvironmentPresence(deadline)")
        val pending = observation.indexOf("ModeBootstrap.pendingEnvironmentDetection()?.await()")
        val collect = observation.indexOf("val read = collectEnvironment(")
        assertTrue(check >= 0 && pending > check && collect > pending)
        assertTrue(observation.contains("ModeRuntime.active == null && remainingEnvironmentTime(deadline) > 0L"))
    }

    @Test fun aRefreshQueuesBehindPublicationInsteadOfReturningWhenItIsLocked() {
        val viewModel = source("com/maplesu/core/ui/viewmodel/HomeViewModel.kt")
        val session = viewModel.substringAfter("private fun startEnvironmentSession(")
            .substringBefore("private suspend fun prepareEnvironmentObservation(")
        assertFalse(session.contains("publishMutex.isLocked"))
        val observe = session.indexOf("observeEnvironment(deadline)")
        val finish = session.indexOf("finishEnvironmentSession(candidate, deadlineExceeded = completed != true)")
        assertTrue(observe >= 0 && finish > observe)
        assertFalse(session.contains("publishState("))
        val probe = viewModel.substringAfter("private suspend fun collectEnvironment(")
            .substringBefore("private suspend fun refreshInformation(")
        assertTrue(probe.contains("environmentMutex.withLock {"))
        assertFalse(probe.contains("publishMutex.isLocked"))
        assertFalse(probe.contains("publishState("))
        val observation = viewModel.substringAfter("private suspend fun observeEnvironment(")
            .substringBefore("private fun HomeStateRead.hasFreshIdentityEvidence()")
        assertFalse(observation.contains("publishMutex.isLocked"))
        assertFalse(observation.contains("publishState("))
        val completion = viewModel.substringAfter("private suspend fun finishEnvironmentSession(")
            .substringBefore("private suspend fun checkEnvironmentPresence(")
        assertTrue(completion.contains("publishState(state, owner, candidate)"))
        assertTrue(viewModel.contains("private val environmentMutex = Mutex()"))
        assertTrue(viewModel.contains("private val publishMutex = Mutex()"))
        val publication = viewModel.substringAfter("private suspend fun publishState(")
            .substringBefore("fun refreshEntryFacts()")
        assertTrue(publication.contains("publishMutex.withLock"))
        val ownerGuard = publication.indexOf("if (!owner.isCurrent(environmentOwner)) return@withLock")
        assertTrue(ownerGuard >= 0 && publication.indexOf("_uiState.update") > ownerGuard)
    }

    @Test fun aPageReturnRefreshesAfterTheFirstVisibleEntry() {
        val page = source("com/maplesu/core/ui/screen/home/HomeScreen.kt")
        assertTrue(page.contains("var initialPageEntryHandled by rememberSaveable { mutableStateOf(false) }"))
        val entry = page.substringAfter("LaunchedEffect(isCurrentPage) {")
            .substringBefore("LifecycleResumeEffect(Unit)")
        assertTrue(entry.contains("if (isCurrentPage) {"))
        assertTrue(entry.contains("if (initialPageEntryHandled) viewModel.refreshOnForeground()"))
        assertTrue(entry.contains("viewModel.refreshEntryFacts()"))
        assertTrue(entry.indexOf("viewModel.refreshOnForeground()") < entry.indexOf("initialPageEntryHandled = true"))
    }

    @Test fun manualRetryJoinsTheBoundedSessionAndClearsProgressAtFinalPublication() {
        val viewModel = source("com/maplesu/core/ui/viewmodel/HomeViewModel.kt")
        val manual = viewModel.substringAfter("fun checkEnvironmentManually() {")
            .substringBefore("fun refreshOnForeground()")
        assertTrue(manual.contains("startEnvironmentSession(explicit = true, inspectInstalledKernel = true)"))
        assertFalse(manual.contains("refreshFlight.runAfterCurrent"))
        assertFalse(manual.contains("refresh()"))
        val session = viewModel.substringAfter("private fun startEnvironmentSession(")
            .substringBefore("private fun remainingEnvironmentTime(")
        val explicit = session.indexOf("environmentExplicitRequest = true")
        val merge = session.indexOf("installedKernelInspectionRequested = installedKernelInspectionRequested || inspectInstalledKernel")
        val guard = session.indexOf("if (environmentSessionJob?.isActive == true || !explicit && environmentSessionJob != null) return")
        val claim = session.indexOf("environmentSessionJob = refreshFlight.launch(viewModelScope)")
        assertTrue(explicit >= 0 && merge > explicit && guard > merge && claim > guard)
        assertTrue(viewModel.contains("private const val HOME_ENVIRONMENT_SESSION_TIMEOUT_MS = 10_000L"))
        assertTrue(session.contains("val deadline = SystemClock.elapsedRealtime() + HOME_ENVIRONMENT_SESSION_TIMEOUT_MS"))
        assertTrue(session.contains("withTimeoutOrNull(HOME_ENVIRONMENT_SESSION_TIMEOUT_MS)"))
        val completion = viewModel.substringAfter("private suspend fun finishEnvironmentSession(")
            .substringBefore("private suspend fun checkEnvironmentPresence(")
        assertTrue(completion.contains("environmentChecking = false, litePending = false"))
        assertTrue(completion.contains("manualEnvironmentChecking = false"))
        val foreground = viewModel.substringAfter("fun refreshOnForeground() {").substringBefore("fun refresh()")
        assertTrue(foreground.contains("refreshEntryFacts()"))
        assertTrue(foreground.contains("startEnvironmentSession()"))
        assertFalse(foreground.contains("explicit = true"))
    }

    @Test fun resumeAndPageEntryKeepIndependentFirstRunGuards() {
        val page = source("com/maplesu/core/ui/screen/home/HomeScreen.kt")
        val resume = page.substringAfter("LifecycleResumeEffect(Unit) {")
            .substringBefore("onPauseOrDispose")
        assertTrue(resume.contains("initialResumeHandled.value && latestIsCurrentPage"))
        assertTrue(resume.contains("viewModel.refreshOnForeground()"))
        assertTrue(resume.contains("viewModel.refreshEntryFacts()"))
        assertFalse(resume.contains("initialPageEntryHandled"))
    }

    @Test fun aHiddenTransactionInvalidatesTheDisplayWithoutWaitingForOtherHiddenFacts() {
        val page = source("com/maplesu/core/ui/screen/home/HomeScreen.kt")
        assertTrue(page.contains("remember(uiState, entryFacts.hidden)"))
        assertTrue(page.contains("uiState.withHiddenFacts(entryFacts.hidden)"))
    }
}
