package com.maplesu.core.ui.viewmodel

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SuperuserPublicationRefreshTest {
    private fun source(name: String): String = listOf(File("src/main/java/$name"), File("manager/src/main/java/$name"))
        .first { it.isFile }.readText()

    @Test fun deploymentPublishesConflatedReadOnlyStatusChanges() {
        val deploy = source("dev/maplesu/manager/runtime/RuntimeDeployment.kt")
        assertTrue(deploy.contains("private val _status = MutableStateFlow(Status())"))
        assertTrue(deploy.contains("val statusChanges: StateFlow<Status> = _status.asStateFlow()"))
        assertTrue(deploy.contains("get() = _status.value"))
        assertTrue(deploy.contains("set(value) { _status.value = value }"))
    }

    @Test fun publicationChangesRebindLoadedRowsWithoutAnotherBackendRead() {
        val vm = source("com/maplesu/core/ui/viewmodel/SuperUserViewModel.kt")
        assertTrue(vm.contains("RuntimeDeployment.statusChanges.collect { refreshEntryStates() }"))
        val refresh = vm.substringAfter("private suspend fun refreshEntryStates()")
            .substringBefore("fun markNeedRefresh()")
        assertTrue(refresh.contains("refreshMutex.withLock"))
        assertTrue(refresh.contains("!_uiState.value.hasLoaded"))
        assertTrue(refresh.contains("ModeRuntime.active != WorkMode.LITE"))
        assertTrue(refresh.contains("withContext(Dispatchers.IO)"))
        assertTrue(refresh.contains("HookSuCompatibility.traditionalReady(ksuApp)"))
        for (field in listOf("groupedApps", "recentlyInstalledResults", "searchResults")) {
            assertTrue(refresh.contains("$field = withManagerSuStates(it.$field, entryReady)"))
        }
        for (backendRead in listOf("loadAppList(", "getAppList(", "refreshProfiles(", "RootExec.", "RuntimeDeployment.start(")) {
            assertFalse(refresh.contains(backendRead))
        }
    }

    @Test fun oneShotWebUiCacheReadDoesNotObserveGlobalPublication() {
        val vm = source("com/maplesu/core/ui/viewmodel/SuperUserViewModel.kt")
        assertTrue(vm.substringBefore(") : ViewModel()").contains("observePublication: Boolean = true"))
        val init = vm.substringAfter("    init {").substringBefore("private suspend fun refreshEntryStates()")
        assertTrue(init.contains("if (observePublication) {"))
        assertTrue(init.substringAfter("if (observePublication) {").contains("RuntimeDeployment.statusChanges.collect"))
        val webUi = source("com/maplesu/core/ui/webui/WebViewHelper.kt")
            .substringAfter("internal fun webUIApps(): List<AppInfo>")
            .substringBefore("fun Activity.setTaskDescription")
        assertTrue(webUi.contains("SuperUserViewModel.loadApps(useCache = true)"))
        assertFalse(webUi.contains("SuperUserViewModel("))
        assertFalse(webUi.contains("statusChanges"))
        assertFalse(webUi.contains("collect"))
        val read = vm.substringAfter("        suspend fun loadApps(").substringBefore("        @JvmStatic")
        val cacheGate = read.indexOf("if (useCache && mode != null && ModeRuntime.active == mode &&")
        val cacheReturn = read.indexOf("return Result.success(cachedApps to cachedUserIds)")
        val repositoryRead = read.indexOf("return repo.getAppList().mapCatching")
        assertTrue(cacheGate >= 0 && cacheReturn > cacheGate && repositoryRead > cacheReturn)
        assertTrue(read.substring(cacheGate, cacheReturn).contains("ModeRuntime.activation === activation"))
        assertTrue(read.substring(cacheGate, cacheReturn).contains("cachedAppsActivation === activation"))
        assertTrue(read.substring(cacheGate, cacheReturn).contains("cachedApps.isNotEmpty()"))
        assertTrue(read.substringAfter("return repo.getAppList().mapCatching").contains("PAGE_QUERY_CONTEXT_CHANGED"))
        assertFalse(read.contains("RuntimeDeployment.statusChanges"))
        assertFalse(read.contains("viewModelScope"))
    }

    @Test fun asyncListWritersShareThePublicationRefreshLock() {
        val vm = source("com/maplesu/core/ui/viewmodel/SuperUserViewModel.kt")
        val sort = vm.substringAfter("fun updateSortConfig(").substringBefore("private fun refilterVisibleApps")
        assertTrue(sort.contains("refreshMutex.withLock"))
        val filter = vm.substringAfter("private fun refilterVisibleApps").substringBefore("fun toggleShowSystemApps")
        assertTrue(filter.contains("refreshMutex.withLock"))
        assertTrue(vm.contains("private suspend fun applySearchText(text: String) = refreshMutex.withLock"))
        val manager = vm.substringAfter("private fun withManagerSuStates(").substringBefore("private fun withLiteSuStates")
        assertTrue(manager.contains("managerSuState("))
        assertFalse(manager.contains("RootExec."))
        assertFalse(manager.contains("HookSuCompatibility.traditionalReady"))
    }
}
