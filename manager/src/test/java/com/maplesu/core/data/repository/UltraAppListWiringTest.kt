package com.maplesu.core.data.repository

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Call-site contract: a pure projection alone would not catch a remaining per-row identity lookup. */
class UltraAppListWiringTest {
    private fun source(path: String): String = listOf(File("src/main/java/$path"), File("manager/src/main/java/$path"))
        .first { it.isFile }.readText()

    private fun repository() = source("com/maplesu/core/data/repository/SuperUserRepositoryImpl.kt")
    private fun initialLoad() = repository().substringAfter("private suspend fun loadUltraAppList()")
        .substringBefore("override suspend fun refreshProfiles(")

    @Test fun initialUltraListDoesNotReadAnAuthorizationIdentityForEveryApplication() {
        assertFalse("Ultra list still performs per-row identity/signature lookups", initialLoad().contains("Natives.getAppProfile("))
    }

    @Test fun initialUltraListRequiresOneSuccessfulAuthorizationSnapshotBeforeMapping() {
        assertTrue("SDK failure must fail the batch before profiles are projected", initialLoad().contains("UltraAppListSnapshot.withPackages("))
        assertTrue(initialLoad().contains("delivery = refreshUltraDelivery()"))
        assertTrue(repository().contains("UltraAuthorization.refreshDetailed(ksuApp)"))
        assertTrue(repository().contains("ManagerAuthorizations.currentDeliveryRead(refreshed.scope, snapshot)"))
        assertTrue(initialLoad().contains("UltraAuthorization.grantedPackages()"))
        assertTrue(initialLoad().contains("grants.isGranted("))
    }

    @Test fun refreshingUltraProfilesAlsoUsesOneSnapshotBeforeTheLegacyPerRowPath() {
        val refresh = repository().substringAfter("override suspend fun refreshProfiles(")
            .substringBefore("private suspend inline fun connectKsuService(")
        val ultra = refresh.substringAfter("if (ModeRuntime.active == WorkMode.LITE && usesReadyUltraBackend())")
            .substringBefore("\n            currentApps.map {")
        assertTrue("Ultra refresh branch is missing", refresh.contains("if (ModeRuntime.active == WorkMode.LITE && usesReadyUltraBackend())"))
        assertTrue(ultra.contains("UltraAppListSnapshot.read("))
        assertTrue(ultra.contains("delivery = refreshUltraDelivery()"))
        assertTrue(ultra.contains("currentDeliveryRead = delivery"))
        assertTrue(ultra.contains("grants.isGranted("))
        assertFalse(ultra.contains("Natives.getAppProfile("))
        assertTrue("Normal/legacy profiles must keep their original backend", refresh.contains("Natives.getAppProfile(it.profileKey, it.uid)"))
    }

    @Test fun actualProfileDetailsAndWritesKeepTheInstallationIdentityChecks() {
        val authorization = source("dev/maplesu/manager/runtime/authorization/ManagerAuthorizations.kt")
        val read = authorization.substringAfter("fun profile(").substringBefore("fun saveProfile(")
        val save = authorization.substringAfter("fun saveProfile(")
        assertTrue(read.contains("AndroidApplicationIdentities(context).read(uid)"))
        assertTrue(save.contains("AndroidApplicationIdentities(context).read(profile.currentUid)"))
        assertTrue(save.contains("profile.name !in identity.members.keys"))
        val details = source("com/maplesu/core/ui/screen/appprofile/AppProfileScreen.kt")
        assertTrue(details.contains("Natives.getAppProfileFreshDetailed(packageName, uid)"))
        assertTrue(details.contains("Natives.setAppProfileDetailed(profileToSave)"))
        assertTrue(details.contains("policy.complete(request, profileToSave, result, observed?.profile)"))
        assertTrue(details.contains("result.pendingApply} unknown=\${result.commitUnknown}"))
    }
    @Test fun ultraProfileDetailsResolveSystemPackageUidsBeforeTheLegacyApplicationIdentity() {
        val authorization = source("dev/maplesu/manager/runtime/authorization/ManagerAuthorizations.kt")
        val read = authorization.substringAfter("fun profile(").substringBefore("fun saveProfile(")
        val ultra = read.substringBefore("val identity = AndroidApplicationIdentities(context).read(uid)")
        assertTrue(ultra.contains("if (usesSdkOnly(context))"))
        assertTrue(ultra.contains("matchesUltraPackage(context, name, uid)"))
        assertTrue(ultra.contains("return Natives.Profile(name,"))
        assertTrue(ultra.contains("!UltraAuthorization.refresh(context)) return null"))
        assertFalse(ultra.contains("AndroidApplicationIdentities"))
    }

    @Test fun ultraProfileWritesDoNotRequireAnOrdinaryAppIdentity() {
        val authorization = source("dev/maplesu/manager/runtime/authorization/ManagerAuthorizations.kt")
        val save = authorization.substringAfter("fun saveProfile(").substringBefore("// Lite supports")
        val ultra = save.substringAfter("if (ultra) {").substringBefore("} else {")
        assertTrue(ultra.contains("matchesUltraPackage(context, profile.name, profile.currentUid)"))
        assertFalse(ultra.contains("AndroidApplicationIdentities"))
        assertTrue(save.substringAfter("} else {").contains("AndroidApplicationIdentities(context).read(profile.currentUid)"))
        val mapping = authorization.substringAfter("private fun matchesUltraPackage(").substringBefore("/** Serial worker")
        assertTrue(mapping.contains("context.packageManager.getApplicationInfo(name, 0).uid == uid"))
    }

}
