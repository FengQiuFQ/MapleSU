package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import dev.maplesu.manager.runtime.authorization.ManagerGrantFailureFixture
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.ModeRuntime
import java.io.File
import java.lang.reflect.Proxy
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.*
import org.junit.Test
import sun.misc.Unsafe

/** Only Android storage and background dispatch are fixtures; both actual mutation consumers execute. */
class UltraAuthorizationFailureScopeTest {
    private val unsafe: Unsafe get() = Unsafe::class.java.getDeclaredField("theUnsafe")
        .apply { isAccessible = true }.get(null) as Unsafe
    private val managerUid = 10123
    private val managerPackage = "dev.maplesu.manager"
    private val boot = "11111111-2222-4333-8444-555555555555"

    private class GrantContext private constructor() : ContextWrapper(null) {
        lateinit var info: ApplicationInfo
        lateinit var folder: File
        lateinit var preferences: (String) -> SharedPreferences
        override fun getApplicationContext(): Context = this
        override fun getApplicationInfo(): ApplicationInfo = info
        override fun getPackageName(): String = "dev.maplesu.manager"
        override fun getFilesDir(): File = File(folder, "files")
        override fun getNoBackupFilesDir(): File = File(folder, "no-backup")
        override fun getDataDir(): File = folder
        override fun createDeviceProtectedStorageContext(): Context = this
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences = preferences(name)
    }

    private fun memoryPreferences(): SharedPreferences {
        val values = mutableMapOf<String, Any>()
        return Proxy.newProxyInstance(SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java)) { _, method, args ->
            when (method.name) {
                "getAll" -> values.toMap()
                "contains" -> values.containsKey(args[0])
                "getString", "getBoolean", "getInt", "getLong", "getFloat", "getStringSet" ->
                    values[args[0]] ?: args[1]
                "edit" -> {
                    val pending = mutableMapOf<String, Any?>()
                    var clear = false
                    Proxy.newProxyInstance(SharedPreferences.Editor::class.java.classLoader,
                        arrayOf(SharedPreferences.Editor::class.java)) { editor, edit, arguments ->
                        when (edit.name) {
                            "putString", "putBoolean", "putInt", "putLong", "putFloat", "putStringSet" -> {
                                pending[arguments[0] as String] = arguments[1]
                                editor
                            }
                            "remove" -> { pending[arguments[0] as String] = null; editor }
                            "clear" -> { clear = true; editor }
                            "commit", "apply" -> {
                                if (clear) values.clear()
                                for ((key, value) in pending) {
                                    if (value == null) values.remove(key) else values[key] = value
                                }
                                if (edit.name == "commit") true else null
                            }
                            else -> error("Unexpected preference edit: ${edit.name}")
                        }
                    }
                }
                else -> error("Unexpected preference call: ${method.name}")
            }
        } as SharedPreferences
    }

    private fun context(): Context = (unsafe.allocateInstance(GrantContext::class.java) as GrantContext).apply {
        info = (unsafe.allocateInstance(ApplicationInfo::class.java) as ApplicationInfo).apply {
            uid = managerUid
            sourceDir = "/fixture/manager/base.apk"
        }
        folder = File(System.getProperty("java.io.tmpdir"), "maplesu-authorization-scope-fixture")
        val stores = mutableMapOf<String, SharedPreferences>()
        preferences = { name -> stores.getOrPut(name, ::memoryPreferences) }
    }

    private class CountingExecutor : AbstractExecutorService() {
        var calls = 0
        override fun execute(command: Runnable) { calls++ }
        override fun shutdown() = Unit
        override fun shutdownNow(): MutableList<Runnable> = mutableListOf()
        override fun isShutdown() = false
        override fun isTerminated() = false
        override fun awaitTermination(timeout: Long, unit: TimeUnit) = true
    }

    private fun checkFailure(route: String, managerTarget: Boolean, scopeCurrent: Boolean = true) {
        val context = context()
        val modeField = ModeRuntime::class.java.getDeclaredField("current").apply { isAccessible = true }
        val detectionField = ModeRuntime::class.java.getDeclaredField("lastDetection").apply { isAccessible = true }
        val bootField = UltraEnvironmentAutoSetup::class.java.getDeclaredField("processBootId").apply { isAccessible = true }
        val probeBootField = UltraEnvironmentProbe::class.java.getDeclaredField("snapshotBootId").apply { isAccessible = true }
        val snapshotsField = UltraEnvironmentProbe::class.java.getDeclaredField("snapshots").apply { isAccessible = true }
        val revisionField = UltraEnvironmentProbe::class.java.getDeclaredField("revision").apply { isAccessible = true }
        val executorField = UltraEnvironmentProbe::class.java.getDeclaredField("executor").apply { isAccessible = true }
        val refreshingField = UltraEnvironmentProbe::class.java.getDeclaredField("refreshing").apply { isAccessible = true }
        val stateField = UltraAuthorization::class.java.getDeclaredField("state").apply { isAccessible = true }
        val state = stateField.get(null) as UltraAuthorizationState
        val observationField = UltraAuthorizationState::class.java.getDeclaredField("observation").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val snapshots = snapshotsField.get(null) as MutableStateFlow<UltraEnvironmentProbe.Snapshot>
        val refreshing = refreshingField.get(null) as AtomicBoolean
        val savedMode = modeField.get(null)
        val savedDetection = detectionField.get(null)
        val savedBoot = bootField.get(null)
        val savedProbeBoot = probeBootField.get(null)
        val savedSnapshot = snapshots.value
        val savedRevision = revisionField.get(null)
        val savedExecutor = executorField.get(null)
        val savedRefreshing = refreshing.get()
        val savedObservation = observationField.get(state)
        val executor = CountingExecutor()
        val executorBase = unsafe.staticFieldBase(executorField)
        val executorOffset = unsafe.staticFieldOffset(executorField)
        try {
            modeField.set(null, ModeActivation.Unresolved)
            detectionField.set(null, null)
            bootField.set(null, boot)
            probeBootField.set(null, boot)
            refreshing.set(false)
            unsafe.putObject(executorBase, executorOffset, executor)
            val owner = UltraRuntimeClient.ManagerOwnerIdentity(android.os.Process.myUid(), 42, "ab".repeat(16))
            UltraEnvironmentProbe.publishSnapshot(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running,
                observedAtElapsedMs = 1, kernelRootVerified = true, managerOwnerIdentity = owner,
                sdkChannelAvailable = true, observedBootId = boot))
            val current = { scopeCurrent && UltraEnvironmentProbe.currentSnapshot(context).managerOwnerIdentity == owner }
            val client = ManagerGrantFailureFixture.client()
            UltraRuntimeClient::class.java.getDeclaredField("loadFailure").apply { isAccessible = true }
                .set(client, "fixture bridge offline")
            val scope = ManagerGrantFailureFixture.scope(client, current)
            val uid = if (managerTarget) managerUid else managerUid + 100000
            val name = if (managerTarget) managerPackage else "example.target"
            val port = object : SuAuthPort {
                override val supportsUidProfiles = true
                override fun uidProfiles() = listOf(SuUidProfile(uid, true, name))
                override fun snapshot(): List<String>? = error("Unexpected package list")
                override fun add(packageName: String): NativeReceipt = error("Unexpected write")
                override fun remove(packageName: String): NativeReceipt = error("Unexpected revoke")
            }
            assertNull(state.refresh(port))
            assertTrue(UltraAuthorization.isGranted(uid))
            val result = if (route == "uid") UltraAuthorization.setUidGranted(context, uid, name, false, scope)
                else UltraAuthorization.setGranted(context, name, false, scope, uid)
            assertFalse(result.succeeded)
            if (scopeCurrent) {
                assertEquals("MAPLESU_BRIDGE_UNAVAILABLE", result.error)
                assertNotNull(result.receipt)
                assertEquals("set_su_uid_profile", result.receipt!!.operation)
                assertEquals(-1001, result.receipt.sdkErrorCode)
                assertFalse(UltraAuthorization.isLoaded())
                assertFalse(UltraAuthorization.isGranted(uid))
                assertTrue(UltraAuthorization.isDeliveryIncomplete())
            } else {
                assertEquals("SU_AUTH_SCOPE_CHANGED", result.error)
                assertNull(result.receipt)
            }
            val observation = UltraEnvironmentProbe.currentSnapshot(context)
            assertEquals("$route discarded the current signed Owner", owner, observation.managerOwnerIdentity)
            assertEquals(boot, observation.observedBootId)
            assertTrue("$route discarded independent Root proof", observation.kernelRootVerified)
            assertTrue(observation.sdkChannelAvailable)
            assertEquals("$route automatically scheduled another probe", 0, executor.calls)
            if (managerTarget && scopeCurrent) {
                assertEquals(result.diagnosticSummary, observation.managerSuFailureDetail)
                assertTrue(current())
            } else assertNull(observation.managerSuFailureDetail)
        } finally {
            unsafe.putObject(executorBase, executorOffset, savedExecutor)
            refreshing.set(savedRefreshing)
            observationField.set(state, savedObservation)
            revisionField.set(null, savedRevision)
            probeBootField.set(null, savedProbeBoot)
            snapshots.value = savedSnapshot
            bootField.set(null, savedBoot)
            detectionField.set(null, savedDetection)
            modeField.set(null, savedMode)
        }
    }

    @Test fun failedManagerUidDeliveryKeepsOwnerRootAndOriginalReceiptWithoutReprobe() = checkFailure("uid", true)
    @Test fun failedManagerPackageDeliveryKeepsOwnerRootAndOriginalReceiptWithoutReprobe() = checkFailure("package", true)
    @Test fun anotherUidFailureNeverBecomesAManagerSuFailure() = checkFailure("uid", false)
    @Test fun anotherPackageFailureNeverBecomesAManagerSuFailure() = checkFailure("package", false)
    @Test fun aChangedScopeDoesNotPublishOldFailureIntoTheCurrentOwnerSnapshot() = checkFailure("uid", true, false)
}
