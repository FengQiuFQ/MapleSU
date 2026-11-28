package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraInstalledIdentityProbe
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.workmode.ModeRuntime
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Explicit current reads only. Each method records its own failure before asserting. */
@RunWith(AndroidJUnit4::class)
class UltraCurrentDeliveryAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context get() = instrumentation.targetContext

    private fun bootId(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id").readText().trim()
    }.getOrNull()

    private fun evidence(name: String, document: JSONObject) {
        val directory = File(context.filesDir, "current-delivery-evidence")
        check(directory.isDirectory || directory.mkdirs()) { "CURRENT_DELIVERY_EVIDENCE_DIRECTORY" }
        File(directory, name).writeText(document.toString(2))
        Log.i("MapleSUCurrentDelivery", "$name stage=${document.optString("stage")} " +
            "code=${document.optString("sdkErrorCode")} elapsedNanos=${document.optLong("elapsedNanos")}")
    }

    @Test fun currentUidReadPreservesItsTypedReceipt() {
        val started = System.nanoTime()
        val deadline = started + TimeUnit.SECONDS.toNanos(10)
        val boot = bootId()
        val activation = ModeRuntime.activation
        val name = "uid-read-${System.currentTimeMillis()}.json"
        val document = JSONObject().put("schema", "maplesu-current-uid-read/1")
            .put("stage", "started").put("callerUid", Process.myUid())
            .put("boot", boot ?: JSONObject.NULL).put("deadlineNanos", deadline)
        evidence(name, document)
        var observed: UltraRuntimeClient.SuUidProfilesSnapshot? = null
        var scopeCurrent = false
        try {
            observed = PageReadDeadline.onWorker(deadline) {
                val client = UltraRuntimeClient().scoped {
                    ModeRuntime.activation === activation && boot != null && bootId() == boot
                }
                client.suUidProfiles()
            }
            val receipt = observed.receipt
            scopeCurrent = ModeRuntime.activation === activation && boot != null && bootId() == boot
            val owner = UltraEnvironmentProbe.currentSnapshot().managerOwnerIdentity
            document.put("stage", "read_returned").put("scopeCurrent", scopeCurrent)
                .put("sdkError", receipt.sdkError).put("sdkErrorCode", receipt.sdkErrorCode)
                .put("operation", receipt.operation).put("readReceiptRaw", receipt.raw)
                .put("authorizationResult", receipt.authorizationResult?.raw ?: JSONObject.NULL)
                .put("profileCount", observed.profiles.size)
                .put("contextOwnerFullUid", owner?.fullUid ?: JSONObject.NULL)
                .put("contextOwnerEpoch", owner?.epoch ?: JSONObject.NULL)
                .put("ownerMetadataSource", "context_only")
        } catch (failure: Exception) {
            document.put("stage", "exception").put("exception", failure.toString())
        } finally {
            document.put("elapsedNanos", System.nanoTime() - started)
            evidence(name, document)
        }
        val receipt = observed?.receipt
        val message = "Current UID READ failed; private receipt=$name; code=${receipt?.sdkErrorCode}"
        assertTrue(message, scopeCurrent)
        assertNotNull(message, receipt)
        assertEquals(message, "get_su_uid_profiles", receipt!!.operation)
        assertTrue(message, receipt.succeeded)
        assertNotNull(message, receipt.authorizationResult)
        assertEquals(message, 1L, receipt.authorizationResult!!.operation)
        assertTrue(message, document.getLong("elapsedNanos") <= TimeUnit.SECONDS.toNanos(10))
    }


    /** A valid negative factory diagnostic is retained; this test grants no SU qualification. */
    @Test fun readCurrentSuRuntimeDiagnosticOnce() {
        val started = System.nanoTime()
        val deadline = started + TimeUnit.SECONDS.toNanos(10)
        val boot = bootId()
        val activation = ModeRuntime.activation
        val name = "su-runtime-${System.currentTimeMillis()}.json"
        val document = JSONObject().put("schema", "maplesu-current-su-runtime-read/1")
            .put("stage", "started").put("callerUid", Process.myUid())
            .put("boot", boot ?: JSONObject.NULL).put("deadlineNanos", deadline)
            .put("qualification", "factory_diagnostic_only")
        evidence(name, document)
        var scopeCurrent = false
        var detail: JSONObject? = null
        try {
            val receipt = PageReadDeadline.onWorker(deadline) {
                val client = UltraRuntimeClient().scoped {
                    ModeRuntime.activation === activation && boot != null && bootId() == boot
                }
                client.suRuntimeStatus()
            }
            scopeCurrent = ModeRuntime.activation === activation && boot != null && bootId() == boot
            detail = JSONObject(receipt.raw).optJSONObject("data")?.optJSONObject("suRuntimeResult")
            document.put("stage", "read_returned").put("scopeCurrent", scopeCurrent)
                .put("sdkError", receipt.sdkError).put("sdkErrorCode", receipt.sdkErrorCode)
                .put("operation", receipt.operation).put("readReceiptRaw", receipt.raw)
                .put("factoryDiagnostic", detail ?: JSONObject.NULL)
        } catch (failure: Exception) {
            document.put("stage", "exception").put("exception", failure.toString())
        } finally {
            document.put("elapsedNanos", System.nanoTime() - started)
            evidence(name, document)
        }
        val message = "Current SU runtime diagnostic missing; private receipt=$name"
        assertTrue(message, scopeCurrent)
        assertEquals(message, "get_su_runtime_status", document.optString("operation"))
        assertNotNull(message, detail)
        assertTrue(message, detail!!.optBoolean("diagnosticAvailable"))
        assertEquals(message, 104, detail!!.getJSONObject("factory").getInt("bytes"))
        val read = detail!!.getJSONObject("read").getJSONObject("management")
        assertTrue(message, read.getBoolean("completed"))
        assertEquals(message, 30, read.getInt("command"))
        assertEquals(message, "104", read.getString("result"))
        assertTrue(message, document.getLong("elapsedNanos") <= TimeUnit.SECONDS.toNanos(10))
    }

    @Test fun readCurrentInstalledHelperOnce() {
        val started = System.nanoTime()
        val deadline = started + TimeUnit.SECONDS.toNanos(10)
        val boot = bootId()
        val activation = ModeRuntime.activation
        val name = "installed-helper-${System.currentTimeMillis()}.json"
        val document = JSONObject().put("schema", "maplesu-current-installed-helper-read/1")
            .put("stage", "started").put("callerUid", Process.myUid())
            .put("boot", boot ?: JSONObject.NULL).put("deadlineNanos", deadline)
            .put("requestedHelperPath", JSONObject.NULL).put("helperReadTimeoutMillis", 300)
            .put("qualification", "current_namespace_readback_only")
        evidence(name, document)
        var observed: NativeReceipt? = null
        var readback: UltraInstalledIdentityProbe.Readback? = null
        var scopeCurrent = false
        try {
            observed = PageReadDeadline.onWorker(deadline) {
                UltraRuntimeClient().scoped {
                    ModeRuntime.activation === activation && boot != null && bootId() == boot
                }.readInstalledHelper(null, timeoutMillis = 300)
            }
            scopeCurrent = ModeRuntime.activation === activation && boot != null && bootId() == boot
            readback = UltraInstalledIdentityProbe.parseOwnerReadback(observed, Process.myUid())
            document.put("stage", "read_returned").put("scopeCurrent", scopeCurrent)
                .put("sdkError", observed.sdkError).put("sdkErrorCode", observed.sdkErrorCode)
                .put("operation", observed.operation).put("readReceiptRaw", observed.raw)
                .put("ownerReadbackValidated", readback != null)
                .put("currentHelperPath", readback?.path ?: JSONObject.NULL)
                .put("currentHelperSha256", readback?.sha256 ?: JSONObject.NULL)
                .put("currentHelperSize", readback?.size ?: JSONObject.NULL)
        } catch (failure: Exception) {
            document.put("stage", "exception").put("exception", failure.toString())
        } finally {
            document.put("elapsedNanos", System.nanoTime() - started)
            evidence(name, document)
        }
        val message = "Current installed helper READ failed; private receipt=$name"
        assertTrue(message, scopeCurrent)
        assertEquals(message, "read_installed_helper", observed?.operation)
        assertNotNull(message, readback)
        assertTrue(message, document.getLong("elapsedNanos") <= TimeUnit.SECONDS.toNanos(10))
    }

    @Test fun readCurrentInstallReceiptsOnce() {
        val started = System.nanoTime()
        val deadline = started + TimeUnit.SECONDS.toNanos(10)
        val boot = bootId()
        val activation = ModeRuntime.activation
        val name = "install-receipts-${System.currentTimeMillis()}.json"
        val command = """
            printf 'MAPLESU_PROBE_BEGIN id-u\n'
            uid=$(/system/bin/id -u)
            uid_status=${'$'}?
            printf '%s\n' "${'$'}uid"
            printf 'MAPLESU_PROBE_END id-u status=%s\n' "${'$'}uid_status"
            printf 'MAPLESU_PROBE_BEGIN id\n'
            /system/bin/id
            id_status=${'$'}?
            printf 'MAPLESU_PROBE_END id status=%s\n' "${'$'}id_status"
            printf 'MAPLESU_RECORD_BEGIN /data/local/maplesu-recovery/signed-installs/a59e6e6f-3d9e-498c-87f1-99e1c396e0f3/record.json\n'
            cat '/data/local/maplesu-recovery/signed-installs/a59e6e6f-3d9e-498c-87f1-99e1c396e0f3/record.json'
            first=${'$'}?
            printf '\nMAPLESU_RECORD_END status=%s\n' "${'$'}first"
            printf 'MAPLESU_RECORD_BEGIN /data/adb/maplesu/installer/a59e6e6f-3d9e-498c-87f1-99e1c396e0f3/record.json\n'
            cat '/data/adb/maplesu/installer/a59e6e6f-3d9e-498c-87f1-99e1c396e0f3/record.json'
            second=${'$'}?
            printf '\nMAPLESU_RECORD_END status=%s\n' "${'$'}second"
            if [ "${'$'}uid_status" -ne 0 ]; then exit "${'$'}uid_status"; fi
            if [ "${'$'}id_status" -ne 0 ]; then exit "${'$'}id_status"; fi
            if [ "${'$'}uid" != 0 ]; then exit 91; fi
            exit 0
        """.trimIndent()
        val document = JSONObject().put("schema", "maplesu-current-install-receipts-read/1")
            .put("stage", "started").put("callerUid", Process.myUid())
            .put("boot", boot ?: JSONObject.NULL).put("deadlineNanos", deadline)
            .put("qualification", "original_task_read_only").put("readOnlyCommand", command)
        evidence(name, document)
        var observed: NativeReceipt? = null
        var scopeCurrent = false
        try {
            observed = PageReadDeadline.onWorker(deadline) {
                UltraRuntimeClient().scoped {
                    ModeRuntime.activation === activation && boot != null && bootId() == boot
                }.runRootCommand(command)
            }
            scopeCurrent = ModeRuntime.activation === activation && boot != null && bootId() == boot
            document.put("stage", "read_returned").put("scopeCurrent", scopeCurrent)
                .put("sdkError", observed.sdkError).put("sdkErrorCode", observed.sdkErrorCode)
                .put("operation", observed.operation).put("readReceiptRaw", observed.raw)
            val decoded = java.net.URLDecoder.decode(observed.string("result").orEmpty(), "UTF-8")
            val uidRead = Regex("MAPLESU_PROBE_BEGIN id-u\n([^\n]*)\nMAPLESU_PROBE_END id-u status=(-?[0-9]+)")
                .find(decoded)
            document.put("actualRootUidVerified", uidRead?.groupValues?.get(1) == "0" &&
                uidRead.groupValues[2].toIntOrNull() == 0)
            val reads = JSONObject()
            for ((label, path) in listOf(
                "signed" to "/data/local/maplesu-recovery/signed-installs/a59e6e6f-3d9e-498c-87f1-99e1c396e0f3/record.json",
                "legacy" to "/data/adb/maplesu/installer/a59e6e6f-3d9e-498c-87f1-99e1c396e0f3/record.json",
            )) {
                val segment = Regex("(?s)MAPLESU_RECORD_BEGIN ${Regex.escape(path)}\n(.*?)\nMAPLESU_RECORD_END status=(-?[0-9]+)")
                    .find(decoded)
                reads.put(label, JSONObject().put("path", path).put("segmentObserved", segment != null)
                    .put("readExitCode", segment?.groupValues?.get(2)?.toIntOrNull() ?: JSONObject.NULL)
                    .put("readOutput", segment?.groupValues?.get(1) ?: JSONObject.NULL))
            }
            document.put("decodedResult", decoded).put("recordReads", reads)
                .put("recordReadQualification", "diagnostic_only_read_errors_do_not_establish_absence")
                .put("twoReadableRecordsConflict", reads.getJSONObject("signed").optInt("readExitCode", -1) == 0 &&
                    reads.getJSONObject("legacy").optInt("readExitCode", -1) == 0)
        } catch (failure: Exception) {
            document.put("stage", "exception").put("exception", failure.toString())
        } finally {
            document.put("elapsedNanos", System.nanoTime() - started)
            evidence(name, document)
        }
        val message = "Original install receipts READ failed; private receipt=$name"
        assertTrue(message, scopeCurrent)
        assertEquals(message, "read_returned", document.optString("stage"))
        assertEquals(message, "run_root_cmd", observed?.operation)
        assertTrue(message, observed?.succeeded == true)
        assertTrue(message, document.optBoolean("actualRootUidVerified"))
        assertTrue(message, document.getLong("elapsedNanos") <= TimeUnit.SECONDS.toNanos(10))
    }

    @Test fun independentUidExecutesTheStandardSuPathOnce() {
        val started = SystemClock.elapsedRealtimeNanos()
        val deadline = started + TimeUnit.SECONDS.toNanos(10)
        val name = "third-party-su-${System.currentTimeMillis()}.json"
        val fixturePackage = instrumentation.context.packageName
        val document = JSONObject().put("schema", "maplesu-current-standard-su/1")
            .put("stage", "started").put("callerUid", Process.myUid())
            .put("boot", bootId() ?: JSONObject.NULL).put("fixturePackage", fixturePackage)
            .put("deadlineElapsedRealtimeNanos", deadline)
        evidence(name, document)
        val ready = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (service == null) ready.completeExceptionally(IllegalStateException("FIXTURE_BINDER_ABSENT"))
                else ready.complete(service)
            }
            override fun onServiceDisconnected(name: ComponentName?) {
                ready.completeExceptionally(IllegalStateException("FIXTURE_DISCONNECTED"))
            }
        }
        val worker = Executors.newSingleThreadExecutor()
        var transaction: Future<Bundle>? = null
        var bound = false
        var observed: Bundle? = null
        try {
            document.put("stage", "binding")
            evidence(name, document)
            bound = context.bindService(Intent().setComponent(ComponentName(fixturePackage,
                IdentityProbeService::class.java.name)), connection, Context.BIND_AUTO_CREATE)
            check(bound) { "FIXTURE_BIND_REJECTED" }
            val binder = ready.get(remaining(deadline), TimeUnit.NANOSECONDS)
            document.put("stage", "standard_su")
            evidence(name, document)
            transaction = worker.submit<Bundle> {
                val request = Parcel.obtain()
                val response = Parcel.obtain()
                try {
                    request.writeInterfaceToken(IdentityProbeService.DESCRIPTOR)
                    request.writeLong(deadline)
                    check(binder.transact(IBinder.FIRST_CALL_TRANSACTION + 11, request, response, 0)) {
                        "FIXTURE_BOUNDED_SU_TRANSACTION_ABSENT"
                    }
                    response.readException()
                    requireNotNull(response.readTypedObject(Bundle.CREATOR)) { "FIXTURE_SU_RECEIPT_ABSENT" }
                } finally {
                    request.recycle()
                    response.recycle()
                }
            }
            observed = transaction.get(remaining(deadline), TimeUnit.NANOSECONDS)
            val receipt = JSONObject()
            for (key in observed.keySet()) {
                val value = observed.get(key)
                receipt.put(key, if (value is ByteArray) String(value, Charsets.UTF_8) else value ?: JSONObject.NULL)
            }
            document.put("stage", "read_returned").put("suReceipt", receipt)
        } catch (failure: Exception) {
            document.put("stage", "exception").put("exception", failure.toString())
        } finally {
            transaction?.cancel(true)
            worker.shutdownNow()
            if (bound) context.unbindService(connection)
            val budget = deadline - SystemClock.elapsedRealtimeNanos()
            document.put("cleanupPending", !worker.isTerminated &&
                (budget <= 0 || !worker.awaitTermination(budget, TimeUnit.NANOSECONDS)))
            document.put("elapsedNanos", SystemClock.elapsedRealtimeNanos() - started)
            evidence(name, document)
        }
        val message = "Third-party standard su failed; private receipt=$name"
        assertNotNull(message, observed)
        val receipt = observed!!
        assertNotEquals(message, Process.myUid(), receipt.getInt("uid", -1))
        assertEquals(message, context.packageManager.getApplicationInfo(fixturePackage, 0).uid, receipt.getInt("uid", -1))
        assertTrue(message, receipt.getBoolean("started"))
        assertTrue(message, receipt.getBoolean("finished"))
        assertEquals(message, 0, receipt.getInt("code", -1))
        assertEquals(message, "0", receipt.getByteArray("stdout")?.toString(Charsets.UTF_8)?.trim())
        assertFalse(message, receipt.getBoolean("cleanupPending"))
        assertFalse(message, document.getBoolean("cleanupPending"))
        assertTrue(message, document.getLong("elapsedNanos") <= TimeUnit.SECONDS.toNanos(10))
    }

    private fun remaining(deadline: Long): Long = (deadline - SystemClock.elapsedRealtimeNanos()).also {
        if (it <= 0) throw TimeoutException("CURRENT_DELIVERY_DEADLINE_EXCEEDED")
    }
}
