package dev.maplesu.manager.runtime.ultra

import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder

/**
 * The native receipt shape emitted by `runtime/ultra/bridge/native_lib_ultra.cpp`.
 *
 * The bridge answers every one of the 30 entries with this object, so success is decided
 * from `ok`, `sdkError == OK` and numeric `sdkErrorCode == 0`. `reason` is diagnostic data - for an install it is
 * the module's own install-callback refusal, which must be shown but must not be read as
 * a success signal.
 */
data class NativeReceipt(
    val schemaVersion: Int,
    val backend: String,
    val bridgeVersion: Int,
    val operation: String,
    val ok: Boolean,
    val sdkError: String,
    val sdkErrorCode: Int,
    val reason: String?,
    val data: JSONObject?,
    val raw: String,
    /** A positive native fact; an absent completion flag does not prove that no mutation ran. */
    val operationCompleted: Boolean = false,
) {
    val succeeded: Boolean get() = ok && sdkError == "OK" && sdkErrorCode == 0

    val authorizationResult: UltraAuthorizationResult? =
        UltraAuthorizationResult.parse(data?.optJSONObject("authorizationResult"))

    fun string(key: String): String? = data?.optString(key)?.takeIf { it.isNotEmpty() && it != "null" }
    fun int(key: String): Int? = data?.let { if (it.has(key)) it.optInt(key) else null }
    fun bool(key: String): Boolean? = data?.let { if (it.has(key)) it.optBoolean(key) else null }
    fun array(key: String): JSONArray? = data?.optJSONArray(key)
    fun obj(key: String): JSONObject? = data?.optJSONObject(key)

    companion object {
        internal fun rootCommand(result: SuExecResult?): NativeReceipt {
            val error = when {
                result == null -> "MAPLESU_ROOT_CHANNEL_UNAVAILABLE"
                result.timedOut -> "MAPLESU_ROOT_COMMAND_TIMEOUT"
                result.failure != null || result.cleanupPending || result.cleanupFailure != null -> "MAPLESU_ROOT_COMMAND_IO_FAILURE"
                result.exitCode != 0 -> "MAPLESU_ROOT_COMMAND_EXIT"
                else -> "OK"
            }
            val output = result?.output.orEmpty()
            val data = JSONObject()
                .put("result", URLEncoder.encode(output, "UTF-8"))
                .put("encoding", "url")
                .put("resultBytes", output.toByteArray(Charsets.UTF_8).size)
                .put("exitCode", result?.exitCode ?: -1)
                .put("timedOut", result?.timedOut == true)
                .put("cleanupPending", result?.cleanupPending == true)
                .put("cleanupFailure", result?.cleanupFailure?.let { failure ->
                    failure.takeIf { it.matches(Regex("[A-Z][A-Z0-9_]{0,63}(?::[A-Za-z][A-Za-z0-9]{0,63})?")) }
                        ?: "PROCESS_CLEANUP_FAILED"
                })
            val raw = JSONObject().put("schemaVersion", 1).put("backend", UltraRuntimeClient.BACKEND)
                .put("bridgeVersion", 0).put("operation", "run_root_cmd").put("ok", error == "OK")
                .put("sdkError", error).put("sdkErrorCode", if (error == "OK") 0 else -1001)
                .put("data", data).toString()
            return checkNotNull(parse(raw))
        }

        /**
         * Parses a bridge answer. Returns null when the text is not a receipt at all -
         * a caller must treat that as a bridge failure, never as success.
         */
        fun parse(raw: String?): NativeReceipt? {
            if (raw.isNullOrBlank()) return null
            val json = runCatching { JSONObject(raw) }.getOrNull() ?: return null
            val backend = dev.maplesu.manager.compat.StoredInputs.receiptBackend(json.optString("backend", ""))
            if (backend.isEmpty()) return null
            val value = json.opt("sdkErrorCode")
            // Android's JSON parser can round tiny nonzero floating values to zero.
            // The bridge emits integers; keep the existing decimal-string input compatibility.
            val code = when (value) {
                is Byte, is Short, is Int, is Long, is String -> value.toString().toIntOrNull()
                else -> null
            } ?: Int.MIN_VALUE
            return NativeReceipt(
                schemaVersion = json.optInt("schemaVersion", 0),
                backend = backend,
                bridgeVersion = json.optInt("bridgeVersion", 0),
                operation = json.optString("operation", ""),
                ok = json.optBoolean("ok", false),
                sdkError = dev.maplesu.manager.compat.StoredInputs.error(json.optString("sdkError", "MAPLESU_BRIDGE_UNPARSEABLE")),
                sdkErrorCode = code,
                reason = json.optString("reason", "").takeIf { it.isNotEmpty() },
                data = json.optJSONObject("data"),
                raw = raw,
                operationCompleted = json.opt("operationCompleted") as? Boolean == true,
            )
        }

        /** A receipt for the case where the bridge never ran (load failure, exception). */
        fun bridgeFailure(operation: String, error: String, detail: String?): NativeReceipt =
            bridgeFailure(operation, error, detail, -1001)

        internal fun bridgeFailure(operation: String, error: String, detail: String?, code: Int): NativeReceipt =
            NativeReceipt(
                schemaVersion = 1,
                backend = UltraRuntimeClient.BACKEND,
                bridgeVersion = 0,
                operation = operation,
                ok = false,
                sdkError = error,
                sdkErrorCode = code,
                reason = detail,
                data = null,
                raw = JSONObject()
                    .put("schemaVersion", 1)
                    .put("backend", UltraRuntimeClient.BACKEND)
                    .put("operation", operation)
                    .put("ok", false)
                    .put("sdkError", error)
                    .put("sdkErrorCode", code)
                    .put("reason", detail ?: "")
                    .toString(),
            )
    }
}

/** Project receipt success consistently without replacing its original numeric code or diagnostics. */
internal fun receiptErrorName(succeeded: Boolean, sdkError: String): String =
    if (succeeded) "OK" else sdkError.takeUnless { it == "OK" } ?: "INVALID_RECEIPT"

/** The five outcomes the spec requires a receipt to distinguish. */
enum class UltraOutcome {
    COMPLETED,
    FAILED,
    PENDING_REBOOT,
    NEEDS_RECONCILIATION,
    CONDITION_UNMET,
}

/** Lifecycle phase of a mutation, recorded in the operation log. */
enum class UltraPhase {
    PREPARED,
    HOST_CALLED,
    HOST_ACCEPTED,
    HOST_COMMITTED_CATALOG_PENDING,
    CATALOG_COMMITTED,
    BUSINESS_PROBED,
    CLEANED_UP,
}

/**
 * MapleSU's structured receipt (spec §3.2). It carries the native receipt plus the fields
 * only the Manager can know. Unknown values stay null and carry a reason in [unknowns] -
 * an absent value is never silently replaced by a default.
 */
data class UltraReceipt(
    val operationId: String,
    val backend: String,
    val operation: String,
    val phase: UltraPhase,
    val outcome: UltraOutcome,
    val sdkError: String,
    val sdkErrorCode: Int,
    val moduleId: String? = null,
    val packageSha256: String? = null,
    val sdkVersion: String? = null,
    val environmentVersion: String? = null,
    val environmentGeneration: Int? = null,
    val requestedVersion: String? = null,
    val installedVersion: String? = null,
    val activeVersion: String? = null,
    val needsReboot: Boolean = false,
    val cleanupOutcome: String? = null,
    val reason: String? = null,
    val data: JSONObject? = null,
    val raw: String? = null,
    val unknowns: Map<String, String> = emptyMap(),
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("schemaVersion", 1)
        put("operationId", operationId)
        put("backend", backend)
        put("operation", operation)
        put("phase", phase.name)
        put("outcome", outcome.name)
        put("sdkError", sdkError)
        put("sdkErrorCode", sdkErrorCode)
        put("moduleId", moduleId ?: JSONObject.NULL)
        put("packageSha256", packageSha256 ?: JSONObject.NULL)
        put("sdkVersion", sdkVersion ?: JSONObject.NULL)
        put("environmentVersion", environmentVersion ?: JSONObject.NULL)
        put("environmentGeneration", environmentGeneration ?: JSONObject.NULL)
        put("requestedVersion", requestedVersion ?: JSONObject.NULL)
        put("installedVersion", installedVersion ?: JSONObject.NULL)
        put("activeVersion", activeVersion ?: JSONObject.NULL)
        put("needsReboot", needsReboot)
        put("cleanupOutcome", cleanupOutcome ?: JSONObject.NULL)
        put("reason", reason ?: JSONObject.NULL)
        put("unknowns", JSONObject(unknowns as Map<*, *>))
        if (data != null) put("data", data)
        if (raw != null) put("rawReceipt", raw)
    }

    companion object {
        /** Builds the Manager receipt around a native answer without inventing any value. */
        fun of(
            operationId: String,
            operation: String,
            native: NativeReceipt?,
            phase: UltraPhase = UltraPhase.HOST_CALLED,
            outcome: UltraOutcome,
            moduleId: String? = null,
            packageSha256: String? = null,
            sdkVersion: String? = null,
            environmentVersion: String? = null,
            environmentGeneration: Int? = null,
            requestedVersion: String? = null,
            installedVersion: String? = null,
            activeVersion: String? = null,
            needsReboot: Boolean = false,
            cleanupOutcome: String? = null,
            data: JSONObject? = null,
            unknowns: Map<String, String> = emptyMap(),
        ): UltraReceipt = UltraReceipt(
            operationId = operationId,
            backend = UltraRuntimeClient.BACKEND,
            operation = operation,
            phase = phase,
            outcome = outcome,
            sdkError = native?.sdkError ?: "MAPLESU_BRIDGE_ABSENT",
            sdkErrorCode = native?.sdkErrorCode ?: Int.MIN_VALUE,
            moduleId = moduleId,
            packageSha256 = packageSha256,
            sdkVersion = sdkVersion,
            environmentVersion = environmentVersion,
            environmentGeneration = environmentGeneration,
            requestedVersion = requestedVersion,
            installedVersion = installedVersion,
            activeVersion = activeVersion,
            needsReboot = needsReboot,
            cleanupOutcome = cleanupOutcome,
            reason = native?.reason,
            data = data ?: native?.data,
            raw = native?.raw,
            unknowns = unknowns,
        )
    }
}

private fun JSONObject.uidReadInteger(name: String, range: LongRange): String? =
    when (val value = opt(name)) {
        is Byte, is Short, is Int, is Long -> value.toString().toLongOrNull()?.takeIf { it in range }?.toString()
        else -> null
    }

private fun JSONObject.uidReadUint(name: String): String? = uidReadInteger(name, 0L..0xffffffffL)
private fun JSONObject.uidReadSint(name: String): String? =
    uidReadInteger(name, Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong())
private fun JSONObject.uidReadBoolean(name: String): String? = (opt(name) as? Boolean)?.toString()
private fun JSONObject.uidReadDecimal(name: String, unsigned: Boolean = false): String? =
    (opt(name) as? String)?.takeIf { value ->
        if (unsigned) value.toULongOrNull()?.toString() == value else value.toLongOrNull()?.toString() == value
    }

/** Fixed public scalars only; this read diagnosis never establishes identity or delivery. */
internal fun NativeReceipt.uidReadDiagnosticSummary(): String {
    if (operation != "get_su_uid_profiles") return "uidRead=false"
    val json = data?.opt("uidReadResult") as? JSONObject ?: return "uidRead=false"
    if (json.uidReadUint("schemaVersion") != "1") return "uidRead=false"
    val available = json.opt("operationResultAvailable") as? Boolean ?: return "uidRead=false"
    val result = json.uidReadDecimal("resultCode") ?: return "uidRead=false"
    val phase = json.uidReadUint("primaryPhase") ?: return "uidRead=false"
    val errno = json.uidReadSint("primaryErrno") ?: return "uidRead=false"
    val mode = json.uidReadUint("authMode") ?: return "uidRead=false"
    val count = json.uidReadUint("recordCount") ?: return "uidRead=false"
    val transport = json.opt("transport") as? JSONObject ?: return "uidRead=false"
    val status = transport.uidReadUint("status") ?: return "uidRead=false"
    val transportErrno = transport.uidReadSint("errno") ?: return "uidRead=false"
    val childWait = transport.uidReadSint("childWaitStatus") ?: return "uidRead=false"
    val valid = transport.uidReadBoolean("valid") ?: return "uidRead=false"
    fun step(name: String): String? {
        val value = json.opt(name) as? JSONObject ?: return null
        val code = value.uidReadDecimal("code") ?: return null
        val systemErrno = value.uidReadSint("systemErrno") ?: return null
        val completed = value.uidReadBoolean("completed") ?: return null
        return " ${name}Code=$code ${name}SystemErrno=$systemErrno ${name}Completed=$completed"
    }
    val payload = if (available) {
        val root = step("root") ?: return "uidRead=false"
        val read = step("read") ?: return "uidRead=false"
        val close = step("close") ?: return "uidRead=false"
        val back = json.opt("readback") as? JSONObject ?: return "uidRead=false"
        val code = back.uidReadDecimal("code") ?: return "uidRead=false"
        val systemErrno = back.uidReadSint("systemErrno") ?: return "uidRead=false"
        val readPhase = back.uidReadUint("phase") ?: return "uidRead=false"
        val capabilities = back.uidReadDecimal("capabilities", unsigned = true) ?: return "uidRead=false"
        val revision = back.uidReadDecimal("revision", unsigned = true) ?: return "uidRead=false"
        val readCount = back.uidReadUint("count") ?: return "uidRead=false"
        val schema = back.uidReadUint("schema") ?: return "uidRead=false"
        val management = back.opt("management") as? JSONObject ?: return "uidRead=false"
        val managementStatus = management.uidReadSint("status") ?: return "uidRead=false"
        val effects = management.uidReadUint("effects") ?: return "uidRead=false"
        val managementResult = management.uidReadDecimal("result", unsigned = true) ?: return "uidRead=false"
        val command = management.uidReadUint("command") ?: return "uidRead=false"
        val completed = management.uidReadBoolean("completed") ?: return "uidRead=false"
        val hasHandle = management.uidReadBoolean("hasHandle") ?: return "uidRead=false"
        root + read + close + " readbackCode=$code readbackSystemErrno=$systemErrno readbackPhase=$readPhase" +
            " capabilities=$capabilities revision=$revision count=$readCount schema=$schema" +
            " managementStatus=$managementStatus managementEffects=$effects managementResult=$managementResult" +
            " managementCommand=$command managementCompleted=$completed managementHasHandle=$hasHandle"
    } else {
        if (listOf("root", "read", "close", "readback").any(json::has)) return "uidRead=false"
        ""
    }
    return "uidRead=true available=$available result=$result phase=$phase errno=$errno authMode=$mode recordCount=$count" +
        " transport=$status transportErrno=$transportErrno childWait=$childWait childWaitStatusValid=$valid" + payload
}
