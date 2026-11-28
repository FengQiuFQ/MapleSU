package dev.maplesu.manager.runtime.ultra

import android.os.Process
import android.util.Log
import dev.maplesu.manager.runtime.ultra.bridge.NativeBridge
import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import dev.maplesu.manager.ultra.model.MapleSuModRunState
import dev.maplesu.manager.runtime.PageReadDeadline
import java.net.URLDecoder
import java.util.concurrent.CancellationException
import org.json.JSONObject

/** A maintenance Root channel bound to the caller lifetime, with no transport replay. */
internal fun interface RootScriptRunner {
    fun run(script: String): SuExecResult?
}

class UltraRuntimeClient() {
    private var rootCommands: RootScriptRunner? = null
    private var identityCurrent: () -> Boolean = { true }
    private var legacyCredential: UltraLegacyCredential? = null
    internal val legacyCredentialFingerprint: String? get() = legacyCredential?.fingerprint

    /** Maintenance may reuse a root channel bound to the same caller lifetime. */
    internal constructor(rootCommands: RootScriptRunner) : this() {
        this.rootCommands = rootCommands
    }

    internal fun scoped(isCurrent: () -> Boolean): UltraRuntimeClient =
        UltraRuntimeClient().also {
            it.rootCommands = rootCommands
            it.legacyCredential = legacyCredential
            it.identityCurrent = { identityCurrent() && isCurrent() }
        }

    internal fun withLegacyCredential(credential: UltraLegacyCredential): UltraRuntimeClient =
        scoped { true }.also { it.legacyCredential = credential }

    /** Read-only readiness snapshot. Each field has its own evidence source. */
    data class Capabilities(
        val bridgeLoaded: Boolean,
        val sdkCompatible: Boolean,
        val sdkVersion: String?,
        val environmentState: String?,
        val ultraEnvironmentReady: Boolean,
        val environmentVersion: String?,
        val environmentGeneration: Int,
        val nativeHostReady: Boolean,
        val earlyBootAvailable: Boolean,
        val moduleRuntimeVerified: Boolean,
        val failure: String?,
        val supportsModuleToggle: Boolean = false,
        val managerOwnerIdentity: ManagerOwnerIdentity? = null,
    )

    /** Signed caller identity only; it carries no Root or environment readiness. */
    data class ManagerOwnerIdentity(val fullUid: Int, val epoch: Long, val hostInstance: String)

    data class ManagerOwnerIdentityResult(val receipt: NativeReceipt, val identity: ManagerOwnerIdentity?) {
        val succeeded: Boolean get() = identity != null
    }

    private val lock = Any()
    private var generation = 0
    @Volatile private var cachedSdkVersion: String? = null
    private var lastEnvironmentState: String? = null

    private val loadFailure: String? = try {
        // Touching the class runs its static initialiser, which loads the library. A
        // missing or unloadable library must surface as a capability, not a crash.
        Class.forName(NativeBridge::class.java.name)
        null
    } catch (error: Throwable) {
        Log.w(TAG, "Ultra bridge unavailable", error)
        "${error.javaClass.simpleName}: ${error.message}"
    }

    val bridgeLoaded: Boolean get() = loadFailure == null

    private fun call(operation: String, block: () -> String?): NativeReceipt {
        // Native SdkCallScope owns request identity and conflict-specific admission.
        // A process-wide Java lock would hold unrelated reads behind a slow JNI worker.
        val deadline = PageReadDeadline.currentNanos()
        if (deadline != null && deadline - System.nanoTime() <= 0) return deadlineExceeded(operation)
        if (Thread.currentThread().isInterrupted) return NativeReceipt.bridgeFailure(
            operation, "MAPLESU_SDK_INTERRUPTED", "The request was cancelled before SDK admission.")
        return localCall(operation, block)
    }

    private fun deadlineExceeded(operation: String) = NativeReceipt.bridgeFailure(operation, "MAPLESU_SDK_DEADLINE_EXCEEDED",
        "The observation deadline elapsed before submission.", -1007)

    // Compiled identity and local OS status never wait for a stateful SDK operation.
    private fun localCall(operation: String, block: () -> String?): NativeReceipt {
        val failure = loadFailure
        if (failure != null) {
            return NativeReceipt.bridgeFailure(operation, "MAPLESU_BRIDGE_UNAVAILABLE", failure)
        }
        val deadline = PageReadDeadline.currentNanos()
        if (Thread.currentThread().isInterrupted) return NativeReceipt.bridgeFailure(
            operation, "MAPLESU_SDK_INTERRUPTED", "The request was cancelled before SDK admission.")
        if (deadline != null && deadline - System.nanoTime() <= 0) return deadlineExceeded(operation)
        return try {
            val answer = if (deadline == null) block()
                else NativeBridge.invokeWithDeadline(operation, deadline) { block() }
            NativeReceipt.parse(answer)
                ?: NativeReceipt.bridgeFailure(operation, "MAPLESU_BRIDGE_UNPARSEABLE", "answer was not a receipt")
        } catch (error: Throwable) {
            if (error is CancellationException) throw error
            if (error is InterruptedException) {
                Thread.currentThread().interrupt()
                throw CancellationException("SDK_CALL_INTERRUPTED").apply { initCause(error) }
            }
            NativeReceipt.bridgeFailure(operation, "MAPLESU_BRIDGE_EXCEPTION", UltraSdkLogging.redact(error.toString()))
        }
    }

    /** The bridge URL-encodes descriptor and package text because the reference WebUI did. */
    fun decodeText(value: String?): String? =
        value?.let { runCatching { URLDecoder.decode(it, "UTF-8") }.getOrDefault(it) }

    internal fun logPolicyScope(): String? = queryManagerOwnerIdentity().identity?.let {
        "${it.fullUid}:${it.epoch}:${it.hostInstance}"
    }

    // --- Environment and version -----------------------------------------------------

    fun sdkBuildIdentity(): NativeReceipt = localCall("get_sdk_build_identity") { NativeBridge.getSdkBuildIdentity() }

    fun sdkVersion(): NativeReceipt = localCall("get_sdk_version") { NativeBridge.getSdkVersion() }
        .also { receipt ->
            if (receipt.succeeded) {
                receipt.string("version")?.let { cachedSdkVersion = it }
            }
        }

    fun environmentState(): NativeReceipt {
        val receipt = callWithIdentity("get_maplesu_environment_state") {
            NativeBridge.getEnvironmentState()
        }
        if (receipt.succeeded) {
            val state = receipt.string("state")
            if (state != null) synchronized(lock) {
                // The environment changed generation: cached host readiness and any open
                // WebUI session belong to the previous one.
                if (state != lastEnvironmentState) {
                    lastEnvironmentState = state
                    generation += 1
                }
            }
        }
        return receipt
    }

    fun installedEnvironmentVersion(): NativeReceipt = callWithIdentity("get_installed_maplesu_environment_version") {
        NativeBridge.getInstalledEnvironmentVersion()
    }

    fun installEnvironment(mode: String, exploit: String): NativeReceipt {
        UltraSdkLogging.invalidate()
        val receipt = callWithIdentity("install_maplesu_environment") {
            NativeBridge.installEnvironment(mode, exploit)
        }
        if (receipt.succeeded) synchronized(lock) { generation += 1 }
        return receipt
    }

    fun uninstallEnvironment(): NativeReceipt {
        UltraSdkLogging.invalidate()
        val receipt = callWithIdentity("uninstall_maplesu_environment") {
            NativeBridge.uninstallEnvironment()
        }
        if (receipt.succeeded) synchronized(lock) { generation += 1 }
        return receipt
    }

    // --- System status, diagnostics, logs --------------------------------------------

    fun systemStatus(): NativeReceipt = localCall("get_system_status") { NativeBridge.getSystemStatusJson() }

    fun queryManagerOwnerIdentity(): ManagerOwnerIdentityResult = parseManagerOwnerIdentity(
        localCall("query_manager_owner_identity") { NativeBridge.queryManagerOwnerIdentity() },
    )

    internal fun probeManagerOwnerRoot(): ManagerOwnerRootResult = parseManagerOwnerRoot(
        localCall("probe_manager_owner_root") { NativeBridge.probeManagerOwnerRoot() },
    )

    internal fun claimManagerIdentity(): UltraLegacyCredential? {
        val receipt = localCall("claim_manager_identity") { NativeBridge.claimManagerIdentity() }
        if (!receipt.succeeded || receipt.bool("liveRootVerified") != false) return null
        return receipt.string("candidate")?.let(UltraLegacyCredential::fromKernelClaim)
    }

    /** Current native factory facts; no Root attempt or readiness promotion. */
    internal fun suRuntimeStatus(): NativeReceipt = callWithIdentity("get_su_runtime_status") {
        NativeBridge.getSuRuntimeStatus()
    }

    fun testRoot(): NativeReceipt = parseRootStatusReport(callWithIdentity("get_root_status_report") {
        NativeBridge.testRoot()
    })

    fun runRootCommand(command: String): NativeReceipt = callWithIdentity("run_root_cmd") {
        val runner = rootCommands
        // A submitted script is never replayed through another transport.
        if (runner != null) NativeReceipt.rootCommand(runner.run(command)).raw
        else NativeBridge.runRootCmd(command)
    }

    private fun callWithIdentity(operation: String, block: () -> String?): NativeReceipt {
        val submit = {
            if (!identityCurrent()) NativeReceipt.bridgeFailure(
                operation, "SDK_IDENTITY_SCOPE_CHANGED", "The SDK caller identity changed before submission.",
            ).raw
            else {
                val credential = legacyCredential
                if (credential == null || operation == "read_installed_helper") block()
                else NativeBridge.invokeWithLegacyCredential(operation, credential.value) { block() }
            }
        }
        return if (operation == "read_installed_helper") localCall(operation, submit) else call(operation, submit)
    }

    internal fun captureModuleEnvironment(): Array<String> {
        var facts: Array<String>? = null
        val receipt = callWithIdentity("capture_module_environment") {
            facts = NativeBridge.captureModuleEnvironment()
            JSONObject().put("schemaVersion", 1).put("backend", BACKEND)
                .put("operation", "capture_module_environment").put("ok", facts != null)
                .put("sdkError", if (facts != null) "OK" else "MAPLESU_MODULE_ENVIRONMENT_MISSING")
                .put("sdkErrorCode", if (facts != null) 0 else -1004).toString()
        }
        if (!receipt.succeeded) throw java.io.IOException("MODULE_ENVIRONMENT_CAPTURE_FAILED:${receipt.sdkError}:${receipt.sdkErrorCode}")
        return requireNotNull(facts)
    }

    internal fun readInstalledHelper(helperPath: String?, timeoutMillis: Int = 300): NativeReceipt {
        val operation = "read_installed_helper"
        if (Thread.currentThread().isInterrupted) return NativeReceipt.bridgeFailure(
            operation, "MAPLESU_SDK_INTERRUPTED", "The request was cancelled before helper readback.")
        val deadline = PageReadDeadline.currentNanos()
        if (deadline != null && deadline - System.nanoTime() <= 0) return deadlineExceeded(operation)
        return callWithIdentity(operation) {
            val remaining = deadline?.let { limit -> (limit - System.nanoTime()) / 1_000_000L }
            when {
                Thread.currentThread().isInterrupted -> NativeReceipt.bridgeFailure(
                    operation, "MAPLESU_SDK_INTERRUPTED", "The request was cancelled before helper readback.").raw
                remaining != null && remaining <= 0 -> deadlineExceeded(operation).raw
                else -> NativeBridge.readInstalledHelper(helperPath,
                    remaining?.coerceAtMost(timeoutMillis.toLong())?.toInt() ?: timeoutMillis)
            }
        }
    }

    fun modulePolicySettings(requested: Int = -1): NativeReceipt =
        callWithIdentity(if (requested < 0) "get_module_policy_settings" else "set_module_policy_settings") {
            NativeBridge.modulePolicySettings(requested)
        }

    internal fun publishPolicyBackend(sha256: String, verifiedBytes: ByteArray): NativeReceipt =
        callWithIdentity("publish_policy_backend") {
            NativeBridge.publishPolicyBackend(sha256, verifiedBytes)
        }

    fun restartZygote64(): NativeReceipt = callWithIdentity("restart_zygote64") {
        NativeBridge.restartZygote64()
    }

    fun testBasics(item: String): NativeReceipt = callWithIdentity("test_maplesu_basics") {
        NativeBridge.testBasics(item)
    }

    fun testDefaultModule(name: String): NativeReceipt = callWithIdentity("test_maplesu_default_module") {
        NativeBridge.testDefaultModule(name)
    }

    fun setLogEnabled(enabled: Boolean): NativeReceipt = callWithIdentity("set_maplesu_log_enabled") {
        NativeBridge.setLogEnabled(enabled)
    }

    fun isLogEnabled(): NativeReceipt = callWithIdentity("is_maplesu_log_enabled") {
        NativeBridge.isLogEnabled()
    }

    fun readLog(): NativeReceipt = callWithIdentity("read_maplesu_log") {
        NativeBridge.readLog()
    }

    fun clearLog(): NativeReceipt = callWithIdentity("clear_maplesu_log") {
        NativeBridge.clearLog()
    }


    fun setAdbForcedDisabled(disabled: Boolean): NativeReceipt = callWithIdentity("set_adb_forced_disabled") {
        NativeBridge.setAdbForcedDisabled(disabled)
    }

    fun isAdbForcedDisabled(): NativeReceipt = callWithIdentity("is_adb_forced_disabled") {
        NativeBridge.isAdbForcedDisabled()
    }

    fun oneplusWriteStage1(): NativeReceipt = callWithIdentity("oneplus_bypass_stage1_and_2") {
        NativeBridge.oneplusBypassWriteStage1()
    }

    fun oneplusIsWorkNormal(): NativeReceipt = callWithIdentity("oneplus_bypass_is_work_normal") {
        NativeBridge.oneplusBypassIsWorkNormal()
    }

    // --- Parasite (H4) ---------------------------------------------------------------

    fun parasitePrecheck(targetPidCmdline: String): NativeReceipt = callWithIdentity("parasite_precheck_app") {
        NativeBridge.parasitePrecheckApp(targetPidCmdline)
    }

    fun parasiteImplantApp(targetPidCmdline: String, soPath: String): NativeReceipt =
        callWithIdentity("parasite_implant_app") {
            NativeBridge.parasiteImplantApp(targetPidCmdline, soPath)
        }

    fun parasiteImplantSuEnv(
        targetPidCmdline: String,
        soPath: String,
        suDir: String,
    ): NativeReceipt = callWithIdentity("parasite_implant_su_env") {
        NativeBridge.parasiteImplantSuEnv(targetPidCmdline, soPath, suDir)
    }

    // --- Application authorization (SDK touchpoints only) ----------------------------

    fun addSuAuth(packageName: String): NativeReceipt = callWithIdentity("add_su_auth_list") {
        NativeBridge.addSuAuth(packageName)
    }

    internal fun refreshSuAuthList(): NativeReceipt = callWithIdentity("refresh_su_auth_list") {
        NativeBridge.refreshSuAuthList()
    }

    fun removeSuAuth(packageName: String): NativeReceipt = callWithIdentity("remove_su_auth_list") {
        NativeBridge.removeSuAuth(packageName)
    }

    fun suAuthList(): NativeReceipt = callWithIdentity("get_su_auth_list") {
        NativeBridge.getSuAuthList()
    }

    fun setSuUidProfile(uid: Int, packageName: String, allow: Boolean): NativeReceipt = callWithIdentity("set_su_uid_profile") {
        NativeBridge.setSuUidProfile(uid, packageName, allow)
    }

    fun suUidProfiles(): SuUidProfilesSnapshot = parseSuUidProfiles(callWithIdentity("get_su_uid_profiles") {
        NativeBridge.getSuUidProfiles()
    })

    data class SuUidProfilesSnapshot(val receipt: NativeReceipt, val profiles: List<SuUidProfile>) {
        val ok: Boolean get() = receipt.succeeded
    }

    fun clearSuAuthList(): NativeReceipt = callWithIdentity("clear_su_auth_list") {
        NativeBridge.clearSuAuthList()
    }

    /**
     * `get_su_auth_list` as a typed snapshot.
     *
     * The bridge's `data` object has exactly these fields (see
     * `runtime/ultra/bridge/native_lib_ultra.cpp`, entry `getSuAuthList`):
     *
     *  - `packages`: legacy user-0 projection of URL-encoded package names.
     *    Full-UID policy consumers use [suUidProfiles]; this projection confirms
     *    persisted authorization configuration, not a working kernel UID table or su hook.
     *  - `count`: number of entries (the same number as `packages.size`).
     *  - `encoding`: always `"url"`, so every string needs [decodeText].
     *  - `authority`: always `false` - the SDK allowlist is a touchpoint, not MapleSU's own
     *    authorization decision (`DirectPolicy` was that, and it is not used on Ultra).
     *
     * A failed receipt is preserved instead of being flattened to an empty list, so a caller
     * can show `sdkError` rather than claiming "no applications".
     */
    data class SuAuthSnapshot(
        val receipt: NativeReceipt,
        val packages: List<String>,
    ) {
        val ok: Boolean get() = receipt.succeeded
        val count: Int get() = packages.size
    }

    fun suAuthSnapshot(): SuAuthSnapshot = parseSuAuthSnapshot(suAuthList())

    // --- Module lifecycle ------------------------------------------------------------

    fun moduleList(): NativeReceipt = callWithIdentity("get_all_modules_list") {
        NativeBridge.getModuleList()
    }

    fun parseModuleDescriptor(zipPath: String): NativeReceipt = callWithIdentity("parse_module_desc_from_zip_file") {
        NativeBridge.parseModuleDescriptor(zipPath)
    }

    fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt =
        callWithIdentity(if (devRunOnce) "install_module_dev_run_once" else "install_module") {
            NativeBridge.installModule(zipPath, devRunOnce)
        }

    fun uninstallModule(id32: String): NativeReceipt = callWithIdentity("uninstall_module") {
        NativeBridge.uninstallModule(id32)
    }

    fun moduleControlCapabilities(): NativeReceipt = callWithIdentity("get_module_control_capabilities") {
        NativeBridge.getModuleControlCapabilities()
    }

    fun moduleControl(id32: String): NativeReceipt = callWithIdentity("get_module_control") {
        NativeBridge.getModuleControl(id32)
    }

    fun setModuleEnabled(id32: String, enabled: Boolean): NativeReceipt = callWithIdentity("set_module_enabled") {
        NativeBridge.setModuleEnabled(id32, enabled)
    }

    fun openModuleWebUi(id32: String): NativeReceipt = callWithIdentity("start_module_web_ui_server_async") {
        NativeBridge.openModuleWebUi(id32)
    }

    /**
     * Decoded module rows from `get_all_modules_list`, using MapleSU's own item model and the
     * reference's field decoding (URLDecoder over exactly the fields the host URL-encodes).
     *
     * An unknown `state` string still becomes NOT_RUNNING on the item - that is what the
     * reference does - but the condition is not hidden: the receipt already says
     * `MAPLESU_BRIDGE_UNKNOWN_MODULE_STATE`, so a caller can show "state pending" instead of
     * claiming the module is stopped.
     */
    fun modules(): List<MapleSuModInstalledItem> = modules(moduleList())

    internal fun modules(receipt: NativeReceipt): List<MapleSuModInstalledItem> {
        if (!receipt.succeeded) return emptyList()
        val array = receipt.array("modules") ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val row = array.optJSONObject(index) ?: continue
                val desc = row.optJSONObject("desc") ?: continue
                add(
                    MapleSuModInstalledItem(
                        decodeText(desc.optString("name", "")),
                        decodeText(desc.optString("desc", "")),
                        decodeText(desc.optString("ver", "")),
                        decodeText(desc.optString("id32", "")),
                        decodeText(desc.optString("author", "")),
                        decodeText(desc.optString("update_json", "")),
                        decodeText(desc.optString("min_sdk_ver", "")),
                        desc.optBoolean("web_ui", false),
                        runStateOf(row.optJSONObject("control")?.optString("runtimeState")
                            ?: row.optString("state", "")),
                    ).apply {
                        val control = row.optJSONObject("control")
                        val known = control?.opt("enabled") is Boolean && control.optInt("abiVersion") == 1 &&
                            control.optBoolean("supportsEnableToggle", false)
                        enabled = if (known) control!!.getBoolean("enabled") else null
                        isEnableToggleSupported = known
                        isNeedsReboot = if (known) control!!.optBoolean("needsReboot", false)
                            else runState == MapleSuModRunState.REMOVED_PENDING_REBOOT
                    }
                )
            }
        }
    }

    /** The reference `MapleSuModInstalledPage.parseRunState` mapping, kept identical. */
    private fun runStateOf(state: String): MapleSuModRunState = when (state) {
        "NotRunning" -> MapleSuModRunState.NOT_RUNNING
        "Running" -> MapleSuModRunState.RUNNING
        "Abnormal" -> MapleSuModRunState.ABNORMAL
        "RemovedPendingReboot" -> MapleSuModRunState.REMOVED_PENDING_REBOOT
        else -> MapleSuModRunState.NOT_RUNNING
    }

    /** One consolidated snapshot; signed owner facts stay independent of readiness. */
    fun capabilities(): Capabilities {
        val ownerIdentity = queryManagerOwnerIdentity().identity
        val version = sdkVersion()
        val state = environmentState()
        val environmentVersion = if (state.succeeded && state.string("state") != "NotInstalled") {
            installedEnvironmentVersion().takeIf { it.succeeded }?.string("version")
        } else {
            null
        }
        val sdkCompatible = version.succeeded && !version.string("version").isNullOrEmpty()
        val envState = state.takeIf { it.succeeded }?.string("state")
        // nativeHostReady is about the *module host*, which this client cannot observe:
        // it stays false until a module is actually installed and read back.
        return Capabilities(
            bridgeLoaded = bridgeLoaded,
            sdkCompatible = sdkCompatible,
            sdkVersion = version.string("version") ?: cachedSdkVersion,
            environmentState = envState,
            // 2026-10-30 P0：曾写成 `Running || Fault`，导致模块动作在 Fault 下被放行；
            // 现在只认 Running，与 UltraEnvironmentProbe.isRunning()/UI 状态胶囊一致。
            ultraEnvironmentReady = UltraReadinessRules.ultraEnvironmentReady(envState),
            environmentVersion = environmentVersion,
            environmentGeneration = synchronized(lock) { generation },
            nativeHostReady = false,
            earlyBootAvailable = false,
            moduleRuntimeVerified = false,
            failure = loadFailure,
            supportsModuleToggle = if (UltraReadinessRules.ultraEnvironmentReady(envState)) {
                val control = moduleControlCapabilities()
                control.succeeded && control.bool("supportsEnableToggle") == true
            } else false,
            managerOwnerIdentity = ownerIdentity?.takeIf { identityCurrent() },
        )
    }

    companion object {
        const val BACKEND = "maplesu_ultra"
        private const val TAG = "MapleSUUltra"
    }
}

/** A successful envelope with malformed/missing list data is not an empty authorization list. */
internal fun parseSuAuthSnapshot(receipt: NativeReceipt): UltraRuntimeClient.SuAuthSnapshot {
    fun invalid() = UltraRuntimeClient.SuAuthSnapshot(
        NativeReceipt.bridgeFailure(
            "get_su_auth_list", "MAPLESU_ULTRA_SU_AUTH_INVALID_SNAPSHOT",
            "Expected URL-encoded package strings and a matching numeric count.",
        ),
        emptyList(),
    )
    if (!receipt.succeeded) return UltraRuntimeClient.SuAuthSnapshot(receipt, emptyList())
    val array = receipt.array("packages") ?: return invalid()
    val count = receipt.data?.opt("count") as? Number ?: return invalid()
    if (count.toDouble() != array.length().toDouble() || receipt.string("encoding") != "url") return invalid()
    val packages = ArrayList<String>(array.length())
    for (index in 0 until array.length()) {
        val encoded = array.opt(index) as? String ?: return invalid()
        val decoded = runCatching { URLDecoder.decode(encoded, "UTF-8") }.getOrNull() ?: return invalid()
        if (decoded.isEmpty() || decoded == "null" ||
            decoded.any { !it.isLetterOrDigit() && it != '.' && it != '_' }) return invalid()
        packages += decoded
    }
    return UltraRuntimeClient.SuAuthSnapshot(receipt, packages)
}

/** Owner facts require the fixed native JSON types, independent of legacy receipt coercion. */
internal fun parseManagerOwnerIdentity(receipt: NativeReceipt): UltraRuntimeClient.ManagerOwnerIdentityResult {
    fun invalid() = UltraRuntimeClient.ManagerOwnerIdentityResult(receipt, null)
    fun integer(json: JSONObject, field: String): Long? = when (val value = json.opt(field)) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }
    if (!receipt.succeeded || receipt.backend != UltraRuntimeClient.BACKEND ||
        receipt.operation != "query_manager_owner_identity") return invalid()
    val json = runCatching { JSONObject(receipt.raw) }.getOrNull() ?: return invalid()
    if (json.opt("backend") as? String != UltraRuntimeClient.BACKEND ||
        json.opt("operation") as? String != "query_manager_owner_identity" ||
        json.opt("ok") as? Boolean != true || json.opt("sdkError") as? String != "OK" ||
        integer(json, "sdkErrorCode") != 0L) return invalid()
    val data = json.opt("data") as? JSONObject ?: return invalid()
    if (data.opt("ownerBound") as? Boolean != true ||
        data.opt("liveRootVerified") as? Boolean != false ||
        integer(data, "protocolVersion") != 3L || integer(data, "metadataVersion") != 3L ||
        integer(data, "ownerSchema") != 1L) return invalid()
    val uid = integer(data, "fullUid") ?: return invalid()
    val epoch = integer(data, "epoch") ?: return invalid()
    val host = data.opt("hostInstance") as? String ?: return invalid()
    if (uid != Process.myUid().toLong() || epoch !in 1L..0xffff_ffffL ||
        host.length != 32 || host.any { it !in '0'..'9' && it !in 'a'..'f' } ||
        host.all { it == '0' }) return invalid()
    return UltraRuntimeClient.ManagerOwnerIdentityResult(receipt,
        UltraRuntimeClient.ManagerOwnerIdentity(uid.toInt(), epoch, host))
}


/** Full-UID records describe stored decisions; native SU delivery is a separate result. */
internal fun parseSuUidProfiles(receipt: NativeReceipt): UltraRuntimeClient.SuUidProfilesSnapshot {
    fun invalid() = UltraRuntimeClient.SuUidProfilesSnapshot(NativeReceipt.bridgeFailure(
        "get_su_uid_profiles", "MAPLESU_ULTRA_SU_UID_INVALID_SNAPSHOT", null), emptyList())
    if (!receipt.succeeded) return UltraRuntimeClient.SuUidProfilesSnapshot(receipt, emptyList())
    val rows = receipt.array("profiles") ?: return invalid()
    val count = receipt.data?.opt("count") as? Number ?: return invalid()
    if (count.toDouble() != rows.length().toDouble() || receipt.string("encoding") != "url" ||
        receipt.data?.opt("decisionsVerified") != true) return invalid()
    val profiles = ArrayList<SuUidProfile>(rows.length())
    val seen = HashSet<Int>()
    for (index in 0 until rows.length()) {
        val row = rows.optJSONObject(index) ?: return invalid()
        val number = row.opt("uid") as? Number ?: return invalid()
        val value = number.toLong()
        if (number.toDouble() != value.toDouble() || value !in 1L..Int.MAX_VALUE.toLong()) return invalid()
        val uid = value.toInt()
        if ((uid < 2000 && uid != 1000) || !seen.add(uid)) return invalid()
        val allow = row.opt("allow") as? Boolean ?: return invalid()
        val encoded = row.opt("package") as? String ?: return invalid()
        val name = runCatching { URLDecoder.decode(encoded, "UTF-8") }.getOrNull() ?: return invalid()
        if (name.isEmpty() || name.length > 255 || name.any { it !in 'a'..'z' && it !in 'A'..'Z' &&
                it !in '0'..'9' && it != '.' && it != '_' }) return invalid()
        profiles += SuUidProfile(uid, allow, name)
    }
    if (profiles.count { it.allow } > 4095) return invalid()
    return UltraRuntimeClient.SuUidProfilesSnapshot(receipt, profiles)
}
