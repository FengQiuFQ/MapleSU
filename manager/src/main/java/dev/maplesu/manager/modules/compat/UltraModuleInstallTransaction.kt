package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import dev.maplesu.manager.runtime.ultra.UltraPhase
import dev.maplesu.manager.runtime.ultra.UltraReceipt
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.UUID

/**
 * 安装前置条件的一次观测：宿主的环境回执 + 解析出的状态字符串。
 *
 * 为什么把「回执」和「状态」一起传：真实实现的 `state` 在 `NativeReceipt.data`（`org.json`）里，
 * 而 `org.json` 在 JVM 单测里是 stub —— 不把这一步做成可注入的观测点，H1 的真实入口测试就只能
 * 假装环境已就绪（那会让「环境未就绪」这一整条分支永远测不到）。
 *
 * 此观测只保留诊断；用户选择的安装由真实宿主返回结果。
 */
data class UltraModuleEnvironmentObservation(
    val receipt: NativeReceipt,
    val state: String?,
)

/** 安装前置条件的观测者（生产：读 `host.environmentState()` 并解析 `data.state`）。 */
fun interface UltraModuleEnvironmentProbe {
    fun read(): UltraModuleEnvironmentObservation
}

/**
 * 一次 install 的输入（**不含 `Context`**）。
 *
 * 为什么不用 `ModuleArchiveInspector.Report`：`Report` 的构造函数是 private，JVM 单测造不出来，
 * 而 H1 要断言的正是「产品入口在门挡住时调用次数为 0」。把输入收敛成判定与事务真正要用的
 * 那几个字段后，产品（由 `Report` 映射）与测试（直接构造本机已确认身份）走的是**同一份代码**，
 * 不再需要「复刻 install 的门步骤」。
 *
 * @param identity 静态检查得到的包身份。门用它命中固定记录，回执用它填 `moduleId` /
 *   `packageSha256`，catalog 用它的 `archiveSha256` 二次确认字节。
 * @param manifestVersion `Report.properties["version"]` 的**原值**：缺失是 `null`，不是空串。
 *   descriptor 交叉检查据此区分「归档没有版本字段」与「宿主读出的版本和归档不一致」。
 */
data class UltraModuleInstallRequest(
    val source: File,
    val identity: UltraModulePackageIdentity,
    val manifestVersion: String?,
    val devRunOnce: Boolean,
    val action: UltraModuleAction,
)

/**
 * catalog（应用私有包存储）的接缝。
 *
 * 生产实现是 `ModuleCatalog`（`manager/.../modules/ModuleCatalog.java`，只做文件 IO，没有 Android
 * 依赖）；测试实现是计数替身。之所以要接缝而不是直接 `new ModuleCatalog(...)`：H1 断言的一部分
 * 就是「被拦时**连 stage 都没发生**」——只数宿主调用数会漏掉「先把字节复制进私有目录再拦」这种
 * 顺序错误。
 */
interface UltraModuleCatalogPort {

    /** 把已确认字节复制进应用私有目录，返回 token。抛异常 = stage 失败。 */
    fun stage(source: File, confirmedArchiveSha256: String): String

    /** token 对应的已 stage 归档路径（宿主只能消费这个路径）。 */
    fun stagedArchive(token: String): File

    /** 宿主确认安装后提交 catalog 记录。抛异常 = commit 失败（回执要区分）。 */
    fun commit(token: String)

    /** Only a known Host commit may recover this operation's local record. */
    fun recoverCommitted(operationId: String, token: String, moduleId: String,
                         confirmedArchiveSha256: String): Boolean = false

    /** 释放 staged 副本（只在「宿主没有应用任何东西」时可做）。 */
    fun discard(token: String)
}

/** 操作日志（`ultra-operations.jsonl`）的接缝：一次操作至少一条回执，`token` 只在待对账时非 null。 */
fun interface UltraModuleJournal {
    fun append(operationId: String, receipt: UltraReceipt, token: String?)

    fun appendDurably(operationId: String, receipt: UltraReceipt, token: String?): Result<Unit> =
        runCatching { append(operationId, receipt, token) }
}

/**
 * 回执 `data` 段的**语义**内容（与 `org.json` 无关）。
 *
 * 拆这一层的唯一原因：`org.json` 在 JVM 单测里是 `android.jar` 的 stub（`new JSONObject()` 直接抛），
 * 而注入的假 JSON 工厂会让「回执字段与改前逐项一致」变得不可验证。所以把「哪些值进 data」
 * 定义成这个纯数据类，由 [UltraModuleReceiptData] 的实现负责序列化：
 *  - 生产：[OrgJsonReceiptData]，与 W2-0 里那两段 `JSONObject()` 逐字段一致；
 *  - 测试：不构造 JSON，断言 [UltraModuleReceiptPayload] 本身（字段含义仍被覆盖）。
 */
sealed interface UltraModuleReceiptPayload {

    /** 被兼容门拦下的回执：`compatibility` / `action` / `reasonCodes` / `matchedRecordId` / `nativeCalls`。 */
    data class CompatibilityBlocked(val decision: UltraModuleGateDecision) : UltraModuleReceiptPayload

    /** 安装成功的回执：`runState` / `minSdkVer` / `webUi` / `crossCheck`。 */
    data class Installed(
        val native: NativeReceipt,
        val minSdk: String?,
        val crossCheck: Map<String, String>,
        val catalogModuleId: String? = null,
    ) : UltraModuleReceiptPayload
}

/** 把 [UltraModuleReceiptPayload] 变成回执里的 `data`（生产实现见 [OrgJsonReceiptData]）。 */
fun interface UltraModuleReceiptData {
    fun create(payload: UltraModuleReceiptPayload): JSONObject?
}

/**
 * 生产实现：`data` 段的**唯一**生产者，字段与 W2-0 的 `install()` 逐项相同。
 *
 * 写成 `when` 覆盖全部 [UltraModuleReceiptPayload] 分支（而不是各调用点就地拼 JSON）：
 * 新增一种 payload 时编译器会在这里报漏分支，不会出现「新分支悄悄没有 data」。
 */
object OrgJsonReceiptData : UltraModuleReceiptData {

    override fun create(payload: UltraModuleReceiptPayload): JSONObject? = when (payload) {
        is UltraModuleReceiptPayload.CompatibilityBlocked -> JSONObject()
            .put("compatibility", payload.decision.verdict.decision.name)
            .put("action", payload.decision.verdict.action.name)
            .put("reasonCodes", JSONArray(payload.decision.verdict.reasonCodes))
            .put("matchedRecordId", payload.decision.verdict.matchedRecordId ?: JSONObject.NULL)
            .put("nativeCalls", 0)

        is UltraModuleReceiptPayload.Installed -> JSONObject(payload.native.data?.toString() ?: "{}")
            .put("minSdkVer", payload.minSdk ?: JSONObject.NULL)
            .put("crossCheck", JSONObject(payload.crossCheck as Map<*, *>))
            .apply { payload.catalogModuleId?.let { put("catalogModuleId", it) } }
    }
}

/** Generic operation completion does not prove a persistent installation commit. */
internal fun confirmedUltraModuleInstall(receipt: NativeReceipt, operation: String): Boolean {
    if (receipt.operation != operation) return false
    val committed = receipt.data?.opt("installCommitted")
    return committed == true || (committed == null && receipt.succeeded)
}

private class PreparedJournalFailure(val detail: Throwable) : RuntimeException(detail)

/**
 * 用户选择后的安装事务：环境探测 → 兼容诊断 → stage → descriptor/journal → host install
 * → 已知宿主提交记账 → catalog commit。兼容记录只留日志，不弹窗、不拒绝用户选择的安装。
 *
 * 宿主调用前失败可丢弃 staged 副本；调用后失败保留副本和 journal 供对账。
 * 真实宿主提交回执决定安装结果；本地归档及诊断记录不代表宿主安装成功。
 * 设备事实、时钟、构建摘要和文件存储均保留可注入接缝，生产和主机回归走同一事务。
 */
class UltraModuleInstallTransaction(
    private val host: UltraModuleHost,
    /**
     * 前置条件观测点。默认实现就是改前那两行：`host.environmentState()` + `receipt.string("state")`。
     * 注入点存在的唯一原因是 JVM 上没有可用的 `org.json`（见 [UltraModuleEnvironmentObservation]）。
     */
    private val environmentProbe: UltraModuleEnvironmentProbe = UltraModuleEnvironmentProbe {
        val receipt = host.environmentState()
        UltraModuleEnvironmentObservation(receipt, receipt.string("state"))
    },
    private val catalog: UltraModuleCatalogPort,
    private val journal: UltraModuleJournal,
    private val evidence: (UltraModuleEvent) -> UltraModuleEvidenceRecordResult,
    private val facts: () -> UltraModuleDeviceFacts,
    private val clockMillis: () -> Long,
    private val buildDigest: () -> UltraModuleBuildDigest,
    private val bootId: () -> String,
    private val processPid: () -> Int?,
    private val newOperationId: () -> String = { UUID.randomUUID().toString() },
    private val receiptData: UltraModuleReceiptData = OrgJsonReceiptData,
    private val gate: UltraModuleExecutionGate = UltraModuleExecutionGate(host),
    private val onCommitted: (String) -> Unit = {},
) {

    /**
     * 执行一次安装（或开发单次运行）。
     *
     * @param stdout 诊断输出（与改前同一批文案：`Staged <token> (...)`、`Installed ...`）。
     * @param stderr 失败/拦截文案（与改前同一批文案，含 `blockingText`、`Staging failed: ...`）。
     */
    fun install(
        request: UltraModuleInstallRequest,
        stdout: (String) -> Unit,
        stderr: (String) -> Unit,
    ): UltraReceipt {
        val operationId = newOperationId()
        val operation = if (request.devRunOnce) "install_module_dev_run_once" else "install_module"
        val identity = request.identity

        val environment = try {
            environmentProbe.read()
        } catch (error: Exception) {
            if (error is InterruptedException || error is java.util.concurrent.CancellationException ||
                Thread.currentThread().isInterrupted) throw error
            null
        }
        if (environment == null || !environment.receipt.succeeded || environment.state != "Running") {
            record(
                UltraModuleCompatibilityGate.preconditionEvent(
                    action = request.action,
                    operationId = operationId,
                    bootId = bootId(),
                    deviceTimeIso = deviceNowIso(),
                    hostUtcIso = deviceNowIso(),
                    processPid = processPid(),
                    buildDigest = buildDigest(),
                    environmentState = environment?.state,
                ).copy(outcome = UltraModuleOutcome.UNKNOWN,
                    detail = "environment=${environment?.state ?: "unreadable"}; observation=diagnostic; install=user_selected"),
            )
        }

        // 用户已经选择安装；兼容记录只入日志，安装结果由真实宿主返回。
        val decision = evaluate(request, operationId)

        val token = try {
            catalog.stage(request.source, identity.archiveSha256)
        } catch (error: Exception) {
            val receipt = UltraReceipt.of(
                operationId = operationId,
                operation = operation,
                native = null,
                phase = UltraPhase.PREPARED,
                outcome = UltraOutcome.FAILED,
                moduleId = identity.id32,
                packageSha256 = identity.archiveSha256,
                unknowns = mapOf("stageError" to (error.message ?: "unknown")),
            )
            journal.append(operationId, receipt, null)
            stderr("Staging failed: ${error.message}")
            return receipt
        }

        val stagedFile = try {
            catalog.stagedArchive(token)
        } catch (error: IOException) {
            // Only this operation's staged copy is owned here; the host has not received it.
            try {
                catalog.discard(token)
            } catch (cleanup: IOException) {
                if (cleanup !== error) error.addSuppressed(cleanup)
            }
            throw error
        }
        stdout("Staged $token (${stagedFile.length()} bytes)")

        // 宿主侧 descriptor：这是唯一读归档的 Ultra 代码，id32/version/minSdk 以它为准。
        // 执行顺序保持 descriptor -> 记账 -> install；用户选择的安装继续交给宿主。
        var id32: String? = null
        var describedVersion: String? = null
        var minSdk: String? = null
        var mismatches: Map<String, String> = emptyMap()
        val result = try {
            gate.executeInstall(decision, stagedFile.absolutePath, request.devRunOnce) { descriptor ->
                val described = descriptor.obj("desc")
                id32 = described?.optString("id32")?.let(::decode)?.takeIf { it.isNotEmpty() }
                describedVersion = described?.optString("ver")?.let(::decode)
                minSdk = described?.optString("min_sdk_ver")?.let(::decode)

                mismatches = buildMap {
                    if (!descriptor.succeeded) {
                        put("descriptor", descriptor.sdkError)
                    } else {
                        if (id32 != null && identity.id32.isNotEmpty() && id32 != identity.id32) {
                            put("id32", "$id32 != ${identity.id32}")
                        }
                        val manifestVersion = request.manifestVersion
                        if (describedVersion != null && manifestVersion != null &&
                            describedVersion != manifestVersion
                        ) {
                            put("version", "$describedVersion != $manifestVersion")
                        }
                    }
                }

                journal.appendDurably(
                    operationId,
                    UltraReceipt.of(
                        operationId, operation, descriptor, UltraPhase.PREPARED, UltraOutcome.NEEDS_RECONCILIATION,
                        moduleId = identity.id32, packageSha256 = identity.archiveSha256,
                        requestedVersion = describedVersion, unknowns = mismatches,
                    ),
                    token = token,
                ).getOrElse { throw PreparedJournalFailure(it) }
            }
        } catch (error: PreparedJournalFailure) {
            // The descriptor callback failed before installModule was invoked.
            val cleanup = runCatching { catalog.discard(token) }
            if (error.detail is java.util.concurrent.CancellationException) throw error.detail
            if (error.detail is InterruptedException) {
                Thread.currentThread().interrupt()
                throw error.detail
            }
            val receipt = UltraReceipt.of(operationId, operation, null, UltraPhase.PREPARED,
                if (cleanup.isSuccess) UltraOutcome.FAILED else UltraOutcome.NEEDS_RECONCILIATION,
                moduleId = identity.id32, packageSha256 = identity.archiveSha256,
                cleanupOutcome = if (cleanup.isSuccess) "staged_discarded" else "staged_discard_failed",
                unknowns = buildMap {
                    put("operationLog", error.detail.message ?: "operation_log_write_failed")
                    cleanup.exceptionOrNull()?.let { put("cleanup", it.message ?: "staged_discard_failed") }
                }).copy(sdkError = "MAPLESU_OPERATION_LOG_WRITE_FAILED", sdkErrorCode = -1001,
                    reason = "The install was not submitted because its operation record could not be saved.")
            stderr(requireNotNull(receipt.reason))
            return receipt
        }
        val execution = when (result) {
            // 兼容 gate 与 WebUI 共用返回类型；安装操作继续执行，保留穷尽处理。
            is UltraModuleInstallExecution.Blocked ->
                return blockedByCompatibility(operationId, operation, identity, result.decision, stderr)

            is UltraModuleInstallExecution.Ran -> result
        }

        val install = execution.install
        val installationCommitted = confirmedUltraModuleInstall(install, operation)
        if (installationCommitted) onCommitted(id32 ?: identity.id32)
        // §4.3：宿主已经被调用（成功或拒绝都必须留下一条，带真实 SDK 返回码）。
        record(
            UltraModuleCompatibilityGate.hostEvent(
                action = request.action,
                operationId = operationId,
                bootId = bootId(),
                deviceTimeIso = deviceNowIso(),
                hostUtcIso = deviceNowIso(),
                processPid = processPid(),
                buildDigest = buildDigest(),
                install = install,
            ),
        )

        if (!installationCommitted) {
            val rolledBack = install.operation == operation &&
                install.data?.opt("installCommitted") == false &&
                install.data?.opt("cleanupComplete") == true && install.data?.opt("cleanupPending") != true
            // These exact receipts are emitted before JNI/SDK submission, never by an install worker.
            val notSubmitted = install.operation == operation && !install.ok &&
                !install.operationCompleted && install.data == null && when (install.sdkError) {
                    "MAPLESU_SDK_BUSY" -> install.sdkErrorCode in setOf(-1001, -1005)
                    "MAPLESU_SDK_DEADLINE_EXCEEDED" -> install.sdkErrorCode == -1007
                    "MAPLESU_SDK_INTERRUPTED", "MAPLESU_BRIDGE_UNAVAILABLE",
                    "SDK_INSTALLATION_SCOPE_CHANGED" -> install.sdkErrorCode == -1001
                    else -> false
                }
            val uncertain = !rolledBack && !notSubmitted
            // Missing completion facts may follow an applied install. Retain its bytes and never replay it.
            val discarded = !uncertain && runCatching { catalog.discard(token) }.isSuccess
            val receipt = UltraReceipt.of(
                operationId, operation, install, UltraPhase.HOST_CALLED,
                if (discarded) UltraOutcome.FAILED else UltraOutcome.NEEDS_RECONCILIATION,
                moduleId = id32 ?: identity.id32, packageSha256 = identity.archiveSha256,
                requestedVersion = describedVersion,
                cleanupOutcome = when {
                    rolledBack && discarded -> "native_rollback_complete_staged_discarded"
                    rolledBack -> "native_rollback_complete_staged_discard_failed"
                    uncertain -> "staged_kept_for_reconciliation"
                    discarded -> "staged_discarded"
                    else -> "staged_discard_failed"
                },
                unknowns = when {
                    uncertain -> mapOf("installation" to "host_result_unverified")
                    discarded -> emptyMap()
                    else -> mapOf("cleanup" to "staged_discard_failed")
                },
            )
            journal.append(operationId, receipt, if (discarded) null else token)
            stderr(install.reason ?: install.sdkError)
            return receipt
        }

        // This invocation's SDK commit is authoritative. Display refresh is independent.
        val needsReboot = install.data?.opt("needsReboot") == true ||
            install.data?.opt("immediateStartupFailed") == true
        val pending = UltraReceipt.of(
            operationId = operationId,
            operation = operation,
            native = install,
            phase = UltraPhase.HOST_COMMITTED_CATALOG_PENDING,
            outcome = if (needsReboot) UltraOutcome.PENDING_REBOOT else UltraOutcome.COMPLETED,
            moduleId = id32 ?: identity.id32,
            packageSha256 = identity.archiveSha256,
            requestedVersion = describedVersion,
            installedVersion = describedVersion ?: request.manifestVersion,
            needsReboot = needsReboot,
            cleanupOutcome = "catalog_commit_pending",
            data = receiptData.create(
                UltraModuleReceiptPayload.Installed(
                    native = install,
                    minSdk = minSdk,
                    crossCheck = mismatches,
                    catalogModuleId = identity.id32,
                ),
            ),
            unknowns = if (!install.succeeded) mapOf("runtime" to (install.reason ?: install.sdkError))
                else emptyMap(),
        )
        val checkpoint = journal.appendDurably(operationId, pending, token)
        val committed = runCatching { catalog.commit(token) }
        val recovered = if (committed.isFailure) runCatching {
            catalog.recoverCommitted(operationId, token, identity.id32, identity.archiveSha256)
        } else Result.success(false)
        val commitFailed = committed.isFailure && recovered.getOrDefault(false) != true
        val receipt = pending.copy(
            phase = if (commitFailed) UltraPhase.HOST_COMMITTED_CATALOG_PENDING else UltraPhase.CATALOG_COMMITTED,
            cleanupOutcome = if (commitFailed) "catalog_commit_failed" else "catalog_committed",
            unknowns = buildMap {
                putAll(pending.unknowns)
                checkpoint.exceptionOrNull()?.let { put("operationLog", it.message ?: "operation_log_write_failed") }
                if (commitFailed) {
                    put("catalog", committed.exceptionOrNull()?.message ?: "catalog_commit_failed")
                    recovered.exceptionOrNull()?.let { put("catalogRecovery", it.message ?: "catalog_recovery_failed") }
                } else if (committed.isFailure) {
                    put("catalogRecovery", "completed_after:${committed.exceptionOrNull()?.message ?: "commit_failed"}")
                }
            },
        )
        val recorded = journal.appendDurably(operationId, receipt, if (commitFailed) token else null)
        val finalReceipt = recorded.exceptionOrNull()?.let { error ->
            receipt.copy(unknowns = receipt.unknowns +
                ("operationLog" to (error.message ?: "operation_log_write_failed")))
        } ?: receipt
        if (commitFailed) {
            stdout("Module installed; its local catalog record is pending. The confirmed package is retained.")
        }
        if (!install.succeeded) stdout("Module installed; diagnostic: ${install.reason ?: install.sdkError}")
        stdout("Installed ${receipt.moduleId.orEmpty()} ${receipt.installedVersion.orEmpty()}" +
            if (needsReboot) " (pending reboot)" else "")
        return finalReceipt
    }

    /**
     * 执行前兼容门（§4.1）的唯一判定点：设备事实 → 判定 → 写一条 `PRE_EXEC_CHECK` 事件。
     *
     * 时序是硬约束：调用点必须在 `catalog.stage` / `parseModuleDescriptor` / `installModule`
     * **之前**——一旦进入后两者，模块原生代码就可能被执行，H1 的「调用次数为 0」就不成立。
     *
     * 无论拦不拦都写一条 §4.3 事件：`UNVERIFIED` 也要可核对（只拦「已确认不兼容」，
     * 但「检查过且未拦」必须留下证据，否则事后无法区分它和「根本没检查」）。
     */
    private fun evaluate(
        request: UltraModuleInstallRequest,
        operationId: String,
    ): UltraModuleGateDecision {
        val decision = gate.evaluate(request.identity, facts(), request.action)
        record(
            UltraModuleCompatibilityGate.evidenceEvent(
                verdict = decision.verdict,
                operationId = operationId,
                bootId = bootId(),
                hostUtcIso = deviceNowIso(),
                processPid = processPid(),
                deviceTimeIso = deviceNowIso(),
                buildDigest = buildDigest(),
            ).copy(outcome = UltraModuleOutcome.UNKNOWN),
        )
        return decision
    }

    /**
     * 命中 `KNOWN_INCOMPATIBLE` 时的回执（不 stage、不写 catalog、不调用宿主）。
     *
     * 语义取舍（与 W2-0 逐项相同，见 `.analysis/.../w2-0/EVIDENCE.md` §1.5）：
     *  - `phase = PREPARED`：既有 [UltraPhase] 里最贴近「已准备好、但还没进入宿主调用」的一档；
     *  - `outcome = CONDITION_UNMET`：条件（兼容性）不满足——既不是成功，也不是执行失败；
     *  - `sdkError` 用 [KNOWN_INCOMPATIBLE_SDK_ERROR]（-1002），因为桥是好的、只是**没调用**；
     *  - `reason` 放中文拦截文案（调用方在 `outcome != COMPLETED` 时展示它）；
     *  - `data.reasonCodes` + `unknowns` 都带稳定原因码，UI/回执按码判断。
     */
    private fun blockedByCompatibility(
        operationId: String,
        operation: String,
        identity: UltraModulePackageIdentity,
        decision: UltraModuleGateDecision,
        stderr: (String) -> Unit,
    ): UltraReceipt {
        val receipt = UltraReceipt.of(
            operationId = operationId,
            operation = operation,
            native = null,
            phase = UltraPhase.PREPARED,
            outcome = UltraOutcome.CONDITION_UNMET,
            moduleId = identity.id32,
            packageSha256 = identity.archiveSha256,
            data = receiptData.create(UltraModuleReceiptPayload.CompatibilityBlocked(decision)),
            unknowns = mapOf(
                "ultraModuleCompatibility" to decision.reasonCodes.joinToString(","),
                "nativeExecution" to
                    "not_started: install_module / parse_module_desc_from_zip_file / " +
                    "start_module_web_ui_server_async were not called",
            ),
        ).copy(
            sdkError = KNOWN_INCOMPATIBLE_SDK_ERROR,
            sdkErrorCode = KNOWN_INCOMPATIBLE_SDK_ERROR_CODE,
            reason = decision.blockingText,
        )
        journal.append(operationId, receipt, token = null)
        stderr(decision.blockingText)
        return receipt
    }

    /** 写一条 §4.3 事件。**写证据不能打断事务**：sink 自己的失败已被记录器降级成 `Dropped`。 */
    private fun record(event: UltraModuleEvent) {
        evidence(event)
    }

    /** 事件发生那一刻的设备时间（ISO-8601 UTC）。每次调用取一次时钟。 */
    private fun deviceNowIso(): String = UltraModuleCompatibilityGate.deviceTimeIso(clockMillis())

    private fun decode(value: String): String =
        runCatching { java.net.URLDecoder.decode(value, "UTF-8") }.getOrDefault(value)

    companion object {

        /**
         * 被拦回执的两个稳定码（**唯一事实源**：`MapleSuModuleBackend` 的同名常量指向这里）。
         *
         * 为什么放在 `compat` 而不是 backend：被拦回执由本类构造，compat 若反过来引用 Android 侧
         * 的 backend 类，JVM 单测就得多背一个 `Context` 相关的类。值必须与 W2-0 逐字相同——
         * 回执、日志与测试都按这个码对齐；`MapleSuModuleBackendGateTest` 会断言两处相等。
         */
        const val KNOWN_INCOMPATIBLE_SDK_ERROR = "MAPLESU_ULTRA_MODULE_KNOWN_INCOMPATIBLE"
        const val KNOWN_INCOMPATIBLE_SDK_ERROR_CODE = -1002
    }
}

/**
 * 环境状态的人类可读标签（回执文案与 capabilities 共用一份，避免两处漂移）。
 *
 * 未知状态原样返回：不把 SDK 的新词表吞成「未知」以外的猜测。
 */
internal fun ultraEnvironmentStateLabel(state: String?): String = when (state) {
    null, "" -> "未知"
    "Running" -> "已就绪"
    "Fault" -> "异常"
    "NotInstalled" -> "未安装"
    else -> state
}
