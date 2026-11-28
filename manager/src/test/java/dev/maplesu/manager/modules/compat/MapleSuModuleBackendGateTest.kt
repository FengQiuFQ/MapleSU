package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import dev.maplesu.manager.ultra.model.MapleSuModRunState
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import dev.maplesu.manager.runtime.ultra.UltraPhase
import dev.maplesu.manager.runtime.ultra.UltraReceipt
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * 直接驱动真实安装事务，检查宿主提交回执、catalog 和 journal 的状态归属。
 * 兼容记录与环境观测保留诊断，用户选择的安装由宿主返回真实结果；列表刷新不决定提交。
 * 宿主、catalog 和日志是计数替身，回执 data 记录纯语义载荷，JSON 使用现有 JVM 测试依赖。
 */
class MapleSuModuleBackendGateTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private companion object {
        // ---- 本机已确认身份（与 UltraModuleCompatibilityRegistry / 冻结排查一致）----
        const val ID32 = "cd08ae9eef7bb885c06f80ef3aea1d5c"
        const val VERSION = "1.9.3"
        const val ARCHIVE_SHA256 = "2fdc08482075a9865d49e2595a2487f07a37ab499aab744d8d9bb09a098d4a31"
        const val PAYLOAD_SHA256 = "a0835b667db5ed33a12b7fa2d2f8ba9ee58b8f7fd538250b62111cffd2a647dc"
        const val NATIVE_ENTRY = "libmodule_app_auto_hider.so"
        const val KERNEL_RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
        const val SDK_VERSION = "5.1.0"
        const val OPERATION_ID = "5b1c9a70-2d3e-4f56-8a9b-0c1d2e3f4a5b"
        const val STAGED_TOKEN = "0123456789abcdef0123456789abcdef"
        const val BOOT_ID = "1f2e3d4c-5b6a-4978-8c9d-0e1f2a3b4c5d"
        const val PROCESS_PID = 4242

        /** 固定的注入时钟。`Instant.ofEpochMilli` 的结果见 [FIXED_ISO]。 */
        const val FIXED_MILLIS = 1_700_000_000_123L
        const val FIXED_ISO = "2023-11-14T22:13:20.123Z"

        /** 构建摘要（管理器 APK 的 SHA-256 形态：64 位小写十六进制）。 */
        val APK_SHA256 = "9f".repeat(32)
    }

    // ------------------------------------------------------------------ 计数型宿主

    /** 计数型宿主：分别记录安装调用与独立的显示列表读取。 */
    private class CountingHost : UltraModuleHost {

        val callOrder = ArrayList<String>()
        var environmentStateCalls = 0
        var parseModuleDescriptorCalls = 0
        var installModuleCalls = 0
        var uninstallModuleCalls = 0
        var modulesCalls = 0
        var openModuleWebUiCalls = 0

        var lastDescriptorPath: String? = null
        var lastInstallPath: String? = null
        var lastDevRunOnce: Boolean? = null
        var lastOpenWebUiId: String? = null

        /** 环境探针的返回状态：默认「已就绪」。 */
        var environmentStateValue = "Running"
        var environmentOk = true
        var environmentFailure: Exception? = null

        /** 宿主的安装回执：默认接受；置 false 模拟「宿主拒绝」。 */
        var installAccepted = true
        var installFailure: NativeReceipt? = null
        var modulesFailure: Exception? = null

        /** 独立显示刷新的内容，不作为本次安装提交证据。 */
        var listedAfterInstall: List<MapleSuModInstalledItem> = emptyList()

        override fun environmentState(): NativeReceipt {
            environmentStateCalls++
            callOrder += "environment"
            environmentFailure?.let { throw it }
            return receipt("get_maplesu_environment_state").copy(
                ok = environmentOk,
                sdkError = if (environmentOk) "OK" else "ENV_FAULT",
                sdkErrorCode = if (environmentOk) 0 else -7,
            )
        }

        override fun parseModuleDescriptor(zipPath: String): NativeReceipt {
            parseModuleDescriptorCalls++
            callOrder += "descriptor"
            lastDescriptorPath = zipPath
            return receipt("parse_module_desc_from_zip_file")
        }

        override fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt {
            installModuleCalls++
            callOrder += "install"
            lastInstallPath = zipPath
            lastDevRunOnce = devRunOnce
            val operation = if (devRunOnce) "install_module_dev_run_once" else "install_module"
            return installFailure ?: if (installAccepted) {
                receipt(operation).copy(data = JSONObject().put("installCommitted", true))
            } else {
                receipt(operation).copy(ok = false, sdkError = "MODULE_REFUSED_BY_HOST", sdkErrorCode = -3)
            }
        }

        override fun uninstallModule(id32: String): NativeReceipt {
            uninstallModuleCalls++
            callOrder += "uninstall"
            return receipt("uninstall_module")
        }

        override fun modules(): List<MapleSuModInstalledItem> {
            modulesCalls++
            callOrder += "modules"
            modulesFailure?.let { throw it }
            return listedAfterInstall
        }

        override fun openModuleWebUI(id32: String): NativeReceipt {
            openModuleWebUiCalls++
            callOrder += "open_webui"
            lastOpenWebUiId = id32
            return receipt("start_module_web_ui_server_async")
        }

        /** 会执行模块原生代码的三个入口的总次数（H1 断言的对象）。 */
        fun moduleExecutionCalls(): Int =
            parseModuleDescriptorCalls + installModuleCalls + openModuleWebUiCalls
    }

    // ------------------------------------------------------------------ 计数型 catalog / journal / 回执 data

    /** 计数型包存储：区分提交、保留对账材料与确认未提交后的丢弃。 */
    private class CountingCatalog(private val stagedFile: File) : UltraModuleCatalogPort {

        val callOrder = ArrayList<String>()
        var stageCalls = 0
        var stagedArchiveCalls = 0
        var commitCalls = 0
        var discardCalls = 0

        var stageFailure: Exception? = null
        var discardFailure: Exception? = null
        var commitFailure: Exception? = null

        override fun stage(source: File, confirmedArchiveSha256: String): String {
            stageCalls++
            callOrder += "stage"
            stageFailure?.let { throw it }
            return STAGED_TOKEN
        }

        override fun stagedArchive(token: String): File {
            stagedArchiveCalls++
            callOrder += "stagedArchive"
            return stagedFile
        }

        override fun commit(token: String) {
            commitCalls++
            callOrder += "commit"
            commitFailure?.let { throw it }
        }

        override fun discard(token: String) {
            discardCalls++
            callOrder += "discard"
            discardFailure?.let { throw it }
        }
    }

    /** 操作日志替身：记下每一条 `(operationId, receipt, token)`。 */
    private class RecordingJournal : UltraModuleJournal {
        val entries = ArrayList<Entry>()

        data class Entry(val operationId: String, val receipt: UltraReceipt, val token: String?)

        override fun append(operationId: String, receipt: UltraReceipt, token: String?) {
            entries += Entry(operationId, receipt, token)
        }
    }

    /** 回执 `data` 替身：保留宿主字段与 catalog 身份的语义内容。 */
    private class RecordingReceiptData : UltraModuleReceiptData {
        val payloads = ArrayList<UltraModuleReceiptPayload>()

        override fun create(payload: UltraModuleReceiptPayload): org.json.JSONObject? {
            payloads += payload
            return null
        }
    }

    // ------------------------------------------------------------------ 夹具

    /** 真实证据写入器：走 W1-C 的脱敏器，落盘内容与设备上同一条路径。 */
    private class EvidenceLines {
        val lines = ArrayList<String>()
        val log = UltraModuleGateEvidenceLog(appendLine = { lines += it })

        fun events(): List<UltraModuleEvent> = lines.map {
            UltraModuleEvidenceJson.decode(it)?.event
                ?: throw AssertionError("证据行不是合法 JSONL: $it")
        }
    }

    private val stagedFile: File by lazy { tmp.newFile("staged.zip") }

    private fun confirmedIdentity() = UltraModulePackageIdentity(
        id32 = ID32,
        version = VERSION,
        archiveSha256 = ARCHIVE_SHA256,
        nativePayloadSha256 = PAYLOAD_SHA256,
        nativeEntryName = NATIVE_ENTRY,
    )

    private fun unknownIdentity() = UltraModulePackageIdentity(
        id32 = "0123456789abcdef0123456789abcdef",
        version = "2.0.0",
        archiveSha256 = "e".repeat(64),
        nativePayloadSha256 = "d".repeat(64),
        nativeEntryName = "libunknown.so",
    )

    /** 本机设备事实（内核 release 可读；变体读不到，与 `UltraModuleDeviceFacts.read` 实际产出一致）。 */
    private fun deviceFacts() = UltraModuleDeviceFacts.of(
        sdkVersion = SDK_VERSION,
        kernelRelease = KERNEL_RELEASE,
        sdkManifestVerified = false,
        kernelVariantId = null,
        bootImageSha256 = null,
    )

    private fun request(
        identity: UltraModulePackageIdentity = confirmedIdentity(),
        devRunOnce: Boolean = false,
        action: UltraModuleAction =
            if (devRunOnce) UltraModuleAction.DEV_RUN_ONCE else UltraModuleAction.INSTALL,
        manifestVersion: String? = identity.version,
    ) = UltraModuleInstallRequest(
        source = tmp.newFile("source-${System.nanoTime()}.zip"),
        identity = identity,
        manifestVersion = manifestVersion,
        devRunOnce = devRunOnce,
        action = action,
    )

    /** 被测对象：**产品类**，全部依赖注入，没有 `Context`。 */
    private fun transaction(
        host: CountingHost,
        catalog: CountingCatalog,
        journal: RecordingJournal,
        evidence: EvidenceLines,
        payloads: RecordingReceiptData,
        clockMillis: () -> Long = { FIXED_MILLIS },
        build: () -> UltraModuleBuildDigest = { UltraModuleBuildDigest.of(APK_SHA256) },
        facts: () -> UltraModuleDeviceFacts = { deviceFacts() },
    ) = UltraModuleInstallTransaction(
        host = host,
        // 环境观测独立注入，以便覆盖诊断、读取失败与取消。
        environmentProbe = {
            UltraModuleEnvironmentObservation(host.environmentState(), host.environmentStateValue)
        },
        catalog = catalog,
        journal = journal,
        evidence = evidence.log::record,
        facts = facts,
        clockMillis = clockMillis,
        buildDigest = build,
        bootId = { BOOT_ID },
        processPid = { PROCESS_PID },
        newOperationId = { OPERATION_ID },
        receiptData = payloads,
    )

    private class Harness(
        val host: CountingHost,
        val catalog: CountingCatalog,
        val journal: RecordingJournal,
        val evidence: EvidenceLines,
        val payloads: RecordingReceiptData,
        val transaction: UltraModuleInstallTransaction,
        val stdout: MutableList<String> = ArrayList(),
        val stderr: MutableList<String> = ArrayList(),
    )

    private fun harness(
        clockMillis: () -> Long = { FIXED_MILLIS },
        build: () -> UltraModuleBuildDigest = { UltraModuleBuildDigest.of(APK_SHA256) },
    ): Harness {
        val host = CountingHost()
        val catalog = CountingCatalog(stagedFile)
        val journal = RecordingJournal()
        val evidence = EvidenceLines()
        val payloads = RecordingReceiptData()
        return Harness(
            host = host,
            catalog = catalog,
            journal = journal,
            evidence = evidence,
            payloads = payloads,
            transaction = transaction(host, catalog, journal, evidence, payloads, clockMillis, build),
        )
    }

    // ------------------------------------------------------------------ (a) 兼容诊断与安装结果分开

    @Test
    fun selectedModuleReachesHostDespiteCompatibilityDiagnostics() {
        val h = harness()
        h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.RUNNING))
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals(listOf("environment", "descriptor", "install"), h.host.callOrder)
        assertEquals(listOf("stage", "stagedArchive", "commit"), h.catalog.callOrder)
        assertEquals(stagedFile.absolutePath, h.host.lastInstallPath)
        assertTrue(h.stderr.isEmpty())
        assertEquals(UltraModuleOutcome.UNKNOWN, h.evidence.events().first().outcome)
        assertTrue(h.evidence.events().first().detail.contains("gate=KNOWN_INCOMPATIBLE"))
    }

    @Test
    fun compatibilityDiagnosticsDoNotMisreportASelectedInstallAsBlocked() {
        val h = harness()
        h.transaction.install(request(), h.stdout::add, h.stderr::add)
        val events = h.evidence.events()
        assertEquals(2, events.size)
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, events[0].phase)
        assertEquals(UltraModuleOutcome.UNKNOWN, events[0].outcome)
        assertTrue(events[0].detail.contains("gate=KNOWN_INCOMPATIBLE"))
        assertEquals(UltraModulePhase.NATIVE_ENTRY, events[1].phase)
        assertEquals(UltraModuleOutcome.SUCCESS, events[1].outcome)
        assertEquals(1, h.host.installModuleCalls)
        assertFalse(h.evidence.lines.any { it.contains(ARCHIVE_SHA256) || it.contains(PAYLOAD_SHA256) })
    }

    @Test
    fun eventsCarryTheBuildDigestAndTheDeviceTimeFromTheInjectedClock() {
        val h = harness()
        h.transaction.install(request(), h.stdout::add, h.stderr::add)

        val event = h.evidence.events().first()
        // 构建摘要：来自注入的生产者，落进字段（不是 null，也不是占位串）。
        assertEquals(APK_SHA256, event.buildDigest)
        assertTrue(h.evidence.lines.first().contains("\"buildDigest\":\"$APK_SHA256\""))
        // detail 里只放来源标记，不放摘要本身（32 位以上十六进制会被脱敏器吃掉）。
        assertTrue(event.detail.contains("build=verified:${UltraModuleBuildDigest.SOURCE_MANAGER_BASE_APK}"))
        // 设备时间：事件发生那一刻取自注入时钟，转成 ISO-8601 UTC。
        assertEquals(FIXED_ISO, event.deviceTimeIso)
        assertEquals(FIXED_ISO, event.hostUtcIso)
        // 脱敏器必须原样接受这条事件（否则「有字段」只是内存里的事，落盘时会被丢掉）。
        assertEquals(event.detail, UltraModuleEvidenceSanitizer().redact(event.detail))
    }

    @Test
    fun deviceTimeFollowsTheInjectedClockInsteadOfAConstant() {
        val first = harness(clockMillis = { FIXED_MILLIS })
        first.transaction.install(request(), first.stdout::add, first.stderr::add)

        val second = harness(clockMillis = { FIXED_MILLIS + 86_400_000L })
        second.transaction.install(request(), second.stdout::add, second.stderr::add)

        assertEquals(FIXED_ISO, first.evidence.events().first().deviceTimeIso)
        assertEquals(
            "时钟被真正读取：换一个注入值，事件时间必须跟着变",
            "2023-11-15T22:13:20.123Z",
            second.evidence.events().first().deviceTimeIso,
        )
    }

    @Test
    fun unavailableBuildDigestIsARecordedReasonAndNotSilentNull() {
        val h = harness(build = {
            UltraModuleBuildDigest.Unavailable(UltraModuleBuildDigest.REASON_APK_UNREADABLE)
        })
        h.transaction.install(request(), h.stdout::add, h.stderr::add)

        val line = h.evidence.lines.first()
        val event = h.evidence.events().first()
        // 字段本身只能是真实摘要或 null —— 占位串会被脱敏器置空，所以「拿不到」写在 detail 里。
        assertNull(event.buildDigest)
        assertTrue(line.contains("\"buildDigest\":null"))
        assertTrue(event.detail.contains("build=unknown:${UltraModuleBuildDigest.REASON_APK_UNREADABLE}"))
        // 「拿不到」与「没写」必须是两个不同的状态码。
        assertFalse(event.detail.contains(UltraModuleBuildDigest.REASON_NOT_PROVIDED))
    }

    // ------------------------------------------------------------------ (b) 未验证包 = 放行并调用宿主

    @Test
    fun unverifiedPackageIsJudgedAndThenExecuted() {
        val h = harness()
        val identity = unknownIdentity()
        h.host.listedAfterInstall = listOf(
            installedItem(identity.id32, identity.version, MapleSuModRunState.RUNNING),
        )
        val receipt = h.transaction.install(
            request(identity = identity),
            h.stdout::add,
            h.stderr::add,
        )

        // 宿主回执确认提交后写本地 catalog，显示列表不参与安装事务。
        assertEquals(
            listOf("environment", "descriptor", "install"),
            h.host.callOrder,
        )
        assertEquals(1, h.host.parseModuleDescriptorCalls)
        assertEquals(1, h.host.installModuleCalls)
        assertEquals(listOf("stage", "stagedArchive", "commit"), h.catalog.callOrder)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(stagedFile.absolutePath, h.host.lastDescriptorPath)
        assertEquals(stagedFile.absolutePath, h.host.lastInstallPath)
        assertEquals(false, h.host.lastDevRunOnce)

        // 回执关联本次宿主提交与本地 catalog 提交。
        assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals("catalog_committed", receipt.cleanupOutcome)
        assertEquals(identity.id32, receipt.moduleId)
        assertEquals(identity.version, receipt.installedVersion)
        assertTrue(receipt.unknowns.isEmpty())
        assertEquals(2, h.stdout.size)
        assertTrue(h.stdout[0].startsWith("Staged $STAGED_TOKEN"))
        assertTrue(h.stdout[1].startsWith("Installed "))
        assertEquals(3, h.journal.entries.size)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, h.journal.entries[0].receipt.outcome)
        assertEquals(STAGED_TOKEN, h.journal.entries[0].token)
        assertEquals(UltraPhase.HOST_COMMITTED_CATALOG_PENDING, h.journal.entries[1].receipt.phase)
        assertEquals(STAGED_TOKEN, h.journal.entries[1].token)
        assertEquals(UltraPhase.CATALOG_COMMITTED, h.journal.entries[2].receipt.phase)
        assertNull(h.journal.entries[2].token)

        // §4.3：两次事件 —— 门放行（UNKNOWN）+ 宿主已调用（SUCCESS）。
        val events = h.evidence.events()
        assertEquals(2, events.size)
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, events[0].phase)
        assertEquals(UltraModuleOutcome.UNKNOWN, events[0].outcome)
        assertTrue(events[0].detail.contains("gate=UNVERIFIED"))
        assertEquals(UltraModulePhase.NATIVE_ENTRY, events[1].phase)
        assertEquals(UltraModuleOutcome.SUCCESS, events[1].outcome)
        assertEquals(0, events[1].returnCode)
        assertTrue(events[1].detail.contains("state=HOST_CALLED"))
        assertEquals(APK_SHA256, events[1].buildDigest)

        // 保留宿主本次提交事实与实际 catalog 身份，不从显示列表补造运行状态。
        val installed = h.payloads.payloads.single() as UltraModuleReceiptPayload.Installed
        assertEquals("install_module", installed.native.operation)
        assertNotNull(installed.native.data)
        assertEquals(true, installed.native.data?.opt("installCommitted"))
        assertTrue("descriptor 没有 min_sdk_ver 时保持 null", installed.minSdk == null)
        assertEquals(identity.id32, installed.catalogModuleId)
        assertTrue(installed.crossCheck.isEmpty())
        assertEquals(0, h.host.modulesCalls)
    }

    @Test
    fun aDifferentListedModuleDoesNotOverrideTheHostCommit() {
        val h = harness()
        h.host.listedAfterInstall = listOf(
            installedItem("ffffffffffffffffffffffffffffffff", "9.9.9", MapleSuModRunState.RUNNING),
        )
        val receipt = h.transaction.install(
            request(identity = unknownIdentity()),
            h.stdout::add,
            h.stderr::add,
        )

        assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals(unknownIdentity().id32, receipt.moduleId)
        assertEquals("catalog_committed", receipt.cleanupOutcome)
        assertEquals(1, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(0, h.host.modulesCalls)
        assertTrue(receipt.unknowns.isEmpty())
        assertTrue(h.stderr.isEmpty())
        assertNull(h.journal.entries.last().token)
    }

    // ------------------------------------------------------------------ (c) 宿主拒绝

    @Test
    fun hostFailureWithoutRollbackFactsKeepsTheStagedCopy() {
        val h = harness()
        h.host.installAccepted = false
        val receipt = h.transaction.install(
            request(identity = unknownIdentity()),
            h.stdout::add,
            h.stderr::add,
        )

        assertEquals(UltraPhase.HOST_CALLED, receipt.phase)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("MODULE_REFUSED_BY_HOST", receipt.sdkError)
        assertEquals("staged_kept_for_reconciliation", receipt.cleanupOutcome)
        assertEquals("host_result_unverified", receipt.unknowns["installation"])
        assertEquals(listOf("stage", "stagedArchive"), h.catalog.callOrder)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(0, h.host.modulesCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)

        // §4.3：HOST_REFUSED 事件必须带真实 SDK 返回码。
        val events = h.evidence.events()
        assertEquals(2, events.size)
        assertEquals(UltraModulePhase.NATIVE_ENTRY, events[1].phase)
        assertEquals(UltraModuleOutcome.FAILURE, events[1].outcome)
        assertEquals(-3, events[1].returnCode)
        assertTrue(events[1].detail.contains("state=HOST_REFUSED"))
    }

    @Test
    fun callbackDeclineNeverCommitsEvenWhenAnOlderModuleIsStillListed() {
        for (devOnce in listOf(false, true)) {
            val h = harness()
            val operation = if (devOnce) "install_module_dev_run_once" else "install_module"
            h.host.installFailure = requireNotNull(NativeReceipt.parse(
                """{"backend":"maplesu_ultra","operation":"$operation","ok":false,
                    "sdkError":"MAPLESU_MODULE_INSTALL_CALLBACK_DECLINED","sdkErrorCode":-1007,
                    "reason":"module requires a different kernel",
                    "data":{"installCallbackAccepted":false,"installCommitted":false,
                    "cleanupComplete":true,"cleanupPending":false}}""",
            ))
            h.host.listedAfterInstall = listOf(
                installedItem(unknownIdentity().id32, "1.0", MapleSuModRunState.RUNNING),
            )
            val receipt = h.transaction.install(
                request(identity = unknownIdentity(), devRunOnce = devOnce), h.stdout::add, h.stderr::add,
            )
            assertEquals(UltraOutcome.FAILED, receipt.outcome)
            assertEquals("MAPLESU_MODULE_INSTALL_CALLBACK_DECLINED", receipt.sdkError)
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(0, h.host.modulesCalls)
            assertEquals(0, h.catalog.commitCalls)
            assertEquals(1, h.catalog.discardCalls)
            assertEquals("native_rollback_complete_staged_discarded", receipt.cleanupOutcome)
            assertEquals("module requires a different kernel", h.stderr.single())
        }
    }

    @Test
    fun lostInstallWorkerReceiptKeepsThePackageAndNeverReplaysEitherMode() {
        for (devOnce in listOf(false, true)) {
            val h = harness()
            val operation = if (devOnce) "install_module_dev_run_once" else "install_module"
            h.host.installFailure = requireNotNull(NativeReceipt.parse(
                """{"backend":"maplesu_ultra","operation":"$operation","ok":false,
                    "sdkError":"MAPLESU_MODULE_INSTALL_INTERRUPTED","sdkErrorCode":-1005,
                    "data":{"reconciliationRequired":true}}""",
            ))
            val receipt = h.transaction.install(
                request(identity = unknownIdentity(), devRunOnce = devOnce), h.stdout::add, h.stderr::add,
            )
            assertEquals(UltraPhase.HOST_CALLED, receipt.phase)
            assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
            assertEquals("staged_kept_for_reconciliation", receipt.cleanupOutcome)
            assertEquals("host_result_unverified", receipt.unknowns["installation"])
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(devOnce, h.host.lastDevRunOnce)
            assertEquals(0, h.host.modulesCalls)
            assertEquals(0, h.catalog.discardCalls)
            assertEquals(0, h.catalog.commitCalls)
            assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
        }
    }

    @Test
    fun legacyAndUnparseableInstallRepliesAlsoRetainReconciliationMaterial() {
        for (error in listOf("ERR_READ_CHILD_ERRCODE", "MAPLESU_BRIDGE_EXCEPTION", "MAPLESU_BRIDGE_UNPARSEABLE")) {
            val h = harness()
            h.host.installFailure = NativeReceipt.bridgeFailure("install_module", error, "reply lost")
            val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
            assertEquals(error, UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(0, h.catalog.discardCalls)
            assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
        }
    }

    @Test
    fun failedStagedCleanupIsReportedAndKeepsItsJournalToken() {
        val h = harness()
        h.host.installFailure = receipt("install_module").copy(
            ok = false, sdkError = "MAPLESU_SDK_BUSY", sdkErrorCode = -1001,
        )
        h.catalog.discardFailure = java.io.IOException("disk error")
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("staged_discard_failed", receipt.cleanupOutcome)
        assertEquals(1, h.catalog.discardCalls)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    @Test
    fun staleAbnormalReadbackDoesNotOverrideEitherModesHostCommit() {
        for (devOnce in listOf(false, true)) {
            val h = harness()
            h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.ABNORMAL))
            val receipt = h.transaction.install(request(devRunOnce = devOnce), h.stdout::add, h.stderr::add)
            assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
            assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
            assertEquals(VERSION, receipt.installedVersion)
            assertNull(receipt.activeVersion)
            assertFalse(receipt.needsReboot)
            assertTrue(receipt.unknowns.isEmpty())
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(0, h.host.modulesCalls)
            assertEquals(1, h.catalog.commitCalls)
            assertEquals(0, h.catalog.discardCalls)
            assertNull(h.journal.entries.last().token)
            assertTrue(h.stdout.any { it.startsWith("Installed ") })
            assertTrue(h.stderr.isEmpty())
        }
    }

    @Test
    fun committedStartupFailureAndCatalogFailureKeepTheirSeparateFacts() {
        val h = harness()
        h.host.installFailure = receipt("install_module").copy(
            ok = false, sdkError = "MODULE_ABNORMAL", sdkErrorCode = -3,
            data = JSONObject().put("installCommitted", true).put("immediateStartupFailed", true),
        )
        h.catalog.commitFailure = java.io.IOException("commit failed")
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.PENDING_REBOOT, receipt.outcome)
        assertEquals(UltraPhase.HOST_COMMITTED_CATALOG_PENDING, receipt.phase)
        assertEquals("MODULE_ABNORMAL", receipt.sdkError)
        assertEquals("MODULE_ABNORMAL", receipt.unknowns["runtime"])
        assertEquals("commit failed", receipt.unknowns["catalog"])
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(0, h.host.modulesCalls)
        assertTrue(receipt.needsReboot)
        assertTrue(h.stdout.any { it.contains("diagnostic: MODULE_ABNORMAL") })
        assertTrue(h.stderr.isEmpty())
    }

    @Test
    fun previousListedVersionDoesNotReplaceTheCommittedInstallVersion() {
        val h = harness()
        h.host.listedAfterInstall = listOf(installedItem(ID32, "older-version", MapleSuModRunState.RUNNING))
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals(VERSION, receipt.installedVersion)
        assertTrue(receipt.unknowns.isEmpty())
        assertEquals(0, h.host.modulesCalls)
        assertEquals(1, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertNull(h.journal.entries.last().token)
    }

    @Test
    fun duplicateDisplayedRowsDoNotOverrideTheHostCommit() {
        val h = harness()
        h.host.listedAfterInstall = listOf(
            installedItem(ID32, VERSION, MapleSuModRunState.RUNNING),
            installedItem(ID32, VERSION, MapleSuModRunState.NOT_RUNNING),
        )
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertTrue(receipt.unknowns.isEmpty())
        assertEquals(0, h.host.modulesCalls)
        assertEquals(1, h.catalog.commitCalls)
        assertNull(h.journal.entries.last().token)
    }

    @Test
    fun aNullDisplayedIdDoesNotReplaceTheConfirmedPackageIdentity() {
        val h = harness()
        h.host.listedAfterInstall = listOf(
            installedItem(ID32, VERSION, MapleSuModRunState.RUNNING).apply { id32 = null },
        )
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals(ID32, receipt.moduleId)
        assertEquals(0, h.host.modulesCalls)
        assertEquals(1, h.catalog.commitCalls)
        assertNull(h.journal.entries.last().token)
    }

    @Test
    fun independentListFailureDoesNotReplayOrInvalidateTheHostCommit() {
        val h = harness()
        h.host.modulesFailure = java.io.IOException("read failed")
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertTrue(receipt.unknowns.isEmpty())
        assertEquals(1, h.host.installModuleCalls)
        assertEquals(0, h.host.modulesCalls)
        assertEquals(1, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertNull(h.journal.entries.last().token)
    }

    @Test
    fun explicitUncommittedReceiptIsNotReplacedByAVisibleOldModule() {
        val h = harness()
        h.host.installFailure = receipt("install_module").copy(
            operationCompleted = true,
            data = JSONObject().put("installCommitted", false),
        )
        h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.RUNNING))
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("host_result_unverified", receipt.unknowns["installation"])
        assertEquals(0, h.host.modulesCalls)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    @Test
    fun anotherOperationsCommitDoesNotConfirmThisInstall() {
        val h = harness()
        h.host.installFailure = receipt("uninstall_module").copy(
            data = JSONObject().put("installCommitted", true),
        )
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals(0, h.catalog.commitCalls)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
    }

    @Test
    fun successfulLegacyInstallReceiptKeepsItsExistingCommitMeaning() {
        val h = harness()
        h.host.installFailure = receipt("install_module")
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
        assertEquals(1, h.catalog.commitCalls)
        assertEquals(0, h.host.modulesCalls)
        assertNull(h.journal.entries.last().token)
    }

    @Test
    fun knownUnsubmittedInstallDiscardsOnlyItsStagedCopy() {
        val h = harness()
        h.host.installFailure = receipt("install_module").copy(
            ok = false, sdkError = "MAPLESU_SDK_BUSY", sdkErrorCode = -1001,
        )
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.FAILED, receipt.outcome)
        assertEquals("MAPLESU_SDK_BUSY", receipt.sdkError)
        assertEquals("staged_discarded", receipt.cleanupOutcome)
        assertEquals(1, h.host.installModuleCalls)
        assertEquals(1, h.catalog.discardCalls)
        assertEquals(0, h.catalog.commitCalls)
        assertNull(h.journal.entries.last().token)
    }

    @Test
    fun deadlineBeforeSubmissionDiscardsOnlyTheStagedCopyWithoutReplaying() {
        for (devRunOnce in listOf(false, true)) {
            val h = harness()
            val operation = if (devRunOnce) "install_module_dev_run_once" else "install_module"
            h.host.installFailure = receipt(operation).copy(
                ok = false, sdkError = "MAPLESU_SDK_DEADLINE_EXCEEDED", sdkErrorCode = -1007,
            )
            val result = h.transaction.install(request(devRunOnce = devRunOnce), h.stdout::add, h.stderr::add)
            assertEquals(UltraOutcome.FAILED, result.outcome)
            assertEquals(UltraPhase.HOST_CALLED, result.phase)
            assertEquals("MAPLESU_SDK_DEADLINE_EXCEEDED", result.sdkError)
            assertEquals(-1007, result.sdkErrorCode)
            assertEquals("staged_discarded", result.cleanupOutcome)
            assertEquals(1, h.host.installModuleCalls)
            assertEquals(1, h.catalog.discardCalls)
            assertEquals(0, h.catalog.commitCalls)
            assertNull(h.journal.entries.last().token)
        }
    }

    @Test
    fun deadlineNameWithContradictorySubmissionFactsKeepsReconciliation() {
        for (failure in listOf(
            receipt("install_module").copy(ok = false, sdkError = "MAPLESU_SDK_DEADLINE_EXCEEDED", sdkErrorCode = -1001),
            receipt("install_module").copy(ok = false, sdkError = "MAPLESU_SDK_DEADLINE_EXCEEDED", sdkErrorCode = -1007, operationCompleted = true),
            receipt("install_module").copy(ok = false, sdkError = "MAPLESU_SDK_DEADLINE_EXCEEDED", sdkErrorCode = -1007, data = JSONObject()),
        )) {
            val h = harness()
            h.host.installFailure = failure
            val result = h.transaction.install(request(), h.stdout::add, h.stderr::add)
            assertEquals(UltraOutcome.NEEDS_RECONCILIATION, result.outcome)
            assertEquals(0, h.catalog.discardCalls)
            assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
            assertEquals(1, h.host.installModuleCalls)
        }
    }

    // ------------------------------------------------------------------ (d) stage 失败

    @Test
    fun stageFailureHappensAfterTheGateAndTouchesNoHostModuleEntry() {
        val h = harness()
        h.catalog.stageFailure = java.io.IOException("MODULE_CATALOG_BUSY")
        val receipt = h.transaction.install(
            request(identity = unknownIdentity()),
            h.stdout::add,
            h.stderr::add,
        )

        assertEquals(UltraPhase.PREPARED, receipt.phase)
        assertEquals(UltraOutcome.FAILED, receipt.outcome)
        assertEquals(mapOf("stageError" to "MODULE_CATALOG_BUSY"), receipt.unknowns)
        // 门放过之后才 stage：门的事件已经写过，宿主模块入口仍然 0 次。
        assertEquals(1, h.catalog.stageCalls)
        assertEquals(0, h.host.moduleExecutionCalls())
        assertEquals(listOf("environment"), h.host.callOrder)
        assertEquals(1, h.evidence.events().size)
        assertTrue(h.stderr.single().contains("Staging failed: MODULE_CATALOG_BUSY"))
    }

    // ------------------------------------------------------------------ (e) 前置条件不满足

    @Test
    fun failedEnvironmentObservationDoesNotBlockTheSelectedInstall() {
        val h = harness()
        h.host.environmentStateValue = "Fault"
        h.host.environmentOk = false
        h.host.listedAfterInstall = listOf(installedItem(ID32, VERSION, MapleSuModRunState.RUNNING))
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)

        assertEquals(UltraPhase.CATALOG_COMMITTED, receipt.phase)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertTrue(h.stderr.isEmpty())
        val event = h.evidence.events().first()
        assertEquals(UltraModulePhase.PRE_EXEC_CHECK, event.phase)
        assertEquals(UltraModuleOutcome.UNKNOWN, event.outcome)
        assertTrue(event.detail.contains("environment=Fault"))
        assertNull(event.returnCode)

        assertEquals(1, h.catalog.stageCalls)
        assertEquals(1, h.catalog.commitCalls)
        assertEquals(listOf("environment", "descriptor", "install"), h.host.callOrder)
    }

    @Test
    fun throwingEnvironmentProbeStillUsesTheActualHostResult() {
        val h = harness()
        h.host.environmentFailure = java.io.IOException("ENVIRONMENT_PROBE_LOST")
        h.host.installAccepted = false
        val receipt = h.transaction.install(request(), h.stdout::add, h.stderr::add)

        assertEquals(UltraPhase.HOST_CALLED, receipt.phase)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, receipt.outcome)
        assertEquals("MODULE_REFUSED_BY_HOST", receipt.sdkError)
        assertEquals(listOf("environment", "descriptor", "install"), h.host.callOrder)
        assertEquals(0, h.catalog.discardCalls)
        assertEquals(STAGED_TOKEN, h.journal.entries.last().token)
        assertEquals(listOf("MODULE_REFUSED_BY_HOST"), h.stderr)
    }

    @Test
    fun interruptedEnvironmentProbeStopsTheCancelledOperation() {
        val h = harness()
        h.host.environmentFailure = InterruptedException("cancelled")
        org.junit.Assert.assertThrows(InterruptedException::class.java) {
            h.transaction.install(request(), h.stdout::add, h.stderr::add)
        }
        assertEquals(0, h.host.moduleExecutionCalls())
        assertEquals(0, h.catalog.stageCalls)
    }

    // ------------------------------------------------------------------ (f) dev-run-once 与 WebUI

    @Test
    fun devRunOnceUsesTheUserSelectedInstallTransaction() {
        val h = harness()
        val receipt = h.transaction.install(request(devRunOnce = true, action = UltraModuleAction.DEV_RUN_ONCE), h.stdout::add, h.stderr::add)
        assertEquals(UltraOutcome.COMPLETED, receipt.outcome)
        assertEquals(1, h.catalog.stageCalls)
        assertEquals(1, h.host.installModuleCalls)
        assertEquals(true, h.host.lastDevRunOnce)
        assertEquals(UltraModuleOutcome.UNKNOWN, h.evidence.events().first().outcome)
    }

    @Test
    fun selectedInstallUsesHostWhileWebUiRetainsItsOwnDecision() {
        val host = CountingHost()
        val gate = UltraModuleExecutionGate(host)
        val decision = gate.evaluate(confirmedIdentity(), deviceFacts(), UltraModuleAction.INSTALL)
        val execution = gate.executeInstall(decision, "/tmp/staged.zip", devRunOnce = false)
        assertTrue(execution is UltraModuleInstallExecution.Ran)
        assertEquals(1, host.parseModuleDescriptorCalls)
        assertEquals(1, host.installModuleCalls)
        val webUi = gate.evaluate(confirmedIdentity(), deviceFacts(), UltraModuleAction.OPEN_WEBUI)
        assertNull(gate.openWebUiIfAllowed(webUi, ID32))
        assertEquals(0, host.openModuleWebUiCalls)
    }

    @Test
    fun openWebUiIsGatedTheSameWay() {
        val host = CountingHost()
        val gate = UltraModuleExecutionGate(host)

        val blocked = gate.evaluate(confirmedIdentity(), deviceFacts(), UltraModuleAction.OPEN_WEBUI)
        assertTrue(blocked.blocked)
        assertNull(gate.openWebUiIfAllowed(blocked, ID32))
        assertEquals(0, host.openModuleWebUiCalls)

        val allowed = gate.evaluate(unknownIdentity(), deviceFacts(), UltraModuleAction.OPEN_WEBUI)
        assertFalse(allowed.blocked)
        val receipt = gate.openWebUiIfAllowed(allowed, ID32)
        assertEquals(1, host.openModuleWebUiCalls)
        assertEquals(ID32, host.lastOpenWebUiId)
        assertTrue(receipt!!.succeeded)
    }

    // ------------------------------------------------------------------ (g) 重复请求无隐藏状态

    @Test
    fun repeatedRequestsRetainDiagnosticsAndExecuteEachSelectedInstall() {
        val h = harness()
        h.transaction.install(request(identity = unknownIdentity()), h.stdout::add, h.stderr::add)
        repeat(2) {
            h.transaction.install(request(), h.stdout::add, h.stderr::add)
        }
        assertEquals(3, h.host.installModuleCalls)
        assertEquals(3, h.host.parseModuleDescriptorCalls)
        assertEquals(3, h.catalog.stageCalls)
        assertEquals(6, h.evidence.events().size)
        assertTrue(h.evidence.events().none { it.outcome == UltraModuleOutcome.BLOCKED })
    }

    // ------------------------------------------------------------------ helpers

    private fun installedItem(id32: String, ver: String, state: MapleSuModRunState) =
        MapleSuModInstalledItem("枫栖示例", "demo", ver, id32, "Maple", "", "", false, state)

    /**
     * 被拦回执的两个稳定码：**与 backend 的公开常量必须逐字相同**。
     *
     * 引用 `MapleSuModuleBackend.KNOWN_INCOMPATIBLE_*`（`const val`，编译期内联）来钉住两处：
     * 任何一侧被改名/改值，这个对照就会失败。不实例化 backend（那需要 `Context`）。
     */
    private object UltraInstallTransactionCodes {
        const val SDK_ERROR = dev.maplesu.manager.modules.MapleSuModuleBackend.KNOWN_INCOMPATIBLE_SDK_ERROR
        const val SDK_ERROR_CODE =
            dev.maplesu.manager.modules.MapleSuModuleBackend.KNOWN_INCOMPATIBLE_SDK_ERROR_CODE
    }
}

/** 一个「成功」的宿主回执。`data` 默认 null：JVM 单测里不碰 `org.json`。 */
private fun receipt(operation: String): NativeReceipt = NativeReceipt(
    schemaVersion = 1,
    backend = UltraRuntimeClient.BACKEND,
    bridgeVersion = 1,
    operation = operation,
    ok = true,
    sdkError = "OK",
    sdkErrorCode = 0,
    reason = null,
    data = null,
    raw = "{}",
)
