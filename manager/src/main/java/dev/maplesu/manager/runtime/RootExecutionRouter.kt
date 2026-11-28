package dev.maplesu.manager.runtime

import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import android.content.Context
import android.os.Looper
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.runtime.ultra.UltraSdkCredentials
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode

/** Current Ultra/Hook or KSU route; unknown modes never use a stored credential. */
enum class RootBackend {
    LITE_KERNEL,
    ULTRA_ENV,
    HOOK,
    /**
     * KernelSU 原生根通道（Normal）：`<nativeLibraryDir>/libksud_ksu.so debug su`，
     * 与 `KsuRootChannel` 同形。**只在 `ModeRuntime.active == KSU` 时被装配/选中**。
     */
    KSU,
    NONE,
    ;

    /** 中文展示名（Settings Lite 隐藏卡「根通道：…」）。 */
    val label: String
        get() = when (this) {
            LITE_KERNEL -> "Ultra 内核"
            ULTRA_ENV -> "Ultra 环境"
            HOOK -> "Ultra 临时环境"
            KSU -> "KSU 内核"
            NONE -> "无"
        }
}

data class RootExecResult(
    val backend: RootBackend,
    val code: Int,
    val output: String,
    val detail: String = "",
) {
    val ok: Boolean get() = backend != RootBackend.NONE && code == 0
}

data class RootCapability(
    val backend: RootBackend,
    val available: Boolean,
    val detail: String = "",
) {
    val label: String get() = backend.label

    companion object {
        val NONE = RootCapability(RootBackend.NONE, available = false)
    }
}

/** 一个根后端（可注入 fake 做主机测试）。 */
interface RootExecutor {
    val backend: RootBackend

    /** 后端当前是否可用（不执行脚本）。 */
    fun available(): Boolean

    /** Runs only for an explicit operation, never for UI capability reads. */
    fun prepareForExecution(): Boolean = available()

    fun run(script: String): RootExecResult
}

/** Ultra `run_root_cmd` 的一次结果（与 org.json 回执解耦，主机可测）。 */
data class UltraRootCommandResult(
    val ok: Boolean,
    val code: Int,
    val output: String = "",
    val detail: String = "",
    val commandCompleted: Boolean = false,
)

fun interface UltraRootCommandRunner {
    fun runRootCommand(script: String): UltraRootCommandResult
}

/**
 * Ultra 环境后端：生产能力来自当前安装身份/boot 的探针；命令始终经实际 SDK 回执确认。
 * 输出由生产 runner 从回执 `data.result`（URL-encoded）解码后传入。
 */
class UltraEnvRootExecutor(
    private val runner: UltraRootCommandRunner,
    private val running: () -> Boolean = { UltraEnvironmentProbe.isRunning() },
    private val prepare: () -> Boolean = running,
    private val onFailure: () -> Unit = {},
) : RootExecutor {
    override val backend: RootBackend = RootBackend.ULTRA_ENV

    override fun available(): Boolean = runCatching { running() }.getOrDefault(false)

    override fun prepareForExecution(): Boolean = runCatching { prepare() }.getOrDefault(false)

    override fun run(script: String): RootExecResult {
        val result = runCatching { runner.runRootCommand(script) }.getOrElse { error ->
            runCatching(onFailure)
            return RootExecResult(
                RootBackend.ULTRA_ENV, -1, "",
                "ULTRA_ROOT_EXCEPTION:${error.javaClass.simpleName}",
            )
        }
        return if (result.ok) {
            RootExecResult(RootBackend.ULTRA_ENV, 0, result.output)
        } else {
            // Admission failures submitted no SDK work and contain no new root evidence.
            // Invalidating here turns a busy startup probe into repeated environment reads.
            val notSubmitted = result.detail == "ULTRA_ROOT_FAILED:MAPLESU_SDK_BUSY" ||
                result.detail == "ULTRA_ROOT_FAILED:MAPLESU_SDK_INTERRUPTED" ||
                result.detail == "ULTRA_ROOT_FAILED:MAPLESU_SDK_DEADLINE_EXCEEDED"
            if (!result.commandCompleted && !notSubmitted) runCatching(onFailure)
            RootExecResult(RootBackend.ULTRA_ENV, result.code, result.output, result.detail)
        }
    }
}

class RootExecutionRouter(
    private val ultraEnv: RootExecutor?,
    private val modeProvider: () -> WorkMode? = { ModeRuntime.active },
    private val clock: () -> Long = { System.nanoTime() / 1_000_000L },
    private val capabilityTtlMillis: Long = 2_000L,
    private val ksuProvider: () -> RootExecutor? = { RootExec.ksuExecutor() },
    private val ultraIdentity: () -> Boolean = { false },
    private val hook: RootExecutor? = null,
) {
    private val lock = Any()
    private val executionLock = ReentrantLock(true)
    private var cachedCapability: RootCapability? = null
    private var cachedAtMillis: Long = 0L

    private fun executors(): List<RootExecutor> {
        val mode = runCatching { modeProvider() }.getOrNull()
        if (mode != WorkMode.KSU) {
            if (runCatching(ultraIdentity).getOrDefault(false)) return listOfNotNull(ultraEnv)
            if (runCatching { hook?.available() == true }.getOrDefault(false)) return listOfNotNull(hook)
        }
        return when (mode) {
            WorkMode.LITE -> listOfNotNull(ultraEnv)
            // KSU is selected only through the registered KSU source.
            WorkMode.KSU -> listOfNotNull(ksuProvider())
            null -> emptyList()
        }
    }

    /**
     * Lite 的可用根来自 Ultra Running 或当前 Ultra Hook Gate；不启动 libsu/旧内核凭据。
     */
    fun rootAvailableForLite(): Boolean = runCatching {
        ultraEnv?.available() == true ||
            (!ultraIdentity() && hook?.available() == true)
    }.getOrDefault(false)

    /** 当前模式下首选后端（UI 显示；不执行）。 */
    fun preferredBackend(): RootBackend {
        val mode = runCatching { modeProvider() }.getOrNull()
        if (mode != WorkMode.KSU && !runCatching(ultraIdentity).getOrDefault(false) &&
            runCatching { hook?.available() == true }.getOrDefault(false)
        ) return RootBackend.HOOK
        return when (mode) {
            WorkMode.LITE -> if (ultraEnv != null) RootBackend.ULTRA_ENV else RootBackend.NONE
            WorkMode.KSU -> if (runCatching { ksuProvider() }.getOrNull() != null) {
                RootBackend.KSU
            } else {
                RootBackend.NONE
            }
            null -> RootBackend.NONE
        }
    }

    fun execute(script: String): RootExecResult = executeSelected(script, ::executors)

    /** Explicit Ultra handover: never select the previously active Normal/Ultra backend. */
    fun executeHook(script: String): RootExecResult = executeSelected(script) { listOfNotNull(hook) }

    private fun executeSelected(script: String, select: () -> List<RootExecutor>): RootExecResult {
        val deadline = PageReadDeadline.currentNanos()
        val budget = deadline?.let { it - System.nanoTime() } ?: TimeUnit.MILLISECONDS.toNanos(1_500L)
        if (budget <= 0) return RootExecResult(RootBackend.NONE, -1007, "", "ROOT_EXECUTION_DEADLINE_EXCEEDED")
        if (Thread.currentThread().isInterrupted) {
            return RootExecResult(RootBackend.NONE, -1, "", "ROOT_EXECUTION_INTERRUPTED")
        }
        val selected = select()
        // Hook commands own independent fork/pipe/waitpid sessions. Serializing
        // them behind installs or SDK startup starves policy and inventory reads.
        // SDK transports keep their existing exclusive admission.
        if (selected.singleOrNull()?.backend == RootBackend.HOOK) return executeOn(script, selected)
        val lockBudget = deadline?.let { it - System.nanoTime() } ?: budget
        if (lockBudget <= 0) return RootExecResult(RootBackend.NONE, -1007, "", "ROOT_EXECUTION_DEADLINE_EXCEEDED")
        val acquired = try { executionLock.tryLock(lockBudget, TimeUnit.NANOSECONDS) }
        catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return RootExecResult(RootBackend.NONE, -1, "", "ROOT_EXECUTION_INTERRUPTED")
        }
        if (!acquired) return if (deadline != null && deadline - System.nanoTime() <= 0) {
            RootExecResult(RootBackend.NONE, -1007, "", "ROOT_EXECUTION_DEADLINE_EXCEEDED")
        } else RootExecResult(RootBackend.NONE, -1, "", "ROOT_EXECUTION_BUSY")
        return try {
            if (deadline != null && deadline - System.nanoTime() <= 0) {
                RootExecResult(RootBackend.NONE, -1007, "", "ROOT_EXECUTION_DEADLINE_EXCEEDED")
            } else {
                // A mode activation or switch may have completed while this request waited.
                executeOn(script, select())
            }
        } finally { executionLock.unlock() }
    }

    private fun executeOn(script: String, selected: List<RootExecutor>): RootExecResult {
        val attempts = mutableListOf<RootExecResult>()
        for (executor in selected) {
            val available = runCatching { executor.prepareForExecution() }.getOrDefault(false)
            if (!available) {
                attempts += RootExecResult(executor.backend, -1, "", "BACKEND_UNAVAILABLE")
                continue
            }
            val result = runCatching { executor.run(script) }.getOrElse { error ->
                RootExecResult(executor.backend, -1, "", "BACKEND_EXCEPTION:${error.javaClass.simpleName}")
            }
            // A failure/absent reply may follow a completed mutation. Only preparation may
            // choose a fallback; once run started, return its original result without replay.
            return result
        }
        val last = attempts.lastOrNull()
        val detail = attempts.joinToString("; ") { "${it.backend}:${it.detail.ifEmpty { "code=${it.code}" }}" }
        return RootExecResult(
            backend = RootBackend.NONE,
            code = last?.code ?: -1,
            output = last?.output.orEmpty(),
            detail = if (detail.isEmpty()) "NO_ROOT_BACKEND" else detail,
        )
    }

    fun capability(forceRefresh: Boolean = false): RootCapability {
        synchronized(lock) {
            val now = clock()
            val cached = cachedCapability
            if (!forceRefresh && cached != null && now - cachedAtMillis < capabilityTtlMillis) {
                return cached
            }
            val result = try {
                executors().firstOrNull { runCatching { it.available() }.getOrDefault(false) }
            } catch (_: Throwable) {
                null
            }
            val capability = if (result == null) {
                RootCapability.NONE
            } else {
                RootCapability(result.backend, available = true)
            }
            cachedCapability = capability
            cachedAtMillis = now
            return capability
        }
    }

    /** Production routes use the current installation identity and live backend evidence. */
    companion object {
        fun production(context: Context): RootExecutionRouter {
            val application = context.applicationContext
            val ultraClient by lazy {
                UltraSdkCredentials.client(application)
            }
            val ultraRunner = UltraRootCommandRunner { script ->
                val command = UltraRootCommandReceipt(script)
                val receipt: NativeReceipt = ultraClient.runRootCommand(command.command)
                command.decodeSdk(receipt, ultraClient::decodeText)
            }
            return RootExecutionRouter(
                hook = HookRootExecutor.production(application),
                ultraEnv = UltraEnvRootExecutor(
                    runner = ultraRunner,
                    running = { UltraEnvironmentProbe.isRootAvailable(application) },
                    prepare = {
                        // The current installation identity selects this transport; the command receipt proves root.
                        // Reprobing before every command consumes the caller's admission budget.
                        Looper.myLooper() != Looper.getMainLooper() &&
                            ModeRuntime.active != WorkMode.KSU &&
                            (UltraEnvironmentProbe.usesUltraBackend(application) ||
                                UltraEnvironmentProbe.refresh(application, force = false) == UltraEnvironmentProbe.State.Running)
                    },
                    onFailure = {
                        UltraEnvironmentProbe.invalidateAvailability()
                        UltraEnvironmentProbe.requestRefresh(application)
                    },
                ),
                ultraIdentity = {
                    !HookRootExecutor.production(application).available() &&
                        UltraEnvironmentProbe.usesUltraBackend(application)
                },
            )
        }
    }
}

/**
 * 进程内根执行门面：UI/legacy 代码通过它拿 router，避免继续直接依赖 libsu `su`。
 * 生产由 Application 启动时 [install]，缺失时 [execute] 返回结构化 NONE（不拒绝服务式 crash）。
 * 主机测试用 [installForTest] 注入 fake router。
 */
object RootExec {
    @Volatile
    private var installed: RootExecutionRouter? = null

    /**
     * KSU 根执行器（Normal 模式的生产后端）。
     *
     * 装配时机：`ModeBootstrap` 在模式激活为 [WorkMode.KSU] 后调用
     * [installKsu]（由 `dev.maplesu.manager.workmode.backend.KsuBackendRegistry` 提供实例）。
     * LITE/未判定时保持 null → KSU 后端不会被任何调用点看到（fail-closed）。
     * 这里不做任何模式判断：模式判断在 router 的 `executors()` 里，未判定路径不会取它。
     */
    @Volatile
    private var ksuExecutor: RootExecutor? = null

    fun install(router: RootExecutionRouter) {
        installed = router
    }

    fun installKsu(executor: RootExecutor?) {
        ksuExecutor = executor
    }

    fun ksuExecutor(): RootExecutor? = ksuExecutor

    fun installForTest(router: RootExecutionRouter?) {
        installed = router
    }

    fun resetForTest() {
        installed = null
        ksuExecutor = null
    }

    fun current(): RootExecutionRouter? = installed

    /** 兼容有 Context 的 legacy 调用点：未安装时按需装配生产 router（进程内只装一次）。 */
    fun execute(context: Context?, script: String): RootExecResult =
        resolve(context)?.execute(script)
            ?: RootExecResult(RootBackend.NONE, -1, "", "ROOT_BACKEND_UNAVAILABLE")

    /** One admission budget for the official libsu task, shared by the router and SDK queues. */
    internal fun executeServiceLaunch(context: Context?, script: String, useHook: Boolean = false): RootExecResult =
        kotlinx.coroutines.runBlocking(PageReadDeadline.context(5_000L)) {
            val command = RootServiceBootstrap.command(script)
            if (useHook) executeHook(context, command) else execute(context, command)
        }

    /** Explicit Hook operation; a failed or expired gate never falls back to another root source. */
    fun executeHook(context: Context?, script: String): RootExecResult =
        resolve(context)?.executeHook(script)
            ?: RootExecResult(RootBackend.NONE, -1, "", "ROOT_BACKEND_UNAVAILABLE")

    private fun resolve(context: Context?): RootExecutionRouter? {
        installed?.let { return it }
        if (context == null) return null
        return synchronized(this) {
            installed ?: runCatching { RootExecutionRouter.production(context.applicationContext) }
                .getOrNull()?.also(::install)
        }
    }

    fun execute(script: String): RootExecResult {
        val router = installed
            ?: return RootExecResult(RootBackend.NONE, -1, "", "ROOT_BACKEND_UNAVAILABLE")
        return router.execute(script)
    }

    fun capability(): RootCapability = installed?.capability() ?: RootCapability.NONE

    fun capability(context: Context): RootCapability = resolve(context)?.capability() ?: RootCapability.NONE

    /** Lite 根可用语义：Ultra Running 或当前 Ultra Hook Gate。 */
    fun rootAvailableForLite(): Boolean = installed?.rootAvailableForLite() ?: false

    fun preferredBackend(): RootBackend = installed?.preferredBackend() ?: RootBackend.NONE

    fun preferredBackend(context: Context): RootBackend = resolve(context)?.preferredBackend() ?: RootBackend.NONE
}
