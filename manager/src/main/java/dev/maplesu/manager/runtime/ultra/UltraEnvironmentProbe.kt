package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.util.Log
import dev.maplesu.manager.workmode.ModeActivation
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

/** Bounded off-main observations; reads never install, pair, or change global policy. */
object UltraEnvironmentProbe {
    enum class State { Running, NotInstalled, Fault, Unknown, NoKey }
    data class Snapshot(
        val state: State = State.Unknown,
        val observedAtElapsedMs: Long = -1,
        val observedAtWallClockMs: Long = 0,
        val detail: String? = null,
        val kernelRootVerified: Boolean = false,
        val kernelChannelAbsent: Boolean = false,
        val managerOwnerIdentity: UltraRuntimeClient.ManagerOwnerIdentity? = null,
        internal val modeActivation: ModeActivation = ModeRuntime.activation,
        val sdkChannelAvailable: Boolean = false,
        val legacyCredentialFingerprint: String? = null,
        val rootProbeDetail: String? = null,
        val managerSuFailureDetail: String? = null,
        internal val observedBootId: String? = null,
    ) {
        val rootAvailable: Boolean get() = kernelRootVerified &&
            state in setOf(State.Running, State.Unknown, State.NotInstalled)
    }

    private const val TAG = "MapleSUUltraProbe"
    private const val CACHE_TTL_MS = 3_000L
    private val ADMISSION_FAILURES = setOf("MAPLESU_SDK_BUSY", "MAPLESU_SDK_INTERRUPTED", "MAPLESU_SDK_DEADLINE_EXCEEDED")
    private val snapshots = MutableStateFlow(Snapshot())
    private val snapshot: Snapshot get() = snapshots.value
    private val lock = Any()
    private val probeLock = ReentrantLock()
    private var revision = 0L
    private var snapshotBootId: String? = null
    private val refreshing = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "maplesu-ultra-probe").apply { isDaemon = true }
    }

    val observations: Flow<Snapshot> = combine(snapshots, ModeRuntime.detectionRevision) { observation, _ ->
        if (observation.modeActivation === ModeRuntime.activation) observation else Snapshot()
    }.distinctUntilChanged()
    val states: Flow<State> = observations.map { it.state }.distinctUntilChanged()
    val rootAvailability: Flow<Boolean> = observations.map { it.rootAvailable }.distinctUntilChanged()

    fun current(): State = currentSnapshot().state
    fun currentSnapshot(): Snapshot = snapshot.takeIf { it.modeActivation === ModeRuntime.activation } ?: Snapshot()
    internal fun currentSnapshot(context: Context): Snapshot = synchronized(lock) {
        val owner = snapshot.managerOwnerIdentity
        scopeOwnerSnapshot(currentSnapshot(), snapshot.managerOwnerIdentity,
            UltraEnvironmentAutoSetup.currentBootId(), snapshotBootId,
            UltraSdkCredentials.suspended(context), UltraSdkCredentials.hookWithoutSdk(context),
            if (owner == null) UltraLegacyCredential.read(context)?.fingerprint else null)
    }

    internal fun publishManagerSuDiagnostic(context: Context, expected: Snapshot, detail: String?): Boolean = synchronized(lock) {
        val current = currentSnapshot(context)
        val boot = UltraEnvironmentAutoSetup.currentBootId()
        if (!managerSuDiagnosticScopeCurrent(expected, current, boot)) return@synchronized false
        snapshots.value = current.copy(managerSuFailureDetail = detail?.takeIf(String::isNotBlank))
        true
    }

    internal fun managerSuDiagnosticScopeCurrent(expected: Snapshot, current: Snapshot, boot: String?): Boolean =
        !boot.isNullOrBlank() && expected.observedBootId == boot && current.observedBootId == boot &&
            expected.modeActivation === ModeRuntime.activation && current.modeActivation === expected.modeActivation &&
            if (expected.managerOwnerIdentity != null) {
                expected.managerOwnerIdentity.fullUid == Process.myUid() &&
                    current.managerOwnerIdentity == expected.managerOwnerIdentity
            } else {
                current.managerOwnerIdentity == null && expected.legacyCredentialFingerprint != null &&
                    current.legacyCredentialFingerprint == expected.legacyCredentialFingerprint
            }
    internal fun webUiOwnerScope(context: Context): ModuleWebUiSessions.OwnerScope? =
        currentSnapshot(context).managerOwnerIdentity?.takeIf { ModeRuntime.active != WorkMode.KSU }?.let {
            ModuleWebUiSessions.OwnerScope(it.fullUid, it.epoch, it.hostInstance)
        }
    internal fun scopeOwnerSnapshot(observation: Snapshot, owner: UltraRuntimeClient.ManagerOwnerIdentity?,
                                   bootId: String?, observedBootId: String?, suspended: Boolean,
                                   hookActive: Boolean = false,
                                   legacyCredentialFingerprint: String? = null): Snapshot = when {
        bootId.isNullOrBlank() || bootId != observedBootId || suspended || hookActive -> Snapshot()
        owner != null && owner.fullUid == Process.myUid() && observation.managerOwnerIdentity == owner -> observation
        owner == null && observation.managerOwnerIdentity == null && legacyCredentialFingerprint != null &&
            observation.legacyCredentialFingerprint == legacyCredentialFingerprint -> observation
        owner == null && observation.managerOwnerIdentity == null ->
            observation.copy(state = State.Unknown, kernelRootVerified = false, sdkChannelAvailable = false,
                legacyCredentialFingerprint = null)
        else -> Snapshot()
    }

    fun isRootAvailable(context: Context): Boolean = usesUltraBackend(context) && currentSnapshot(context).rootAvailable
    fun isKernelRootVerified(context: Context): Boolean = ModeRuntime.active != WorkMode.KSU && currentSnapshot(context).kernelRootVerified
    internal fun hasCurrentRootProof(context: Context): Boolean = rootProofCurrent(currentSnapshot(context), SystemClock.elapsedRealtime())
    internal fun rootProofCurrent(observation: Snapshot, nowElapsedMs: Long): Boolean = observation.rootAvailable &&
        observation.observedAtElapsedMs >= 0 && nowElapsedMs - observation.observedAtElapsedMs in 0 until CACHE_TTL_MS
    fun isRunning(): Boolean = current() == State.Running
    fun isSafeMode(): Boolean = ModeRuntime.active != WorkMode.KSU && current() == State.Fault
    fun isSafeMode(context: Context): Boolean = usesUltraBackend(context) && currentSnapshot(context).state == State.Fault
    fun usesUltraBackend(context: Context): Boolean = ModeRuntime.active != WorkMode.KSU &&
        !UltraSdkCredentials.suspended(context) && !UltraSdkCredentials.hookWithoutSdk(context) &&
        currentSnapshot(context).let { it.managerOwnerIdentity?.fullUid == Process.myUid() ||
            it.legacyCredentialFingerprint != null }

    fun invalidateAvailability() = synchronized(lock) {
        revision++
        publishSnapshot(if (snapshot.modeActivation === ModeRuntime.activation && snapshot.state == State.Fault)
            snapshot.copy(observedAtElapsedMs = -1) else Snapshot())
    }

    fun requestRefresh(context: Context) {
        if (!refreshing.compareAndSet(false, true)) return
        val app = context.applicationContext
        executor.execute {
            try { refresh(app, force = false) }
            catch (error: Exception) { Log.w(TAG, "Ultra observation deferred", error) }
            finally { refreshing.set(false) }
        }
    }

    fun refresh(context: Context, force: Boolean = true): State = observe(context, force, fresh = false).state

    /** The returned value belongs to this read; retained runtime observations are never substituted. */
    internal fun observeFresh(context: Context): Snapshot = observe(context, force = true, fresh = true)

    /** Identity discovery never waits for a health worker or starts a Root operation. */
    internal fun observeFreshIdentity(context: Context): Snapshot {
        check(Looper.myLooper() != Looper.getMainLooper()) { "ULTRA_PROBE_BACKGROUND_THREAD_REQUIRED" }
        val app = context.applicationContext
        val activation = ModeRuntime.activation
        val boot = UltraEnvironmentAutoSetup.currentBootId()
            ?: return Snapshot(detail = "ULTRA_PROBE_BOOT_UNAVAILABLE", modeActivation = activation)
        val removalCurrent = dev.maplesu.manager.modules.UltraRootKeyStore.captureOwnerMarker(app)
        fun current() = ModeRuntime.activation === activation &&
            UltraEnvironmentAutoSetup.currentBootId() == boot && removalCurrent() &&
            !UltraSdkCredentials.suspended(app)
        return observeFreshIdentity(::current, { UltraRuntimeClient().queryManagerOwnerIdentity() }, activation)
            .copy(observedBootId = boot)
    }

    internal fun observeFreshIdentity(
        current: () -> Boolean,
        queryOwner: () -> UltraRuntimeClient.ManagerOwnerIdentityResult,
        activation: ModeActivation = ModeRuntime.activation,
    ): Snapshot {
        fun unknown(detail: String) = Snapshot(detail = detail, modeActivation = activation)
        fun allowed() = !Thread.currentThread().isInterrupted && current()
        if (!allowed()) return unknown("ULTRA_PROBE_SCOPE_CHANGED")
        return try {
            val observed = queryOwner()
            if (!allowed()) return unknown("ULTRA_PROBE_SCOPE_CHANGED")
            val owner = observed.identity?.takeIf { observed.receipt.succeeded && it.fullUid == Process.myUid() }
            Snapshot(
                observedAtElapsedMs = SystemClock.elapsedRealtime(),
                observedAtWallClockMs = System.currentTimeMillis(),
                detail = observationDetail(observed.receipt, invalidIdentity = owner == null && observed.receipt.succeeded),
                managerOwnerIdentity = owner,
                modeActivation = activation,
            )
        } catch (error: Exception) {
            if (error is java.util.concurrent.CancellationException) throw error
            if (error is InterruptedException) {
                Thread.currentThread().interrupt()
                return unknown("MAPLESU_SDK_INTERRUPTED")
            }
            unknown("ULTRA_PROBE_FAILED:${error.message ?: error.javaClass.simpleName}")
        }
    }

    private fun observe(context: Context, force: Boolean, fresh: Boolean): Snapshot {
        check(Looper.myLooper() != Looper.getMainLooper()) { "ULTRA_PROBE_BACKGROUND_THREAD_REQUIRED" }
        val app = context.applicationContext
        val activation = ModeRuntime.activation
        fun unknown(detail: String) = Snapshot(detail = detail, modeActivation = activation)
        val boot = UltraEnvironmentAutoSetup.currentBootId() ?: return unknown("ULTRA_PROBE_BOOT_UNAVAILABLE")
        val removalCurrent = dev.maplesu.manager.modules.UltraRootKeyStore.captureOwnerMarker(app)
        fun current() = !Thread.currentThread().isInterrupted && ModeRuntime.activation === activation &&
            (fresh || ModeRuntime.active != WorkMode.KSU) && UltraEnvironmentAutoSetup.currentBootId() == boot &&
            removalCurrent() && !UltraSdkCredentials.suspended(app) && !UltraSdkCredentials.hookWithoutSdk(app) &&
            (!fresh || !UltraIdentityRecovery.blocked(app, freshIdentity = true))
        if (!current()) return unknown("ULTRA_PROBE_SCOPE_CHANGED")
        val expectedRevision = synchronized(lock) {
            if (!probeLock.tryLock()) return if (fresh) unknown("MAPLESU_SDK_BUSY") else currentSnapshot(app)
            revision
        }
        try {
            val client = UltraRuntimeClient().scoped(::current)
            val ownerResult = client.queryManagerOwnerIdentity()
            val owner = ownerResult.identity
            if (!current()) return unknown("ULTRA_PROBE_SCOPE_CHANGED")
            val legacy = if (owner == null) UltraLegacyCredential.read(app) else null
            if (legacy != null) {
                val legacyClient = UltraRuntimeClient().withLegacyCredential(legacy).scoped(::current)
                val receipt = legacyClient.environmentState()
                val rootVerified = current() && UltraIdentityRecovery.uid(legacyClient) == 0 && current()
                val next = if (!receipt.succeeded) State.Unknown else when (receipt.string("state")) {
                    "Running" -> State.Running
                    "NotInstalled" -> State.NotInstalled
                    "Fault" -> State.Fault
                    else -> State.Unknown
                }
                return synchronized(lock) {
                    if (expectedRevision != revision || !current() || !legacy.isCurrent(app))
                        return@synchronized unknown("ULTRA_PROBE_SCOPE_CHANGED")
                    snapshotBootId = boot
                    publish(next, observationDetail(receipt), rootVerified,
                        receipt.sdkError == "ERR_MODULE_NO_BOOT", activation = activation,
                        sdkChannelAvailable = receipt.succeeded || rootVerified,
                        legacyCredentialFingerprint = legacy.fingerprint)
                }
            }
            if (!current()) return unknown("ULTRA_PROBE_SCOPE_CHANGED")
            if (owner == null) return synchronized(lock) {
                if (expectedRevision != revision || !current()) return@synchronized unknown("ULTRA_PROBE_SCOPE_CHANGED")
                snapshotBootId = boot
                publish(State.Unknown, observationDetail(ownerResult.receipt, invalidIdentity = ownerResult.receipt.succeeded), false,
                    ownerResult.receipt.sdkError == "ERR_MODULE_NO_BOOT", activation = activation)
            }
            val cached = if (fresh) null else currentSnapshot(app)
            val sameOwner = cached?.managerOwnerIdentity == owner && snapshotBootId == boot
            val age = cached?.let { SystemClock.elapsedRealtime() - it.observedAtElapsedMs } ?: Long.MAX_VALUE
            if (!force && cached != null && sameOwner &&
                canReuse(cached.state, age, cached.kernelRootVerified || cached.kernelChannelAbsent) &&
                cached.kernelRootVerified) return cached
            val receipt = client.environmentState()
            val root = if (current()) client.probeManagerOwnerRoot() else null
            val confirmed = if (current()) client.queryManagerOwnerIdentity().identity else null
            val measured = healthSnapshot(receipt, root, owner, confirmed, activation).copy(observedBootId = boot)
            return synchronized(lock) {
                if (expectedRevision != revision || !current()) return@synchronized unknown("ULTRA_PROBE_SCOPE_CHANGED")
                snapshotBootId = boot
                val observed = if (cached != null && sameOwner && measured.managerOwnerIdentity == owner) {
                    measured.copy(state = stateAfterAdmission(cached.state, measured.state, receipt.sdkError, true))
                } else measured
                publishSnapshot(observed, activation)
                observed
            }
        } catch (error: Exception) {
            if (error is java.util.concurrent.CancellationException) throw error
            Log.w(TAG, "Ultra observation failed", error)
            return unknown("ULTRA_PROBE_FAILED:${error.message ?: error.javaClass.simpleName}")
        } finally { probeLock.unlock() }
    }

    internal fun canReuse(state: State, age: Long, kernelResolved: Boolean = false): Boolean =
        (state != State.Unknown || kernelResolved) && age in 0 until CACHE_TTL_MS

    internal fun verifyKernelRoot(state: State, receiptSucceeded: Boolean, rootUid: () -> Int?): Boolean =
        (receiptSucceeded || state == State.Unknown) &&
            (state == State.Running || state == State.Unknown || state == State.NotInstalled) &&
            runCatching(rootUid).getOrNull() == 0

    internal fun observationDetail(receipt: NativeReceipt, invalidIdentity: Boolean = false): String =
        "operation=${receipt.operation};sdkError=${receipt.sdkError};sdkErrorCode=${receipt.sdkErrorCode}" +
            if (invalidIdentity) ";identity=invalid_reply" else ""

    internal fun healthSnapshot(
        receipt: NativeReceipt,
        root: ManagerOwnerRootResult?,
        owner: UltraRuntimeClient.ManagerOwnerIdentity,
        confirmed: UltraRuntimeClient.ManagerOwnerIdentity?,
        activation: ModeActivation = ModeRuntime.activation,
    ): Snapshot {
        val retained = confirmed ?: owner
        val sameOwner = owner == confirmed
        val rootVerified = sameOwner && root?.proof?.owner == retained
        val state = if (!sameOwner || !receipt.succeeded) State.Unknown else when (receipt.string("state")) {
            "Running" -> State.Running
            "NotInstalled" -> State.NotInstalled
            "Fault" -> State.Fault
            else -> State.Unknown
        }
        return Snapshot(
            state = state,
            observedAtElapsedMs = SystemClock.elapsedRealtime(),
            observedAtWallClockMs = System.currentTimeMillis(),
            detail = (if (confirmed != null && !sameOwner) "ULTRA_PROBE_OWNER_CHANGED:" else "") + observationDetail(receipt),
            kernelRootVerified = rootVerified,
            kernelChannelAbsent = receipt.sdkError == "ERR_MODULE_NO_BOOT" || root?.receipt?.sdkError == "ERR_MODULE_NO_BOOT",
            managerOwnerIdentity = retained,
            modeActivation = activation,
            sdkChannelAvailable = sameOwner && (receipt.succeeded || rootVerified),
            rootProbeDetail = root?.receipt?.raw?.takeUnless { rootVerified },
        )
    }

    internal fun recoveryFingerprint(state: State, safeMode: Boolean, kernelRootVerified: Boolean = false,
                                     kernelChannelAbsent: Boolean = false, detail: String? = null,
                                     managerOwnerBound: Boolean = false): String? = when {
        state == State.Running -> "ultra:running"
        state == State.Fault && safeMode -> "ultra:fault"
        kernelRootVerified && (state == State.Unknown || state == State.NotInstalled) -> "ultra:kernel"
        // A scoped signed Owner proves installation, independently of runtime readiness.
        managerOwnerBound -> "ultra:owner"
        state == State.Unknown -> throw IllegalStateException("ULTRA_RECOVERY_PROBE_UNKNOWN" +
            ((detail?.takeIf(String::isNotBlank) ?: "ERR_MODULE_NO_BOOT".takeIf { kernelChannelAbsent })
                ?.let { ":$it" } ?: ""))
        state == State.NoKey -> throw IllegalStateException("ULTRA_RECOVERY_IDENTITY_UNKNOWN")
        else -> null
    }

    internal fun stateAfterAdmission(previous: State, next: State, sdkError: String?, sameIdentity: Boolean): State =
        if (sameIdentity && sdkError in ADMISSION_FAILURES) previous else next

    internal fun suEnabledState(state: State): Boolean? = when (state) {
        State.Running -> true
        State.Fault, State.NotInstalled -> false
        State.Unknown, State.NoKey -> null
    }

    internal fun publishSnapshot(observation: Snapshot, activation: ModeActivation = ModeRuntime.activation) = synchronized(lock) {
        if (activation === ModeRuntime.activation && ModeRuntime.active != WorkMode.KSU) {
            observation.managerOwnerIdentity?.let {
                ModuleWebUiSessions.observedOwner(ModuleWebUiSessions.OwnerScope(it.fullUid, it.epoch, it.hostInstance))
            }
        }
        val previous = snapshot
        val sameDiagnosticScope = managerSuDiagnosticScopeCurrent(previous, observation, observation.observedBootId)
        snapshots.value = observation.copy(modeActivation = activation,
            managerSuFailureDetail = observation.managerSuFailureDetail ?:
                previous.managerSuFailureDetail.takeIf { sameDiagnosticScope })
    }

    private fun publish(state: State, detail: String?, kernelRootVerified: Boolean,
                        kernelChannelAbsent: Boolean,
                        ownerIdentity: UltraRuntimeClient.ManagerOwnerIdentity? = null,
                        activation: ModeActivation = ModeRuntime.activation,
                        sdkChannelAvailable: Boolean = false,
                        legacyCredentialFingerprint: String? = null): Snapshot {
        val observed = Snapshot(
            state = state,
            observedAtElapsedMs = SystemClock.elapsedRealtime(),
            observedAtWallClockMs = System.currentTimeMillis(),
            detail = detail,
            kernelRootVerified = kernelRootVerified,
            kernelChannelAbsent = kernelChannelAbsent,
            managerOwnerIdentity = ownerIdentity,
            sdkChannelAvailable = sdkChannelAvailable,
            legacyCredentialFingerprint = legacyCredentialFingerprint,
            modeActivation = activation,
            observedBootId = snapshotBootId,
        )
        publishSnapshot(observed, activation)
        return observed
    }
}
