package dev.maplesu.manager.runtime.ultra

import java.util.concurrent.CancellationException

/** Preserve a completed SDK attempt when the subsequent local verification throws. */
internal class UltraAuthorizationRestoreException(
    val result: UltraAuthorizationRestoreResult,
    val original: Exception,
) : RuntimeException("MANAGER_AUTH_RESTORE_EXCEPTION", original)

/** One reconciliation pass can include a primary mutation and its necessary identity-change revoke. */
internal class UltraAuthorizationRestoreResult private constructor(
    val status: String,
    val primary: UltraAuthorizationAttempt? = null,
    val inverse: UltraAuthorizationAttempt? = null,
    val refresh: UltraAuthorizationAttempt? = null,
) {
    /** Missing or future details never establish that a transient failure is safe to replay. */
    val retryableBeforeCommit: Boolean
        get() {
            if (status !in setOf("MAPLESU_SDK_BUSY", "ERR_MODULE_SU_LIST_NOT_FOUND", "ERR_MODULE_READ_FILE") ||
                inverse != null || (primary != null && refresh != null)) return false
            val receipt = (primary ?: refresh)?.receipt ?: return false
            val detail = receipt.authorizationResult ?: return false
            val transport = detail.transport
            val transferred = transport.status == 1L && transport.valid && transport.childWaitStatus == 0
            val notTransferred = transport.status == 0L && !transport.valid && transport.childWaitStatus == 0
            return !receipt.succeeded && detail.operationResultAvailable && detail.diagnosticsComplete &&
                detail.operation in 1L..4L && detail.resultCode != "0" && detail.commitState == 1L &&
                detail.restoreState in 1L..2L && detail.deliveryState in 0L..2L && transport.errno == 0 &&
                (transferred || notTransferred)
        }

    val diagnosticSummary: String
        get() = buildString {
            append("status=${suAuthLogCode(status)}")
            append(" primary={${primary?.diagnosticSummary ?: "sdkReceipt=false"}}")
            append(" inverse={${inverse?.diagnosticSummary ?: "sdkReceipt=false"}}")
            append(" refresh={${refresh?.diagnosticSummary ?: "sdkReceipt=false"}}")
        }

    fun withStatus(status: String): UltraAuthorizationRestoreResult =
        UltraAuthorizationRestoreResult(status, primary, inverse, refresh)

    override fun toString(): String = diagnosticSummary

    companion object {
        fun local(status: String = "OK"): UltraAuthorizationRestoreResult = UltraAuthorizationRestoreResult(status)
        fun primary(attempt: UltraAuthorizationAttempt, status: String = attempt.error ?: "OK"): UltraAuthorizationRestoreResult =
            UltraAuthorizationRestoreResult(if (status == "OK") attempt.error ?: status else status, primary = attempt)
        fun refresh(attempt: UltraAuthorizationAttempt): UltraAuthorizationRestoreResult =
            UltraAuthorizationRestoreResult(attempt.error ?: "OK", refresh = attempt)
        fun identityChanged(primary: UltraAuthorizationAttempt?, inverse: UltraAuthorizationAttempt): UltraAuthorizationRestoreResult =
            UltraAuthorizationRestoreResult("MANAGER_IDENTITY_CHANGED" + (inverse.error?.let { ":$it" } ?: ""), primary, inverse)
    }
}

/** A live root service shares successful UID restoration; failed or changed scopes retry. */
internal class UltraBootAuthorizationRestore(private val pause: (Long) -> Unit = Thread::sleep) {
    private var restored: Pair<String, String>? = null

    @Synchronized
    fun invalidate() { restored = null }

    fun maintain(suspended: () -> Boolean, restore: () -> String,
                 onResult: (String) -> Unit = {}): String =
        maintainAttempt(suspended, { UltraAuthorizationRestoreResult.local(restore()) }, { onResult(it.status) })

    /** An existing lifecycle task decides when another SDK write is needed. */
    fun maintainAttempt(suspended: () -> Boolean, restore: () -> UltraAuthorizationRestoreResult,
                        onResult: (UltraAuthorizationRestoreResult) -> Unit = {}): String {
        var previous: String? = null
        while (true) {
            if (Thread.currentThread().isInterrupted) return "MAPLESU_SDK_INTERRUPTED"
            if (suspended()) return "SUSPENDED"
            val result = try {
                restore()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return "MAPLESU_SDK_INTERRUPTED"
            } catch (completed: UltraAuthorizationRestoreException) {
                completed.result
            } catch (_: Exception) {
                UltraAuthorizationRestoreResult.local("MANAGER_AUTH_RESTORE_EXCEPTION")
            }
            if (Thread.currentThread().isInterrupted) return "MAPLESU_SDK_INTERRUPTED"
            if (result.status == "SUSPENDED" || result.status == "MAPLESU_SDK_INTERRUPTED") return result.status
            val diagnostic = result.diagnosticSummary
            if (previous != diagnostic) {
                onResult(result)
                previous = diagnostic
            }
            if (result.status == "MAPLESU_SDK_DEADLINE_EXCEEDED") return result.status
            try {
                pause(5_000L)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return "MAPLESU_SDK_INTERRUPTED"
            }
        }
    }

    /** An explicit caller may wait for a pending installation identity. */
    fun ensureWhenIdentityAvailable(bootId: String?, ownerFingerprint: String,
                                    suspended: () -> Boolean, restore: () -> String): String {
        while (true) {
            if (Thread.currentThread().isInterrupted) return "MAPLESU_SDK_INTERRUPTED"
            if (suspended()) return "SUSPENDED"
            val result = ensure(bootId, ownerFingerprint) {
                if (suspended()) "SUSPENDED" else restore()
            }
            if (result != "MANAGER_IDENTITY_PENDING") return result
            try {
                pause(1_000L)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return "MAPLESU_SDK_INTERRUPTED"
            }
        }
    }

    fun ensure(bootId: String?, ownerFingerprint: String, restore: () -> String): String =
        ensureAttempt(bootId, ownerFingerprint) { UltraAuthorizationRestoreResult.local(restore()) }.status

    fun ensure(bootId: String?, ownerFingerprint: String, suspended: () -> Boolean,
               restore: () -> String): String =
        ensureAttempt(bootId, ownerFingerprint, suspended) { UltraAuthorizationRestoreResult.local(restore()) }.status

    fun ensureAttempt(bootId: String?, ownerFingerprint: String,
                      restore: () -> UltraAuthorizationRestoreResult): UltraAuthorizationRestoreResult =
        ensureAttempt(bootId, ownerFingerprint, { false }, restore)

    @Synchronized
    fun ensureAttempt(bootId: String?, ownerFingerprint: String, suspended: () -> Boolean,
                      restore: () -> UltraAuthorizationRestoreResult): UltraAuthorizationRestoreResult {
        val scope = bootId?.takeIf { it.isNotBlank() }?.let { it to ownerFingerprint }
        if (suspended()) {
            restored = null
            return UltraAuthorizationRestoreResult.local("SUSPENDED")
        }
        if (scope != null && scope == restored) return UltraAuthorizationRestoreResult.local()
        restored = null
        if (Thread.currentThread().isInterrupted) return UltraAuthorizationRestoreResult.local("MAPLESU_SDK_INTERRUPTED")
        var result = restore()
        for (delay in longArrayOf(250L, 750L)) {
            if (suspended()) return result.withStatus("SUSPENDED")
            if (Thread.currentThread().isInterrupted) return result.withStatus("MAPLESU_SDK_INTERRUPTED")
            // Only the same structured receipt can prove this attempt did not commit.
            if (!result.retryableBeforeCommit) break
            try {
                pause(delay)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return result.withStatus("MAPLESU_SDK_INTERRUPTED")
            }
            if (Thread.currentThread().isInterrupted) return result.withStatus("MAPLESU_SDK_INTERRUPTED")
            if (suspended()) return result.withStatus("SUSPENDED")
            result = restore()
        }
        if (suspended()) return result.withStatus("SUSPENDED")
        if (Thread.currentThread().isInterrupted) return result.withStatus("MAPLESU_SDK_INTERRUPTED")
        if (result.status == "OK") restored = scope
        return result
    }
}
