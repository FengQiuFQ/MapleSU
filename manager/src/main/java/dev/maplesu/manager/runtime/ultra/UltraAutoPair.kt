package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.os.Looper
import java.util.concurrent.CancellationException

/** Reconciles actual SDK and standard-SU readiness; it stores no pairing secret. */
object UltraAutoPair {
    data class Result(val paired: Boolean, val state: UltraEnvironmentProbe.State, val reason: String,
                      val detail: String? = null)

    fun ensure(context: Context, maintenance: Boolean = true): Result {
        check(Looper.myLooper() != Looper.getMainLooper()) { "ULTRA_READINESS_BACKGROUND_THREAD_REQUIRED" }
        val app = context.applicationContext
        if (UltraIdentityRecovery.blocked(app)) return Result(false, UltraEnvironmentProbe.State.Unknown, "RECOVERY_SUSPENDED")
        UltraEnvironmentProbe.refresh(app, force = false)
        val observation = UltraEnvironmentProbe.currentSnapshot(app)
        val owner = observation.managerOwnerIdentity
        if (owner == null && observation.legacyCredentialFingerprint == null)
            return Result(false, observation.state, "INSTALL_IDENTITY_PENDING")
        rootFailure(observation)?.let { return it }
        val current = UltraSdkCredentials.captureOwnerMarker(app)
        val scope = (if (owner != null) UltraAuthorization.captureOwnerScope(app, owner, current)
            else UltraAuthorization.captureScope(app)?.takeIf {
                it.client.legacyCredentialFingerprint == observation.legacyCredentialFingerprint
            }) ?: return Result(false, observation.state, "SDK_IDENTITY_SCOPE_CHANGED")
        val failures = mutableListOf<String>()
        return complete(observation, scope.current, verifyManagerSu = {
            val su = UltraSuChannel(timeoutMillis = 700L)
            UltraSelfWhitelist.verifyExec(current = scope.current, probe = {
                (su.rootUid() == 0).also { verified ->
                    if (!verified) su.lastFailure?.let(failures::add)
                }
            },
                rootVerified = { UltraEnvironmentProbe.hasCurrentRootProof(app) },
                refresh = {
                    val result = if (owner != null) UltraSelfWhitelist.ensureOwner(app, owner, scope.current)
                        else UltraSelfWhitelist.ensureCurrentAuthority(app, scope.client, scope.current)
                    if (!result.succeeded) {
                        result.failure?.let(failures::add)
                        result.detail?.let(failures::add)
                        result.receipt?.authorizationDiagnosticSummary()?.let(failures::add)
                    }
                    result.succeeded
                })
        }, maintain = { if (maintenance) UltraPairingMaintenance.request(app) },
            failureDetail = { failures.distinct().joinToString("\n").takeIf(String::isNotBlank) })
            .also { result ->
                UltraEnvironmentProbe.publishManagerSuDiagnostic(app, observation,
                    if (result.paired) null else listOfNotNull(result.reason, result.detail).joinToString("\n"))
            }
    }

    internal fun complete(observation: UltraEnvironmentProbe.Snapshot, current: () -> Boolean,
                          verifyManagerSu: () -> Boolean, maintain: () -> Unit,
                          failureDetail: () -> String? = { null }): Result {
        rootFailure(observation)?.let { return it }
        if (!current()) return Result(false, UltraEnvironmentProbe.State.Unknown, "SDK_IDENTITY_SCOPE_CHANGED")
        var exceptionDetail: String? = null
        val verified = try {
            !Thread.currentThread().isInterrupted && verifyManagerSu()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            exceptionDetail = "MANAGER_SU_INTERRUPTED"
            false
        } catch (error: Exception) {
            val errno = Regex("(?:error|errno)\\s*[=:]\\s*([0-9]{1,10})").find(error.message.orEmpty())?.groupValues?.get(1)
            exceptionDetail = "MANAGER_SU_EXCEPTION:type=${error.javaClass.simpleName}" +
                errno?.let { ";errno=$it" }.orEmpty()
            false
        }
        if (!current()) return Result(false, UltraEnvironmentProbe.State.Unknown, "SDK_IDENTITY_SCOPE_CHANGED")
        if (verified) maintain()
        val detail = if (verified) null else listOfNotNull(failureDetail(), exceptionDetail)
            .distinct().joinToString("\n").takeIf(String::isNotBlank)?.let(UltraSdkLogging::redact)
        return if (current()) Result(verified, observation.state, if (verified) "RUNNING" else "MANAGER_SU_UNVERIFIED", detail)
            else Result(false, UltraEnvironmentProbe.State.Unknown, "SDK_IDENTITY_SCOPE_CHANGED")
    }

    private fun rootFailure(observation: UltraEnvironmentProbe.Snapshot): Result? {
        if (observation.rootAvailable) return null
        val detail = observation.rootProbeDetail?.takeIf(String::isNotBlank)?.let { UltraSdkLogging.redact(it) }
        return Result(false, observation.state, "SDK_ROOT_UNVERIFIED" + detail?.let { ":$it" }.orEmpty())
    }
}
