package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.util.Log
import dev.maplesu.manager.workmode.ModeRuntime

object UltraAuthorization {
    private const val TAG = "MapleSUUltraAuth"

    private val state = UltraAuthorizationState(currentUserId = android.os.Process.myUid() / 100000)

    internal class Scope(val client: UltraRuntimeClient, val current: () -> Boolean,
                        val cacheCurrent: () -> Boolean)

    internal fun captureScope(context: Context): Scope? = capture(context, null) { true }

    internal fun captureScope(context: Context, session: UltraBootSdkSession,
                              expectedCurrent: () -> Boolean): Scope? = capture(context, session, expectedCurrent)

    internal fun captureClientScope(context: Context, client: UltraRuntimeClient,
                                    expectedCurrent: () -> Boolean): Scope? {
        val scope = capture(context, null, expectedCurrent) ?: return null
        return Scope(client.scoped(scope.current), scope.current, scope.cacheCurrent)
    }

    internal fun captureOwnerScope(context: Context, session: UltraRuntimeClient.ManagerOwnerIdentity,
                                   expectedCurrent: () -> Boolean): Scope? {
        val observed = UltraEnvironmentProbe.currentSnapshot(context)
        if (observed.managerOwnerIdentity != session) return null
        val scope = capture(context, null) {
            expectedCurrent() && session.fullUid == android.os.Process.myUid() &&
            UltraEnvironmentProbe.currentSnapshot(context).let {
                it.managerOwnerIdentity == session
            }
        } ?: return null
        return Scope(scope.client, scope.current) { scope.cacheCurrent() && scope.current() }
    }

    private fun capture(context: Context, session: UltraBootSdkSession?,
                        expectedCurrent: () -> Boolean): Scope? = runCatching {
        if (!expectedCurrent()) return@runCatching null
        val app = context.applicationContext
        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        if (session != null && session.bootId != bootId) return@runCatching null
        val activation = ModeRuntime.activation
        val observation = UltraEnvironmentProbe.currentSnapshot(app)
        val observedOwner = observation.managerOwnerIdentity
        val observedLegacy = observation.legacyCredentialFingerprint
        val sessionCurrent = UltraSdkSession.captureOwnerMarker(app)
        val installationCurrent = UltraSdkCredentials.captureOwnerMarker(app)
        val cacheCurrent = {
            ModeRuntime.activation === activation && sessionCurrent() && installationCurrent() &&
                UltraEnvironmentProbe.currentSnapshot(app).let {
                    it.managerOwnerIdentity == observedOwner && it.legacyCredentialFingerprint == observedLegacy
                }
        }
        val current = {
            expectedCurrent() && !Thread.currentThread().isInterrupted && cacheCurrent() && bootId != null &&
                UltraEnvironmentAutoSetup.currentBootId() == bootId
        }
        val owner = when {
            session != null -> UltraSdkSession.client(app, session)
            observedOwner != null -> UltraRuntimeClient()
            else -> UltraSdkCredentials.client(app, current)
        }
        val client = owner.scoped(current)
        if (current()) Scope(client, current, cacheCurrent) else null
    }.getOrNull()

    /** Select the SDK owner, never the legacy root transport, even during a transient probe failure. */
    fun isActive(context: Context): Boolean = UltraEnvironmentProbe.usesUltraBackend(context)

    fun isLoaded(): Boolean = state.snapshot.loaded

    fun grantedPackages(): Set<String> = state.snapshot.let { if (it.loaded) it.packages else emptySet() }

    fun isGranted(packageName: String): Boolean = state.snapshot.let { it.loaded && packageName in it.packages }

    fun isGranted(uid: Int): Boolean = state.snapshot.let { it.uidProfilesLoaded && it.profiles[uid]?.allow == true }

    fun uidProfiles(): Map<Int, SuUidProfile> = state.snapshot.let { if (it.uidProfilesLoaded) it.profiles else emptyMap() }

    fun isDeliveryIncomplete(): Boolean = state.snapshot.deliveryIncomplete

    internal data class RefreshResult(val scope: Scope,
                                      val snapshot: UltraRuntimeClient.SuUidProfilesSnapshot?,
                                      val error: String?) {
        val succeeded: Boolean get() = error == null
        val readReceipt: NativeReceipt? get() = snapshot?.receipt
        val diagnosticSummary: String get() = "error=${error?.let(::suAuthLogCode) ?: "OK"}" +
            (readReceipt?.let { " readReceipt=[${it.authorizationDiagnosticSummary()}]" } ?: "")
    }

    /** Re-reads the allowlist. Blocking (JNI); call from a background thread. */
    fun refresh(context: Context): Boolean = refreshDetailed(context)?.succeeded == true

    internal fun refresh(scope: Scope): Boolean = refreshDetailed(scope).succeeded

    internal fun refreshDetailed(context: Context): RefreshResult? = captureScope(context)?.let(::refreshDetailed)

    /** Carries this single live read to page consumers; State's cache is not delivery proof. */
    internal fun refreshDetailed(scope: Scope): RefreshResult {
        var snapshot: UltraRuntimeClient.SuUidProfilesSnapshot? = null
        val read = state.refreshDetailed(UltraSelfWhitelist.clientPort(scope.client) { snapshot = it },
            scope.current, scope.cacheCurrent)
        val current = scope.current()
        val result = RefreshResult(scope, snapshot.takeIf { current },
            if (current) read.error else "SU_AUTH_SCOPE_CHANGED")
        if (!result.succeeded) Log.w(TAG, "get_su_auth_list failed ${result.diagnosticSummary}")
        else Log.i(TAG, "su_auth list loaded count=${state.snapshot.packages.size} ${result.diagnosticSummary}")
        return result
    }

    /** Grants one package. Blocking (JNI); call from a background thread. */
    fun grant(context: Context, packageName: String): Boolean = setGrantedExplicit(context, packageName, true).succeeded

    /** Revokes one package. Blocking (JNI); call from a background thread. */
    fun revoke(context: Context, packageName: String): Boolean = setGrantedExplicit(context, packageName, false).succeeded

    /** Explicit requests prepare once outside the authority/mirror transaction. */
    internal fun setGrantedExplicit(context: Context, packageName: String, allow: Boolean): UltraAuthorizationAttempt {
        if (packageName.isBlank()) return UltraAuthorizationAttempt.local("EMPTY_PACKAGE")
        val scope = captureScope(context) ?: return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
        val preparation = prepareExplicitMutation(context, scope)
        val attempt = preparation.blockedCode?.let { UltraAuthorizationAttempt.local(it) }
            ?: setGranted(context, packageName, allow, scope)
        return attempt.withPreparation(preparation).also {
            Log.i(TAG, "su_auth explicit ${it.diagnosticSummary}")
        }
    }

    internal fun setUidGrantedExplicit(context: Context, uid: Int, packageName: String, allow: Boolean): UltraAuthorizationAttempt {
        if (!matchesUid(context, uid, packageName)) return UltraAuthorizationAttempt.local("PROFILE_IDENTITY_MISMATCH")
        val scope = captureScope(context) ?: return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
        val preparation = prepareExplicitMutation(context, scope)
        val attempt = preparation.blockedCode?.let { UltraAuthorizationAttempt.local(it) }
            ?: setUidGranted(context, uid, packageName, allow, scope)
        return attempt.withPreparation(preparation)
    }

    internal fun setUidGranted(context: Context, uid: Int, packageName: String, allow: Boolean,
                               scope: Scope? = null, durableDecisionCommitted: Boolean = false,
                               identityRead: dev.maplesu.manager.runtime.authorization.SuperuserControl.CurrentIdentityRead? = null,
                               authorityRevision: Long? = null): UltraAuthorizationAttempt {
        mutationBlockedReason(context)?.let { return UltraAuthorizationAttempt.local(it) }
        val owner = scope ?: captureScope(context) ?: return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
        if (identityRead != null) {
            if (authorityRevision == null || !identityRead.matches(owner, authorityRevision, uid, packageName, allow))
                return UltraAuthorizationAttempt.local("PROFILE_IDENTITY_MISMATCH")
        } else if (allow && !matchesUid(context, uid, packageName)) {
            return UltraAuthorizationAttempt.local("PROFILE_IDENTITY_MISMATCH")
        }
        val expected = UltraEnvironmentProbe.currentSnapshot(context)
        return state.setUidGranted(UltraSelfWhitelist.clientPort(owner.client), uid, packageName, allow,
            owner.current, owner.cacheCurrent, durableDecisionCommitted).also { attempt ->
            if (!attempt.succeeded && owner.current() && uid == context.applicationInfo.uid &&
                packageName == context.packageName) {
                UltraEnvironmentProbe.publishManagerSuDiagnostic(context, expected, attempt.diagnosticSummary)
            }
            Log.i(TAG, "su_auth uid=$uid allow=$allow ${attempt.diagnosticSummary}")
        }
    }

    private fun matchesUid(context: Context, uid: Int, packageName: String): Boolean = uid >= 0 &&
        packageName.isNotBlank() && runCatching {
            context.packageManager.getPackagesForUid(uid)?.contains(packageName) == true
        }.getOrDefault(false)

    /** Mirrors and daemons use only the live SDK transaction, never environment installation. */
    internal fun setGranted(context: Context, packageName: String, allow: Boolean): UltraAuthorizationAttempt {
        if (packageName.isBlank()) return UltraAuthorizationAttempt.local("EMPTY_PACKAGE")
        val scope = captureScope(context) ?: return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
        return setGranted(context, packageName, allow, scope)
    }

    internal fun setGranted(context: Context, packageName: String, allow: Boolean,
                            scope: Scope): UltraAuthorizationAttempt {
        mutationBlockedReason(context)?.let { return UltraAuthorizationAttempt.local(it) }
        val uid = runCatching { context.packageManager.getApplicationInfo(packageName, 0).uid }.getOrNull()
            ?: return UltraAuthorizationAttempt.local("PROFILE_IDENTITY_UNAVAILABLE")
        return setGranted(context, packageName, allow, scope, uid)
    }

    internal fun setGranted(context: Context, packageName: String, allow: Boolean,
                            scope: Scope, uid: Int): UltraAuthorizationAttempt {
        val expected = UltraEnvironmentProbe.currentSnapshot(context)
        val attempt = state.setUidGranted(UltraSelfWhitelist.clientPort(scope.client), uid, packageName, allow,
            scope.current, scope.cacheCurrent)
        if (!attempt.succeeded) {
            if (scope.current() && uid == context.applicationInfo.uid && packageName == context.packageName) {
                UltraEnvironmentProbe.publishManagerSuDiagnostic(context, expected, attempt.diagnosticSummary)
            }
            Log.w(TAG, "su_auth mutation failed package=$packageName allow=$allow " +
                "error=${suAuthLogCode(requireNotNull(attempt.error))} ${attempt.diagnosticSummary}")
            return attempt
        }
        Log.i(TAG, "su_auth ${if (allow) "granted" else "revoked"} package=$packageName " +
            "count=${state.snapshot.packages.size} listReadback=true ${attempt.diagnosticSummary}")
        return attempt
    }

    /** Every package sharing [uid] that is on the allowlist (PackageManager only, no root). */
    fun grantedPackagesForUid(context: Context, uid: Int): List<String> = runCatching {
        context.packageManager.getPackagesForUid(uid)?.filter { isGranted(uid) }.orEmpty()
    }.getOrDefault(emptyList())

    /** Missing userspace still gets its existing bounded setup; helper state never grants SU. */
    internal fun prepareExplicitMutation(context: Context): UltraAuthorizationAttempt.Preparation {
        // The existing Hook authority may establish its first SDK session here.
        if (dev.maplesu.manager.runtime.HookRootExecutor.production(context).available() &&
            UltraSdkSession.current(context) == null) return prepareExplicitMutation(context, null)
        val scope = captureScope(context) ?: return UltraAuthorizationAttempt.Preparation(
            false, false, "BLOCKED", "SU_AUTH_SCOPE_CHANGED")
        return prepareExplicitMutation(context, scope)
    }

    private fun prepareExplicitMutation(context: Context, scope: Scope?): UltraAuthorizationAttempt.Preparation {
        val app = context.applicationContext
        val current = scope?.current ?: { true }
        if (!current()) return UltraAuthorizationAttempt.Preparation(
            false, false, "BLOCKED", "SU_AUTH_SCOPE_CHANGED")
        controlBlockedReason(app)?.let {
            return UltraAuthorizationAttempt.Preparation(false, false, "BLOCKED", it)
        }
        var setupInvoked = false
        return try {
            val observed = UltraEnvironmentProbe.refresh(app, force = false)
            (mutationBlockedReason(app) ?: "SU_AUTH_SCOPE_CHANGED".takeUnless { current() })?.let {
                return UltraAuthorizationAttempt.Preparation(false, false, "BLOCKED", it)
            }
            val preparation = if (observed == UltraEnvironmentProbe.State.Unknown ||
                observed == UltraEnvironmentProbe.State.NotInstalled) {
                // The SDK validates existing copies/control; setup owns creating them.
                // Its reconciliation calls only setGranted(), so this never recurses.
                setupInvoked = true
                val result = UltraEnvironmentAutoSetup.ensure(app, current)
                UltraAuthorizationAttempt.Preparation(result.attempted, result.installed, result.reason)
            } else UltraAuthorizationAttempt.Preparation(false, false, "STATE_$observed")
            preparation.copy(blockedCode = mutationBlockedReason(app) ?:
                "SU_AUTH_SCOPE_CHANGED".takeUnless { current() })
        } catch (error: Exception) {
            if (error is InterruptedException) Thread.currentThread().interrupt()
            UltraAuthorizationAttempt.Preparation(if (setupInvoked) null else false,
                if (setupInvoked) null else false,
                "PREPARATION_FAILED:${error.javaClass.simpleName}",
                blockedCode = if (Thread.currentThread().isInterrupted) "SU_AUTH_CANCELLED" else null)
        }
    }

    private fun mutationBlockedReason(context: Context): String? =
        controlBlockedReason(context) ?: "SU_AUTH_ENVIRONMENT_FAULT".takeIf {
            UltraEnvironmentProbe.isSafeMode(context)
        }

    private fun controlBlockedReason(context: Context): String? = when {
        Thread.currentThread().isInterrupted -> "SU_AUTH_CANCELLED"
        else -> UltraEnvironmentAutoSetup.blockedReason(context)?.let { "SU_AUTH_BLOCKED:$it" }
    }

}
