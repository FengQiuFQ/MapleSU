package dev.maplesu.manager.runtime.authorization

import android.content.Context
import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.HookRootExecutor
import dev.maplesu.manager.runtime.SuDelivery
import dev.maplesu.manager.runtime.SuPathWiring
import dev.maplesu.manager.runtime.SuPublication
import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.runtime.State
import dev.maplesu.manager.runtime.stateFor
import dev.maplesu.manager.runtime.ultra.UltraAuthorization
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import dev.maplesu.manager.runtime.ultra.UltraSdkSession
import dev.maplesu.manager.runtime.ultra.UltraSuChannel

/** App-private management API. Request adapters must capture the caller UID before consulting policy. */
internal object ManagerAuthorizations {
    /** A boot SDK is another transport for this same authority, including after restore. */
    fun usesManagerAuthority(context: Context): Boolean =
        dev.maplesu.manager.workmode.ModeRuntime.active != dev.maplesu.manager.workmode.WorkMode.KSU &&
            (HookRootExecutor.production(context).available() || UltraSdkSession.current(context) != null ||
                UltraEnvironmentProbe.currentSnapshot(context).managerOwnerIdentity != null)

    private fun usesSdkOnly(context: Context): Boolean =
        UltraEnvironmentProbe.usesUltraBackend(context) && !usesManagerAuthority(context)

    /** No policy or authorization file is cached in the application process. */
    fun policy(context: Context): RemotePolicy = RemotePolicy(context.applicationContext)

    class RemotePolicy internal constructor(private val context: Context) {
        /**
         * Policy reads and writes go through the one transaction, never through a cached
         * copy. Ultra keeps its existing SDK path: a one-shot root process restarts the
         * system on a Ultra kernel, and the SDK's `su_auth` list is the Ultra mirror.
         */
        val isEnabled: Boolean get() = if (usesSdkOnly(context)) true
        else SuperuserControl.snapshot(context)?.enabled ?: false

        fun setEnabled(enabled: Boolean) {
            check(!usesSdkOnly(context)) { "SU_GLOBAL_SWITCH_UNSUPPORTED" }
            SuperuserControl.setEnabled(context, enabled).requireApplied()
        }

        fun hasCurrentGrant(uid: Int): Boolean {
            if (usesSdkOnly(context)) {
                return UltraAuthorization.refresh(context) && UltraAuthorization.isGranted(uid)
            }
            // Still the one-shot root tool (`AuthorizationTool` -> `SuperuserOps.has`),
            // never the resident executor: that tool now answers with the same
            // ManagerSuperuserPolicy decision the endpoints use, including the journal's
            // tombstone and the current install identity.
            return DirectPolicy.hasGrantStrict(context, uid) == true
        }

        fun grant(uid: Int) {
            if (usesSdkOnly(context)) {
                val name = context.packageManager.getPackagesForUid(uid)?.sorted()?.firstOrNull()
                    ?: throw IllegalStateException(SuCodes.SU_CALLER_PACKAGE_UNAVAILABLE)
                val attempt = UltraAuthorization.setUidGrantedExplicit(context, uid, name, true)
                check(attempt.succeeded) { attempt.diagnosticSummary }
                return
            }
            SuperuserControl.grant(context, uid).requireApplied()
        }

        fun revoke(uid: Int) {
            if (usesSdkOnly(context)) {
                val name = context.packageManager.getPackagesForUid(uid)?.sorted()?.firstOrNull()
                    ?: throw IllegalStateException(SuCodes.SU_CALLER_PACKAGE_UNAVAILABLE)
                val attempt = UltraAuthorization.setUidGrantedExplicit(context, uid, name, false)
                SuperuserControl.completeSessionRevocation(context, uid,
                    SuperuserControl.Result(attempt.decisionCommitted, code = attempt.error,
                        pendingApply = attempt.pendingApply, detail = attempt.diagnosticSummary)).requireApplied()
                return
            }
            val result = SuperuserControl.revoke(context, uid)
            result.requireApplied()
        }

        fun currentGrantCount(): Int =
            if (usesSdkOnly(context)) UltraAuthorization.uidProfiles().values.count { it.allow }
            else SuperuserControl.snapshot(context)?.let { snapshot ->
                val identities = AndroidApplicationIdentities(context)
                snapshot.grants.keys.count { uid ->
                    val identity = runCatching { identities.read(uid) }.getOrNull()
                    ManagerSuperuserPolicy.decide(snapshot, uid, identity).allowed
                }
            } ?: 0
    }

    @JvmOverloads
    fun profile(context: Context, name: String?, uid: Int, forceRefresh: Boolean = false): Natives.Profile? {
        // Ultra authorizes installed package names, including Shell and shared system UIDs.
        // The legacy signing/ordinary-app identity rule belongs only to DirectPolicy.
        // Ultra: the allowlist is the SDK's su_auth list, cached by [UltraAuthorization.refresh].
        // No root process is started to answer "is this package granted".
        if (usesSdkOnly(context)) {
            if (name == null || !matchesUltraPackage(context, name, uid)) return null
            // First read in this process (e.g. deep link straight into an app profile): load
            // the allowlist once. Callers are on an IO thread and subsequent reads hit the cache.
            if ((forceRefresh || !UltraAuthorization.isLoaded()) && !UltraAuthorization.refresh(context)) return null
            return Natives.Profile(name, currentUid = uid,
                allowSu = UltraAuthorization.isGranted(uid))
        }
        val identity = AndroidApplicationIdentities(context).read(uid) ?: return null
        if (name !in identity.members.keys) return null
        // Short-lived root tool: reading one grant must not start the resident endpoint.
        val snapshot = SuperuserControl.snapshot(context) ?: return null
        return ManagerSuProfiles.read(snapshot, requireNotNull(name), identity)
    }

    /** One live SDK result, bound to its caller scope and observation deadline. */
    internal class CurrentDeliveryRead(
        val uidProfiles: UltraRuntimeClient.SuUidProfilesSnapshot?,
        val entryConfirmed: Boolean? = null,
        val entryCode: String? = null,
        val entryDetail: String = "",
        private val current: () -> Boolean,
    ) {
        fun isCurrent(): Boolean = current()

        fun confirms(uid: Int, packageName: String, allow: Boolean): Boolean = confirms(uid, setOf(packageName), allow)

        fun confirms(uid: Int, members: Set<String>, allow: Boolean): Boolean =
            isCurrent() && uidProfiles?.ok == true && uidProfiles.profiles.singleOrNull { it.uid == uid }
                ?.let { it.packageName in members && it.allow == allow } == true

        val code: String? get() = when {
            uidProfiles?.ok == false -> uidProfiles.receipt.sdkError
            !isCurrent() -> "SU_AUTH_SCOPE_CHANGED"
            uidProfiles == null -> "PROFILE_CURRENT_DELIVERY_UNCONFIRMED"
            else -> null
        }

        val detail: String get() = listOfNotNull(uidProfiles?.receipt?.raw,
            "SU_AUTH_SCOPE_CHANGED".takeUnless { isCurrent() }).joinToString("\n")
    }

    /** Read once for a whole page; a cached authorization list is never an input. */
    internal fun currentDeliveryRead(context: Context): CurrentDeliveryRead =
        PageReadDeadline.onWorker(PageReadDeadline.limitNanos(5_000L)) {
            val scope = UltraAuthorization.captureScope(context)
                ?: return@onWorker CurrentDeliveryRead(null, current = { false })
            if (!scope.current()) return@onWorker CurrentDeliveryRead(null, current = { false })
            currentDeliveryRead(scope, scope.client.suUidProfiles())
        }

    /** Reuse the caller's same live UID read, without issuing a second SDK request. */
    internal fun currentDeliveryRead(scope: UltraAuthorization.Scope,
                                     read: UltraRuntimeClient.SuUidProfilesSnapshot): CurrentDeliveryRead {
        val deadline = PageReadDeadline.limitNanos(5_000L)
        val current = { scope.current() && deadline - System.nanoTime() > 0L }
        if (!read.ok || !current()) return CurrentDeliveryRead(read, current = current)
        val channel = UltraSuChannel()
        val entry = PageReadDeadline.onWorker(deadline) { channel.rootUid() }
        return CurrentDeliveryRead(read, entryConfirmed = entry == 0 && current(),
            entryCode = channel.lastFailure ?: "SU_AUTH_SCOPE_CHANGED".takeUnless { current() },
            entryDetail = channel.lastFailure.orEmpty(), current = current)
    }

    /** One fresh read keeps the stored decision separate from its mirror watermark. */
    internal fun profileDetailed(context: Context, name: String?, uid: Int): Natives.ProfileReadResult =
        PageReadDeadline.onWorker(PageReadDeadline.limitNanos(5_000L)) { profileDetailedCurrent(context, name, uid) }

    private fun profileDetailedCurrent(context: Context, name: String?, uid: Int): Natives.ProfileReadResult {
        val members = context.packageManager.getPackagesForUid(uid)?.toSet().orEmpty()
        if (name.isNullOrBlank() || uid < 0 || name !in members)
            return Natives.ProfileReadResult(null, code = "PROFILE_IDENTITY_MISMATCH")
        if (usesSdkOnly(context)) {
            return sdkProfileDetailed(name, uid, members, currentDeliveryRead(context))
        }
        val identity = AndroidApplicationIdentities(context).read(uid)
            ?: return Natives.ProfileReadResult(null, code = "PROFILE_IDENTITY_UNAVAILABLE")
        if (name !in identity.members)
            return Natives.ProfileReadResult(null, code = "PROFILE_IDENTITY_MISMATCH")
        val read = SuperuserControl.snapshotDetailed(context)
        val snapshot = read.snapshot ?: return Natives.ProfileReadResult(null, code = read.code, detail = read.detail)
        if (UltraSdkSession.current(context) != null || UltraEnvironmentProbe.usesUltraBackend(context))
            return profileDetailed(snapshot, name, identity, currentDeliveryRead(context))
        val profile = ManagerSuProfiles.read(snapshot, name, identity)
        return profileDetailed(snapshot, name, identity,
            currentState = stateFor(context, name, profile.allowSu))
    }

    internal fun sdkProfileDetailed(name: String, uid: Int, members: Set<String>,
                                    current: CurrentDeliveryRead): Natives.ProfileReadResult {
        if (name !in members) return Natives.ProfileReadResult(null, code = "PROFILE_IDENTITY_MISMATCH")
        val read = current.uidProfiles
        if (read?.ok != true || !current.isCurrent())
            return Natives.ProfileReadResult(null, code = current.code, detail = current.detail)
        val row = read.profiles.singleOrNull { it.uid == uid }
        if (row == null) {
            // No stored decision keeps the original editable default; absence is no delivery proof.
            return Natives.ProfileReadResult(Natives.Profile(name, currentUid = uid))
        }
        if (row.packageName !in members)
            return Natives.ProfileReadResult(null, deliveryConfirmed = false,
                code = "PROFILE_CURRENT_DELIVERY_MISMATCH", detail = current.detail)
        val profile = Natives.Profile(name, currentUid = uid, allowSu = row.allow)
        val confirmed = current.confirms(uid, members, row.allow)
        val code = current.code
        val detail = listOf(current.detail, current.entryDetail).filter { it.isNotEmpty() }.joinToString("\n")
        val stillCurrent = current.isCurrent()
        return Natives.ProfileReadResult(profile, deliveryConfirmed = confirmed && stillCurrent,
            code = code ?: if (!stillCurrent) "SU_AUTH_SCOPE_CHANGED" else current.entryCode,
            detail = detail, entryConfirmed = current.entryConfirmed.takeIf { stillCurrent })
    }

    internal fun profileDetailed(snapshot: AuthorizationSnapshot, name: String,
                                 identity: ApplicationIdentity, current: CurrentDeliveryRead? = null,
                                 currentState: State? = null): Natives.ProfileReadResult {
        if (name !in identity.members)
            return Natives.ProfileReadResult(null, code = "PROFILE_IDENTITY_MISMATCH")
        val profile = ManagerSuProfiles.read(snapshot, name, identity)
        val latest = snapshot.applied.asReversed().maxByOrNull { it.rev }
        val applied = !snapshot.pendingApply() && latest?.ok == true && latest.rev >= snapshot.rev
        val runtimeConfirmed = current?.confirms(identity.uid, identity.members.keys, profile.allowSu) == true ||
            currentState == State.WIRED || currentState == State.DELIVERED
        val currentCode = current?.code
        val currentDetail = current?.detail
        val stillCurrent = current?.isCurrent() != false
        val confirmed = applied && runtimeConfirmed && stillCurrent
        val code = currentCode ?: when {
            !stillCurrent -> "SU_AUTH_SCOPE_CHANGED"
            !applied -> SuCodes.SU_AUTH_APPLY_PENDING
            !runtimeConfirmed -> "PROFILE_CURRENT_DELIVERY_UNCONFIRMED"
            else -> current?.entryCode
        }
        return Natives.ProfileReadResult(profile, deliveryConfirmed = confirmed,
            code = code,
            detail = listOfNotNull(
                currentDetail?.takeIf { it.isNotEmpty() && code != null },
                current?.entryDetail?.takeIf { it.isNotEmpty() },
                "currentRuntimeProof=absent".takeIf { current == null && currentState == null },
                "decisionRev=${snapshot.rev}",
                latest?.let { "backend=${it.backend} appliedRev=${it.rev} appliedOk=${it.ok}" }
                    ?: "appliedReceipt=absent",
                latest?.detail?.takeIf { !applied && it.isNotEmpty() },
            ).takeUnless { code == null }?.joinToString("; ").orEmpty(),
            entryConfirmed = current?.entryConfirmed?.takeIf { current.isCurrent() }
                ?: (currentState == State.WIRED).takeIf { currentState != null })
    }

    fun saveProfile(context: Context, profile: Natives.Profile): Boolean =
        saveProfileDetailed(context, profile).succeeded

    internal fun saveProfileDetailed(context: Context, profile: Natives.Profile): Natives.ProfileWriteResult {
        val ultra = usesSdkOnly(context)
        if (ultra) {
            if (!matchesUltraPackage(context, profile.name, profile.currentUid)) return Natives.ProfileWriteResult(false, code = "PROFILE_IDENTITY_MISMATCH")
        } else {
            val identity = AndroidApplicationIdentities(context).read(profile.currentUid)
                ?: return Natives.ProfileWriteResult(false, code = "PROFILE_IDENTITY_UNAVAILABLE")
            if (profile.name !in identity.members.keys) return Natives.ProfileWriteResult(false, code = "PROFILE_IDENTITY_MISMATCH")
        }
        val stored = try { ManagerSuProfiles.fromNative(profile) }
        catch (error: IllegalArgumentException) {
            return Natives.ProfileWriteResult(false, code = "PROFILE_INVALID", detail = error.message.orEmpty())
        }
        // The legacy SDK allowlist has no complete-profile transport or persistence.
        if (ultra && stored != SuProfile.legacy(stored.name, stored.currentUid, stored.allowSu))
            return Natives.ProfileWriteResult(false, code = "PROFILE_FIELDS_UNSUPPORTED")
        // Ultra: one SDK call is the whole write. There is no image to deliver, no PATH to
        // implant and no publication to refresh - the kernel consults the su_auth list on the
        // next request, so the grant is effective as soon as addSuAuth returns. Skipping the
        // delivery chain is not an optimisation: every step of it starts libmaplesu_runtime,
        // which restarts the system on a Ultra kernel.
        if (ultra) {
            val attempt = UltraAuthorization.setUidGrantedExplicit(context, profile.currentUid, profile.name, profile.allowSu)
            val decision = SuperuserControl.Result(attempt.decisionCommitted, code = attempt.error,
                pendingApply = attempt.pendingApply, detail = attempt.diagnosticSummary)
            val result = if (profile.allowSu) decision else
                SuperuserControl.completeSessionRevocation(context, profile.currentUid, decision)
            return Natives.ProfileWriteResult(result.ok, result.pendingApply,
                attempt.commitUnknown, result.code, result.detail)
        }
        // Writes go through the one transaction (journal -> bin -> mirror -> applied), so
        // the UI, the resident restricted Binder and the Ultra endpoint all see the same
        // revision. A missing root transport answers SU_TRANSPORT_UNAVAILABLE and the row
        // stays unsaved; nothing is written locally to look successful.
        val preparation = if (UltraSdkSession.current(context) != null ||
            HookRootExecutor.production(context).available()) UltraAuthorization.prepareExplicitMutation(context) else null
        if (preparation?.blockedCode != null) return Natives.ProfileWriteResult(false,
            code = preparation.blockedCode, detail = preparation.diagnosticSummary)
        val written = SuperuserControl.saveProfile(context, stored)
        val result = Natives.ProfileWriteResult(written.ok, written.pendingApply,
            commitUnknown = !written.ok, code = written.code,
            detail = listOfNotNull(preparation?.diagnosticSummary, written.detail)
                .filter { it.isNotEmpty() }.joinToString("; "))
        if (!result.succeeded) return result
        // The SDK is the exec-su transport on a boot session; never launch Direct delivery.
        if (UltraSdkSession.current(context) != null) return result
        if (UltraEnvironmentProbe.currentSnapshot(context).managerOwnerIdentity != null) return result
        // SuperuserControl already queued Hook publication after the decision.
        if (HookRootExecutor.production(context).available()) return result
        // Plan A: the authorization change carries the delivery with it, but the delivery
        // must never run on the caller's thread - it starts root processes and the caller
        // may well be the UI, which would ANR. The authorization result is returned
        // immediately; the post is delivered on a serial worker and never undoes it.
        val packageName = profile.name
        val allow = profile.allowSu
        post.execute {
            runCatching {
                if (allow) {
                    val delivered = SuDelivery.deliver(context, packageName)
                    android.util.Log.i("MapleSU",
                        "SU_AUTH_DELIVER package=$packageName ok=${delivered.ok} detail=${delivered.detail}")
                    if (delivered.ok) {
                        // A closed application has no process for the PATH to live in. Ask for
                        // one for two seconds so the grant completes now instead of leaving
                        // the application "delivered but not wired" until it is opened.
                        SuPathWiring.ensureRunning(context, packageName)
                        val wired = SuPathWiring.wire(context, packageName)
                        android.util.Log.i("MapleSU",
                            "SU_AUTH_WIRE package=$packageName ok=${wired.ok} detail=${wired.detail}")
                        // An application with no JNI library has nothing to implant, so the
                        // grant would look complete while a bare `su` still failed. PATH
                        // injection is the mechanism for exactly that case.
                        if (!wired.ok && (wired.reason == SuPathWiring.Reason.NO_CANDIDATES ||
                                wired.reason == SuPathWiring.Reason.NO_PATCHABLE ||
                                SuPathWiring.hasNoNativeLibraries(context, packageName))) {
                            val injected = SuPathWiring.injectPath(context, packageName)
                            android.util.Log.i("MapleSU",
                                "SU_AUTH_INJECT package=$packageName ok=${injected.ok} " +
                                    "detail=${injected.detail}")
                        }
                    }
                } else {
                    val withdrawn = SuDelivery.withdraw(context, packageName)
                    android.util.Log.i("MapleSU",
                        "SU_AUTH_WITHDRAW package=$packageName ok=${withdrawn.ok} detail=${withdrawn.detail}")
                }
            }.onFailure {
                android.util.Log.w("MapleSU", "SU_AUTH_POST_FAILED package=$packageName ${it.javaClass.simpleName}")
            }
            // The shared client carries the uid list, so a grant or a revoke has to be
            // reflected there immediately: otherwise the new grant cannot use the shared
            // client until the next Manager start, and a revoked application keeps its
            // access for just as long.
            runCatching<Boolean> { SuPublication.publish(context) }
                .onFailure { android.util.Log.w("MapleSU", "SU_PUBLISH_FAILED ${it.javaClass.simpleName}") }
        }
        return result
    }

    private fun matchesUltraPackage(context: Context, name: String?, uid: Int): Boolean =
        !name.isNullOrBlank() && uid >= 0 && runCatching {
            context.packageManager.getPackagesForUid(uid)?.contains(name) == true
        }.getOrDefault(false)

    /** Serial worker so two authorizations cannot deliver/wire the same application at once. */
    private val post = java.util.concurrent.Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "maplesu-auth-post").apply { isDaemon = true }
    }
}
