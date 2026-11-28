// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

/** Serializes read/write/readback, including Manager self-whitelist refreshes. */
internal val suAuthTransactionLock = Any()

/** A full Android UID has one decision, including all packages sharing that UID. */
data class SuUidProfile(val uid: Int, val allow: Boolean, val packageName: String)

/** SDK decisions and native delivery proof; actual command execution is accepted separately. */
internal class UltraAuthorizationState(
    private val currentUserId: Int = 0,
    private val publish: (Int) -> Unit = {},
) {
    data class Snapshot(val packages: Set<String> = emptySet(), val loaded: Boolean = false,
                        val deliveryIncomplete: Boolean = false,
                        val profiles: Map<Int, SuUidProfile> = emptyMap(), val uidProfilesLoaded: Boolean = false)

    data class RefreshResult(val error: String?, val readReceipt: NativeReceipt? = null) {
        val succeeded: Boolean get() = error == null
        val diagnosticSummary: String get() = "error=${error?.let(::suAuthLogCode) ?: "OK"}" +
            (readReceipt?.let { " readReceipt=[${it.authorizationDiagnosticSummary()}]" } ?: "")
    }

    private data class Observation(val snapshot: Snapshot, val current: () -> Boolean)

    private val unavailable = Snapshot()
    @Volatile private var observation = Observation(unavailable) { true }

    val snapshot: Snapshot
        get() = observation.let { if (it.current()) it.snapshot else unavailable }

    fun refresh(port: SuAuthPort, current: () -> Boolean = { true },
                cacheCurrent: () -> Boolean = current): String? = refreshDetailed(port, current, cacheCurrent).error

    fun refreshDetailed(port: SuAuthPort, current: () -> Boolean = { true },
                        cacheCurrent: () -> Boolean = current): RefreshResult = synchronized(suAuthTransactionLock) {
        if (!current()) return RefreshResult("SU_AUTH_SCOPE_CHANGED")
        if (port.supportsUidProfiles) {
            val profiles = port.uidProfiles()
            val receipt = port.uidProfileReadReceipt()
            if (!current()) return RefreshResult("SU_AUTH_SCOPE_CHANGED")
            if (profiles == null) return RefreshResult(port.uidProfileReadError() ?: "READ_FAILED", receipt)
            // A list read verifies the stored decision, not native su delivery.
            updateProfiles(profiles, cacheCurrent, snapshot.deliveryIncomplete)
            return RefreshResult(null, receipt)
        }
        val packages = port.snapshot()
        if (!current()) return RefreshResult("SU_AUTH_SCOPE_CHANGED")
        if (packages == null) return RefreshResult("READ_FAILED")
        update(packages.toSet(), cacheCurrent)
        return RefreshResult(null)
    }

    fun setGranted(port: SuAuthPort, packageName: String, allow: Boolean,
                   current: () -> Boolean = { true },
                   cacheCurrent: () -> Boolean = current): UltraAuthorizationAttempt = synchronized(suAuthTransactionLock) {
        if (packageName.isBlank()) return UltraAuthorizationAttempt.local("EMPTY_PACKAGE")
        if (!current()) return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
        val deliveryIncomplete = snapshot.deliveryIncomplete
        fun changed(attempt: UltraAuthorizationAttempt): UltraAuthorizationAttempt? =
            if (current()) null else attempt.withReadback(false).withFailure("SU_AUTH_SCOPE_CHANGED")
        if (!allow) {
            // Only a fresh SDK snapshot, never the cache or a read error, proves absence.
            val before = port.snapshot()?.toSet()
            if (!current()) return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
            if (before == null) return UltraAuthorizationAttempt.local("READ_FAILED")
            if (packageName !in before) {
                update(before, cacheCurrent)
                if (deliveryIncomplete) {
                    if (!current()) return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
                    val attempt = UltraAuthorizationAttempt.from(port.refreshUidMapping())
                    changed(attempt)?.let { return it }
                    if (!attempt.succeeded) return attempt
                    val after = port.snapshot()?.toSet()
                    changed(attempt)?.let { return it }
                    if (after == null) return attempt.withFailure("READBACK_FAILED")
                    if (packageName in after) {
                        update(after, cacheCurrent)
                        return attempt.withReadback(false).withFailure("READBACK_MISMATCH")
                    }
                    update(after, cacheCurrent, deliveryIncomplete = false)
                    return attempt.withReadback(true)
                }
                val unchanged = UltraAuthorizationAttempt.local().withReadback(true, noMutation = true)
                return changed(unchanged) ?: unchanged
            }
        }
        if (!current()) return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
        val attempt = UltraAuthorizationAttempt.from(if (allow) port.add(packageName) else port.remove(packageName))
        changed(attempt)?.let { return it }
        if (!attempt.succeeded) {
            if (attempt.error == SU_DELIVERY_INCOMPLETE) {
                observation = Observation(snapshot.copy(deliveryIncomplete = true), cacheCurrent)
                val readback = port.snapshot()
                changed(attempt)?.let { return it }
                readback?.let {
                    val packages = it.toSet()
                    update(packages, cacheCurrent)
                    return attempt.withReadback(packages.contains(packageName) == allow)
                }
            }
            return attempt
        }
        val packages = port.snapshot()?.toSet()
        changed(attempt)?.let { return it }
        if (packages == null) return attempt.withFailure("READBACK_FAILED")
        if (packages.contains(packageName) != allow) {
            update(packages, cacheCurrent)
            return attempt.withReadback(false).withFailure("READBACK_MISMATCH")
        }
        update(packages, cacheCurrent, deliveryIncomplete = false)
        return attempt.withReadback(true)
    }

    fun setUidGranted(port: SuAuthPort, uid: Int, packageName: String, allow: Boolean,
                      current: () -> Boolean = { true }, cacheCurrent: () -> Boolean = current,
                      durableDecisionCommitted: Boolean = false): UltraAuthorizationAttempt =
        synchronized(suAuthTransactionLock) {
            if (uid < 0 || (uid < 2000 && uid != 1000) || packageName.isBlank())
                return UltraAuthorizationAttempt.local("PROFILE_IDENTITY_INVALID")
            if (!current()) return UltraAuthorizationAttempt.local("SU_AUTH_SCOPE_CHANGED")
            var attempt = UltraAuthorizationAttempt.from(port.setUidProfile(uid, packageName, allow))
            if (!current()) return attempt.withReadback(false).withFailure("SU_AUTH_SCOPE_CHANGED")
            val result = attempt.receipt?.authorizationResult
            if (attempt.succeeded) {
                if (result?.deliveryConfirmed != true || result.operation != if (allow) 1L else 2L) {
                    attempt = attempt.withFailure("SU_UID_DELIVERY_UNCONFIRMED")
                } else if (result.commitState != 2L && !(durableDecisionCommitted && result.commitState == 0L)) {
                    attempt = attempt.withFailure("SU_UID_COMMIT_UNCONFIRMED")
                }
                // The mirror caller knows the durable decision. Keep the SDK's Unknown
                // commit fact intact; it describes only this runtime synchronization.
            }
            val after = port.uidProfiles()
            val readReceipt = port.uidProfileReadReceipt()
            if (!current()) return attempt.withReadback(false).withFailure("SU_AUTH_SCOPE_CHANGED")
            attempt = attempt.withReadReceipt(readReceipt)
            if (after == null) {
                // The write may have committed. An older grant list is no longer a current observation.
                observation = Observation(snapshot.copy(loaded = false, uidProfilesLoaded = false,
                    deliveryIncomplete = true), cacheCurrent)
                return attempt.withFailure(port.uidProfileReadError() ?: "READBACK_FAILED")
            }
            val match = after.singleOrNull { it.uid == uid }?.allow == allow
            updateProfiles(after, cacheCurrent, !attempt.succeeded || !match)
            attempt = attempt.withReadback(match)
            if (!match) attempt.withFailure("READBACK_MISMATCH") else attempt
        }

    private fun updateProfiles(profiles: List<SuUidProfile>, current: () -> Boolean, incomplete: Boolean) {
        val packages = profiles.filter { it.allow && it.uid / 100000 == currentUserId }.mapTo(linkedSetOf()) { it.packageName }
        observation = Observation(Snapshot(packages, loaded = true, deliveryIncomplete = incomplete,
            profiles = profiles.associateBy { it.uid }, uidProfilesLoaded = true), current)
        publish(profiles.count { it.allow })
    }

    private fun update(packages: Set<String>, current: () -> Boolean,
                       deliveryIncomplete: Boolean = snapshot.deliveryIncomplete) {
        observation = Observation(Snapshot(packages, loaded = true, deliveryIncomplete = deliveryIncomplete,
            profiles = snapshot.profiles, uidProfilesLoaded = snapshot.uidProfilesLoaded), current)
        publish(packages.size)
    }
}
