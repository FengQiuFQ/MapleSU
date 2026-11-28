package dev.maplesu.manager.runtime

import android.content.Context
import android.util.Log
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraSdkCredentials
import dev.maplesu.manager.workmode.superuser.ImplantPreparation
import dev.maplesu.manager.workmode.superuser.LiteImplantCodes
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import dev.maplesu.manager.workmode.superuser.LiteImplantRecorderProvider
import java.io.File
import java.security.MessageDigest

/**
 * Publishes the shipped, unmodified SU client to one authorised application.
 * The client uses the current caller's SU admission; its bytes carry no reusable secret.
 *
 * <p>Boundaries enforced here:
 *  - only an identity with an active grant is delivered to; everything else is refused
 *    before a single byte is written;
 *  - the Manager never delivers to itself;
 *  - [withdraw] removes the delivered file after the durable authority revokes access.
 */
object SuDelivery {
    data class Result(val ok: Boolean, val path: String? = null, val detail: String = "")

    /** Filesystem name inside the target's library directory. */
    private const val NAME = "su"

    fun deliveredPath(context: Context, packageName: String): String? = runCatching {
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        File(info.nativeLibraryDir, NAME).absolutePath
    }.getOrNull()

    /**
     * True when the delivered image is present.
     *
     * <p>This is the cheapest durable delivery signal: it needs no root because the
     * installed client and the target library directory are traversable.
     * It says nothing about wiring, and it never decides access - the grant does that.
     */
    fun imagePresent(context: Context, packageName: String): Boolean {
        val path = deliveredPath(context, packageName) ?: return false
        return File(path).isFile
    }

    fun deliver(context: Context, packageName: String): Result {
        val application = context.applicationContext
        // W19 写者静默：切换期间拒绝任何新投递（fail closed，不写目标 App）。
        LiteImplantQuiesceGate.blockedCode()?.let { code ->
            return Result(false, detail = code)
        }
        if (packageName == application.packageName) return Result(false, detail = "refusing to deliver to the manager itself")
        val uid = runCatching { application.packageManager.getApplicationInfo(packageName, 0).uid }.getOrNull()
            ?: return Result(false, detail = "unknown package")
        // Short-lived root tool: the grant check must not start (or keep) a resident
        // executor merely to answer one question.
        val enabled = DirectPolicy.isEnabled(application)
            ?: return Result(false, detail = "AUTH_STATE_UNAVAILABLE")
        if (!enabled) return Result(false, detail = "AUTH_DISABLED")
        when (DirectPolicy.hasGrantStrict(application, uid)) {
            true -> Unit
            false -> return Result(false, detail = "AUTH_NOT_GRANTED")
            null -> return Result(false, detail = "AUTH_STATE_UNAVAILABLE")
        }
        val current = UltraSdkCredentials.captureOwnerMarker(application)
        if (!current()) return Result(false, detail = "SDK_IDENTITY_SCOPE_CHANGED")

        val source = File(application.applicationInfo.nativeLibraryDir, "libmaplesu_su.so")
        if (!source.isFile) return Result(false, detail = "client image unavailable")
        val directory = runCatching {
            File(application.packageManager.getApplicationInfo(packageName, 0).nativeLibraryDir)
        }.getOrNull() ?: return Result(false, detail = "target library directory unknown")
        val target = File(directory, NAME).absolutePath
        // W19: back up and register before changing the target or creating directories.
        val preparation = prepareImplantRecord(packageName, uid, target, source, directory)
        if (preparation != null && !preparation.ok) return Result(false, detail = preparation.code)
        if (!current()) return Result(false, detail = "SDK_IDENTITY_SCOPE_CHANGED")
        // /proc/self/exe must resolve to the installed Manager image: the existing client
        // derives its APK/bootstrap paths there and retains the executing caller's fullUID.
        val pending = "$target.maplesu-new"
        try {
            val script = """
                set -eu
                /system/bin/mkdir -p ${quote(directory.absolutePath)}
                /system/bin/chown 0:0 ${quote(directory.absolutePath)}
                /system/bin/chmod 0755 ${quote(directory.absolutePath)}
                /system/bin/chcon u:object_r:apk_data_file:s0 ${quote(directory.absolutePath)}
                /system/bin/chmod 0755 ${quote(directory.parent.orEmpty())}
                /system/bin/chcon u:object_r:apk_data_file:s0 ${quote(directory.parent.orEmpty())}
                trap ${quote("/system/bin/rm -f ${quote(pending)}")} EXIT
                /system/bin/ln -sfn ${quote(source.absolutePath)} ${quote(pending)}
                /system/bin/chown -h $uid:$uid ${quote(pending)}
                /system/bin/chcon -h u:object_r:apk_data_file:s0 ${quote(pending)}
                /system/bin/mv -f ${quote(pending)} ${quote(target)}
                test -x ${quote(target)}
                /system/bin/printf 'DELIVERED:%s\n' ${quote(target)}
            """.trimIndent()
            if (!current()) return Result(false, detail = "SDK_IDENTITY_SCOPE_CHANGED")
            when (DirectPolicy.hasGrantStrict(application, uid)) {
                true -> Unit
                false -> return Result(false, detail = "AUTH_NOT_GRANTED")
                null -> return Result(false, detail = "AUTH_STATE_UNAVAILABLE")
            }
            val outcome = runRoot(application, script)
            if (outcome.first != 0) {
                return Result(false, detail = "delivery failed (${outcome.first}): ${outcome.second.take(160)}")
            }
            if (!current()) return Result(false, detail = "SDK_IDENTITY_SCOPE_CHANGED")
            Log.i("MapleSU", "SU_CLIENT_DELIVERED package=$packageName uid=$uid")
            if (preparation != null) {
                runCatching { LiteImplantRecorderProvider.current()?.afterDelivery(preparation) }
            }
            return Result(true, target, "delivered")
        } catch (error: java.io.IOException) {
            return Result(false, detail = "delivery failed: ${error.javaClass.simpleName}")
        }
    }

    /** Removes only the delivered image; access revocation belongs to the durable authority. */
    fun withdraw(context: Context, packageName: String): Result {
        val application = context.applicationContext
        val path = deliveredPath(application, packageName) ?: return Result(false, detail = "unknown package")
        val script = """
            set -eu
            /system/bin/rm -f ${quote(path)}
            if [ -e ${quote(path)} ]; then exit 3; fi
            /system/bin/printf 'WITHDRAWN\n'
        """.trimIndent()
        val outcome = runRoot(application, script)
        return if (outcome.first == 0) Result(true, null, "withdrawn")
        else Result(false, detail = "withdraw failed (${outcome.first}): ${outcome.second.take(160)}")
    }

    /** Digest of all bytes actually delivered. */
    fun deliveredDigest(context: Context, packageName: String): String? {
        val path = deliveredPath(context, packageName) ?: return null
        return deliveredImageSha(File(path))
    }

    /**
     * W19：投递前备份 `nativeLibraryDir/su`（若已存在）并登记未激活条目。
     * 未安装 recorder（旧行为）→ null；安装后任何失败 → 调用方必须放弃写入。
     */
    private fun prepareImplantRecord(
        packageName: String,
        uid: Int,
        target: String,
        source: File,
        directory: File,
    ): ImplantPreparation? {
        val recorder = LiteImplantRecorderProvider.current() ?: return null
        val sha = deliveredImageSha(source)
            ?: return ImplantPreparation.failed(LiteImplantCodes.BACKUP_FAILED, "image digest")
        val createdDirs = buildList {
            directory.parentFile?.takeIf { !it.exists() }?.let { add(it.absolutePath) }
            if (!directory.exists()) add(directory.absolutePath)
        }
        return runCatching {
            recorder.beforeDelivery(packageName, uid, target, sha, createdDirs, System.currentTimeMillis())
        }.getOrElse { ImplantPreparation.failed(LiteImplantCodes.BACKUP_FAILED, it.javaClass.simpleName) }
    }

    /** The record binds the complete raw client image, including its final byte. */
    private fun deliveredImageSha(source: File): String? = runCatching {
        val digest = MessageDigest.getInstance("SHA-256")
        source.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }.getOrNull()

    /**
     * Every delivery step runs as one short-lived direct-admission process: no root
     * service, no Binder connection and nothing left behind between operations.
     */
    private fun runRoot(context: Context, script: String): Pair<Int, String> {
        val result = DirectRoot.run(context, script)
        return result.code to result.output
    }

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}

/**
 * How far one identity actually got, for display; it never decides access.
 *
 * <p>The three layers are separate facts and the row must not merge them:
 *  1. a grant (authorization),
 *  2. the delivered image inside the target's library directory,
 *  3. PATH wiring, which only exists inside a live process and therefore cannot be
 *     completed while the target is closed.
 *
 * <p>[WIRED] is never inferred from "some `lib*.so` exists": every application with native
 * code has those, so that reading reported every delivered application as wired. It needs the
 * one signal that means the application can actually resolve a bare `su` right now - the
 * published directory inside the live process environment ([SuAutoWire.probeWiring]'s
 * `pathWired`). A root-owned side library is *not* that signal: it only proves an implant
 * happened at some point (MT keeps one while its PATH never changed), which is why
 * [SuAutoWire.implanted] - the OR that [SuAutoWire.reconcile] uses to avoid implanting twice -
 * must not be reused here.
 */
enum class State {
    /** No grant: nothing was delivered to this identity, and nothing will be. */
    NOT_AUTHORIZED,

    /**
     * Granted, image in place, target running, and the live PATH does not contain the
     * published directory yet: the copy exists and nothing is stale - wiring just is not in
     * effect yet. The row claims the copy, not a working `su`.
     */
    DELIVERED,

    /** A Direct grant exists, but delivery or PATH wiring has not been confirmed. */
    PENDING_WIRING,

    /** The authority was saved but its backend has not applied the revision. */
    AUTHORIZATION_PENDING,

    /** The Hook authority exists but the traditional su entry is not ready. */
    ENTRY_UNAVAILABLE,

    /** Granted, delivered and PATH-wired: a bare `su` resolves inside the application. */
    WIRED,

    /**
     * A grant record exists but it belongs to a different installation of the package: the
     * application was updated, reinstalled or re-signed. Authorization is bound to the
     * installed identity, so the old record no longer admits it and nothing is delivered.
     * Reporting "not authorized" would hide why it stopped working; the remedy is to
     * authorize the new installation again.
     */
    STALE,
}

/** Reports saved authority and publication separately; it never grants or deploys. */
internal fun managerSuState(granted: Boolean, stale: Boolean, pending: Boolean, entryReady: Boolean): State = when {
    stale -> State.STALE
    !granted -> State.NOT_AUTHORIZED
    pending -> State.AUTHORIZATION_PENDING
    !entryReady -> State.ENTRY_UNAVAILABLE
    else -> State.WIRED
}

/**
 * What one row should show.
 *
 * @param granted the grant bit the caller already knows (the profile snapshot the row was
 *   built from). Passed in so a screen never has to read policy per row.
 */
fun stateFor(
    context: Context,
    packageName: String,
    granted: Boolean,
    stale: Boolean = false,
): State = statesFor(context, mapOf(packageName to granted), stale = setOfNotNull(packageName.takeIf { stale }))[packageName]
    ?: State.NOT_AUTHORIZED

/**
 * The display state of a whole screen's rows.
 *
 * <p>[identities] maps a package name to the grant bit its row already carries. Nothing here
 * grants or decides anything: it describes what is on disk.
 *
 * <p>Cost is why this exists as a batch. The delivery check is one `stat` per granted row,
 * but the wiring signal needs root, and a root process per row is exactly what made the
 * superuser list take tens of seconds. Every granted row on the screen is therefore answered
 * by one [SuAutoWire.probeWiring] call; call it off the main thread.
 */
fun statesFor(
    context: Context,
    identities: Map<String, Boolean>,
    stale: Set<String> = emptySet(),
): Map<String, State> {
    if (identities.isEmpty()) return emptyMap()
    if (HookRootExecutor.production(context).available()) {
        val wired = HookSuCompatibility.traditionalReady(context)
        return identities.mapValues { (packageName, isGranted) ->
            managerSuState(isGranted, packageName in stale, pending = false, entryReady = wired)
        }
    }
    // Ultra uses its durable fullUID authority and kernel SU entry. Its list does not
    // deploy a traditional client or start PATH probes for display reads.
    if (UltraEnvironmentProbe.usesUltraBackend(context)) {
        if (identities.none { it.value }) return identities.mapValues { (name, _) ->
            managerSuState(false, name in stale, pending = false, entryReady = false)
        }
        val read = ManagerAuthorizations.currentDeliveryRead(context)
        val states = identities.mapValues { (packageName, isGranted) ->
            val uid = if (isGranted) runCatching { context.packageManager.getApplicationInfo(packageName, 0).uid }.getOrNull() else null
            val members = uid?.let { runCatching { context.packageManager.getPackagesForUid(it).orEmpty().toSet() }.getOrNull() }
            val applied = uid != null && packageName in members.orEmpty() &&
                members.orEmpty().any { read.confirms(uid, it, isGranted) }
            managerSuState(isGranted, stale = packageName in stale,
                pending = isGranted && read.isCurrent() && read.uidProfiles?.ok == true && uid != null && !applied,
                entryReady = applied && read.entryConfirmed == true)
        }
        return if (read.isCurrent()) states else identities.mapValues { (name, granted) ->
            managerSuState(granted, name in stale, pending = false, entryReady = false)
        }
    }
    val application = context.applicationContext
    val granted = identities.filterValues { it }.keys
    // Nothing is delivered to an identity without a grant, so asking root about those rows
    // would only spend a process to learn that the answer is "nothing there".
    if (granted.isEmpty()) return identities.keys.associateWith { State.NOT_AUTHORIZED }
    val probes = SuAutoWire.probeWiring(application, granted)
    return identities.mapValues { (packageName, isGranted) ->
        val probe = probes?.get(packageName)
        when {
            // A record that no longer matches the installed package: say so, because the
            // application stopped working for a reason the user can act on.
            packageName in stale -> State.STALE
            !isGranted -> State.NOT_AUTHORIZED
            // Delivery follows the grant, so a grant without an image is a delivery that has
            // not happened yet (or failed). The row must not claim a copy it cannot see.
            !SuDelivery.imagePresent(application, packageName) -> State.PENDING_WIRING
            // Without a probe there is no wiring evidence at all; reporting "wired" then
            // would be a guess, and guessing is the defect this state machine replaces.
            probe == null -> State.PENDING_WIRING
            // PATH only. A side library proves an implant happened, not that this application
            // resolves `su` (MT keeps one with an untouched PATH); claiming "wired" there is
            // the lie this item exists to remove. The OR belongs to reconcile's re-implant
            // guard, not to what the user is told.
            probe.pathWired -> State.WIRED
            // The PATH signal exists only inside a live process, so a closed target is pending:
            // it has to run once before wiring can take effect.
            !probe.running -> State.PENDING_WIRING
            // An implant is on disk but the environment never changed - MT's state after an
            // earlier implant. Something is wired on paper and nothing works: pending, and
            // re-wiring is the action, not "look at the copy".
            probe.sideLibrary -> State.PENDING_WIRING
            // Running, nothing stale, delivery in place; the live PATH just does not show the
            // published directory (a wiring attempt that has not run yet or did not take).
            else -> State.DELIVERED
        }
    }
}
