package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.switch.HookResult
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.UUID

/** Private, bounded framing shared by the manager and its already-root helper. */
internal object ModeSwitchRootProtocol {
    const val MAGIC = 0x4d535257
    const val VERSION = 3
    const val TOKEN_BYTES = 32
    const val MAX_SCRIPT_BYTES = 128 * 1024
    const val MAX_OUTPUT_BYTES = 1024 * 1024
    const val MAX_DETAIL_BYTES = 256
    const val PING = 1
    const val EXEC = 2
    const val UNINSTALL = 3
    const val ACQUIRE = 4
    const val RELEASE = 5
    const val UNAVAILABLE = "MODE_SWITCH_ROOT_SESSION_UNAVAILABLE"
    const val UNCERTAIN = "MODE_SWITCH_ROOT_OPERATION_UNCERTAIN"
    const val BAD_REQUEST = "MODE_SWITCH_ROOT_REQUEST_INVALID"
    const val LEASE_REQUIRED = "MODE_SWITCH_ROOT_LEASE_REQUIRED"

    data class Reply(val code: Int, val output: String = "", val detail: String = "")

    fun request(output: OutputStream, token: ByteArray, operation: Int, payload: String) {
        require(token.size == TOKEN_BYTES && operation in PING..RELEASE)
        val limit = payloadLimit(operation)
        val bytes = payload.toByteArray(Charsets.UTF_8)
        require(bytes.size <= limit)
        val wire = DataOutputStream(output)
        wire.writeInt(MAGIC)
        wire.writeInt(VERSION)
        wire.write(token)
        wire.writeByte(operation)
        writeBytes(wire, bytes)
        wire.flush()
    }

    /** peerUid comes from SO_PEERCRED or the verified Binder caller, never a request field. */
    fun serve(peerUid: Int, managerUid: Int, input: InputStream, output: OutputStream,
              token: ByteArray, handler: (Int, String) -> Reply) {
        if (peerUid != managerUid || token.size != TOKEN_BYTES) return
        val wire = DataInputStream(input)
        if (wire.readInt() != MAGIC || wire.readInt() != VERSION) return
        val provided = ByteArray(TOKEN_BYTES)
        wire.readFully(provided)
        val accepted = MessageDigest.isEqual(provided, token)
        provided.fill(0)
        if (!accepted) return
        val operation = wire.readUnsignedByte()
        if (operation !in PING..RELEASE) return
        val payload = readBytes(wire, payloadLimit(operation))
        val reply = try { handler(operation, payload.toString(Charsets.UTF_8)) }
            finally { payload.fill(0) }
        respond(output, reply)
    }

    fun response(input: InputStream): Reply {
        val wire = DataInputStream(input)
        check(wire.readInt() == MAGIC && wire.readInt() == VERSION) { BAD_REQUEST }
        return Reply(wire.readInt(), readBytes(wire, MAX_OUTPUT_BYTES).toString(Charsets.UTF_8),
            readBytes(wire, MAX_DETAIL_BYTES).toString(Charsets.UTF_8))
    }

    fun respond(output: OutputStream, reply: Reply) {
        val wire = DataOutputStream(output)
        wire.writeInt(MAGIC)
        wire.writeInt(VERSION)
        wire.writeInt(reply.code)
        writeBytes(wire, reply.output.toByteArray(Charsets.UTF_8).also { require(it.size <= MAX_OUTPUT_BYTES) })
        writeBytes(wire, reply.detail.toByteArray(Charsets.UTF_8).also { require(it.size <= MAX_DETAIL_BYTES) })
        wire.flush()
    }

    private fun readBytes(input: DataInputStream, maximum: Int): ByteArray {
        val size = input.readInt()
        require(size in 0..maximum) { BAD_REQUEST }
        return ByteArray(size).also(input::readFully)
    }

    private fun writeBytes(output: DataOutputStream, bytes: ByteArray) {
        output.writeInt(bytes.size)
        output.write(bytes)
    }

    const val REBOOT_REQUESTED = "MODE_SWITCH_REBOOT_REQUESTED"

    internal fun uninstallAndReboot(remove: () -> Reply, reboot: () -> Reply): Reply {
        val removed = remove()
        if (removed.code != 0) return removed
        // Run before writing the reply: manager death must not strand an uninstalled source.
        val requested = reboot()
        return if (requested.code == 0) Reply(0, REBOOT_REQUESTED) else requested
    }

    fun validSwitchId(value: String): Boolean = runCatching {
        UUID.fromString(value).toString() == value
    }.getOrDefault(false)

    private fun payloadLimit(operation: Int): Int = when (operation) {
        UNINSTALL -> 0
        ACQUIRE, RELEASE -> 36
        else -> MAX_SCRIPT_BYTES
    }
}

internal interface ModeSwitchRootConnection : Closeable {
    val peerUid: Int
    val input: InputStream
    val output: OutputStream
}

/** A transaction keeps its original helper. Lost writes never start a replacement or a rollback. */
internal class ModeSwitchRootPin(
    private val prepare: () -> HookResult,
    private val run: (String) -> RootExecResult,
    private val uninstall: () -> HookResult,
    private val acquireLease: (String) -> HookResult = { HookResult.failed(ModeSwitchRootProtocol.UNAVAILABLE) },
    private val releaseLease: (String) -> HookResult = { HookResult.failed(ModeSwitchRootProtocol.UNAVAILABLE) },
) {
    private var pinned = false
    private var failure: String? = null

    @Synchronized
    fun ensureReady(): HookResult {
        failure?.let { return HookResult.failed(it) }
        if (pinned) return HookResult.OK
        return prepare().also {
            if (it.ok) pinned = true
            else if (it.code == ModeSwitchRootProtocol.UNCERTAIN) failure = it.code
        }
    }

    /** Observations do not start a daemon; an established or failed transaction keeps its owner. */
    @Synchronized
    fun observe(script: String, read: (String) -> RootExecResult): RootExecResult =
        if (pinned || failure != null) execute(script) else read(script)

    @Synchronized
    fun execute(script: String): RootExecResult {
        val ready = ensureReady()
        if (!ready.ok) return RootExecResult(RootBackend.NONE, -1, "", ready.code)
        return run(script).also { latch(it.detail) }
    }

    @Synchronized
    fun uninstallUltra(): HookResult {
        val ready = ensureReady()
        if (!ready.ok) return ready
        return uninstall().also { if (!it.ok) latch(it.code) }
    }

    @Synchronized
    fun acquire(switchId: String): HookResult {
        val ready = ensureReady()
        if (!ready.ok) return ready
        return acquireLease(switchId).also { if (!it.ok) latch(it.code) }
    }

    @Synchronized
    fun release(switchId: String): HookResult {
        failure?.let { return HookResult.failed(it) }
        return releaseLease(switchId).also { if (!it.ok) latch(it.code) }
    }

    private fun latch(code: String?) {
        if (code == ModeSwitchRootProtocol.UNCERTAIN || code == ModeSwitchRootProtocol.UNAVAILABLE) {
            failure = code
        }
    }
}

/** No mutation is retried: a lost reply may mean the requested write already happened. */
internal class ModeSwitchRootChannel(
    private val token: () -> ByteArray,
    private val connect: (timeoutMillis: Int) -> ModeSwitchRootConnection,
    private val launch: () -> RootExecResult,
    private val pause: () -> Unit = { Thread.sleep(150) },
    private val onFailure: (String, Exception) -> Unit = { _, _ -> },
) {
    @Synchronized
    fun ensureReady(): HookResult {
        val initial = ping()
        if (initial.ok || initial.code == ModeSwitchRootProtocol.UNCERTAIN) return initial
        val started = try { launch() } catch (error: Exception) {
            onFailure("launch", error)
            null
        }
        if (started?.ok != true) return HookResult.failed(ModeSwitchRootProtocol.UNAVAILABLE)
        repeat(20) {
            val result = ping()
            if (result.ok || result.code == ModeSwitchRootProtocol.UNCERTAIN) return result
            pause()
        }
        return HookResult.failed(ModeSwitchRootProtocol.UNAVAILABLE)
    }

    @Synchronized
    fun execute(script: String): RootExecResult {
        if (script.isBlank() || '\u0000' in script ||
            script.toByteArray(Charsets.UTF_8).size > ModeSwitchRootProtocol.MAX_SCRIPT_BYTES) {
            return RootExecResult(RootBackend.ULTRA_ENV, -1, "", ModeSwitchRootProtocol.BAD_REQUEST)
        }
        val reply = exchange(ModeSwitchRootProtocol.EXEC, script)
        return RootExecResult(RootBackend.ULTRA_ENV, reply.code, reply.output, reply.detail)
    }

    @Synchronized
    fun uninstallUltra(): HookResult {
        val reply = exchange(ModeSwitchRootProtocol.UNINSTALL, "")
        return if (reply.code == 0) HookResult(true,
            code = if (reply.output == ModeSwitchRootProtocol.REBOOT_REQUESTED) reply.output else "")
            else HookResult.failed(reply.detail.ifEmpty { ModeSwitchRootProtocol.UNAVAILABLE })
    }

    @Synchronized
    fun acquire(switchId: String): HookResult = lease(ModeSwitchRootProtocol.ACQUIRE, switchId)

    @Synchronized
    fun release(switchId: String): HookResult = lease(ModeSwitchRootProtocol.RELEASE, switchId)

    private fun lease(operation: Int, switchId: String): HookResult {
        if (!ModeSwitchRootProtocol.validSwitchId(switchId)) return HookResult.failed(ModeSwitchRootProtocol.BAD_REQUEST)
        val reply = exchange(operation, switchId)
        return if (reply.code == 0) HookResult.OK
        else HookResult.failed(reply.detail.ifEmpty { ModeSwitchRootProtocol.UNAVAILABLE })
    }

    private fun ping(): HookResult {
        val reply = exchange(ModeSwitchRootProtocol.PING, "")
        return if (reply.code == 0 && reply.output == "0" && reply.detail.isEmpty()) HookResult.OK
        else HookResult.failed(reply.detail.ifEmpty { ModeSwitchRootProtocol.UNAVAILABLE })
    }

    private fun exchange(operation: Int, payload: String): ModeSwitchRootProtocol.Reply {
        var sent = false
        var stage = "connect"
        return try {
            connect(if (operation == ModeSwitchRootProtocol.PING) 1_000 else 180_000).use { connection ->
                stage = "peer"
                check(connection.peerUid == 0) { ModeSwitchRootProtocol.UNAVAILABLE }
                stage = "token"
                val secret = token()
                try {
                    // Conservatively treat any failure while sending as an uncertain mutation.
                    sent = operation != ModeSwitchRootProtocol.PING
                    stage = "request"
                    ModeSwitchRootProtocol.request(connection.output, secret, operation, payload)
                } finally { secret.fill(0) }
                stage = "response"
                ModeSwitchRootProtocol.response(connection.input)
            }
        } catch (error: Exception) {
            onFailure(stage, error)
            ModeSwitchRootProtocol.Reply(-1, detail = if (sent) ModeSwitchRootProtocol.UNCERTAIN
                else ModeSwitchRootProtocol.UNAVAILABLE)
        }
    }
}

/** Shared across reconnects. An operation with an uncertain end quarantines later mutations. */
internal class ModeSwitchRootRequests(
    private val execute: (String) -> ModeSwitchRootProtocol.Reply,
    private val uninstall: () -> ModeSwitchRootProtocol.Reply,
    private val acquire: (String) -> HookResult = { HookResult.failed(ModeSwitchRootProtocol.UNAVAILABLE) },
    private val release: (String) -> HookResult = { HookResult.failed(ModeSwitchRootProtocol.UNAVAILABLE) },
    private val isHeld: () -> Boolean = { false },
) {
    private var uncertain = false

    @Synchronized
    fun handle(operation: Int, payload: String): ModeSwitchRootProtocol.Reply {
        if (uncertain) return ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.UNCERTAIN)
        val result = when (operation) {
            ModeSwitchRootProtocol.PING -> if (payload.isEmpty()) ModeSwitchRootProtocol.Reply(0, "0")
                else ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.BAD_REQUEST)
            ModeSwitchRootProtocol.EXEC -> if (payload.isNotBlank() && '\u0000' !in payload) execute(payload)
                else ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.BAD_REQUEST)
            ModeSwitchRootProtocol.UNINSTALL -> if (payload.isEmpty()) {
                if (isHeld()) uninstall()
                else ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.LEASE_REQUIRED)
            } else ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.BAD_REQUEST)
            ModeSwitchRootProtocol.ACQUIRE, ModeSwitchRootProtocol.RELEASE -> {
                if (!ModeSwitchRootProtocol.validSwitchId(payload)) {
                    ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.BAD_REQUEST)
                } else {
                    val lease = if (operation == ModeSwitchRootProtocol.ACQUIRE) acquire(payload) else release(payload)
                    ModeSwitchRootProtocol.Reply(if (lease.ok) 0 else -1, detail = if (lease.ok) "" else lease.code)
                }
            }
            else -> ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.BAD_REQUEST)
        }
        if (result.detail == ModeSwitchRootProtocol.UNCERTAIN) uncertain = true
        return result
    }
}
