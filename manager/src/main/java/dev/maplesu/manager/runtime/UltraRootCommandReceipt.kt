package dev.maplesu.manager.runtime

import java.util.UUID
import dev.maplesu.manager.runtime.ultra.NativeReceipt

/** The SDK returns its own status, not the shell's; carry one bounded, per-call exit receipt. */
internal class UltraRootCommandReceipt(script: String, nonce: String = UUID.randomUUID().toString()) {
    private val marker = "\nMAPLESU_ROOT_EXIT:$nonce:"

    init { require(nonce.matches(Regex("[a-zA-Z0-9-]{1,64}"))) }

    // A subshell retains explicit exit/exec/set -e in existing scripts without losing the receipt.
    val command: String = """
        (
        $script
        ) 2>&1
        _maplesu_root_exit=${'$'}?
        printf '\nMAPLESU_ROOT_EXIT:$nonce:%s\n' "${'$'}_maplesu_root_exit"
    """.trimIndent()

    /** Keep this invocation's output and scalar failure facts; no reason/raw/command logging. */
    fun decodeSdk(receipt: NativeReceipt, decodeText: (String?) -> String?): UltraRootCommandResult {
        val output = decodeText(receipt.string("result")).orEmpty()
        if (receipt.succeeded) return decode(output)
        val decoded = decode(output)
        val name = receipt.sdkError.takeIf { it.matches(Regex("[A-Z0-9_]{1,96}")) } ?: "UNKNOWN"
        val facts = receipt.obj("rootCommand")
        val detail = buildString {
            append("ULTRA_ROOT_FAILED:").append(name)
            if (facts != null || name !in setOf("MAPLESU_SDK_BUSY", "MAPLESU_SDK_INTERRUPTED",
                "MAPLESU_SDK_DEADLINE_EXCEEDED")) {
                append(";sdkCode=").append(receipt.sdkErrorCode)
            }
            if (facts != null) {
                fun appendNumbers(values: org.json.JSONObject, keys: List<String>, prefix: String = "") {
                    for (key in keys) {
                        val value = values.opt(key)
                        if (value is Byte || value is Short || value is Int || value is Long ||
                            value is String && value.toLongOrNull() != null)
                            append(';').append(prefix).append(key).append('=').append(value)
                    }
                }
                fun appendBooleans(values: org.json.JSONObject, keys: List<String>, prefix: String = "") {
                    for (key in keys) {
                        (values.opt(key) as? Boolean)?.let {
                            append(';').append(prefix).append(key).append('=').append(if (it) 1 else 0)
                        }
                    }
                }
                appendNumbers(facts, listOf("error", "phase", "systemError", "workingDirectoryError",
                    "shellStatus", "shellError", "transportPhase", "transportError", "childStatus",
                    "vendorChildStatus", "rootProcess", "rootError", "rootSystemError", "threadsTotal",
                    "cpusetMoved", "stuneMoved", "cgroupError"))
                appendBooleans(facts, listOf("receiptComplete", "shellCloseAttempted", "childStatusValid",
                    "vendorChildStatusValid", "rootInvocationKnown", "rootAttempted", "rootReturned",
                    "rootReportReceived", "ownerMode", "environmentCompleted"))
                (facts.opt("rootPhase") as? String)?.takeIf { it.matches(Regex("[A-Za-z0-9_-]{1,32}")) }?.let {
                    append(";rootPhase=").append(it)
                }
                for (group in listOf("credentials", "taskState")) {
                    facts.optJSONObject(group)?.let { values ->
                        appendNumbers(values, listOf("error", "status", "effects"), "$group.")
                        appendBooleans(values, listOf("attempted", "replyObserved", "completed"), "$group.")
                    }
                }
            }
        }
        // A valid shell marker may delimit output, but never repairs an SDK or
        // session-cleanup failure or proves that Root is still available.
        return UltraRootCommandResult(false, receipt.sdkErrorCode.takeIf { it != 0 } ?: -1,
            if (decoded.commandCompleted) decoded.output else output, detail)
    }

    fun decode(output: String): UltraRootCommandResult {
        val start = output.lastIndexOf(marker)
        val codeText = if (start < 0) "" else output.substring(start + marker.length)
        val code = codeText.takeIf { it.matches(Regex("(?:0|[1-9][0-9]{0,2})\n")) }
            ?.trimEnd()?.toIntOrNull()?.takeIf { it in 0..255 }
        if (code == null) return UltraRootCommandResult(false, -1, output,
            "ULTRA_ROOT_COMMAND_RESULT_UNCONFIRMED")
        return UltraRootCommandResult(code == 0, code, output.substring(0, start),
            if (code == 0) "" else "ULTRA_ROOT_COMMAND_EXIT:$code", commandCompleted = true)
    }
}
