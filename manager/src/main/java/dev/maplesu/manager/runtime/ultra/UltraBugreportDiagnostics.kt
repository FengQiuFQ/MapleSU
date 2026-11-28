// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import java.io.File
import java.net.URLDecoder
import org.json.JSONObject

/** Uses the current-task SDK channel independently of the standard SU shell channel. */
internal object UltraBugreportDiagnostics {
    interface Port {
        fun sdkBuildIdentity(): NativeReceipt
        fun environment(): NativeReceipt
        fun authorizations(): UltraRuntimeClient.SuAuthSnapshot
        fun rootCommand(command: String): NativeReceipt
        fun selfSu(): Pair<Int?, String?>
        fun installedHelperPath(): String? = null
    }

    fun collect(directory: File, enabled: Boolean, portProvider: () -> Port) {
        if (!enabled) return
        val port = portProvider()
        val report = StringBuilder(
            "Package-list readback and Manager-only su probe; not a target-app execution proof.\n",
        )
        fun record(label: String, read: () -> NativeReceipt): NativeReceipt? =
            runCatching(read).fold(
                onSuccess = { receipt ->
                    report.append("$label: ok=${receipt.succeeded} sdkError=${receipt.sdkError} sdkErrorCode=${receipt.sdkErrorCode}\n")
                    receipt.obj("rootCommand")?.let { root ->
                        fun appendFields(values: JSONObject, fields: List<String>, prefix: String = "") {
                            for (field in fields) {
                                val value = values.opt(field)
                                val text = when {
                                    value is Boolean -> value.toString()
                                    (value is Number || value is String) && value.toString().toLongOrNull() != null -> value.toString()
                                    field == "rootPhase" && value is String && value.matches(Regex("[A-Za-z0-9_-]{1,32}")) -> value
                                    else -> continue
                                }
                                report.append("$label.rootCommand.$prefix$field=$text\n")
                            }
                        }
                        // Fixed diagnostic scalars only; never serialize commands, output or handles.
                        appendFields(root, listOf(
                            "error", "phase", "systemError", "workingDirectoryError",
                            "shellCloseAttempted", "shellStatus", "shellError", "transportPhase", "transportError",
                            "childStatus", "childStatusValid", "vendorChildStatus", "vendorChildStatusValid",
                            "receiptComplete", "rootProcess", "rootInvocationKnown", "rootAttempted", "rootReturned",
                            "rootReportReceived", "rootPhase", "rootError", "rootSystemError", "ownerMode",
                            "environmentCompleted", "threadsTotal", "cpusetMoved", "stuneMoved", "cgroupError",
                        ))
                        for (group in listOf("credentials", "taskState")) {
                            root.optJSONObject(group)?.let { values ->
                                appendFields(values, listOf("attempted", "replyObserved", "error", "status", "effects", "completed"), "$group.")
                            }
                        }
                    }
                    receipt
                },
                onFailure = { error ->
                    if (error is InterruptedException) Thread.currentThread().interrupt()
                    report.append("$label: EXCEPTION:${error.javaClass.simpleName}\n")
                    null
                },
            )
        record("sdk_build", port::sdkBuildIdentity)?.let { identity ->
            if (identity.succeeded) {
                for (field in listOf("buildId", "sdkSha256", "helperBuildId")) {
                    report.append("$field=${identity.string(field)}\n")
                }
            }
        }
        record("environment", port::environment)?.let { report.append("state=${it.string("state")}\n") }
        record("su_auth") {
            port.authorizations().also { snapshot ->
                if (snapshot.ok) report.append("packages=${snapshot.packages.joinToString(",")}\n")
            }.receipt
        }
        record("sdk_root_identity") { port.rootCommand("id; getenforce") }?.let { receipt ->
            if (receipt.succeeded) runCatching {
                check(receipt.string("encoding") == "url")
                // Keep actual line breaks: URL/JSON-escaped newlines hide key boundaries from redaction.
                report.append("sdk_root_identity_output:\n")
                    .append(URLDecoder.decode(receipt.string("result").orEmpty(), "UTF-8")).append('\n')
            }
        }
        // Fixed, read-only commands. Do not call SuRedirectPrint: SDK init also changes UID-control storage.
        val commands = linkedMapOf(
            "ultra-recovery.txt" to recoveryDiagnostics(),
            "ultra-module-policy.txt" to modulePolicyDiagnostics(),
            "packages.txt" to "cat /data/system/packages.list",
            "dmesg.txt" to "dmesg | tail -n 500",
            "logcat.txt" to "logcat -b all -d -t 2000 -v threadtime",
        )
        val helper = runCatching { port.installedHelperPath() }.getOrNull()
        if (helper != null && helper.matches(Regex("/data/[A-Za-z0-9]{16}/init"))) {
            commands["ultra-environment-boot.txt"] = bootDiagnostics(helper)
        } else report.append("boot_diagnostics: HELPER_PATH_UNAVAILABLE\n")
        for ((name, command) in commands) {
            val destination = File(directory, name)
            if (destination.length() > 0L) continue
            val receipt = record(name) { port.rootCommand(command) } ?: continue
            if (!receipt.succeeded) continue
            val encoded = receipt.string("result") ?: continue
            runCatching {
                check(receipt.string("encoding") == "url")
                val text = URLDecoder.decode(encoded, "UTF-8")
                destination.writeText(if (name in setOf("ultra-environment-boot.txt", "ultra-recovery.txt", "ultra-module-policy.txt"))
                    UltraSdkLogging.redact(text) else text)
            }.onFailure { report.append("$name: DECODE_OR_WRITE_FAILED:${it.javaClass.simpleName}\n") }
        }
        runCatching { port.selfSu() }.fold(
            onSuccess = { (uid, failure) -> report.append("manager_no_key_su: uid=$uid failure=$failure\n") },
            onFailure = { report.append("manager_no_key_su: EXCEPTION:${it.javaClass.simpleName}\n") },
        )
        // .txt is included in BugreportArchive's root-key/token redaction pass.
        File(directory, "ultra-authorization.txt").writeText(report.toString())
    }

    /** Export existing evidence only; exporting never installs hooks or repeats SDK probes. */
    private fun modulePolicyDiagnostics(): String = """
        echo 'module_policy_diagnostics:'
        date -u
        uname -a
        printf 'page_size='; getconf PAGESIZE 2>/dev/null || echo UNREADABLE
        printf 'current_boot='; cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo UNREADABLE
        printf 'enforcement='; getenforce 2>/dev/null || echo UNREADABLE
        for N in requested effective attempt experimental experimental-support; do
            echo "state:${'$'}N:"
            F="/data/adb/maplesu/module-policy/${'$'}N"
            if [ -f "${'$'}F" ] && [ ! -L "${'$'}F" ]; then
                head -c 128 "${'$'}F" 2>/dev/null || echo UNREADABLE
            else echo MISSING_OR_UNREADABLE; fi
            echo
        done
        echo 'kernel_notes:hex:'
        od -An -tx1 -N512 /sys/kernel/notes 2>/dev/null || echo UNREADABLE
        echo 'btf_metadata:'
        stat -c 'size=%s mode=%a' /sys/kernel/btf/vmlinux 2>/dev/null || echo MISSING_OR_UNREADABLE
        echo 'kernel_config:bounded_262144_bytes:'
        if [ -f /proc/config.gz ]; then
            gzip -dc /proc/config.gz 2>/dev/null | head -c 262144
        else echo MISSING_OR_UNREADABLE; fi
        echo
        for N in compatibility.previous.log compatibility.log; do
            echo "evidence:${'$'}N:"
            F="/data/adb/maplesu/module-policy/${'$'}N"
            if [ -f "${'$'}F" ] && [ ! -L "${'$'}F" ]; then
                tail -c 65536 "${'$'}F" 2>/dev/null || echo UNREADABLE
            else echo MISSING_OR_UNREADABLE; fi
            echo
        done
        echo 'module_policy_diagnostics_end'
    """.trimIndent()

    /** Read restore facts through the same working Ultra channel; never export keys, token or nonce. */
    private fun recoveryDiagnostics(): String = """
        R='/data/adb/maplesu/recovery'
        echo 'recovery_state:'
        printf 'hidden='
        H=${'$'}(cat /data/adb/maplesu/lite_hidden 2>/dev/null)
        case "${'$'}H" in 0|1) echo "${'$'}H";; *) echo UNREADABLE;; esac
        STAGE=${'$'}(sed -nE 's/^(pending|confirmed):[a-f0-9-]{36}${'$'}/\1/p' "${'$'}R/manager-restore.ticket" 2>/dev/null)
        case "${'$'}STAGE" in pending|confirmed) echo "handover=${'$'}STAGE";; *) echo 'handover=MISSING_OR_INVALID';; esac
        for name in manager.apk manifest.json identity.json webui.conf parasite-start.sh liteweb.pid webui.paused; do
            echo "file:${'$'}name:"
            stat -c 'uid=%u mode=%a size=%s' "${'$'}R/${'$'}name" 2>/dev/null || echo MISSING_OR_UNREADABLE
        done
        echo 'manager_uninstall:'
        sed -nE '/^MAPLESU_MANAGER_UNINSTALL (PREPARED|ABSENT) uid=[0-9]+ data=retained${'$'}/p' "${'$'}R/manager-uninstall.receipt" 2>/dev/null
        echo 'manager_package:'
        pm path 'dev.maplesu.manager' 2>&1
        pm list packages -U --user 0 'dev.maplesu.manager' 2>&1
        echo 'manager_launcher:'
        cmd package resolve-activity --brief --user 0 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER 'dev.maplesu.manager' 2>&1
        echo 'host_backups:'
        COUNT=0
        for D in "${'$'}R/host"/*; do
            [ -d "${'$'}D" ] && [ ! -L "${'$'}D" ] || continue
            COUNT=${'$'}((COUNT+1)); [ "${'$'}COUNT" -le 16 ] || { echo TRUNCATED_HOSTS; break; }
            echo "host:${'$'}{D##*/}"
            if [ -f "${'$'}D/host.manifest" ] && [ ! -L "${'$'}D/host.manifest" ]; then
                head -c 16384 "${'$'}D/host.manifest" 2>/dev/null
                echo
            else echo MANIFEST_MISSING_OR_UNREADABLE; fi
            FILES=0
            for F in "${'$'}D"/*.orig; do
                [ -f "${'$'}F" ] && [ ! -L "${'$'}F" ] || continue
                FILES=${'$'}((FILES+1)); [ "${'$'}FILES" -le 64 ] || { echo TRUNCATED_FILES; break; }
                sha256sum "${'$'}F" 2>/dev/null || echo ORIGINAL_UNREADABLE
            done
        done
        echo 'restore_results:'
        if [ -f "${'$'}R/liteweb.log" ] && [ ! -L "${'$'}R/liteweb.log" ]; then
            tail -c 32768 "${'$'}R/liteweb.log" 2>/dev/null | grep -E '^MAPLESU_(RESTORE|MANAGER_UNINSTALL|RECOVERY_UNAVAILABLE) ' | tail -n 16
        fi
        echo 'recovery_state_end'
    """.trimIndent()

    /** Fixed, bounded reads only. Missing/unreadable receipts never become a successful boot. */
    private fun bootDiagnostics(helper: String): String = """
        echo 'current_boot_id:'
        cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo UNREADABLE
        echo 'uptime:'
        cat /proc/uptime 2>/dev/null || echo UNREADABLE
        echo 'boot_completed:'
        getprop sys.boot_completed
        echo 'boot_reason:'
        getprop ro.boot.bootreason
        getprop sys.boot.reason
        H='$helper'
        D='${helper.substringBeforeLast('/')}'
        for name in init ${dev.maplesu.manager.compat.StoredInputs.ENVIRONMENT_VERSION_FILE} init.safe_flag init.boot_fail_protect init.log.enable init.boot_session.work init.boot_session.duplicate init.boot_session.completed; do
            case "${'$'}name" in
                ${dev.maplesu.manager.compat.StoredInputs.ENVIRONMENT_VERSION_FILE}) echo 'file:maplesu.sdk.ver:';;
                *) echo "file:${'$'}name:";;
            esac
            if [ -e "${'$'}D/${'$'}name" ]; then
                stat -c 'uid=%u mode=%a size=%s' "${'$'}D/${'$'}name" 2>/dev/null || echo METADATA_UNREADABLE
            else
                echo MISSING_OR_UNREADABLE
            fi
        done
        for suffix in safe_flag boot_fail_protect log.enable; do
            echo "value:${'$'}suffix:hex:"
            if [ -f "${'$'}H.${'$'}suffix" ] && [ ! -L "${'$'}H.${'$'}suffix" ]; then
                od -An -tx1 -N16 "${'$'}H.${'$'}suffix" 2>/dev/null || echo UNREADABLE
            else
                echo MISSING_OR_UNREADABLE
            fi
        done
        for suffix in boot_session.work boot_session.duplicate boot_session.completed; do
            echo "receipt:${'$'}suffix:"
            if [ -f "${'$'}H.${'$'}suffix" ] && [ ! -L "${'$'}H.${'$'}suffix" ]; then
                head -c 128 "${'$'}H.${'$'}suffix" 2>/dev/null || echo UNREADABLE
            else
                echo MISSING_OR_UNREADABLE
            fi
            echo
        done
        echo 'helper_log_tail:'
        if [ -f "${'$'}H.log" ] && [ ! -L "${'$'}H.log" ]; then
            tail -c 32768 "${'$'}H.log" 2>/dev/null || echo UNREADABLE
        else
            echo MISSING_OR_UNREADABLE
        fi
    """.trimIndent()
}
