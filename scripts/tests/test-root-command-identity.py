"""Replay production Root command identity admission and JNI receipt assembly on the host."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import shutil
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from native_toolchain import jdk_tool

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def block(source, marker):
    """Extract a braced production declaration, ignoring comments and literals."""
    start = source.index(marker)
    opening = source.index("{", start)
    tokens = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]')
    depth = 0
    for token in tokens.finditer(source, opening):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                return source[start:token.end()]
    raise AssertionError("Unclosed production declaration: " + marker)


def write(out, name, value):
    path = out / name
    path.write_text(value, encoding="utf-8")
    return path


KOTLIN_TEST = r'''package dev.maplesu.manager.runtime.ultra
import dev.maplesu.manager.runtime.PageReadDeadline
import dev.maplesu.manager.runtime.ultra.bridge.NativeBridge
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class RootCommandIdentityTest {
 private val denied = """{"schemaVersion":1,"backend":"maplesu_ultra","operation":"run_root_cmd","ok":false,"sdkError":"ERR_MODULE_OPEN_FILE","sdkErrorCode":-19934,"data":{"rootCommand":{"phase":5,"systemError":13,"rootAttempted":false}}}"""
 @Before fun reset() {
  Thread.interrupted(); NativeBridge.calls = 0; NativeBridge.lastCommand = "unset"; NativeBridge.answer = denied
  NativeBridge.deadlineCalls = 0; NativeBridge.callbackCalls = 0
  PageReadDeadline.beforeRead = null; PageReadDeadline.deadline = null
 }
 private fun noSubmission(receipt: NativeReceipt, error: String) {
  assertFalse(receipt.succeeded); assertEquals(error, receipt.sdkError); assertEquals(0, NativeBridge.calls)
 }
 @Test fun keylessCallSubmitsTheCommandOnceAndPreservesTheNativeFailure() {
  val result = UltraRuntimeClient().runRootCommand("id")
  assertEquals(1, NativeBridge.calls); assertEquals("id", NativeBridge.lastCommand); assertEquals(denied, result.raw)
 }
 @Test fun successfulNativeReceiptRetainsOutputAndCompletion() {
  NativeBridge.answer = """{"schemaVersion":1,"backend":"maplesu_ultra","operation":"run_root_cmd","ok":true,"sdkError":"OK","sdkErrorCode":0,"operationCompleted":true,"data":{"result":"uid%3D0","resultBytes":5}}}"""
  val result = UltraRuntimeClient().runRootCommand("id")
  assertTrue(result.succeeded); assertTrue(result.operationCompleted); assertEquals("uid%3D0", result.string("result"))
  assertEquals(1, NativeBridge.calls)
 }
 @Test fun invalidatedCallerScopeDoesNotSubmit() {
  noSubmission(UltraRuntimeClient().scoped { false }.runRootCommand("id"), "SDK_IDENTITY_SCOPE_CHANGED")
 }
 @Test fun invalidatedRunnerScopeDoesNotRunOrFallBackToJni() {
  var count = 0
  val client = UltraRuntimeClient(RootScriptRunner { count++; SuExecResult(0, "unexpected") }).scoped { false }
  noSubmission(client.runRootCommand("id"), "SDK_IDENTITY_SCOPE_CHANGED"); assertEquals(0, count)
 }
 @Test fun identityChangingWhileEnteringAdmissionDoesNotSubmit() {
  var current = true
  val client = UltraRuntimeClient().scoped { current }
  PageReadDeadline.beforeRead = { current = false }
  noSubmission(client.runRootCommand("id"), "SDK_IDENTITY_SCOPE_CHANGED")
 }
 @Test fun nestedScopeKeepsTheParentsInvalidation() {
  var parent = true
  val client = UltraRuntimeClient().scoped { parent }.scoped { true }
  parent = false
  noSubmission(client.runRootCommand("id"), "SDK_IDENTITY_SCOPE_CHANGED")
 }
 @Test fun nestedScopeKeepsTheChildsInvalidation() {
  noSubmission(UltraRuntimeClient().scoped { true }.scoped { false }.runRootCommand("id"), "SDK_IDENTITY_SCOPE_CHANGED")
 }
 @Test fun everySubmissionRechecksTheSameLifetime() {
  var current = true
  val client = UltraRuntimeClient().scoped { current }
  assertEquals(denied, client.runRootCommand("id").raw); current = false
  val result = client.runRootCommand("unexpected")
  assertEquals("SDK_IDENTITY_SCOPE_CHANGED", result.sdkError); assertEquals(1, NativeBridge.calls)
 }
 @Test fun activeScopedRunnerExecutesExactlyOnce() {
  var count = 0
  val client = UltraRuntimeClient(RootScriptRunner { command ->
   count++; assertEquals("id", command); SuExecResult(0, "runner output")
  }).scoped { true }.scoped { true }
  val receipt = client.runRootCommand("id")
  assertTrue(receipt.succeeded); assertEquals("runner+output", receipt.string("result"))
  assertEquals(1, count); assertEquals(0, NativeBridge.calls)
 }
 @Test fun runnerExitFailureIsNeverReplayedThroughJni() {
  var count = 0
  val client = UltraRuntimeClient(RootScriptRunner { count++; SuExecResult(7, "runner output") })
  val receipt = client.runRootCommand("id")
  assertEquals(1, count); assertEquals(0, NativeBridge.calls); assertEquals("MAPLESU_ROOT_COMMAND_EXIT", receipt.sdkError)
  assertEquals("runner+output", receipt.string("result")); assertEquals(7, receipt.int("exitCode"))
 }
 @Test fun missingRunnerResponseIsNotReplayedThroughJni() {
  var count = 0
  val client = UltraRuntimeClient(RootScriptRunner { count++; null })
  assertEquals("MAPLESU_ROOT_CHANNEL_UNAVAILABLE", client.runRootCommand("id").sdkError)
  assertEquals(1, count); assertEquals(0, NativeBridge.calls)
 }
 @Test fun timedOutRunnerIsNotReplayedThroughJni() {
  var count = 0
  val client = UltraRuntimeClient(RootScriptRunner { count++; SuExecResult(-1, "partial", timedOut = true) })
  assertEquals("MAPLESU_ROOT_COMMAND_TIMEOUT", client.runRootCommand("id").sdkError)
  assertEquals(1, count); assertEquals(0, NativeBridge.calls)
 }
 @Test fun runnerIoFailureIsNotReplayedThroughJni() {
  var count = 0
  val client = UltraRuntimeClient(RootScriptRunner { count++; SuExecResult(-1, "partial", failure = "EIO") })
  assertEquals("MAPLESU_ROOT_COMMAND_IO_FAILURE", client.runRootCommand("id").sdkError)
  assertEquals(1, count); assertEquals(0, NativeBridge.calls)
 }
 @Test fun runnerExceptionIsReportedOnceWithoutTransportReplay() {
  var count = 0
  val client = UltraRuntimeClient(RootScriptRunner { count++; throw IllegalStateException("runner fixture") })
  assertEquals("MAPLESU_BRIDGE_EXCEPTION", client.runRootCommand("id").sdkError)
  assertEquals(1, count); assertEquals(0, NativeBridge.calls)
 }
 @Test fun expiredAdmissionDoesNotSubmit() {
  PageReadDeadline.deadline = System.nanoTime() - 1
  val receipt = UltraRuntimeClient().runRootCommand("id")
  noSubmission(receipt, "MAPLESU_SDK_DEADLINE_EXCEEDED")
  assertEquals(-1007, receipt.sdkErrorCode); assertEquals(0, NativeBridge.deadlineCalls)
  assertEquals(0, NativeBridge.callbackCalls)
 }
 @Test fun activeDeadlinePassesTheExactLimitAndInvokesTheCallbackOnce() {
  val deadline = System.nanoTime() + 1_000_000_000L
  PageReadDeadline.deadline = deadline
  val receipt = UltraRuntimeClient().runRootCommand("id")
  assertEquals(denied, receipt.raw); assertEquals(1, NativeBridge.calls)
  assertEquals(1, NativeBridge.deadlineCalls); assertEquals(1, NativeBridge.callbackCalls)
  assertEquals("run_root_cmd", NativeBridge.deadlineOperation)
  assertEquals(deadline, NativeBridge.deadlineNanos)
 }
 @Test fun cancelledAdmissionDoesNotSubmit() {
  Thread.currentThread().interrupt()
  try { noSubmission(UltraRuntimeClient().runRootCommand("id"), "MAPLESU_SDK_INTERRUPTED") }
  finally { Thread.interrupted() }
 }
}
'''


def kotlin(out, client_text, receipt_text):
    imports = '''package dev.maplesu.manager.runtime.ultra
import dev.maplesu.manager.runtime.ultra.bridge.NativeBridge
import dev.maplesu.manager.runtime.PageReadDeadline
import java.util.concurrent.CancellationException
'''
    methods = [block(client_text, marker) for marker in ["private fun call(", "private fun deadlineExceeded(",
        "private fun localCall(", "internal fun scoped(", "internal constructor(rootCommands:",
        "fun runRootCommand(", "private fun callWithIdentity(", "companion object {"]]
    # deadlineExceeded() is an expression function; its next brace belongs to localCall().
    methods[1] = client_text[client_text.index("private fun deadlineExceeded("):client_text.index("    // Compiled identity")].strip()
    methods[3] = client_text[client_text.index("internal fun scoped("):client_text.index("    /** Read-only readiness")].strip()
    assembled = imports + '''class UltraRuntimeClient() {
 private var rootCommands: RootScriptRunner? = null
 private var identityCurrent: () -> Boolean = { true }
 private var legacyCredential: UltraLegacyCredential? = null
 private val loadFailure: String? = null
''' + "\n".join(methods) + "\n}\n"
    types = block(client_text, "internal fun interface RootScriptRunner") + "\n" + block(
        (ROOT / "manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraSuChannel.kt").read_text(encoding="utf-8-sig"),
        "data class SuExecResult(")
    sources = [write(out, "UltraRuntimeClient.kt", assembled),
        write(out, "RuntimeTypes.kt", "package dev.maplesu.manager.runtime.ultra\n" + types),
        write(out, "NativeReceipt.kt", "package dev.maplesu.manager.runtime.ultra\nimport org.json.*\nimport java.net.URLEncoder\n" + block(receipt_text, "data class NativeReceipt(")),
        write(out, "RootCommandIdentityTest.kt", KOTLIN_TEST),
        write(out, "Fixtures.kt", '''package dev.maplesu.manager.runtime.ultra
class UltraAuthorizationResult { companion object { fun parse(value: org.json.JSONObject?): UltraAuthorizationResult? = null } }
class UltraLegacyCredential(val value: String)
object UltraSdkLogging { fun redact(value: String?) = value.orEmpty() }
'''),
        write(out, "Deadline.kt", '''package dev.maplesu.manager.runtime
object PageReadDeadline { var beforeRead: (() -> Unit)? = null; var deadline: Long? = null; fun currentNanos(): Long? { beforeRead?.invoke(); return deadline } }
'''),
        write(out, "StoredInputs.kt", '''package dev.maplesu.manager.compat
object StoredInputs { fun receiptBackend(value: String) = value; fun error(value: String) = value }
''')]
    bridge_source = (ROOT / "manager/src/main/java/dev/maplesu/manager/runtime/ultra/bridge/NativeBridge.java").read_text(encoding="utf-8-sig")
    declaration = re.search(r"public static native String runRootCmd\([^;]*;", bridge_source)
    assert declaration, "Production Root command JNI declaration is absent"
    bridge_method = declaration[0].replace(" native ", " ").removesuffix(";") + " { calls++; lastCommand = cmd; return answer; }"
    deadline_declaration = re.search(r"public static native String invokeWithDeadline\([^;]*;", bridge_source)
    legacy_declaration = re.search(r"public static native String invokeWithLegacyCredential\([^;]*;", bridge_source)
    assert deadline_declaration and legacy_declaration, "Production callback JNI declarations are absent"
    deadline_method = deadline_declaration[0].replace(" native ", " ").removesuffix(";") + (
        " { deadlineCalls++; NativeBridge.deadlineNanos = deadlineNanos; deadlineOperation = operation; "
        "callbackCalls++; try { return callback.call(); } catch (Exception error) { throw new RuntimeException(error); } }")
    legacy_method = legacy_declaration[0].replace(" native ", " ").removesuffix(";") + (
        " { try { return callback.call(); } catch (Exception error) { throw new RuntimeException(error); } }")
    bridge = write(out, "NativeBridge.java", "package dev.maplesu.manager.runtime.ultra.bridge;\n" +
        "public final class NativeBridge {\n public static int calls; public static String lastCommand, answer;\n " +
        "public static int deadlineCalls, callbackCalls; public static long deadlineNanos; public static String deadlineOperation;\n" +
        bridge_method + "\n" + deadline_method + "\n" + legacy_method + "\n}\n")
    deps = [cached_jar(*item) for item in [("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"), ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.json", "json", "20240303"), ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3")]]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    java, javac = jdk_tool(), jdk_tool("javac")
    classes = out / "classes"
    classes.mkdir(exist_ok=True)
    cp = os.pathsep.join(map(str, [classes, *deps]))
    return [[java, "-Xmx256m", "-cp", os.pathsep.join(map(str, [compiler, *deps])),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-nowarn", "-jvm-target", "21",
        "-classpath", cp, "-d", classes, *sources, bridge],
        [javac, "-encoding", "UTF-8", "-cp", cp, "-d", classes, bridge],
        [java, "-cp", cp, "org.junit.runner.JUnitCore", "dev.maplesu.manager.runtime.ultra.RootCommandIdentityTest"]]


def native(out, source, selected):
    helpers = [block(source, name) for name in ["std::string jstring_to_utf8(", "std::string url_encode_copy(",
        "cJSON* begin(", "void mark_ok(", "void mark_sdk_error(", "void mark_bridge_error(",
        "void mark_call_bridge_error(", "jstring finish(", "struct JsonDeleter", "cJSON* owner_u64(",
        "cJSON* owner_error(", "bool attach_owned_json(cJSON* object, const char* field, cJSON* child) {",
        "cJSON* owner_root_command_json(", "cJSON* root_command_result_json(",
        "template <typename Body>\njstring guarded(", "KModErr authenticated_primary_error(",
        "void authenticated_receipt_alloc(", "void mark_authenticated_ok(", "void restore_authenticated_mode(",
        "template <typename Body>\njstring guarded_authenticated("]]
    helpers[8] += ";\nusing OwnedJson = std::unique_ptr<cJSON, JsonDeleter>;"
    method = block(source, 'extern "C" JNIEXPORT jstring JNICALL\nJava_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_runRootCmd(')
    write(out, "root_command_production.inc", "\n\n".join(helpers) + "\n\n" + method)
    binary = out / "native-root-identity.exe"
    return [[(os.environ.get("CXX") or shutil.which("g++") or "g++"), "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
        "-I" + str(out), "-I" + str(selected / "runtime/ultra/bridge"), "-I" + str(ROOT / "runtime/ultra/bridge"),
        "-I" + str(ROOT / "runtime/maplesu-sdk/include"), "-I" + str(ROOT / "runtime/maplesu-sdk/sdk/include"),
        "-I" + str(ROOT / "runtime/ultra/third_party/cJSON"), "-I" + str(ROOT / "runtime/ultra/third_party/include"),
        choose(selected, ROOT / "runtime/tests/ultra_root_command_identity_test.cpp"), ROOT / "runtime/ultra/third_party/cJSON/cJSON.cpp",
        "-static-libgcc", "-static-libstdc++", "-o", binary], [binary]]


def choose(selected, path):
    candidate = selected / path.relative_to(ROOT)
    return candidate if candidate.is_file() else path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT, help="Read selected test/bridge candidates from this tree; other sources stay read-only")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    selected = args.source_root.resolve()
    paths = [choose(selected, ROOT / name) for name in ["runtime/ultra/bridge/native_lib_ultra.cpp",
        "manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraRuntimeClient.kt",
        "manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraReceipt.kt",
        "manager/src/main/java/dev/maplesu/manager/runtime/ultra/bridge/NativeBridge.java",
        "manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraSuChannel.kt",
        "runtime/ultra/bridge/manager_owner_identity.h", "runtime/maplesu-sdk/sdk/include/maplesu_root_command_private.h",
        "runtime/maplesu-sdk/include/maplesu_sdk/maplesu_root.h", "runtime/maplesu-sdk/sdk/include/maplesu_request_private.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_root_private.h", "runtime/ultra/bridge/manager_owner_root_probe.h", "runtime/ultra/bridge/sdk_call_scope.h",
        "runtime/ultra/bridge/sdk_error_receipt.h", "runtime/ultra/third_party/cJSON/cJSON.cpp",
        "runtime/tests/ultra_root_command_identity_test.cpp", "scripts/tests/test-root-command-identity.py"]]
    digests = {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    texts = [path.read_text(encoding="utf-8-sig") for path in paths[:3]]
    runs = {}
    for name, commands in [("kotlin", kotlin(out, texts[1], texts[2])), ("native", native(out, texts[0], selected))]:
        logs = []
        codes = []
        for command in commands:
            env = os.environ.copy()
            env["PATH"] = str(Path(shutil.which(os.environ.get("CXX") or "g++") or os.environ.get("CXX") or "g++").resolve().parent) + os.pathsep + env["PATH"]
            result = subprocess.run(list(map(str, command)), cwd=ROOT, env=env, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=55)
            codes.append(result.returncode)
            logs.append(result.stdout + result.stderr)
            if result.returncode:
                break
        write(out, name + ".log", "\n".join(logs))
        runs[name] = dict(exitCodes=codes, passed=all(code == 0 for code in codes))
        print(name + ": " + str(codes) + "\n" + "\n".join(logs))
    unchanged = all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name, digest in digests.items())
    record = dict(passed=all(run["passed"] for run in runs.values()) and unchanged, runs=runs,
        recordedAt=datetime.now(timezone.utc).isoformat(), sourceSha256=digests, inputsUnchanged=unchanged,
        deviceAccess=False, sdkBuild=False, apkBuild=False,
        scope="Extracted production Kotlin identity lifetime/admission/routing/receipt and real RootScriptRunner/SuExecResult declarations and JNI method/guards/JSON with real cJSON, SDK diagnostic types and RequestAuthModeScope; keyless public Root declarations are included without legacy overloads. JNI VM, SDK execution, auth transport, SDK admission and Android observations are host fixtures. No device Root result is asserted.")
    write(out, "RESULT.json", json.dumps(record, indent=2) + "\n")
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
