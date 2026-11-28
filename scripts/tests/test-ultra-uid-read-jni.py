"""Exercise the actual UID-read JNI body and guards with typed SDK results."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path, help="Saved production native_lib_ultra.cpp")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    root = args.repo.resolve() if args.repo else Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve() if args.source else root / "runtime/ultra/bridge/native_lib_ultra.cpp"
    fixture = args.fixture.resolve() if args.fixture else root / "runtime/tests/ultra_uid_read_jni_test.cpp"
    fixture_container = "/repo/" + fixture.relative_to(root).as_posix()
    fixture_scope = fixture.parent.parent / "ultra/bridge/sdk_call_scope.cpp"
    sources = [source, fixture, Path(__file__).resolve(), fixture_scope, *[root / name for name in [
        "runtime/ultra/bridge/sdk_call_scope.cpp", "runtime/ultra/bridge/sdk_call_scope.h",
        "runtime/ultra/bridge/sdk_error_receipt.h", "runtime/ultra/bridge/su_authorization_receipt.h",
        "runtime/ultra/bridge/manager_owner_identity.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_request_private.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h",
        "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/su_auth_result_private.h",
        "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/su_uid_profile_private.h",
        "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/su_uid_read_result_private.h",
        "runtime/maplesu-sdk/include/maplesu_sdk/maplesu_su_auth.h",
        "runtime/ultra/third_party/include/urlEncodeUtils.h",
        "runtime/ultra/third_party/cJSON/cJSON.cpp", "runtime/ultra/third_party/cJSON/cJSON.h",
        "runtime/tests/ultra_uid_read_jni_test.cpp", "scripts/tests/test-ultra-uid-read-jni.py",
        "scripts/tests/test-root-command-identity.py"]]]

    def hashes():
        return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}

    before = hashes()
    block = runpy.run_path(str(root / "scripts/tests/test-root-command-identity.py"))["block"]
    production = source.read_text(encoding="utf-8-sig")
    markers = ["std::string url_encode_copy(", "cJSON* begin(", "void mark_ok(", "void mark_sdk_error(",
               "void mark_bridge_error(", "void mark_call_bridge_error(", "jstring finish(",
               "struct JsonDeleter", "bool attach_owned_json(cJSON* object, const char* field, cJSON* child) {",
               "template <typename Body>\njstring guarded(", "KModErr authenticated_primary_error(",
               "void authenticated_receipt_alloc(", "void mark_authenticated_ok(",
               "void restore_authenticated_mode(", "template <typename Body>\njstring guarded_authenticated("]
    declarations = [block(production, marker) for marker in markers]
    declarations[7] += ";\nusing OwnedJson = std::unique_ptr<cJSON, JsonDeleter>;"
    if "cJSON* write_uid_read_result(" in production:
        declarations.append(block(production, "cJSON* write_uid_read_result("))
    declarations.append(block(production, "struct SuRuntimeReadResult") + ";")
    declarations.append(block(production, "cJSON* write_su_runtime_read_result("))
    for method in ["getSuAuthList", "getSuUidProfiles", "getSuRuntimeStatus"]:
        declarations.append(block(production, 'extern "C" JNIEXPORT jstring JNICALL\n'
            "Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_" + method + "("))
    (out / "uid_read_production.inc").write_text("\n\n".join(declarations) + "\n", encoding="utf-8")
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--cpus", "1", "--memory", "512m", "--tmpfs", "/tmp:rw,size=32m",
              "--mount", f"type=bind,source={root},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/case", "-w", "/case",
              "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"]
    includes = ["/case", "/repo/runtime/ultra/bridge", "/repo/runtime/ultra/third_party/cJSON",
                "/repo/runtime/ultra/third_party/include", "/repo/runtime/tests", "/repo/runtime/maplesu-sdk/include",
                "/repo/runtime/maplesu-sdk/sdk/include"]
    compile_argv = ["g++", "-std=c++17", "-O1", "-g", "-pthread", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "-fno-pie", "-no-pie", *["-I" + name for name in includes],
                    fixture_container,
                    "/repo/runtime/ultra/third_party/cJSON/cJSON.cpp", "-o", "uid-read-jni.test"]
    records = []
    for stage, argv in [("compile", compile_argv), ("run", ["./uid-read-jni.test"])]:
        started = time.monotonic()
        result = subprocess.run(docker + argv, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=55)
        output = result.stdout + result.stderr
        (out / f"{stage}.log").write_text(output, encoding="utf-8")
        print(output, end="")
        records.append(dict(stage=stage, argv=docker + argv, exitCode=result.returncode,
                            seconds=time.monotonic() - started))
        if result.returncode:
            break
    after = hashes()
    passed = len(records) == 2 and all(record["exitCode"] == 0 for record in records) and before == after
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=passed, stages=records,
                  inputsBefore=before, inputsAfter=after, sourcesStable=before == after,
                  deviceOperations=0, formalBuild=False,
                  scope="Extracted actual production UID/package-list JNI functions, JSON guards and real SDK scope. "
                        "SDK typed outputs, authentication storage and VM publication use explicit fixture seams; "
                        "no real UID gateway, Android Root, complete SDK/APK or device qualification.")
    (out / "RESULT.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
