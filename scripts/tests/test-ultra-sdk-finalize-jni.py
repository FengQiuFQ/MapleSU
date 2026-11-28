"""Run the real SDK scope and extracted production JNI guard through final cleanup."""
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
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = ["runtime/ultra/bridge/native_lib_ultra.cpp", "runtime/ultra/bridge/sdk_call_scope.cpp",
               "runtime/ultra/bridge/sdk_call_scope.h", "runtime/ultra/bridge/sdk_error_receipt.h",
               "runtime/ultra/bridge/su_authorization_receipt.h",
               "runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h",
               "runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h",
               "runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h",
               "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/su_auth_result_private.h",
               "runtime/ultra/third_party/cJSON/cJSON.cpp", "runtime/ultra/third_party/cJSON/cJSON.h",
               "runtime/tests/ultra_sdk_finalize_jni_test.cpp", "scripts/tests/test-ultra-sdk-finalize-jni.py",
               "scripts/tests/test-root-command-identity.py"]

    def hashes():
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources}

    before = hashes()
    block = runpy.run_path(str(root / sources[-1]))["block"]
    production = (root / sources[0]).read_text(encoding="utf-8-sig")
    markers = ["cJSON* begin(", "void mark_ok(", "void mark_sdk_error(", "void mark_bridge_error(",
               "void mark_call_bridge_error(", "jstring finish(", "template <typename Body>\njstring guarded("]
    (out / "sdk_finalize_production.inc").write_text("\n\n".join(block(production, m) for m in markers), encoding="utf-8")
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--cpus", "1", "--memory", "512m", "--tmpfs", "/tmp:rw,size=32m",
              "--mount", f"type=bind,source={root},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/case", "-w", "/case",
              "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"]
    includes = ["/case", "/repo/runtime/ultra/bridge", "/repo/runtime/ultra/third_party/cJSON",
                "/repo/runtime/maplesu-sdk/include", "/repo/runtime/maplesu-sdk/sdk/include"]
    compile_argv = ["g++", "-std=c++17", "-O1", "-g", "-pthread", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                    *["-I" + name for name in includes], "/repo/runtime/tests/ultra_sdk_finalize_jni_test.cpp",
                    "/repo/runtime/ultra/third_party/cJSON/cJSON.cpp", "-Wl,--wrap=pthread_create",
                    "-o", "sdk-finalize-jni.test"]
    records = []
    for stage, argv in [("compile", compile_argv), ("run", ["./sdk-finalize-jni.test"])]:
        started = time.monotonic()
        result = subprocess.run(docker + argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=55)
        output = result.stdout + result.stderr
        (out / f"{stage}.log").write_text(output, encoding="utf-8")
        print(output, end="")
        records.append(dict(stage=stage, argv=docker + argv, exitCode=result.returncode, seconds=time.monotonic() - started))
        if result.returncode:
            break
    after = hashes()
    passed = len(records) == 2 and all(r["exitCode"] == 0 for r in records) and before == after
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=passed, stages=records,
                  inputsBefore=before, inputsAfter=after, sourcesStable=before == after,
                  deviceOperations=0, formalBuild=False,
                  scope="Real SDK scope, registry, FD/cleanup worker and extracted actual JNI guard/JSON functions. "
                        "JNI VM and explicit libc faults are fixture seams; no Android Root, SDK/APK build or device qualification.")
    (out / "RESULT.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
