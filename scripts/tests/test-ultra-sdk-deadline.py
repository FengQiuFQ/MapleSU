"""Exercise current production SDK admission and JNI deadline scopes on the host."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
block = runpy.run_path(str(ROOT / "scripts/tests/test-root-command-identity.py"))["block"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    inputs = ["runtime/ultra/bridge/native_lib_ultra.cpp", "runtime/ultra/bridge/sdk_call_scope.cpp",
              "runtime/ultra/bridge/sdk_call_scope.h", "runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h",
              "runtime/tests/ultra_sdk_deadline_test.cpp", "runtime/tests/ultra_sdk_deadline_jni_test.cpp",
              "runtime/ultra/third_party/cJSON/cJSON.cpp", "runtime/ultra/third_party/cJSON/cJSON.h",
              "scripts/tests/test-ultra-sdk-deadline.py"]
    def hashes():
        return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}
    before = hashes()
    source = (ROOT / inputs[0]).read_text(encoding="utf-8-sig")
    markers = ["std::string jstring_to_utf8(", "cJSON* begin(", "void mark_bridge_error(", "jstring finish(",
               'extern "C" JNIEXPORT jstring JNICALL\nJava_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_invokeWithDeadline(']
    (out / "deadline_jni_production.inc").write_text("\n\n".join(block(source, marker) for marker in markers), encoding="utf-8")
    shell = """set -eu
C=/opt/ddk/clang/clang-r510928
for T in scope jni; do
  if [ "$T" = scope ]; then S=ultra_sdk_deadline_test.cpp; else S=ultra_sdk_deadline_jni_test.cpp; fi
  $C/bin/clang++ -std=c++17 -stdlib=libc++ -pthread -O1 -Wall -Wextra -Werror -Wno-unused-function -I/out -I/repo/runtime/ultra/bridge -I/repo/runtime/ultra/third_party/cJSON -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu -Wl,--wrap=fork -Wl,--wrap=pipe2 -Wl,--wrap=waitpid -Wl,--wrap=close /repo/runtime/tests/$S /repo/runtime/ultra/bridge/sdk_call_scope.cpp /repo/runtime/ultra/third_party/cJSON/cJSON.cpp -o /out/deadline-$T.test
  /out/deadline-$T.test
done
"""
    command = ["docker", "run", "--rm", "--network", "none", "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
               "--mount", f"type=bind,source={out},target=/out", "--entrypoint", "sh",
               "ghcr.io/ylarod/ddk-min:android15-6.6-20260828", "-c", shell]
    started = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    (out / "run.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    after = hashes()
    record = {"recordedAt": datetime.now(timezone.utc).isoformat(), "command": command,
              "exitCode": result.returncode, "seconds": time.monotonic() - started,
              "inputsBefore": before, "inputsAfter": after, "sourceStable": before == after,
              "scope": "Current bridge admission and JNI function bodies; VM and SDK deadline TLS storage are fixtures.",
              "sdkBuild": False, "apkBuild": False, "deviceExecuted": False}
    (out / "RESULT.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(result.stdout + result.stderr)
    raise SystemExit(result.returncode if result.returncode else 0 if before == after else 2)


if __name__ == "__main__":
    main()
