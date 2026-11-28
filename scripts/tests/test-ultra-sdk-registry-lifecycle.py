"""Exercise the real bridge pipe registry, owner lifetime and final cleanup receipt."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tsan", action="store_true", help="Also run ThreadSanitizer; preserve any startup failure.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = ["runtime/ultra/bridge/sdk_call_scope.cpp", "runtime/ultra/bridge/sdk_call_scope.h",
               "runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h",
               "runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h",
               "runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h",
               "runtime/tests/ultra_sdk_registry_lifecycle_test.cpp",
               "scripts/tests/test-ultra-sdk-registry-lifecycle.py"]

    def hashes():
        return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources}

    before = hashes()
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--cpus", "1", "--memory", "512m", "--tmpfs", "/tmp:rw,size=32m",
              "--mount", f"type=bind,source={root},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/case", "-w", "/case",
              "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"]
    records = []
    for sanitizer, label in [("address,undefined", "asan-ubsan"), *([("thread", "tsan")] if args.tsan else [])]:
        binary = f"registry-{label}.test"
        compile_argv = ["g++", "-std=c++17", "-O1", "-g", "-pthread", "-Wall", "-Wextra", "-Werror",
                        f"-fsanitize={sanitizer}", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                        "/repo/runtime/tests/ultra_sdk_registry_lifecycle_test.cpp",
                        "-Wl,--wrap=pthread_create", "-o", binary]
        for stage, argv in [(f"compile-{label}", compile_argv), (f"run-{label}", [f"./{binary}"])]:
            started = time.monotonic()
            result = subprocess.run(docker + argv, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=55)
            output = result.stdout + result.stderr
            (out / f"{stage}.log").write_text(output, encoding="utf-8")
            print(output, end="")
            records.append(dict(stage=stage, argv=docker + argv, exitCode=result.returncode,
                                seconds=time.monotonic() - started))
            if stage.startswith("compile-") and result.returncode:
                break
    after = hashes()
    passed = len(records) == (4 if args.tsan else 2) and all(r["exitCode"] == 0 for r in records) and before == after
    outputs = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in out.iterdir() if path.is_file()}
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=passed, stages=records,
                  inputsBefore=before, inputsAfter=after, sourcesStable=before == after, outputs=outputs,
                  threadSanitizerRequested=args.tsan, deviceOperations=0, formalBuild=False,
                  scope="Real sdk_call_scope.cpp wrappers, registry/admission mutexes, fork, FD reuse and cleanup worker. "
                        "Libc boundaries provide explicit faults and events; no Android Root or complete SDK/APK/device qualification.")
    (out / "RESULT.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
