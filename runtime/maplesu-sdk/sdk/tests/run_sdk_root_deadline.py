#!/usr/bin/env python3
"""Replay selected complete m060/m046 with real m023 deadline and host Root boundary seams."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from run_sdk_operation_deadline import IMAGE, ROOT, SDK


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--host-32", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    tree = args.baseline.resolve() if args.baseline else ROOT
    root_path = tree / "runtime/maplesu-sdk/sdk/src/maplesu_core/maplesu_root.cpp"
    fork_path = tree / "runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp"
    context_path = ROOT / "runtime/ultra/authorization/request_context.cpp"
    fixture_path = SDK / "tests/sdk_root_deadline.cpp"
    seam_path = SDK / "tests/root_vendor_order_fixture.cpp"
    inputs = [root_path, fork_path, context_path, fixture_path, seam_path, Path(__file__),
              SDK / "tests/run_sdk_operation_deadline.py", SDK / "include/maplesu_root_private.h",
              SDK / "include/maplesu_root_command_private.h", SDK / "include/maplesu_request_private.h",
              SDK / "include/maplesu_deadline_private.h", SDK / "include/maplesu_operation_wait_private.h",
              SDK / "include/maplesu_operation_fork_private.h",
              SDK / "src/maplesu/compat/fork_legacy_abi.h", SDK / "src/maplesu/compat/fork_exports_legacy_abi.h",
              SDK / "src/maplesu/compat/root_legacy_abi.h", SDK / "src/maplesu_core/fixed_transfer_io.h",
              ROOT / "runtime/maplesu-sdk/include/module_err_def.h",
              ROOT / "runtime/ultra/authorization/request_protocol.h"]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    seam = seam_path.read_text(encoding="utf-8").split("\nnamespace {\nunsigned checks, failures, scenarios;")[0]
    seam = seam.replace('extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return 0; }', "")
    seam = seam.replace("// EXACT_ROOT_SOURCE", '#include "/repo/' + root_path.relative_to(ROOT).as_posix() + '"')
    generated = fixture_path.read_text(encoding="utf-8").replace("// EXACT_ROOT_FIXTURE_PREFIX", seam)
    (out / "sdk_root_deadline.cpp").write_text(generated, encoding="utf-8")
    (out / "fork_pipe.cpp").write_bytes(fork_path.read_bytes())
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:rw,size=32m", "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/work", "-w", "/work", IMAGE]
    compile_command = docker + ["g++", "-std=c++20", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                               "-pthread", "-I/repo/runtime/maplesu-sdk/sdk/include",
                               "-I/repo/runtime/maplesu-sdk/include", "-I/repo/runtime/maplesu-sdk/sdk/src",
                               "-I/repo/runtime/maplesu-sdk/sdk/src/maplesu/process",
                               "-I/repo/runtime/maplesu-sdk/sdk/src/maplesu_core", "sdk_root_deadline.cpp",
                               "fork_pipe.cpp", "/repo/runtime/ultra/authorization/request_context.cpp",
                               "-Wl,--wrap=pipe2", "-o", "sdk-root-deadline"]
    if args.baseline:
        compile_command += ["-DMAPLESU_DEADLINE_BASELINE"]
    if args.host_32:
        compile_command += ["-m32"]
    commands = []
    for name, command in (("compile", compile_command), ("run", docker + ["./sdk-root-deadline"])):
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                   timeout=90)
        output = completed.stdout + completed.stderr
        (out / f"{name}.log").write_text(output, encoding="utf-8")
        commands.append({"name": name, "argv": command, "exit": completed.returncode, "output": output})
        if completed.returncode:
            break
    stable = all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in before.items())
    passed = len(commands) == 2 and all(item["exit"] == 0 for item in commands) and stable
    report = {"passed": passed, "baseline": bool(args.baseline), "hostBits": 32 if args.host_32 else 64,
              "sources": before,
              "sourcesUnchanged": stable, "commands": commands,
              "scope": "complete selected m060/m046 translation units; actual m023 TLS; real host "
                       "pipe/fork/shell/child wait; Root credentials/session APIs explicit fixture seams; "
                       "unknown effects and pending reaping remain unconfirmed; no device/real kernel latency claim"}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
