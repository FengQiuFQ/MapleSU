#!/usr/bin/env python3
"""Test actual selected SDK pipe source and exact environment wait with host processes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"


def extract(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--baseline", type=Path,
                        help="Frozen pre-fix tree; deadline fixture is injected only for the red run")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    tree = args.baseline.resolve() if args.baseline else ROOT
    fork_path = tree / "runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp"
    context_path = tree / "runtime/ultra/authorization/request_context.cpp"
    environment_path = tree / "runtime/ultra/boot/environment_state.cpp"
    fixture_path = SDK / "tests/sdk_operation_deadline.cpp"
    inputs = [fork_path, context_path, environment_path, fixture_path, Path(__file__),
              SDK / "src/maplesu/compat/fork_legacy_abi.h",
              SDK / "src/maplesu/compat/fork_exports_legacy_abi.h",
              SDK / "src/maplesu_core/fixed_transfer_io.h",
              ROOT / "runtime/maplesu-sdk/include/module_err_def.h"]
    if not args.baseline:
        inputs += [SDK / "include/maplesu_deadline_private.h",
                   SDK / "include/maplesu_operation_wait_private.h",
                   SDK / "include/maplesu_operation_fork_private.h"]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    wait_body = extract(environment_path.read_text(encoding="utf-8"),
                        'extern "C" pid_t maplesu_wait_environment_child(')
    generated = fixture_path.read_text(encoding="utf-8").replace("// EXACT_ENVIRONMENT_WAIT", wait_body)
    # Relative fixture headers are bound to the actual repository, even for frozen source input.
    generated = generated.replace('"../src/', '"/repo/runtime/maplesu-sdk/sdk/src/')
    (out / "sdk_operation_deadline.cpp").write_text(generated, encoding="utf-8")
    (out / "fork_pipe.cpp").write_bytes(fork_path.read_bytes())
    if not args.baseline:
        (out / "request_context.cpp").write_bytes(context_path.read_bytes())
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:rw,size=32m", "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/work", "-w", "/work", IMAGE]
    compile_command = docker + ["g++", "-std=c++20", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                               "-pthread", "-I/repo/runtime/maplesu-sdk/sdk/include",
                               "-I/repo/runtime/maplesu-sdk/include",
                               "-I/repo/runtime/maplesu-sdk/sdk/src/maplesu/process",
                               "sdk_operation_deadline.cpp", "fork_pipe.cpp"]
    compile_command += (["-DMAPLESU_DEADLINE_BASELINE"] if args.baseline else ["request_context.cpp"])
    compile_command += ["-Wl,--wrap=syscall", "-o", "sdk-operation-deadline"]
    commands = []
    for name, command in (("compile", compile_command), ("run", docker + ["./sdk-operation-deadline"])):
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                   timeout=90)
        output = completed.stdout + completed.stderr
        (out / f"{name}.log").write_text(output, encoding="utf-8")
        commands.append({"name": name, "argv": command, "exit": completed.returncode, "output": output})
        if completed.returncode:
            break
    stable = all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in before.items())
    passed = len(commands) == 2 and all(command["exit"] == 0 for command in commands) and stable
    report = {"passed": passed, "baseline": bool(args.baseline), "sources": before,
              "sourcesUnchanged": stable, "commands": commands,
              "scope": "actual selected m046 full translation unit; exact m257 wait; "
                       + ("injected TLS deadline fixture for pre-fix red run" if args.baseline else
                          "actual m023 TLS definition") + "; host only, no device or kernel latency claim"}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
