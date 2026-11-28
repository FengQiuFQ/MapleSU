"""Exercise the full selected m023 source at the actual raw-syscall boundary."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "runtime/maplesu-sdk/sdk"
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--host-32", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    tree = args.baseline.resolve() if args.baseline else ROOT
    request = tree / "runtime/maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp"
    fork_path = tree / "runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp"
    seam_path = ROOT / "runtime/tests/ultra_sdk_keyless_transport_test.cpp"
    fixture_path = ROOT / "runtime/tests/ultra_sdk_operation_deadline_test.cpp"
    sources = [request, fork_path, seam_path, fixture_path, Path(__file__),
               SDK / "include/maplesu_deadline_private.h", SDK / "include/maplesu_operation_wait_private.h",
               SDK / "include/maplesu_operation_fork_private.h",
               SDK / "include/maplesu_request_private.h", SDK / "include/maplesu_request_identity.h",
               SDK / "src/module/module_current_identity.cpp", ROOT / "runtime/ultra/authorization/request_context.cpp",
               ROOT / "runtime/ultra/authorization/kernel_read.cpp",
               ROOT / "runtime/ultra/authorization/kernel_read_metadata.h",
               ROOT / "runtime/ultra/authorization/request_protocol.h"]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    prefix = seam_path.read_text(encoding="utf-8").split("\nint main() {")[0]
    prefix = prefix.replace('#include "../maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp"',
                            '#include "/work/module_base_kernel_request.cpp"')
    prefix = prefix.replace("case MAPLESU_REQUEST_ALLOC:",
                            "case MAPLESU_REQUEST_CRED_ROOT:\n"
                            "    response.metadata_length = MAPLESU_EFFECT_COMMITTED; break;\n"
                            "case MAPLESU_REQUEST_ALLOC:")
    prefix = prefix.replace("r.response_user > UINT32_MAX",
                            "(sizeof(uintptr_t) == 4 || r.response_user > UINT32_MAX)")
    prefix = prefix.replace("const auto& r = *reinterpret_cast<const maplesu_request_owner_v3*>(pointer);",
                            "check(sizeof(uintptr_t) != 4 || (pointer >> 32) == 0,\n"
                            "        \"32-bit producer zero extends frame pointer to unchanged u64 wire\");\n"
                            "    const auto& r = *reinterpret_cast<const maplesu_request_owner_v3*>(pointer);")
    prefix = prefix.replace("std::memcpy(reinterpret_cast<void*>(r.response_user), &response, sizeof(response));",
                            "std::memcpy(reinterpret_cast<void*>(r.response_user), &response, sizeof(response));\n"
                            "    if (r.command == expire_on_command) maplesu_request_set_operation_deadline_nanos(1);")
    fixture = fixture_path.read_text(encoding="utf-8").replace("// EXACT_TRANSPORT_FIXTURE_PREFIX", prefix)
    (out / "operation_deadline.cpp").write_text(fixture, encoding="utf-8")
    (out / "module_base_kernel_request.cpp").write_bytes(request.read_bytes())
    (out / "fork_pipe.cpp").write_bytes(fork_path.read_bytes())
    (out / "kernel_module_kit_umbrella.h").write_text('#pragma once\n#include "module_err_def.h"\n', encoding="utf-8")
    (out / "module_base_kernel_mem.h").write_text('#pragma once\n#include <cstdint>\n'
                                                'namespace kernel_module {uint32_t get_page_size();}\n', encoding="utf-8")
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:rw,size=32m", "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
              "--mount", f"type=bind,source={out},target=/work", "-w", "/work", IMAGE]
    compile_command = docker + ["g++", "-std=c++20", "-O1", "-g", "-pthread",
                               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                               "-I/work", "-I/repo/runtime/maplesu-sdk/sdk/include",
                               "-I/repo/runtime/maplesu-sdk/include",
                               "-I/repo/runtime/maplesu-sdk/sdk/src/kernel_request",
                               "-I/repo/runtime/maplesu-sdk/sdk/src",
                               "-I/repo/runtime/maplesu-sdk/sdk/src/maplesu/process",
                               "-DMAPLESU_KERNEL_READ_CANONICAL", "operation_deadline.cpp",
                               "/repo/runtime/ultra/authorization/kernel_read.cpp",
                               "/repo/runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp",
                               "/repo/runtime/ultra/authorization/request_context.cpp",
                               "/work/fork_pipe.cpp",
                               "-Wl,--wrap=syscall,--wrap=getuid,--wrap=geteuid", "-o", "operation-deadline"]
    if args.baseline:
        compile_command += ["-DMAPLESU_DEADLINE_BASELINE"]
    if args.host_32:
        compile_command += ["-m32"]
    commands = []
    for name, command in (("compile", compile_command), ("run", docker + ["./operation-deadline"])):
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
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
              "scope": "complete selected m023 request source and actual m023 deadline TLS; "
                       "raw syscall/capabilities/credentials explicit fixture; expired zero dispatch, "
                       "unconfirmed CLOSE and post-dispatch committed receipt; no real kernel/device latency claim"}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
