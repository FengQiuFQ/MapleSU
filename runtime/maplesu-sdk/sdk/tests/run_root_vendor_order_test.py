#!/usr/bin/env python3
"""Run keyless production m060 Root entrypoints with real m046 fork/pipes and protected untouched host flags."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

from run_p4_root_receipt_test import IMAGE, ROOT, SDK, selected_member


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT, help="Read selected sources from this tree; unchanged dependencies stay read-only")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    selected = args.source_root.resolve()
    def choose(path):
        candidate = selected / path.relative_to(ROOT)
        return candidate if candidate.is_file() else path
    root_member = selected_member(60)
    fork_member = selected_member(46)
    source_path = choose(SDK / root_member["sources"][0])
    fork_path = choose(SDK / fork_member["sources"][0])
    fixture_path = choose(SDK / "tests/root_vendor_order_fixture.cpp")
    inputs = [source_path, fork_path, fixture_path, Path(__file__),
        SDK / "tests/run_p4_root_receipt_test.py", SDK / "include/maplesu_root_private.h",
        SDK / "include/maplesu_deadline_private.h", SDK / "include/maplesu_operation_wait_private.h",
        SDK / "include/maplesu_operation_fork_private.h",
        choose(SDK / "include/maplesu_root_command_private.h"), SDK / "include/maplesu_request_private.h",
        SDK / "src/maplesu/compat/fork_legacy_abi.h", SDK / "src/maplesu/compat/fork_exports_legacy_abi.h",
        SDK / "src/maplesu_core/fixed_transfer_io.h", SDK / "src/maplesu/compat/root_legacy_abi.h",
        ROOT / "runtime/maplesu-sdk/include/maplesu_sdk/maplesu_root.h",
        ROOT / "runtime/ultra/authorization/request_protocol.h", ROOT / "runtime/maplesu-sdk/include/module_err_def.h"]
    before = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    fixture = fixture_path.read_text(encoding="utf-8-sig")
    generated = fixture.replace("// EXACT_ROOT_SOURCE", '#include "/repo/' + source_path.relative_to(ROOT).as_posix() + '"')
    (out / "root_vendor_order.cpp").write_text(generated, encoding="utf-8")
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,exec,size=64m", "-e", "ASAN_OPTIONS=detect_leaks=1",
        "-e", "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
        "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
        "--mount", f"type=bind,source={out},target=/work", "-w", "/work", IMAGE]
    stages = []
    for name, command in [
        ("compile", docker + ["g++", "-std=c++20", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
            "-I/repo/" + selected.relative_to(ROOT).as_posix() + "/runtime/maplesu-sdk/sdk/include",
            "-I/repo/runtime/maplesu-sdk/sdk/include", "-I/repo/runtime/maplesu-sdk/include",
            "-I/repo/runtime/maplesu-sdk/sdk/src", "-I/repo/runtime/maplesu-sdk/sdk/src/maplesu_core",
            "-I/repo/runtime/maplesu-sdk/sdk/src/maplesu/process", "root_vendor_order.cpp",
            "/repo/" + fork_path.relative_to(ROOT).as_posix(), "-Wl,--wrap=pipe2", "-o", "root-vendor-order"]),
        ("run", docker + ["./root-vendor-order"])]:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=55)
        log = result.stdout + result.stderr
        (out / (name + ".log")).write_text(log, encoding="utf-8")
        stages.append(dict(name=name, exitCode=result.returncode, argv=command))
        print(name + ": " + str(result.returncode) + "\n" + log[-12000:])
        if result.returncode:
            break
    stable = all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest for path, digest in before.items())
    selection_stable = all(selected_member(member["idx"])["sources"] == member["sources"]
                           for member in (root_member, fork_member))
    report = dict(passed=len(stages) == 2 and all(stage["exitCode"] == 0 for stage in stages) and stable and selection_stable,
        recordedUtc=datetime.now(timezone.utc).isoformat(), stages=stages, sourcesUnchanged=stable, sourceSha256=before,
        manifestSelectionUnchanged=selection_stable,
        selectedMembers=[dict(idx=member["idx"], name=member["name"], sources=member["sources"]) for member in (root_member, fork_member)],
        scope="Complete manifest-selected production m060 and m046 TUs; m046 is linked as its own TU, no historical fork-helper extraction. Real Linux fork/pipes/popen and euid10498 to euid0 host credential fixture, real root:root0711 directory whose absent/existing0777 flags remain untouched. ManagerOwner/EarlyHelper, invalid source, permission/post-commit/session, shell/output/CLOSE/wait and fork-local diagnostics. m070/auth/OEM and zero page deadline are explicit fixtures; no kernel/device Root or shared-deadline runtime result.",
        deviceAccess=False, sdkBuild=False, apkBuild=False)
    (out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
