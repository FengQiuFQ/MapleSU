#!/usr/bin/env python3
"""Exercise actual m060 receipt bodies with m046 transport and real host fork/pipes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"


def selected_member(index):
    members = [json.loads(line) for line in (SDK / "manifest.jsonl").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    member = next(member for member in members if member["idx"] == index)
    expected = {46: "src/maplesu/process/fork_pipe.cpp", 60: "src/maplesu_core/maplesu_root.cpp"}
    if member["sources"] != [expected[index]]:
        raise ValueError(f"m{index:03} source selection changed: {member['sources']}")
    return member


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    root_member = selected_member(60)
    fork_member = selected_member(46)
    source_path = SDK / root_member["sources"][0]
    fork_path = SDK / fork_member["sources"][0]
    fixture_path = SDK / "tests/p4_root_receipt_fixture.cpp"
    sources = [source_path, fork_path, fixture_path, Path(__file__),
        SDK / "include/maplesu_root_private.h", SDK / "include/maplesu_root_command_private.h",
        SDK / "include/maplesu_deadline_private.h", SDK / "include/maplesu_operation_wait_private.h",
        SDK / "include/maplesu_operation_fork_private.h",
        SDK / "include/maplesu_request_private.h", ROOT / "runtime/ultra/authorization/request_protocol.h",
        ROOT / "runtime/maplesu-sdk/include/module_err_def.h",
        SDK / "src/maplesu/compat/fork_legacy_abi.h", SDK / "src/maplesu/compat/fork_exports_legacy_abi.h",
        SDK / "src/maplesu/compat/root_legacy_abi.h", SDK / "src/maplesu_core/fixed_transfer_io.h"]
    before = {str(path.relative_to(ROOT)).replace("\\", "/"):
        hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    source = source_path.read_text(encoding="utf-8-sig")
    assert "if (result.root_transition.credentials_managed) close_command_owner(result);" in source
    fixture = fixture_path.read_text(encoding="utf-8-sig").replace("// EXACT_ROOT_SOURCE",
        '#include "/repo/' + source_path.relative_to(ROOT).as_posix() + '"')
    generated = out / "p4_root_receipt.cpp"
    generated.write_text(fixture, encoding="utf-8")
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=32m", "-e", "ASAN_OPTIONS=detect_leaks=1",
        "-e", "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
        "--mount", f"type=bind,source={ROOT},target=/repo,readonly",
        "--mount", f"type=bind,source={out},target=/work", "-w", "/work", IMAGE]
    commands = []
    for name, command in (
        ("compile", docker + ["g++", "-std=c++20", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
            "-ffunction-sections", "-fdata-sections",
            "-I/repo/runtime/maplesu-sdk/sdk/include", "-I/repo/runtime/maplesu-sdk/include",
            "-I/repo/runtime/maplesu-sdk/sdk/src", "p4_root_receipt.cpp",
            "/repo/" + fork_path.relative_to(ROOT).as_posix(), "-Wl,--gc-sections", "-o", "p4-root-receipt"]),
        ("run", docker + ["./p4-root-receipt"])):
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=55)
        output = completed.stdout + completed.stderr
        (out / f"{name}.log").write_text(output, encoding="utf-8")
        commands.append({"name": name, "argv": command, "exit": completed.returncode,
            "output": output})
        if completed.returncode:
            break
    stable = all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == value
        for path, value in before.items())
    selection_stable = all(selected_member(member["idx"])["sources"] == member["sources"]
                           for member in (root_member, fork_member))
    passed = len(commands) == 2 and all(item["exit"] == 0 for item in commands) and stable and selection_stable
    report = {"passed": passed, "sources": before, "sourcesUnchanged": stable,
        "manifestSelectionUnchanged": selection_stable,
        "selectedMembers": [dict(idx=member["idx"], name=member["name"], sources=member["sources"]) for member in (root_member, fork_member)],
        "commands": commands,
        "scope": "Complete manifest-selected m060/m046 TUs compiled; m046 linked separately. Actual m060 receipt/close paths and real host fork/pipes are exercised. Other uncalled m060 entrypoints are linker-discarded; kernel close API and zero page deadline are fixtures. No shared-deadline runtime, formal SDK/APK or device qualification."}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": passed, "sourcesUnchanged": stable,
        "commands": [{"name": item["name"], "exit": item["exit"], "output": item["output"]}
            for item in commands], "receipt": str(out / "results.json")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
