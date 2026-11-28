#!/usr/bin/env python3
"""Compile complete current deadline producer/consumer TUs for both Android SDK ABIs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = SDK / "manifest.jsonl"
    members = [json.loads(line) for line in manifest.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    selected = [row for row in members if row["idx"] in (23, 46, 60, 257)]
    sources = list(dict.fromkeys((SDK / path).resolve() for row in selected for path in row["sources"]))
    inputs = [Path(__file__), manifest, *sources,
              SDK / "include/maplesu_deadline_private.h", SDK / "include/maplesu_operation_wait_private.h",
              SDK / "include/maplesu_operation_fork_private.h", SDK / "include/maplesu_root_command_private.h"]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path) for path in inputs}
    commands = []
    for abi, target in (("arm64-v8a", "aarch64-linux-android31"), ("armeabi-v7a", "armv7a-linux-androideabi31")):
        for source in sources:
            name = abi + "-" + source.stem
            obj = out / (name + ".o")
            command = [str(args.clang), "--target=" + target, "-std=c++20", "-Oz", "-fPIC", "-fexceptions",
                       "-ffunction-sections", "-fdata-sections", "-I" + str(SDK / "include"),
                       "-I" + str(ROOT / "runtime/maplesu-sdk/include"), "-I" + str(SDK / "src"),
                       "-c", str(source), "-o", str(obj)]
            completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            log = completed.stdout + completed.stderr
            (out / (name + ".log")).write_text(log, encoding="utf-8")
            row = {"abi": abi, "source": source.relative_to(ROOT).as_posix(), "argv": command,
                   "exit": completed.returncode, "log": str(out / (name + ".log"))}
            if not completed.returncode:
                row["object"] = {"bytes": obj.stat().st_size, "sha256": digest(obj)}
            commands.append(row)
            print(name, completed.returncode, log[-2000:])
    stable = all(digest(ROOT / path) == value for path, value in hashes.items())
    passed = len(commands) == len(sources) * 2 and all(row["exit"] == 0 for row in commands) and stable
    report = {"passed": passed, "recordedUtc": datetime.now(timezone.utc).isoformat(),
              "sourceInputsStable": stable, "sourceSha256": hashes, "compilerSha256": digest(args.clang),
              "selectedMembers": [{key: row[key] for key in ("idx", "name", "sources")} for row in selected],
              "commands": commands, "scope": "Complete manifest-selected m023/m046/m060/m257 source TUs, "
              "NDK Android API31 arm64+armv7; compile only, no composed archive/ABI link/official package/device claim"}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
