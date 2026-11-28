"""Exercise the production installation Mutation with real directory I/O and a fixture gateway."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[4]
IMAGE = "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"
INPUTS = [
    "runtime/maplesu-sdk/sdk/tests/installation_state_commit.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/installation_state.h",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/executable_publish_result.h",
    "runtime/maplesu-sdk/sdk/include/maplesu_storage_private.h",
    "runtime/maplesu-sdk/sdk/include/maplesu_request_private.h",
    "runtime/ultra/authorization/request_protocol.h",
]
CASES = ["success", "gateway-kept-session", "gateway-lost-session", "gateway-unknown",
         "gateway-unknown-committed", "gateway-committed-error",
         "changed-generation", "changed-record", "replaced-directory", "prewrite-failure",
         "sync-failure", "compensate-write-failure", "compensate-sync-failure"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("--out must be empty")
    before = {s: hashlib.sha256((REPO / s).read_bytes()).hexdigest() for s in INPUTS}
    script = """set -eu
ulimit -c 0
cd /case
C=/opt/ddk/clang/clang-r510928
export LD_LIBRARY_PATH=$C/lib/x86_64-unknown-linux-gnu
$C/bin/clang++ -stdlib=libc++ -std=c++20 -O0 -g0 -ffunction-sections -fdata-sections -I/repo/runtime/maplesu-sdk/include -I/repo/runtime/maplesu-sdk/sdk/include /repo/runtime/maplesu-sdk/sdk/tests/installation_state_commit.cpp -Wl,--gc-sections -Wl,--wrap=fsetxattr -Wl,--wrap=fgetxattr -Wl,--wrap=fsync -o state.test
failed=0
"""
    for case in CASES:
        # Every scenario gets a fresh container-local directory, never the host filesystem.
        script += f"rm -rf /data/ABCDEFGHIJKLMNOP /data/ABCDEFGHIJKLMNOP-previous\n./state.test {case} || failed=1\n"
    script += 'exit "$failed"\n'
    (out / "run.sh").write_text(script, newline="\n")
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={REPO},target=/repo,readonly",
               "--mount", f"type=bind,source={out},target=/case", "--entrypoint", "sh", IMAGE, "/case/run.sh"]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    log = result.stdout + result.stderr
    (out / "run.log").write_text(log)
    after = {s: hashlib.sha256((REPO / s).read_bytes()).hexdigest() for s in INPUTS}
    report = dict(exit_code=result.returncode, cases=CASES, command=command, before=before, after=after,
                  inputs_stable=before == after, device_acceptance=False, publication="fixture", gateway="fixture",
                  lifetime="fixture", mutation="production complete header", posix="real", trusted_attribute="user xattr fixture")
    (out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(log)
    return result.returncode or (0 if before == after else 1)


if __name__ == "__main__":
    raise SystemExit(main())
