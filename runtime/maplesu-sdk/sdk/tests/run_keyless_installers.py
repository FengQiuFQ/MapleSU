"""Run selected keyless installer sources; identity, assets and SELinux are fixtures."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

REPO = Path(__file__).resolve().parents[4]
IMAGE = "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"
SOURCES = [
    "runtime/maplesu-sdk/sdk/src/maplesu_assets/maplesu_unsafe_su_install.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/resetprop_install.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/webui_loader_install.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/bootstrap_install.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/executable_publish.cpp",
    "runtime/maplesu-sdk/sdk/tests/keyless_installers.cpp",
]
BOUNDARIES = [
    "runtime/maplesu-sdk/sdk/src/module_base/module_base_disk_storage.cpp",
    "runtime/maplesu-sdk/sdk/src/module/module_append_package_parser.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/lifecycle.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/compat/installer_legacy.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/bootstrap_state.cpp",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/result_channel.c",
    "runtime/maplesu-sdk/sdk/src/maplesu/install/launch_guard.c",
    "runtime/maplesu-sdk/sdk/tests/keyless_metadata_storage.cpp",
    "runtime/maplesu-sdk/sdk/tests/keyless_lifecycle_boundary.cpp",
]
METADATA_HEADERS = [
    "runtime/maplesu-sdk/sdk/tools/tests/request_metadata/aarch64_asm_helper.h",
    "runtime/maplesu-sdk/sdk/tools/tests/request_metadata/module_base_kernel_func_executor.h",
]

def exact_function(text, prefix):
    start = text.index(prefix)
    cursor = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[cursor] == "{") - (text[cursor] == "}")
        cursor += 1
    return text[start:cursor]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    subset = parser.add_mutually_exclusive_group()
    subset.add_argument("--lifecycle-only", action="store_true")
    subset.add_argument("--installers-only", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        parser.error("--out must be empty")
    inputs = SOURCES if args.installers_only else BOUNDARIES[2:7] + BOUNDARIES[-1:] if args.lifecycle_only else SOURCES + BOUNDARIES + METADATA_HEADERS
    inputs = inputs + [
        "runtime/maplesu-sdk/sdk/tests/run_keyless_installers.py",
        "runtime/maplesu-sdk/sdk/tests/installer_stub/kernel_module_kit_umbrella.h",
        "runtime/maplesu-sdk/sdk/src/maplesu/install/installation_state.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_request_identity.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_request_private.h",
        "runtime/maplesu-sdk/sdk/include/maplesu_storage_private.h",
    ]
    before = {s: hashlib.sha256((REPO / s).read_bytes()).hexdigest() for s in inputs}
    (out / "payload_assets.generated.h").write_text("namespace maplesu::sdk {\n" + "\n".join(
        f"static const unsigned char {name}[] = {{0x7f,0x45,0x4c,0x46,{i},0x00,0x91,0xff}};"
        for i, name in enumerate(("su_data", "resetprop_file_data", "webui_loader_data", "autorun_bootstrap_file_data"), 1)) + "\n}\n")
    (out / "payload_sizes.generated.h").write_text("namespace maplesu::sdk {\n" + "\n".join(
        f"constexpr unsigned long {name} = 8;" for name in ("kSuPayloadSize", "kResetpropPayloadSize", "kWebuiLoaderPayloadSize", "kAutorunBootstrapPayloadSize")) + "\n}\n")
    flags = "-stdlib=libc++ -std=c++20 -O0 -g0 -ffunction-sections -fdata-sections -DMAPLESU_PAYLOAD_ASSETS=1 -I/case -I/repo/runtime/maplesu-sdk/sdk/tests/installer_stub -I/repo/runtime/maplesu-sdk/include -I/repo/runtime/maplesu-sdk/sdk/include -I/repo/runtime/maplesu-sdk/sdk/src/maplesu_assets"
    script = "set -eu\nulimit -c 0\ncd /case\nC=/opt/ddk/clang/clang-r510928\nexport LD_LIBRARY_PATH=$C/lib/x86_64-unknown-linux-gnu\n"
    if not args.lifecycle_only:
        script += "$C/bin/clang++ " + flags + " " + " ".join("/repo/" + source for source in SOURCES) + " -Wl,--gc-sections -Wl,--wrap=fsetxattr -Wl,--wrap=setxattr -Wl,--wrap=renameat -o installers.test\n./installers.test\n"
    if not args.lifecycle_only and not args.installers_only:
        metadata_include = out / "metadata-fixture"
        metadata_include.mkdir()
        for header in METADATA_HEADERS:
            (metadata_include / Path(header).name).write_bytes((REPO / header).read_bytes())
        metadata_flags = flags.replace("-I/repo/runtime/maplesu-sdk/include", "-I/case/metadata-fixture -I/repo/runtime/maplesu-sdk/include")
        script += "$C/bin/clang++ " + metadata_flags + " -pthread /repo/runtime/maplesu-sdk/sdk/tests/keyless_metadata_storage.cpp -Wl,--gc-sections -o metadata.test\n./metadata.test\n"
    lifecycle = (REPO / BOUNDARIES[2]).read_text(encoding="utf-8-sig")
    boundary = (REPO / BOUNDARIES[-1]).read_text()
    boundary = boundary.replace("// @INSERT_IDENTITY@", exact_function(lifecycle, "bool installer_identity_valid("))
    boundary = boundary.replace("// @INSERT_INSTALL@", exact_function(lifecycle, "core::err_t install_environment("))
    boundary = boundary.replace("// @INSERT_UNINSTALL@", exact_function(lifecycle, "core::err_t uninstall_environment("))
    boundary = boundary.replace("// @INSERT_VERSION@", exact_function(lifecycle, "core::err_t installed_version("))
    bootstrap = (REPO / BOUNDARIES[4]).read_text(encoding="utf-8-sig")
    boundary = boundary.replace("// @INSERT_STATE@", exact_function(bootstrap, "EnvironmentState environment_state("))
    (out / "lifecycle-selected.cpp").write_text(boundary, newline="\n")
    if not args.installers_only:
        script += "$C/bin/clang++ " + flags + " lifecycle-selected.cpp -Wl,--wrap=fork -Wl,--wrap=sync -o lifecycle.test\n./lifecycle.test\n"
    syntax_flags = flags.replace("-I/repo/runtime/maplesu-sdk/sdk/tests/installer_stub", "-I/repo/runtime/maplesu-sdk/sdk/tools/tests/module_state/include")
    for source in ([] if args.installers_only else BOUNDARIES[2:5]):
        script += "$C/bin/clang++ " + syntax_flags + " -fsyntax-only /repo/" + source + "\n"
    if not args.installers_only:
        script += "$C/bin/clang -std=gnu11 -fsyntax-only " + " ".join("/repo/" + source for source in BOUNDARIES[5:7]) + "\nprintf 'LIFECYCLE_SYNTAX_PASS cpp=3 c=2\\n'\n"
    (out / "run.sh").write_text(script, newline="\n")
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={REPO},target=/repo,readonly", "--mount", f"type=bind,source={out},target=/case", "--entrypoint", "sh", IMAGE, "/case/run.sh"]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    log = result.stdout + result.stderr
    (out / "run.log").write_text(log)
    after = {s: hashlib.sha256((REPO / s).read_bytes()).hexdigest() for s in inputs}
    report = dict(exit_code=result.returncode, command=command, lifecycle_only=args.lifecycle_only, installers_only=args.installers_only, device_acceptance=False, formal_payload=False, identity="fixture", worker_admission="fixture", selinux="fixture", publisher="not_run" if args.lifecycle_only else "production", exact_lifecycle_bodies=not args.installers_only, lifecycle_side_effect_endpoints="not_run" if args.installers_only else "fixture", inputs=[dict(path=s, sha256=before[s]) for s in inputs], inputs_after=after, inputs_stable=before == after)
    (out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(log)
    return result.returncode or (0 if before == after else 1)

if __name__ == "__main__":
    raise SystemExit(main())
