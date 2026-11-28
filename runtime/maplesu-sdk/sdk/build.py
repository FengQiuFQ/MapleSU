#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MapleSU Ultra SDK -- single build entry for the whole 260-member archive.

One command rebuilds every declared archive member from source, packs the
static library with the frozen ordinal order, stages the helper + embedded
assets, and gates the result member-by-member against the frozen epoch:

    py runtime/maplesu-sdk/sdk/build.py --all --kernel-source-618 <source> \
        --kernel-objtree-618 <prepared-output> --kernel-toolchain-618 <llvm>

Stages (in pipeline order)
--------------------------
``check-env``   pinned toolchain + frozen snapshot identity        exit 2
``manifest``    sdk/manifest/*.json -> manifest.jsonl + coverage   exit 3
``bootstrap``   six-family Kbuild -> source core -> backend/helper exit 9
``payloads``    source programs -> build/out/assets/*.bin         exit 9
``compile``     manifest TU(s) -> build/obj/<member>               exit 4
``compose``     multi-TU members fused (ld.lld -r / llvm-link)       exit 4
``pack``        llvm-ar qc member-by-member + llvm-ar s            exit 5
``assets``      helper + embedded payload assets -> build/out/     exit 8
``gate``        keyless public ABI + archive/ordinal/layout checks  exit 7
``report``      build/report/build-report.json + console summary

Legacy stages kept for compatibility: ``--check``, ``--compile``,
``--partial-link`` (alias of compose), ``--link-sample`` (exit 5) and
``--verify`` (substitution contract for the four sample members, exit 6).
Current ``--all --source-selection <receipt>`` links the complete archive and
all public APIs/macros; historical reference mode retains link-sample/verify.

Inputs, and what is *never* read
--------------------------------
The only archive this entry treats as ground truth is the frozen snapshot under
``runtime/maplesu-sdk/maintenance/freeze/``; the live (concurrently rebuilt)
live lib tree under runtime/maplesu-sdk is never opened. The compile stage opens **no**
``.a`` at all -- that is asserted from the outside by
``verify_sample.py`` V3.02 (audit hook: zero archive opens in the compile phase).

Determinism
-----------
* fixed ``SOURCE_DATE_EPOCH`` (default 1700000000) exported to every child;
* no timestamps or absolute paths are written into ``.o``/``.bc``/``.a`` bytes;
* ``llvm-ar`` is deterministic by default (mtime 0), members are appended in
  ascending manifest order and the index is written last;
* two clean builds of the same tree produce byte-identical ``build/obj/**`` and
  byte-identical packed archive (verified: see notes/work/ARCH/STATUS.md).

Exit codes
----------
0 ok, 2 environment/toolchain, 3 manifest, 4 compile/compose, 5 archive/link,
6 member integrity (legacy ``--verify``), 7 member gate, 8 assets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

SDK_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SDK_DIR / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import sdk_common as S                     # noqa: E402
import gen_manifest                        # noqa: E402
import member_gate                         # noqa: E402
import keyless_gate                        # noqa: E402
import build_helper as HB                   # noqa: E402
import source_backend as SB                 # noqa: E402
import gen_payload_headers as PH            # noqa: E402
import source_provenance as P               # noqa: E402

MAPLESU_SDK_ROOT = S.MAPLESU_SDK_ROOT
REPO_ROOT = S.REPO_ROOT

INCLUDE_DIR = MAPLESU_SDK_ROOT / "include"
SDK_INCLUDE_DIR = SDK_DIR / "include"
MANIFEST_PATH = SDK_DIR / "manifest.jsonl"
MANIFEST_DIR = SDK_DIR / "manifest"
VENDOR_RULES_PATH = SDK_DIR / "third_party" / "build_rules.json"
ASSETS_SPEC_PATH = SDK_DIR / "assets" / "ASSETS.json"
GATE_ALLOW_PATH = SDK_DIR / "notes" / "gate-allow.json"
HARNESS_SOURCE = SDK_DIR / "harness" / "sample_chain_harness.cpp"
PAYLOAD_TOOL = TOOLS_DIR / "extract_payloads.py"
PAYLOAD_BUILD_TOOL = TOOLS_DIR / "build_payloads.py"
PAYLOAD_MANIFEST_NAME = "PAYLOADS.json"

BUILD_DIR = SDK_DIR / "build"
OBJ_DIR = BUILD_DIR / "obj"
PAYLOAD_GEN_DIR = BUILD_DIR / "assets-gen"
TU_DIR = OBJ_DIR / "tu"
OUT_DIR = BUILD_DIR / "out"
LINK_DIR = BUILD_DIR / "link"
LOG_DIR = BUILD_DIR / "logs"
REPORT_DIR = BUILD_DIR / "report"

ARCHIVE_OUT = OUT_DIR / "libkernel_module_kit_static.a"   # residual: declared build output
HELPER_OUT = OUT_DIR / "helper" / "autorun_bootstrap"
SOURCE_HELPER_OUT = OUT_DIR / "source" / "helper" / "autorun_bootstrap"
ASSETS_OUT = OUT_DIR / "assets"
PAYLOAD_SOURCE_OVERRIDES: dict[Path, Path] = {}

SAMPLE_IDX = (23, 24, 29, 34)
# Memory frame helpers and Hook fork coordination require the same source
# executor and identity providers in the substitution link.
SAMPLE_LINK_IDX = (*SAMPLE_IDX, 25, 39)
SAMPLE_NAMES = {
    23: "module_base_kernel_request.o",
    24: "module_base_kernel_mem.o",
    29: "module_base_kernel_func_hook.o",
    34: "module_base_cpu_icache_sync.o",
}
DIAGNOSTIC_FLAGS = ["-Wall", "-Wextra"]
HARNESS_EXPORT = "maplesu_sample_chain_probe"

EXIT_OK = S.EXIT_OK
EXIT_TOOLCHAIN = S.EXIT_TOOLCHAIN
EXIT_MANIFEST = S.EXIT_MANIFEST
EXIT_COMPILE = S.EXIT_COMPILE
EXIT_ARCHIVE = S.EXIT_ARCHIVE
EXIT_INTEGRITY = S.EXIT_INTEGRITY
EXIT_GATE = S.EXIT_GATE
EXIT_ASSETS = S.EXIT_ASSETS
EXIT_PAYLOADS = 9

EXPECTED_MEMBERS = 260   # fallback only; the loaded freeze snapshot decides at run time

# Source mode builds the SDK core, paired backend and complete helper before the
# installer headers. Reference images are selected only by --reference-payloads.
# Build success remains separate from device acceptance.
SOURCE_PAYLOADS = True


def expected_members(freeze=None) -> int:
    """Member count of the reference archive in use.

    The build input moved from a 258-member archive to a fixed 260-member one,
    so every contract check follows the snapshot instead of a constant.
    """
    if freeze is not None:
        try:
            return len(freeze.members)
        except AttributeError:
            pass
    return EXPECTED_MEMBERS


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


class StageError(RuntimeError):
    """A stage failed; carries the process exit code."""

    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def log(stage: str, message: str) -> None:
    print(f"[{stage}] {message}", flush=True)


def rel(path: Path | str) -> str:
    return S.rel(path)


def fmt_cmd(argv: Sequence[str | Path]) -> str:
    return S.fmt_cmd(argv)


def run_checked(stage: str, what: str, argv: Sequence[str | Path], log_name: str,
                failure_code: int, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command, log it, and raise StageError with its stderr on failure."""
    log(stage, "  $ " + fmt_cmd(argv))
    started = time.monotonic()
    completed = S.run(argv, cwd=cwd)
    elapsed = time.monotonic() - started
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    S.write_text(LOG_DIR / log_name,
                 "$ " + fmt_cmd(argv) + f"\n\n[exit code] {completed.returncode}\n\n"
                 f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}\n")
    if completed.returncode != 0:
        print(f"\n[{stage}] FAILED: {what} (exit {completed.returncode})", file=sys.stderr)
        print(f"[{stage}] command: {fmt_cmd(argv)}", file=sys.stderr)
        if (completed.stdout or "").strip():
            print(f"[{stage}] stdout:\n{completed.stdout[-4000:]}", file=sys.stderr)
        if (completed.stderr or "").strip():
            print(f"[{stage}] stderr:\n{completed.stderr[-4000:]}", file=sys.stderr)
        print(f"[{stage}] log: {rel(LOG_DIR / log_name)}", file=sys.stderr)
        raise StageError(f"{what} failed", failure_code)
    log(stage, f"  ok ({elapsed:.2f}s)")
    return completed


# --------------------------------------------------------------------------- #
# Manifest model
# --------------------------------------------------------------------------- #


@dataclass
class ManifestEntry:
    idx: int
    name: str
    sources: list[Path]
    source_raw: list[str]
    flags_profile: str
    status: str
    layout: str
    group: str = "ungrouped"
    kind: str = "SINGLE"
    recovery: dict[str, Any] = field(default_factory=dict)
    original: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    extra_flags: list[str] = field(default_factory=list)
    origin: str = "manifest-json"
    compose: list[dict[str, Any]] = field(default_factory=list)
    blocked_by: list[str] = field(default_factory=list)
    recipe: dict[str, Any] = field(default_factory=dict)
    reference_input: dict[str, Any] | None = None

    @property
    def object_path(self) -> Path:
        # One output directory per member index.
        #
        # The archive really does contain three distinct members named
        # `patch_base.o` (module_root / su_redirect / global PatchBase, ordinals
        # 41/48/55).  With a flat OBJ_DIR/<name> path the three compiles share
        # one file, the last one wins, and the archive silently ends up with the
        # same object packed three times - which is exactly what the member gate
        # caught as "T missing 11 / T extra 8" on idx 71.
        # Keeping the basename intact preserves the ar member name.
        return OBJ_DIR / f"m{self.idx:04d}" / self.name

    @property
    def is_blocked(self) -> bool:
        return self.status == S.STATUS_PARTIAL and not self.sources

    @property
    def is_vendor_copy(self) -> bool:
        return self.status == S.STATUS_VENDOR_COPY

    @property
    def needs_fusion(self) -> bool:
        return len(self.sources) > 1

    def source_kind(self) -> str:
        if not self.sources:
            return "none"
        suffix = self.sources[0].suffix.lower()
        if suffix == ".c":
            return "c"
        if suffix in (".ll", ".bc"):
            return "ir"
        return "cxx"


def resolve_source(raw: str) -> Path | None:
    return gen_manifest.resolve_source(raw)


def validate_keyless_sources(entries: list[ManifestEntry]) -> dict[str, Any]:
    """Keep active API members on their first-party source, not frozen ABI objects."""
    critical = {23, 35, 39, 41, 42, *range(45, 64), 70, 81, 255, 256}
    selected = []
    for entry in entries:
        if entry.idx not in critical:
            continue
        if entry.status == S.STATUS_VENDOR_COPY or not entry.sources or any(
                source.suffix not in (".c", ".cpp", ".cc", ".S", ".s") or
                not (source.is_relative_to(SDK_DIR / "src") or
                     source.is_relative_to(REPO_ROOT / "runtime/ultra"))
                for source in entry.sources):
            raise StageError(f"m{entry.idx:03d} requires current first-party keyless sources", EXIT_MANIFEST)
        selected.append({"idx": entry.idx, "sources": [rel(source) for source in entry.sources]})
    return {"rootKeyRequired": False, "members": selected}


def load_manifest(path: Path, allow_partial: bool) -> tuple[list[ManifestEntry], dict[str, Any]]:
    """Read manifest.jsonl. Does not touch any archive (the compile phase must not)."""
    path = Path(path)
    if not path.is_file():
        raise StageError(
            f"manifest not found: {rel(path)}; run 'build.py --gen-manifest' "
            f"(or --all) to collect sdk/manifest/*.json", EXIT_MANIFEST)

    entries: list[ManifestEntry] = []
    seen_idx: dict[int, str] = {}
    errors: list[str] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{lineno}: invalid JSON ({exc})")
            continue
        if not isinstance(record, dict):
            errors.append(f"{path.name}:{lineno}: expected an object")
            continue
        idx = record.get("idx")
        if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
            errors.append(f"{path.name}:{lineno}: bad idx {idx!r}")
            continue
        name = record.get("name")
        if not isinstance(name, str) or not name.endswith(".o"):
            errors.append(f"{path.name}:{lineno}: bad member name {name!r}")
            continue
        status = record.get("status")
        if status not in S.VALID_STATUS:
            errors.append(f"{path.name}:{lineno}: bad status {status!r}")
            continue
        layout = record.get("layout")
        if layout not in ("bitcode", "elf"):
            errors.append(f"{path.name}:{lineno}: bad layout {layout!r} for {name}")
            continue
        profile = record.get("flagsProfile")
        if profile not in S.FLAG_PROFILES:
            errors.append(f"{path.name}:{lineno}: unknown flagsProfile {profile!r} for {name}")
            continue
        raw_sources = record.get("sources") or []
        if not isinstance(raw_sources, list):
            errors.append(f"{path.name}:{lineno}: sources must be a list")
            continue
        sources: list[Path] = []
        for entry in raw_sources:
            if not isinstance(entry, str):
                errors.append(f"{path.name}:{lineno}: source entry is not a string")
                continue
            resolved = resolve_source(entry)
            if resolved is None:
                errors.append(f"{path.name}:{lineno}: source escapes the repository: {entry!r}")
                continue
            if not resolved.is_file():
                errors.append(f"{path.name}:{lineno}: source missing: {entry!r}")
                continue
            sources.append(resolved)
        blocked_by = record.get("blockedBy") or []
        if not isinstance(blocked_by, list) or any(not isinstance(b, str) for b in blocked_by):
            errors.append(f"{path.name}:{lineno}: blockedBy must be a list of strings")
            blocked_by = []
        if not sources:
            if status == S.STATUS_PARTIAL and blocked_by:
                pass                      # declared blocker: not built, counted separately
            elif status == S.STATUS_VENDOR_COPY:
                pass                      # materialised from the freeze in compose
            else:
                errors.append(f"{path.name}:{lineno}: no usable source for {name} "
                              f"(status {status}, blockedBy={blocked_by})")
                continue
        extra_flags = record.get("extraFlags") or []
        if not isinstance(extra_flags, list) or any(not isinstance(f, str) for f in extra_flags):
            errors.append(f"{path.name}:{lineno}: extraFlags must be a list of strings")
            extra_flags = []
        compose = record.get("compose") or []
        if not isinstance(compose, list) or any(not isinstance(step, dict) for step in compose):
            errors.append(f"{path.name}:{lineno}: compose must be a list of step objects")
            compose = []
        if idx in seen_idx:
            errors.append(f"{path.name}:{lineno}: idx {idx} already declared by {seen_idx[idx]}")
            continue
        seen_idx[idx] = name
        entries.append(ManifestEntry(
            idx=idx, name=name, sources=sources, source_raw=list(raw_sources),
            flags_profile=profile, status=status, layout=layout,
            group=str(record.get("group") or "ungrouped"),
            kind=str(record.get("kind") or "SINGLE"),
            recovery=dict(record.get("recovery") or {}),
            original=dict(record.get("original") or {}),
            notes=str(record.get("notes") or ""),
            extra_flags=list(extra_flags),
            origin=str(record.get("origin") or "manifest-json"),
            compose=list(compose),
            blocked_by=list(blocked_by),
            recipe=dict(record.get("recipe") or {}),
            reference_input=record.get("referenceInput"),
        ))
    if errors:
        for message in errors[:40]:
            print(f"[manifest] {message}", file=sys.stderr)
        raise StageError(f"{len(errors)} manifest record error(s)", EXIT_MANIFEST)

    entries.sort(key=lambda item: item.idx)
    total_members = expected_members()
    missing = sorted(set(range(total_members)) - set(seen_idx))
    meta = {
        "path": rel(path),
        "records": len(entries),
        "declared_all": not missing,
        "missing_idx": missing,
        "status_counts": _counts(entry.status for entry in entries),
        "layout_counts": _counts(entry.layout for entry in entries),
        "profile_counts": _counts(entry.flags_profile for entry in entries),
        "groups": _counts(entry.group for entry in entries),
        "origin_counts": _counts(entry.origin for entry in entries),
    }
    if missing and not allow_partial:
        preview = ", ".join(str(idx) for idx in missing[:20])
        raise StageError(
            f"manifest covers {len(entries)}/{total_members} members "
            f"(missing idx: {preview}{'…' if len(missing) > 20 else ''}); "
            f"re-run with --allow-partial for an interim build", EXIT_MANIFEST)
    return entries, meta


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


# --------------------------------------------------------------------------- #
# Vendor build rules (sdk/third_party/build_rules.json)
# --------------------------------------------------------------------------- #


@dataclass
class VendorRule:
    lib: str
    version: str
    profile: str
    layout: str
    cflags: list[str]
    defines: list[str]
    include_dirs: list[str]
    lib_root: Path
    member_source: str
    per_source: dict[str, Any] = field(default_factory=dict)


class VendorRules:
    """Index of ``third_party/build_rules.json`` keyed by archive member name."""

    def __init__(self, path: Path, rules: dict[str, VendorRule], errors: list[str],
                 profiles: dict[str, Any]) -> None:
        self.path = path
        self.rules = rules
        self.errors = errors
        self.profiles = profiles

    @classmethod
    def load(cls, path: Path) -> "VendorRules":
        rules: dict[str, VendorRule] = {}
        errors: list[str] = []
        profiles: dict[str, Any] = {}
        path = Path(path)
        if not path.is_file():
            return cls(path, rules, ["build_rules.json absent"], profiles)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return cls(path, rules, [f"build_rules.json unreadable: {exc}"], profiles)
        profiles = dict(raw.get("profiles") or {})
        third_party_root = (SDK_DIR / str((raw.get("paths") or {}).get("thirdPartyRoot", "third_party")))
        libs = raw.get("libs") or []
        if isinstance(libs, dict):
            libs = list(libs.values())
        for lib in libs:
            if not isinstance(lib, dict):
                continue
            name = str(lib.get("lib") or "")
            version = str(lib.get("version") or "")
            profile = str(lib.get("profile") or "")
            cflags = [str(f) for f in (lib.get("cflags") or [])]
            defines = [str(f) for f in (lib.get("defines") or [])]
            include_dirs = [str(d) for d in (lib.get("includeDirs") or [])]
            lib_root = third_party_root / name / version
            members = lib.get("members") or {}
            if not isinstance(members, dict):
                errors.append(f"{name}: members is not an object")
                continue
            if not lib_root.is_dir():
                errors.append(f"{name}: lib root not found ({rel(lib_root)})")
            for member_name, member_source in members.items():
                rules[str(member_name)] = VendorRule(
                    lib=name, version=version, profile=profile,
                    layout=str(lib.get("layout") or ""), cflags=cflags,
                    defines=defines, include_dirs=include_dirs, lib_root=lib_root,
                    member_source=str(member_source),
                    per_source=dict(lib.get("perSource") or {}),
                )
        return cls(path, rules, errors, profiles)

    def for_member(self, name: str) -> VendorRule | None:
        return self.rules.get(name)

    def effective(self, rule: VendorRule, source: Path) -> dict[str, Any]:
        """Merged compile recipe for one member source.

        ``perSource`` entries are **additive** by default (libzip's mkstemp needs
        ``-include unistd.h`` on top of the library flags); when a perSource entry
        names its own ``profile`` that profile's cflags replace the library ones
        (civetweb's CivetServer.cpp is the bitcode exception inside an ELF library).
        Dropping the base cflags here would silently lose ``-target`` and compile
        the TU for the host, so the merge is explicit.
        """
        source_rel = self._relative_source(rule, source)
        per = rule.per_source.get(source_rel) if source_rel else None
        per = per if isinstance(per, dict) else {}
        profile = str(per.get("profile") or rule.profile)
        profile_spec = self.profiles.get(profile) or {}
        base = list(rule.cflags)
        if per.get("profile") and profile_spec.get("cflags"):
            base = [str(f) for f in profile_spec["cflags"]]
        extra = [str(f) for f in (per.get("cflags") or []) if str(f) not in base]
        defines = list(rule.defines) + [str(f) for f in (per.get("defines") or [])]
        emit = [str(f) for f in (profile_spec.get("emit") or ["-c"]) if str(f) != "-c"]
        language = str(profile_spec.get("language") or "")
        if language not in ("c", "c++"):
            language = "c" if source.suffix.lower() == ".c" else "c++"
        return {
            "profile": profile,
            "cflags": base + extra + defines,
            "emit": emit,
            "language": language,
            "layout": str(per.get("layout") or rule.layout or ""),
            "note": str(per.get("notes") or ""),
        }

    @staticmethod
    def _relative_source(rule: VendorRule, source: Path) -> str | None:
        try:
            return source.resolve().relative_to(rule.lib_root.resolve()).as_posix()
        except (ValueError, OSError):
            return rule.member_source or None

    def emit_flags(self, rule: VendorRule) -> list[str]:
        spec = self.profiles.get(rule.profile) or {}
        emit = [str(f) for f in (spec.get("emit") or ["-c"])]
        return [flag for flag in emit if flag != "-c"]

    def language(self, rule: VendorRule, source: Path) -> str:
        spec = self.profiles.get(rule.profile) or {}
        language = str(spec.get("language") or "")
        if language in ("c", "c++"):
            return language
        return "c" if source.suffix.lower() == ".c" else "c++"

    def describe(self) -> dict[str, Any]:
        return {
            "path": rel(self.path) if self.path else None,
            "present": self.path.is_file(),
            "members": len(self.rules),
            "libs": sorted({rule.lib for rule in self.rules.values()}),
            "profiles": sorted({rule.profile for rule in self.rules.values()}),
            "errors": self.errors,
        }


# --------------------------------------------------------------------------- #
# Stage: check-env
# --------------------------------------------------------------------------- #


def stage_check_env(tc: S.Toolchain, args: argparse.Namespace, report: dict[str, Any]) -> None:
    versions: dict[str, str] = {}
    for tool, args_list in (("clang", ("--version",)), ("llvm-ar", ("--version",)),
                            ("ld.lld", ("--version",))):
        completed = run_checked("check", f"{tool} {' '.join(args_list)}",
                                [tc.tool(tool), *args_list], f"tool-{tool}.log",
                                EXIT_TOOLCHAIN)
        output = (completed.stdout or "") + (completed.stderr or "")
        lines = [line.strip() for line in output.splitlines() if "version" in line.lower()]
        versions[tool] = lines[0] if lines else output.strip().splitlines()[0]
        versions[tool + ".raw"] = output
    if S.EXPECTED_CLANG not in versions.get("clang", ""):
        raise StageError(f"clang is not {S.EXPECTED_CLANG!r}: {versions.get('clang')!r}",
                         EXIT_TOOLCHAIN)
    for tool, expected in (("llvm-ar", S.EXPECTED_LLVM), ("ld.lld", S.EXPECTED_LLD)):
        if expected not in versions.get(tool + ".raw", ""):
            raise StageError(f"{tool} is not {expected!r}", EXIT_TOOLCHAIN)
    if tc.ndk.name != S.EXPECTED_NDK_VERSION and not os.environ.get("MAPLESU_ALLOW_NDK_DRIFT"):
        raise StageError(
            f"NDK {tc.ndk.name!r} is not the pinned {S.EXPECTED_NDK_VERSION!r} "
            f"(set MAPLESU_ALLOW_NDK_DRIFT=1 to accept drift)", EXIT_TOOLCHAIN)
    for tool in S.REQUIRED_TOOLS:
        if not tc.has(tool):
            raise StageError(f"required tool missing: {tool}", EXIT_TOOLCHAIN)

    snapshot = S.find_freeze(args.archive)
    archive = S.read_archive(snapshot.archive)
    listed = S.llvm_ar_list(tc, snapshot.archive)
    if listed != archive.names:
        raise StageError("ar parser disagrees with llvm-ar t on the frozen archive", EXIT_TOOLCHAIN)
    if len(archive.members) != expected_members(archive):
        raise StageError(f"frozen archive member count is inconsistent: "
                         f"{len(archive.members)}", EXIT_TOOLCHAIN)
    vendor = VendorRules.load(VENDOR_RULES_PATH)

    log("check", f"NDK: {tc.ndk.name}  clang: {versions['clang']}")
    log("check", f"llvm-ar: {versions['llvm-ar']}  ld.lld: {versions['ld.lld']}")
    log("check", f"frozen archive: {rel(snapshot.archive)} sha256={archive.sha256[:16]} "
                 f"members={len(archive.members)}")
    log("check", f"vendor rules: {len(vendor.rules)} members from "
                 f"{rel(vendor.path) if vendor.path.is_file() else 'ABSENT'}")
    if not tc.has("llvm-link"):
        log("check", "NOTE: llvm-link absent; multi-TU bitcode members cannot be fused")
    if vendor.errors:
        for message in vendor.errors:
            log("check", f"WARNING vendor rules: {message}")

    report["toolchain"] = {
        "ndk_root": rel(tc.ndk),
        "ndk_version": tc.ndk.name,
        "bin_dir": rel(tc.bin_dir),
        "versions": {key: value for key, value in versions.items() if not key.endswith(".raw")},
        "target": "aarch64-linux-android21",
        "profiles": S.profile_descriptions(),
        "vendor_rules": vendor.describe(),
    }
    report["frozen"] = snapshot.describe()
    report["frozen"]["members"] = len(archive.members)
    report["frozen"]["duplicate_names"] = archive.duplicate_groups()


# --------------------------------------------------------------------------- #
# Stage: manifest
# --------------------------------------------------------------------------- #


def capture_source_selection(path: Path, root: Path) -> dict[str, Any]:
    """Bind a selected source composition to receipts without running a build."""
    root = root.resolve()
    path = Path(path).resolve()
    try:
        if not path.is_relative_to(root):
            raise ValueError("source selection is outside repository")
        before = P.file_record(path, root)
        selection = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(selection, dict) or selection.get("schema") != "maplesu-sdk-source-selection/1":
            raise ValueError("unsupported source selection schema")
        rows = selection.get("files")
        if not isinstance(rows, list) or not rows:
            raise ValueError("source selection has no files")
        seen = set()
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("path"), str)
                    or type(row.get("size")) is not int or row["size"] < 0
                    or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))):
                raise ValueError("malformed selected input")
            name = row["path"]
            source = (root / name).resolve()
            if (Path(name).is_absolute()
                    or not source.is_relative_to(root) or source in seen):
                raise ValueError("invalid or duplicate selected input: " + str(name))
            seen.add(source)
            if P.file_record(source, root) != {key: row[key] for key in ("path", "size", "sha256")}:
                raise ValueError("selected input changed: " + name)
        if P.file_record(path, root) != before:
            raise ValueError("source selection changed during capture")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise StageError("source selection: " + str(exc), EXIT_MANIFEST) from exc
    return {"manifest": before, "files": rows}


def stage_manifest(args: argparse.Namespace, report: dict[str, Any]) -> dict[str, Any]:
    manifest_dir = Path(args.manifest_dir) if args.manifest_dir else MANIFEST_DIR
    report.setdefault("input_snapshots", []).extend(P.snapshot_inputs(
        [(path, "manifest") for path in sorted(manifest_dir.glob("*.json"))
         if gen_manifest.MEMBER_FILE_RE.match(path.name)], S.REPO_ROOT))
    result = gen_manifest.generate(
        manifest_dir=Path(args.manifest_dir) if args.manifest_dir else MANIFEST_DIR,
        out_path=Path(args.manifest),
        coverage_path=Path(args.coverage) if args.coverage else None,
        catalog_path=Path(args.catalog) if args.catalog else None,
        allow_partial=args.allow_partial,
        no_legacy=args.no_legacy,
        allow_shrink=args.allow_shrink,
        write=True,
        archive_override=args.archive,
        idx_mode=args.idx_base,
        require_normalized=args.require_normalized,
        skip_invalid=args.skip_invalid,
        quiet=False,
    )
    summary = result.summary()
    report["manifest_stage"] = summary
    if not result.ok:
        raise StageError(
            f"member metadata is invalid ({len(result.errors)} error(s)); "
            f"see {rel(gen_manifest.COVERAGE_MD)}", EXIT_MANIFEST)
    if result.missing_idx and not args.allow_partial:
        raise StageError(
            f"manifest covers {len(result.records)}/{expected_members()} members; "
            f"pass --allow-partial for an interim build", EXIT_MANIFEST)
    return summary


# --------------------------------------------------------------------------- #
# Stage: compile
# --------------------------------------------------------------------------- #


def include_flags() -> list[str]:
    flags: list[str] = []
    for directory in (INCLUDE_DIR, SDK_INCLUDE_DIR):
        if directory.is_dir():
            flags += ["-I", str(directory)]
    return flags


def payload_cpp_flags(entry: ManifestEntry, source: Path) -> list[str]:
    """Only the four installer TUs consume the generated payload arrays."""
    members = {row[4] for row in PH.TABLE}
    native_installers = {
        "maplesu_unsafe_resetprop_install.o": "resetprop_install.cpp",
        "maplesu_unsafe_webui_loader_install.o": "webui_loader_install.cpp",
        "maplesu_autorun_bootstrap_install.o": "bootstrap_install.cpp",
    }
    if entry.name not in members or source.name not in (
            entry.name[:-2] + ".cpp", native_installers.get(entry.name)):
        return []
    return ["-DMAPLESU_PAYLOAD_ASSETS=1", "-I", str(PAYLOAD_GEN_DIR)]


def compile_out_path(entry: ManifestEntry, source_index: int) -> Path:
    if len(entry.sources) == 1:
        return entry.object_path
    stem = entry.sources[source_index].stem
    suffix = ".bc" if entry.layout == "bitcode" else ".o"
    return TU_DIR / f"{entry.idx:04d}_{source_index}_{stem}{suffix}"


def compile_command(entry: ManifestEntry, source: Path, out_path: Path, tc: S.Toolchain,
                    vendor: VendorRules, werror: bool, stage: str = "single") -> list[str]:
    rule = vendor.for_member(entry.name)
    kind = entry.source_kind() if len(entry.sources) == 1 else (
        "c" if source.suffix.lower() == ".c" else "cxx")
    if rule is not None:
        recipe = vendor.effective(rule, source)
        driver = tc.tool("clang++" if recipe["language"] == "c++" else "clang")
        flags = list(recipe["cflags"])
        flags += list(recipe["emit"])
        for directory in rule.include_dirs:
            flags += ["-I", str(rule.lib_root / directory)]
        flags += S.expand_flags(entry.extra_flags)
    else:
        driver = tc.tool("clang" if kind == "c" else "clang++")
        flags = S.profile_flags(entry.flags_profile, kind, entry.extra_flags)
        flags += DIAGNOSTIC_FLAGS
        flags += include_flags()
    # The archive member's layout is measured truth (head -c4 of the frozen body);
    # a profile that disagrees with it is data drift, not a reason to emit the wrong
    # container. Force the emit mode from the layout and record the conflict.
    if stage == "ir":
        # first pass of a two-stage member: produce optimised IR only
        if "-emit-llvm" not in flags:
            flags.append("-emit-llvm")
    elif stage == "obj":
        # second pass: take that IR and emit the native object
        flags = [flag for flag in flags if flag != "-emit-llvm"]
    elif entry.layout == "bitcode" and "-emit-llvm" not in flags:
        flags.append("-emit-llvm")
    elif entry.layout == "elf" and "-emit-llvm" in flags:
        flags.remove("-emit-llvm")
    if werror:
        flags.append("-Werror")
    flags += payload_cpp_flags(entry, source)
    selected_source = PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source)
    return [str(driver), *flags, *P.dependency_flags(selected_source, out_path),
            "-c", str(selected_source), "-o", str(out_path)]


def payload_ir_array(text: str, symbol: str) -> tuple[re.Match[str], bytes]:
    """Read the one LLVM array definition used by an installer, without LLVM tools."""
    pattern = (r"(?m)^(?P<prefix>@" + re.escape(symbol)
               + r" = [^\n]*?)(?P<type>\[(?P<count>\d+) x i(?P<bits>8|64)\]) "
               + r'(?P<value>c"(?:\\[0-9A-Fa-f]{2}|[^"\\])*"|\[[^\n]*\])'
               + r"(?P<tail>,[^\n]*)?$")
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1:
        raise StageError(f"installer must define {symbol} exactly once", EXIT_PAYLOADS)
    match = matches[0]
    value = match["value"]
    bits = int(match["bits"])
    if value.startswith('c"') and bits == 8:
        tokens = re.findall(r"\\([0-9A-Fa-f]{2})|([^\\])", value[2:-1])
        blob = bytes(int(escaped, 16) if escaped else ord(char) for escaped, char in tokens)
    else:
        values = re.findall(r"i" + str(bits) + r" (-?\d+)", value)
        blob = b"".join((int(item) % (1 << bits)).to_bytes(bits // 8, "little")
                        for item in values)
    if len(blob) != int(match["count"]) * bits // 8:
        raise StageError(f"installer {symbol}: array initializer length mismatch", EXIT_PAYLOADS)
    return match, blob


def replace_payload_ir(text: str, symbol: str, reference: bytes,
                       selected: bytes) -> tuple[str, int]:
    match, original = payload_ir_array(text, symbol)
    if original != reference:
        raise StageError(f"installer {symbol}: embedded bytes differ from the reference asset",
                         EXIT_PAYLOADS)
    if selected == reference:
        return text, 0
    if not selected:
        raise StageError(f"installer {symbol}: selected payload is empty", EXIT_PAYLOADS)
    # Opaque pointers make the array element type private to this definition.
    # Keep the symbol/linkage/alignment, and resize every sizeof-derived literal
    # (allocation, memcpy, publish length and dereferenceable attributes).
    value = 'c"' + "".join(f"\\{byte:02X}" for byte in selected) + '"'
    definition = (match["prefix"] + f"[{len(selected)} x i8] " + value
                  + (match["tail"] or ""))
    before, after = text[:match.start()], text[match.end():]
    old_type = match["type"]
    new_type = f"[{len(selected)} x i8]"
    before, after = before.replace(old_type, new_type), after.replace(old_type, new_type)
    size_pattern = r"(?<![\w.])" + str(len(reference)) + r"(?![\w.])"
    before, count_before = re.subn(size_pattern, str(len(selected)), before)
    after, count_after = re.subn(size_pattern, str(len(selected)), after)
    count = count_before + count_after
    if not count:
        raise StageError(f"installer {symbol}: no payload size references found", EXIT_PAYLOADS)
    rewritten = before + definition + after
    if payload_ir_array(rewritten, symbol)[1] != selected:
        raise StageError(f"installer {symbol}: rewritten bytes differ", EXIT_PAYLOADS)
    return rewritten, count


def prepare_payload_sources(entries: list[ManifestEntry], report: dict[str, Any]) -> None:
    """Select actual installer inputs and record the resources compiled into them."""
    PAYLOAD_SOURCE_OVERRIDES.clear()
    by_member = {entry.name: entry for entry in entries}
    selected_dir = ASSETS_OUT if SOURCE_PAYLOADS else SDK_DIR / "assets"
    payload_manifest = (json.loads((ASSETS_OUT / PAYLOAD_MANIFEST_NAME).read_text(encoding="utf-8"))
                        if SOURCE_PAYLOADS else {})
    programs = {row["asset"]: row for row in payload_manifest.get("programs") or []}
    rows = []
    payload_inputs = []
    for asset, _name, _header, symbol, member in PH.TABLE:
        if member in by_member:
            payload_inputs += [(SDK_DIR / "assets" / asset, "asset"), (selected_dir / asset, "asset")]
    if payload_manifest:
        payload_inputs.append((ASSETS_OUT / PAYLOAD_MANIFEST_NAME, "manifest"))
    report.setdefault("input_snapshots", []).extend(P.snapshot_inputs(payload_inputs, S.REPO_ROOT))
    for asset, _name, _header, symbol, member in PH.TABLE:
        entry = by_member.get(member)
        if entry is None:
            continue
        sources = [path for path in entry.sources if path.suffix == ".ll"
                   or payload_cpp_flags(entry, path)]
        if len(sources) != 1:
            raise StageError(f"{member}: expected one installer IR or C++ input", EXIT_PAYLOADS)
        source = sources[0]
        reference = (SDK_DIR / "assets" / asset).read_bytes()
        selected = (selected_dir / asset).read_bytes()
        build_source = source
        count = 0
        headers = []
        if source.suffix == ".ll":
            text = source.read_text(encoding="utf-8")
            rewritten, count = replace_payload_ir(text, symbol, reference, selected)
            if rewritten != text:
                build_source = PAYLOAD_GEN_DIR / "installer-ir" / source.name
                S.write_text(build_source, rewritten)
                PAYLOAD_SOURCE_OVERRIDES[source.resolve()] = build_source
        else:
            for name in [PH.UMBRELLA, PH.SIZES_HEADER, *[row[2] for row in PH.TABLE]]:
                path = PAYLOAD_GEN_DIR / name
                if not path.is_file():
                    raise StageError(f"{member}: generated payload header missing: {rel(path)}",
                                     EXIT_PAYLOADS)
                headers.append({"path": rel(path), "bytes": path.stat().st_size,
                                "sha256": S.sha256_file(path)})
        rows.append({"member": member, "symbol": symbol, "asset": asset,
                     "source": rel(source), "build_source": rel(build_source),
                     "source_kind": "ir" if source.suffix == ".ll" else "cxx",
                     "generated_headers": headers, "asset_path": rel(selected_dir / asset),
                     "bytes": len(selected), "sha256": S.sha256_bytes(selected),
                     "origin": "source-built" if SOURCE_PAYLOADS and
                     programs.get(asset, {}).get("status") == "built" else "reference-copy",
                     "size_references_updated": count})
    report["payload_inputs"] = {"mode": "source"
                               if SOURCE_PAYLOADS else "reference", "members": rows}


def ensure_payload_headers(args: argparse.Namespace) -> None:
    """Generate headers matching the selected assets for source consumers and evidence."""
    tool = TOOLS_DIR / "gen_payload_headers.py"
    if not tool.is_file():
        raise StageError("payload header generator missing", EXIT_PAYLOADS)
    payload_manifest = ASSETS_OUT / PAYLOAD_MANIFEST_NAME
    if SOURCE_PAYLOADS and payload_manifest.is_file():
        assets_dir = ASSETS_OUT
        log("payloads",
            f"embedding source-built payloads from {rel(assets_dir)} (--source-payloads)")
    else:
        assets_dir = SDK_DIR / "assets"
        if SOURCE_PAYLOADS:
            raise StageError("source payload manifest absent; run --payloads first", EXIT_PAYLOADS)
        else:
            log("payloads",
                f"embedding pinned reference payloads from {rel(assets_dir)} "
                f"(use --source-payloads for the source-built programs)")
    argv = [sys.executable, str(tool), "--out", str(PAYLOAD_GEN_DIR),
            "--assets", str(assets_dir)]
    if SOURCE_PAYLOADS and payload_manifest.is_file():
        # Built programs are verified against the payload build's own manifest;
        # vendor images are verified against ASSETS.json by the generator.
        argv += ["--manifest", str(payload_manifest)]
    completed = S.run(argv, cwd=S.REPO_ROOT)
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    tail = detail[-1] if detail else ""
    if completed.returncode != 0:
        raise StageError(f"payload header generation failed (exit {completed.returncode}): {tail}",
                         EXIT_PAYLOADS)
    log("payloads", f"generated payload headers -> {rel(PAYLOAD_GEN_DIR)}")


def stage_compile(entries: list[ManifestEntry], tc: S.Toolchain, args: argparse.Namespace,
                  report: dict[str, Any], vendor: VendorRules) -> None:
    OBJ_DIR.mkdir(parents=True, exist_ok=True)
    TU_DIR.mkdir(parents=True, exist_ok=True)
    compile_entries = [entry for entry in entries if entry.sources]
    for entry in compile_entries:
        reference_error = gen_manifest.reference_input_error(entry.reference_input, entry.sources)
        if reference_error:
            code, message = reference_error
            raise StageError(f"m{entry.idx:04d} {code}: {message}", EXIT_COMPILE)
    jobs = max(1, min(int(args.jobs or 1), 16))
    log("compile", f"{len(compile_entries)} member(s) to compile with -j{jobs}")

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    lock_rows: list[dict[str, Any]] = []

    def build_one(entry: ManifestEntry) -> tuple[dict[str, Any], dict[str, Any] | None]:
        produced: list[dict[str, Any]] = []
        failure: dict[str, Any] | None = None
        two_stage = int((entry.recipe or {}).get("stages") or 1) >= 2
        for index, source in enumerate(entry.sources):
            out_path = compile_out_path(entry, index)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            stage_source = source
            if two_stage:
                # The frozen producer built these members from optimised IR, so the
                # second pass has to recompile IR instead of the source itself; that
                # is what reproduces its instruction selection.
                ir_path = TU_DIR / f"{entry.idx:04d}_{index}_{source.stem}.stage1.bc"
                ir_path.parent.mkdir(parents=True, exist_ok=True)
                ir_argv = compile_command(entry, source, ir_path, tc, vendor, args.werror, stage="ir")
                ir_path.unlink(missing_ok=True)
                P.depfile_path(ir_path).unlink(missing_ok=True)
                ir_precompile = P.precompile_snapshot(ir_argv, PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source),
                                                       ir_path, Path.cwd(), S.REPO_ROOT)
                ir_done = S.run(ir_argv)
                ir_log = LOG_DIR / f"compile-m{entry.idx:04d}-{index}-ir.log"
                S.write_text(ir_log,
                             "$ " + fmt_cmd(ir_argv) + f"\n\n[exit code] {ir_done.returncode}\n\n"
                             f"--- stdout ---\n{ir_done.stdout}\n--- stderr ---\n{ir_done.stderr}\n")
                if ir_done.returncode != 0 or not ir_path.is_file():
                    failure = {"idx": entry.idx, "name": entry.name, "source": rel(source),
                               "stage": "ir", "exit": ir_done.returncode, "log": rel(ir_log),
                               "stderr_tail": (ir_done.stderr or '').strip().splitlines()[-12:]}
                    return {"idx": entry.idx, "name": entry.name,
                            "sources": [rel(source)], "status": "fail"}, failure
                ir_step = {"source": rel(source),
                           "build_source": rel(PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source)),
                           "object": rel(ir_path), "bytes": ir_path.stat().st_size,
                           "sha256": S.sha256_file(ir_path),
                           **P.dependency_receipt(PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source),
                                                  ir_path, Path.cwd(), S.REPO_ROOT, precompile=ir_precompile)}
                stage_source = ir_path
            argv = compile_command(entry, stage_source, out_path, tc, vendor, args.werror,
                                   stage="obj" if two_stage else "single")
            log_name = f"compile-m{entry.idx:04d}" + (f"-{index}" if len(entry.sources) > 1 else "") + ".log"
            selected_source = PAYLOAD_SOURCE_OVERRIDES.get(stage_source.resolve(), stage_source)
            out_path.unlink(missing_ok=True)
            P.depfile_path(out_path).unlink(missing_ok=True)
            precompile = P.precompile_snapshot(argv, selected_source, out_path, Path.cwd(), S.REPO_ROOT)
            completed = S.run(argv)
            S.write_text(LOG_DIR / log_name,
                         "$ " + fmt_cmd(argv) + f"\n\n[exit code] {completed.returncode}\n\n"
                         f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}\n")
            if completed.returncode != 0 or not out_path.is_file() or out_path.stat().st_size == 0:
                failure = {
                    "idx": entry.idx, "name": entry.name, "source": rel(source),
                    "exit": completed.returncode, "log": rel(LOG_DIR / log_name),
                    "stderr_tail": (completed.stderr or "").strip().splitlines()[-12:],
                }
                return {"idx": entry.idx, "name": entry.name, "sources": [
                    rel(source)], "status": "fail"}, failure
            produced.append({
                "idx": entry.idx, "name": entry.name, "source": rel(source),
                "source_sha256": S.sha256_file(source),
                "build_source": rel(PAYLOAD_SOURCE_OVERRIDES.get(stage_source.resolve(), stage_source)),
                "build_source_sha256": S.sha256_file(
                    PAYLOAD_SOURCE_OVERRIDES.get(stage_source.resolve(), stage_source)),
                "object": rel(out_path), "bytes": out_path.stat().st_size,
                "sha256": S.sha256_file(out_path),
                "stage": "compile",
                "layout": S.layout_of(out_path.read_bytes()[:4]),
                "log": rel(LOG_DIR / log_name),
                **P.dependency_receipt(selected_source, out_path, Path.cwd(), S.REPO_ROOT,
                                       precompile=precompile),
                **({"compile_steps": [ir_step]} if two_stage else {}),
            })
        return {
            "idx": entry.idx, "name": entry.name,
            "sources": [rel(source) for source in entry.sources],
            "source_sha256": {rel(source): S.sha256_file(source) for source in entry.sources},
            "build_source_sha256": {
                rel(PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source)):
                S.sha256_file(PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source))
                for source in entry.sources},
            "profile": entry.flags_profile,
            "layout": entry.layout,
            "profile_layout_conflict": S.profile_emit_llvm(entry.flags_profile)
            != (entry.layout == "bitcode"),
            "vendor_lib": (vendor.for_member(entry.name).lib
                           if vendor.for_member(entry.name) else None),
            "status": "ok", "outputs": produced,
        }, failure

    if jobs == 1:
        results = [build_one(entry) for entry in compile_entries]
    else:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(build_one, compile_entries))
    for row, failure in results:
        lock_rows.append(row)
        if failure:
            failures.append(failure)
        else:
            log("compile", f"  ok m{row['idx']:03d} {row['name']} "
                           f"({len(row.get('outputs') or [])} TU)")
    rows = lock_rows

    skipped = [entry for entry in entries
               if not entry.sources and (entry.is_vendor_copy or entry.is_blocked)]
    report["compile"] = {
        "members": len(compile_entries),
        "jobs": jobs,
        "include_dirs": [rel(directory) for directory in (INCLUDE_DIR, SDK_INCLUDE_DIR)
                         if directory.is_dir()],
        "werror": bool(args.werror),
        "rows": rows,
        "failures": failures,
        "vendor_copy_skipped": [{"idx": e.idx, "name": e.name} for e in skipped],
    }
    if failures:
        for failure in failures[:12]:
            log("compile", f"  FAIL m{failure['idx']:03d} {failure['name']}: "
                           f"{'; '.join(failure['stderr_tail'][-3:])[:300]}")
        raise StageError(
            f"{len(failures)}/{len(compile_entries)} member(s) failed to compile; "
            f"first log: {failures[0]['log']}", EXIT_COMPILE)
    log("compile", f"compiled {len(compile_entries)} member(s) "
                   f"({sum(len(row.get('outputs') or []) for row in rows)} TU object(s))")


# --------------------------------------------------------------------------- #
# Stage: compose
# --------------------------------------------------------------------------- #


def _step_flags(argv: Sequence[str], drop_values: set[str]) -> list[str]:
    """Keep only the flag part of an author-published step argv."""
    flags: list[str] = []
    index = 0
    while index < len(argv):
        token = str(argv[index])
        if token == "-c":
            index += 1
            if index < len(argv) and not str(argv[index]).startswith("-"):
                index += 1
            continue
        if token == "-o":
            index += 2
            continue
        if token in drop_values:
            index += 1
            continue
        flags.append(token)
        index += 1
    return flags


def _run_compose_steps(entry: ManifestEntry, tc: S.Toolchain,
                       problems: list[str],
                       tu_receipts: list[dict[str, Any]] | None = None,
                       link_inputs: list[dict[str, Any]] | None = None) -> list[Path] | None:
    """Execute the author's compose[] recipe, redirecting outputs into build/obj/tu.

    Returns the fused member object paths, or None when a step could not be run.
    """
    compile_steps = [step for step in entry.compose
                     if str(step.get("tool", "")).startswith(("clang", "cc"))]
    link_steps = [step for step in entry.compose
                  if str(step.get("tool", "")) in ("ld.lld", "ld", "llvm-link")]
    if not compile_steps:
        problems.append(f"m{entry.idx:03d}: compose[] has no compile step")
        return None
    if len(compile_steps) != len(entry.sources):
        problems.append(f"m{entry.idx:03d}: compose compile steps differ from declared sources")
        return None
    sources: list[Path] = []
    for index, step in enumerate(compile_steps):
        raw_input = str(step.get("input") or "")
        source = gen_manifest.resolve_source(raw_input) if raw_input else entry.sources[index]
        if source is None or not source.is_file():
            problems.append(f"m{entry.idx:03d}: compose step {step.get('step')!r} "
                            f"input unresolved: {raw_input!r}")
            return None
        if source.resolve() != entry.sources[index].resolve():
            problems.append(f"m{entry.idx:03d}: compose step {step.get('step')!r} "
                            f"input differs from declared source: {raw_input!r}")
            return None
        argv = [str(token) for token in step.get("argv") or []]
        if "-c" in argv and argv.index("-c") + 1 < len(argv):
            published_input = argv[argv.index("-c") + 1]
            if not published_input.startswith("-"):
                published_source = gen_manifest.resolve_source(published_input)
                if published_source is None or published_source.resolve() != source.resolve():
                    problems.append(f"m{entry.idx:03d}: compose step {step.get('step')!r} "
                                    f"argv input differs from declared source: {published_input!r}")
                    return None
        sources.append(source)
    outputs: list[Path] = []
    for index, (step, source) in enumerate(zip(compile_steps, sources)):
        argv = [str(token) for token in step.get("argv") or []]
        raw_input = str(step.get("input") or "")
        suffix = ".bc" if entry.layout == "bitcode" else ".o"
        out_path = TU_DIR / f"{entry.idx:04d}_step{index}_{source.stem}{suffix}"
        drop = {raw_input, str(step.get("output") or ""), str(source)}
        # The author's argv may spell the input relative to the repo root or to the
        # sdk directory; both must be dropped or clang sees two input files.
        for base in (S.REPO_ROOT, S.SDK_DIR):
            try:
                drop.add((base / raw_input).resolve().as_posix())
                drop.add(os.path.relpath((base / raw_input), S.REPO_ROOT).replace("\\", "/"))
            except (OSError, ValueError):
                continue
        flags = _step_flags(argv, drop)
        if not any(flag.startswith(("-target", "--target")) for flag in flags):
            flags.insert(0, "--target=aarch64-linux-android21")
        tool = "clang++" if str(step.get("tool")) != "clang" else "clang"
        driver = tc.tool(tool) if tc.has(tool) else tc.tool("clang++")
        selected_source = PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source)
        flags += include_flags() + payload_cpp_flags(entry, source)
        command = [driver, *flags, *P.dependency_flags(selected_source, out_path),
                   "-c", str(selected_source), "-o", str(out_path)]
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        out_path.unlink(missing_ok=True)
        P.depfile_path(out_path).unlink(missing_ok=True)
        precompile = P.precompile_snapshot(command, selected_source, out_path, S.REPO_ROOT, S.REPO_ROOT)
        completed = S.run(command, cwd=S.REPO_ROOT)
        S.write_text(LOG_DIR / f"compose-m{entry.idx:04d}-step{index}.log",
                     "$ " + fmt_cmd(command) + f"\n\n[exit code] {completed.returncode}"
                     f"\n\n--- stdout ---\n{completed.stdout}"
                     f"\n--- stderr ---\n{completed.stderr}\n")
        if completed.returncode != 0 or not out_path.is_file():
            problems.append(f"m{entry.idx:03d}: compose step {step.get('step')!r} failed "
                            f"(exit {completed.returncode})")
            return None
        outputs.append(out_path)
        if tu_receipts is not None:
            tu_receipts.append({"idx": entry.idx, "name": entry.name,
                                "source": rel(source), "build_source": rel(selected_source),
                                "object": rel(out_path), "stage": "compose",
                                "bytes": out_path.stat().st_size,
                                "sha256": S.sha256_file(out_path),
                                **P.dependency_receipt(selected_source, out_path,
                                                       S.REPO_ROOT, S.REPO_ROOT, precompile=precompile)})
    link_flags: list[str] = ["-r"]
    if link_steps:
        published = [str(t) for t in link_steps[0].get("argv") or []]
        link_flags = [flag for flag in published
                      if flag.startswith("-") and flag not in ("-o", "-r", "-c")]
        link_flags.insert(0, "-r")
    if entry.layout == "bitcode" and tc.has("llvm-link"):
        command = [tc.tool("llvm-link"), "-o", str(entry.object_path),
                   *[str(path) for path in outputs]]
    else:
        command = [tc.tool("ld.lld"), *link_flags, *[str(p) for p in outputs],
                   "-o", str(entry.object_path)]
    # The per-member output directory only exists once the compiler has written
    # into it; a composed member never compiles into it directly, so create it.
    entry.object_path.parent.mkdir(parents=True, exist_ok=True)
    if link_inputs is not None:
        link_inputs.extend(P.file_record(path, S.REPO_ROOT) for path in outputs)
    entry.object_path.unlink(missing_ok=True)
    completed = S.run(command, cwd=S.REPO_ROOT)
    S.write_text(LOG_DIR / f"compose-m{entry.idx:04d}-link.log",
                 "$ " + fmt_cmd(command) + f"\n\n[exit code] {completed.returncode}"
                 f"\n\n--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}\n")
    if completed.returncode != 0 or not entry.object_path.is_file() or entry.object_path.stat().st_size == 0:
        problems.append(f"m{entry.idx:03d}: compose link failed "
                        f"(exit {completed.returncode})")
        return None
    return outputs


def stage_compose(entries: list[ManifestEntry], tc: S.Toolchain, args: argparse.Namespace,
                  report: dict[str, Any], snapshot: S.FreezeSnapshot | None = None) -> None:
    OBJ_DIR.mkdir(parents=True, exist_ok=True)
    reference = S.read_archive(snapshot.archive).by_idx() if snapshot is not None else {}
    rows: list[dict[str, Any]] = []
    problems: list[str] = []

    for entry in entries:
        row: dict[str, Any] = {"idx": entry.idx, "name": entry.name, "layout": entry.layout,
                               "object": rel(entry.object_path), "object_inputs": []}
        if entry.is_vendor_copy and not entry.sources:
            member = reference.get(entry.idx)
            if member is None:
                problems.append(f"m{entry.idx:03d}: frozen member not found for vendor-copy")
                continue
            if S.active_member_name(member.name) != entry.name:
                problems.append(f"m{entry.idx:03d}: frozen member is {member.name}, "
                                f"manifest says {entry.name}")
                continue
            entry.object_path.write_bytes(member.data)
            row.update({"mode": "vendor-copy", "source": rel(snapshot.archive),
                        "bytes": member.size, "sha256": member.sha256})
            rows.append(row)
            continue
        if entry.is_blocked:
            row.update({"mode": "blocked", "blockedBy": entry.blocked_by})
            rows.append(row)
            continue
        if not entry.sources:
            problems.append(f"m{entry.idx:03d}: no source and not vendor-copy")
            continue
        if len(entry.sources) == 1:
            if not entry.object_path.is_file():
                problems.append(f"m{entry.idx:03d}: object missing; run --compile first")
                continue
            row["mode"] = "single-tu"
            row["object_inputs"] = [P.file_record(entry.object_path, S.REPO_ROOT)]
        else:
            out_path = entry.object_path
            if entry.compose:
                # The author published the exact 4-step recipe (compile-tu1..3 +
                # partial-link) that reproduces this member, including flags the
                # profile does not carry (-fvisibility=hidden, -D_FORTIFY_SOURCE=2).
                # Reuse the step flags verbatim but redirect every output into this
                # build directory, so --build-dir stays isolated.
                row["outputs"] = []
                outputs = _run_compose_steps(entry, tc, problems, row["outputs"], row["object_inputs"])
                if outputs is None:
                    continue
                row["mode"] = "compose-steps"
            else:
                outputs = [compile_out_path(entry, index) for index in range(len(entry.sources))]
                missing = [rel(path) for path in outputs if not path.is_file()]
                if missing:
                    problems.append(f"m{entry.idx:03d}: TU object(s) missing: {missing[:3]}")
                    continue
                out_path.parent.mkdir(parents=True, exist_ok=True)
                row["object_inputs"] = [P.file_record(path, S.REPO_ROOT) for path in outputs]
                out_path.unlink(missing_ok=True)
                if entry.layout == "bitcode":
                    if not tc.has("llvm-link"):
                        problems.append(f"m{entry.idx:03d}: {len(outputs)} bitcode TUs need "
                                        f"llvm-link, which is absent")
                        continue
                    argv = [tc.tool("llvm-link"), "-o", str(out_path),
                            *[str(p) for p in outputs]]
                    run_checked("compose", f"llvm-link m{entry.idx:03d}", argv,
                                f"compose-m{entry.idx:04d}.log", EXIT_COMPILE)
                    row["mode"] = "llvm-link"
                else:
                    argv = [tc.tool("ld.lld"), "-r", "-o", str(out_path),
                            *[str(p) for p in outputs]]
                    run_checked("compose", f"ld.lld -r m{entry.idx:03d}", argv,
                                f"compose-m{entry.idx:04d}.log", EXIT_COMPILE)
                    row["mode"] = "ld.lld-r"
            row["tus"] = [rel(path) for path in outputs]
        if not entry.object_path.is_file() or entry.object_path.stat().st_size == 0:
            problems.append(f"m{entry.idx:03d}: compose produced no nonempty object")
            continue
        produced_layout = S.layout_of(entry.object_path.read_bytes()[:4])
        row["produced_layout"] = produced_layout
        row["bytes"] = entry.object_path.stat().st_size
        row["sha256"] = S.sha256_file(entry.object_path)
        row["inputs"] = [
            {"source": rel(source), "source_sha256": S.sha256_file(source),
             "build_source": rel(PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source)),
             "build_source_sha256": S.sha256_file(
                 PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source))}
            for source in entry.sources]
        if produced_layout != entry.layout:
            problems.append(f"m{entry.idx:03d} {entry.name}: produced layout "
                            f"{produced_layout!r} != declared {entry.layout!r}")
        rows.append(row)

    # Legacy sample-chain relocatable object: kept so the historical --partial-link
    # evidence keeps existing (the four members joined with ld.lld -r).
    sample = [entry for entry in entries if entry.idx in SAMPLE_IDX]
    sample_report: dict[str, Any] | None = None
    if len(sample) == 4 and all(entry.object_path.is_file() for entry in sample):
        LINK_DIR.mkdir(parents=True, exist_ok=True)
        partial = LINK_DIR / "sample-chain.partial.o"
        argv = [tc.tool("ld.lld"), "-r", *[str(e.object_path) for e in sample],
                "-o", str(partial)]
        run_checked("compose", "ld.lld -r (four sample members)", argv,
                    "partial-link.log", EXIT_ARCHIVE)
        defined = S.nm_defined_only(tc, partial)
        undefined = S.nm_undefined_only(tc, partial)
        sample_report = {
            "object": rel(partial),
            "bytes": partial.stat().st_size,
            "sha256": S.sha256_file(partial),
            "defined_externals": len(defined.defined),
            "undefined_externals": len(undefined.undefined),
            "members": [entry.name for entry in sample],
        }
        log("compose", f"sample chain: {rel(partial)} "
                       f"({sample_report['defined_externals']} defined / "
                       f"{sample_report['undefined_externals']} imported externals)")

    report["compose"] = {"members": len(rows), "rows": rows, "problems": problems,
                         "sample_chain": sample_report}
    if problems:
        for problem in problems[:12]:
            log("compose", f"  PROBLEM {problem}")
        raise StageError(f"{len(problems)} compose problem(s)", EXIT_COMPILE)
    log("compose", f"composed {len(rows)} member(s)")


# --------------------------------------------------------------------------- #
# Stage: pack (llvm-ar qc per member, then llvm-ar s)
# --------------------------------------------------------------------------- #


def stage_pack(entries: list[ManifestEntry], tc: S.Toolchain, args: argparse.Namespace,
               report: dict[str, Any], archive: Path | None = None) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    archive = archive or ARCHIVE_OUT
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        archive.unlink()
    ordered = sorted((entry for entry in entries if not entry.is_blocked),
                     key=lambda entry: entry.idx)
    blocked = [{"idx": entry.idx, "name": entry.name, "blockedBy": entry.blocked_by}
               for entry in entries if entry.is_blocked]
    missing = [entry.name for entry in ordered if not entry.object_path.is_file()]
    if missing:
        raise StageError(f"{len(missing)} member object(s) missing, e.g. {missing[:5]}; "
                         f"run --compile/--compose first", EXIT_ARCHIVE)

    object_snapshots = {entry.idx: P.file_record(entry.object_path, S.REPO_ROOT) for entry in ordered}
    compositions = {row["idx"]: row for row in (report.get("compose") or {}).get("rows", [])}
    for entry in ordered:
        composition = compositions.get(entry.idx)
        saved = object_snapshots[entry.idx]
        if composition and (composition.get("sha256"), composition.get("bytes")) != (saved["sha256"], saved["size"]):
            raise StageError(f"m{entry.idx:04d}: composed object changed before pack", EXIT_ARCHIVE)
    chunk_size = max(1, int(args.ar_chunk))
    appended = 0
    for start in range(0, len(ordered), chunk_size):
        chunk = ordered[start:start + chunk_size]
        argv = [tc.tool("llvm-ar"), "qc", str(archive),
                *[str(entry.object_path) for entry in chunk]]
        run_checked("pack", f"llvm-ar qc members {start}..{start + len(chunk) - 1}",
                    argv, f"ar-append-{start:04d}.log", EXIT_ARCHIVE)
        appended += len(chunk)
    run_checked("pack", "llvm-ar s (write the symbol index)", 
                [tc.tool("llvm-ar"), "s", str(archive)], "ar-index.log", EXIT_ARCHIVE)

    parsed = S.read_archive(archive)
    expected_names = [entry.name for entry in ordered]
    problems: list[str] = []
    if parsed.names != expected_names:
        first = next((i for i, (a, b) in enumerate(zip(expected_names, parsed.names))
                      if a != b), min(len(expected_names), len(parsed.names)))
        problems.append(
            f"archive member sequence differs at ordinal {first}: expected "
            f"{expected_names[first] if first < len(expected_names) else '<end>'!r}, got "
            f"{parsed.names[first] if first < len(parsed.names) else '<end>'!r}")
    if len(parsed.members) != len(ordered):
        problems.append(f"archive has {len(parsed.members)} members, expected {len(ordered)}")
    substituted = []
    for member, entry in zip(parsed.members, ordered):
        expected = object_snapshots[entry.idx]
        if (member.sha256 != expected["sha256"] or member.size != expected["size"]
                or P.file_record(entry.object_path, S.REPO_ROOT) != expected):
            substituted.append({"name": entry.name, "idx": entry.idx,
                                "object": rel(entry.object_path)})
    if substituted:
        problems.append(f"{len(substituted)} member body/bodies differ from the compiled "
                        f"object: {[row['name'] for row in substituted[:5]]}")

    report["pack"] = {
        "archive": rel(archive),
        "bytes": parsed.size,
        "sha256": parsed.sha256,
        "members": len(parsed.members),
        "expected_members": len(ordered),
        "blocked_members": blocked,
        "appended_in_chunks_of": chunk_size,
        "append_invocations": appended,
        "layout_counts": _counts(member.layout for member in parsed.members),
        "duplicate_names": parsed.duplicate_groups(),
        "first_names": parsed.names[:5],
        "last_names": parsed.names[-5:],
        "substituted": substituted,
        "member_inputs": [
            {"idx": entry.idx, "name": entry.name, "object": rel(entry.object_path),
             "object_sha256": object_snapshots[entry.idx]["sha256"],
             "object_bytes": object_snapshots[entry.idx]["size"],
             "sources": [
                 {"source": rel(source), "source_sha256": S.sha256_file(source),
                  "build_source": rel(PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source)),
                  "build_source_sha256": S.sha256_file(
                      PAYLOAD_SOURCE_OVERRIDES.get(source.resolve(), source))}
                 for source in entry.sources]}
            for entry in ordered],
        "problems": problems,
    }
    if problems:
        for problem in problems:
            log("pack", f"  PROBLEM {problem}")
        raise StageError(f"{len(problems)} archive problem(s)", EXIT_ARCHIVE)
    log("pack", f"{rel(archive)}: {parsed.size:,d} B, {len(parsed.members)} members, "
                f"sha256={parsed.sha256[:16]}, duplicates={parsed.duplicate_groups()}")


# --------------------------------------------------------------------------- #
# Stage: payloads (embedded programs compiled from sdk/src/payload)
# --------------------------------------------------------------------------- #


def stage_source_bootstrap(entries: list[ManifestEntry], tc: S.Toolchain,
                           args: argparse.Namespace, report: dict[str, Any],
                           vendor: VendorRules) -> list[ManifestEntry]:
    """Build this invocation's SDK core before the helper embeds its installer."""
    bundle = args.policy_bundle_source
    if bundle is None:
        try:
            report['source_kernel'] = SB.build_kernel_bundle(BUILD_DIR / 'kernel',
                source_618=args.kernel_source_618, objtree_618=args.kernel_objtree_618,
                toolchain_618=args.kernel_toolchain_618)
            bundle = S.REPO_ROOT / report['source_kernel']['bundle']
        except (OSError, ValueError, KeyError) as exc:
            raise StageError(f'kernel source build failed: {exc}', EXIT_PAYLOADS) from exc
    try:
        SB.bundle_inputs(Path(bundle).resolve())
    except (OSError, ValueError, KeyError) as exc:
        raise StageError(f'kernel source inputs invalid: {exc}', EXIT_PAYLOADS) from exc
    installers = {row[4] for row in PH.TABLE}
    core = [entry for entry in entries if entry.name not in installers]
    if len(entries) - len(core) != len(installers) or any(not entry.sources for entry in core):
        raise StageError('source bootstrap requires source-backed core and four installers', EXIT_MANIFEST)
    sdk = BUILD_DIR / 'bootstrap/sdk'
    bootstrap: dict[str, Any] = {}
    report['bootstrap'] = bootstrap
    stage_compile(core, tc, args, bootstrap, vendor)
    stage_compose(core, tc, args, bootstrap)
    stage_pack(core, tc, args, bootstrap, sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a')
    shutil.copytree(INCLUDE_DIR, sdk / 'include', dirs_exist_ok=True)
    try:
        report['source_backend'] = SB.build_backend(tc, sdk, bundle,
            BUILD_DIR / 'backend', cmake=args.cmake, jobs=args.jobs)
    except (OSError, ValueError, KeyError) as exc:
        raise StageError(f'backend source build failed: {exc}', EXIT_PAYLOADS) from exc
    return [entry for entry in entries if entry.name in installers]


def merge_bootstrap_rows(report: dict[str, Any], stage: str) -> None:
    partial = report['bootstrap'][stage]
    current = report[stage]
    current['rows'] = sorted(partial['rows'] + current['rows'], key=lambda row: row['idx'])
    current['members'] = len(current['rows'])


def stage_payloads(args: argparse.Namespace, report: dict[str, Any],
                   tc: S.Toolchain) -> None:
    """Compile the installed payload programs before anything embeds them.

    Four archive members carry a whole userland program as a byte array; this
    stage turns ``sdk/src/payload/<program>/`` into ``build/out/assets/*.bin`` and
    the ``PAYLOADS.json`` manifest, which the header generator and the assets
    stage consume. Source mode builds the paired helper first; explicit reference
    mode copies the comparison images without compiling an experimental helper.
    """
    if not PAYLOAD_BUILD_TOOL.is_file():
        raise StageError(f"payload builder missing: {rel(PAYLOAD_BUILD_TOOL)}",
                         EXIT_PAYLOADS)
    argv = [sys.executable, str(PAYLOAD_BUILD_TOOL), "--out", str(ASSETS_OUT),
            "--build-dir", str(BUILD_DIR / "payload"),
            "--log-dir", str(LOG_DIR / "payloads"), "--ndk", str(tc.ndk)]
    if SOURCE_PAYLOADS:
        SOURCE_HELPER_OUT.parent.mkdir(parents=True, exist_ok=True)
        helper_report = REPORT_DIR / "helper-build.json"
        report.setdefault("input_snapshots", []).extend(P.snapshot_inputs(
            [(HB.MANIFEST, "manifest")], S.REPO_ROOT))
        try:
            helper_build = HB.build_helper(
                tc, SOURCE_HELPER_OUT, HB.load_manifest(), helper_report,
                log_dir=LOG_DIR / "helper", sdk_archive=(S.REPO_ROOT / report['bootstrap']['pack']['archive']).resolve(),
                backend_identity=(S.REPO_ROOT / report['source_backend']['pairing']).resolve())
        except HB.HelperBuildError as exc:
            raise StageError(f"helper source build failed: {exc}", EXIT_PAYLOADS) from exc
        if helper_build.get("readiness") != "source-candidate-unvalidated-device":
            raise StageError("helper builder did not emit a complete-source candidate", EXIT_PAYLOADS)
        report["source_helper"] = helper_build
        argv += ["--source-helper", str(SOURCE_HELPER_OUT),
                 "--source-helper-report", str(helper_report),
                 "--sdk-archive", str((S.REPO_ROOT / report['bootstrap']['pack']['archive']).resolve())]
    else:
        argv.append("--reference-only")
    completed = S.run(argv, cwd=S.REPO_ROOT)
    S.write_text(LOG_DIR / "payloads.log",
                 "$ " + fmt_cmd(argv) + f"\n\n[exit code] {completed.returncode}\n\n"
                 f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}\n")
    manifest_path = ASSETS_OUT / PAYLOAD_MANIFEST_NAME
    manifest: dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StageError(f"payload manifest unreadable: {exc}", EXIT_PAYLOADS)
    problems: list[str] = []
    if completed.returncode != 0:
        problems.append(f"payload builder exited {completed.returncode}")
    if not manifest:
        problems.append(f"payload manifest not written: {rel(manifest_path)}")
    for program in manifest.get("programs") or []:
        status = program.get("status")
        asset = program.get("asset")
        published = ASSETS_OUT / str(asset)
        if status == "built" and not published.is_file():
            problems.append(f"{asset}: built but not published")
        if status == "failed":
            problems.append(f"{asset}: payload build failed")
    report["payloads"] = {
        "manifest": rel(manifest_path),
        "programs_root": manifest.get("programs_root"),
        "toolchain": manifest.get("toolchain"),
        "summary": manifest.get("summary"),
        "programs": [
            {"asset": program.get("asset"), "status": program.get("status"),
             "bytes": (program.get("built") or {}).get("bytes"),
             "sha256": (program.get("built") or {}).get("sha256"),
             "source_dir": program.get("source_dir")}
            for program in manifest.get("programs") or []
        ],
        "log": rel(LOG_DIR / "payloads.log"),
        "provenance": manifest.get("provenance"),
    }
    if problems:
        for problem in problems[:12]:
            log("payloads", f"  PROBLEM {problem}")
        raise StageError(f"{len(problems)} payload problem(s)", EXIT_PAYLOADS)
    log("payloads", f"{manifest.get('summary', {}).get('built', 0)} built, "
                    f"{manifest.get('summary', {}).get('reference_copy', 0)} reference-copy "
                    f"-> {rel(ASSETS_OUT)}")


# --------------------------------------------------------------------------- #
# Stage: assets (helper + embedded payload resources)
# --------------------------------------------------------------------------- #


def stage_assets(args: argparse.Namespace, report: dict[str, Any],
                 snapshot: S.FreezeSnapshot, tc: S.Toolchain) -> None:
    problems: list[str] = []

    ASSETS_OUT.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "schema": "maplesu-sdk-assets-stage/1",
        "generated_by": "runtime/maplesu-sdk/sdk/build.py --assets",
        "freeze": {"snapshot": rel(snapshot.root),
                   "archive_sha256": snapshot.archive_sha256,
                   "helper_sha256": snapshot.helper_sha256},
        "helper": {},
        "assets": [],
        "backend": [],
        "embedded": {"status": "not-attempted"},
    }

    # 1) embedded payload programs.  They are build output of the payload stage
    #    (build/out/assets/*.bin + PAYLOADS.json); the declared sdk/assets images
    #    are the pinned reference and are only staged when the payload stage has
    #    not produced a program yet.
    payload_manifest_path = ASSETS_OUT / PAYLOAD_MANIFEST_NAME
    payload_manifest: dict[str, Any] = {}
    if payload_manifest_path.is_file():
        try:
            payload_manifest = json.loads(payload_manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"PAYLOADS.json unreadable: {exc}")
    if SOURCE_PAYLOADS and payload_manifest.get("input_mode") != "source":
        problems.append("source assets require the source payload manifest")
    if not SOURCE_PAYLOADS and payload_manifest.get("input_mode") != "reference":
        payload_manifest = {}
    for program in payload_manifest.get("programs") or []:
        asset_name = Path(str(program.get("asset") or "")).name
        if not asset_name:
            continue
        target = ASSETS_OUT / asset_name
        published = program.get("published") or {}
        if not target.is_file():
            problems.append(f"payload program missing from {rel(ASSETS_OUT)}: {asset_name}")
            continue
        sha = S.sha256_file(target)
        manifest["assets"].append({
            "asset": asset_name,
            "out": rel(target),
            "bytes": target.stat().st_size,
            "sha256": sha,
            "origin": "source-built" if program.get("status") == "built" else "reference-copy",
            "source_dir": program.get("source_dir"),
            "matches_payload_manifest": (not published.get("sha256")) or sha == published["sha256"],
            "reference": program.get("reference"),
        })
        if published.get("sha256") and sha != published["sha256"]:
            problems.append(f"payload {asset_name}: sha256 {sha[:16]} != payload manifest "
                            f"{str(published['sha256'])[:16]}")
    manifest["payloads"] = ("source-built" if SOURCE_PAYLOADS and any(
        entry.get("origin") == "source-built" for entry in manifest["assets"])
                            else "vendor-reference")

    # 1b) reference metadata only: the pinned images stay available for
    #     provenance checks even when every program is source-built.
    declared: list[dict[str, Any]] = []
    staged_names = {Path(str(entry.get("asset") or "")).name
                    for entry in manifest["assets"]}
    if ASSETS_SPEC_PATH.is_file():
        try:
            spec = json.loads(ASSETS_SPEC_PATH.read_text(encoding="utf-8"))
            declared = list(spec.get("assets") or [])
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"ASSETS.json unreadable: {exc}")
        manifest["reference_assets"] = []
        for asset in declared:
            asset_path = asset.get("asset")
            if not isinstance(asset_path, str):
                continue
            source_path = SDK_DIR / asset_path
            name = Path(asset_path).name
            expected = str(asset.get("sha256") or "")
            if not source_path.is_file():
                problems.append(f"declared reference asset missing: {asset_path}")
                continue
            source_sha = S.sha256_file(source_path)
            reference_entry = {"asset": asset_path, "source": rel(source_path),
                               "bytes": source_path.stat().st_size,
                               "sha256": source_sha,
                               "declared_sha256": expected,
                               "matches_declared": (not expected) or source_sha == expected}
            if expected and source_sha != expected:
                problems.append(f"reference asset {asset_path}: sha256 {source_sha[:16]} "
                                f"!= declared {expected[:16]}")
            manifest["reference_assets"].append(reference_entry)
            if name in staged_names:
                # The payload stage already published this program; the pinned
                # image is provenance, never a replacement.
                continue
            if SOURCE_PAYLOADS:
                problems.append(f"source payload missing: {name}")
                continue
            # Explicit reference mode keeps comparison images together.
            shutil.copyfile(source_path, ASSETS_OUT / name)
            sha = S.sha256_file(ASSETS_OUT / name)
            manifest["assets"].append({
                "asset": asset_path, "out": rel(ASSETS_OUT / name),
                "bytes": (ASSETS_OUT / name).stat().st_size, "sha256": sha,
                "origin": "reference-copy",
                "declared_sha256": expected,
                "matches_declared": (not expected) or sha == expected,
                "matches_payload_manifest": True,
            })
        for spec_name in ("ASSETS.json", "ASSETS.sha256"):
            if (SDK_DIR / "assets" / spec_name).is_file():
                shutil.copyfile(SDK_DIR / "assets" / spec_name, ASSETS_OUT / spec_name)
    else:
        manifest["assets_note"] = f"{rel(ASSETS_SPEC_PATH)} absent; no embedded payloads staged"

    # The runtime helper is exactly the selected installer payload, never a second build.
    autorun = ASSETS_OUT / "autorun_bootstrap.bin"
    helper_program = next((program for program in payload_manifest.get("programs") or []
                           if program.get("asset") == "autorun_bootstrap.bin"), {})
    if autorun.is_file():
        HELPER_OUT.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(autorun, HELPER_OUT)
        manifest["helper"] = {"path": rel(HELPER_OUT), "out": rel(HELPER_OUT),
                              "bytes": HELPER_OUT.stat().st_size,
                              "sha256": S.sha256_file(HELPER_OUT),
                              "builtFromSource": SOURCE_PAYLOADS and helper_program.get("status") == "built",
                              "origin": "source-built" if SOURCE_PAYLOADS else "reference-copy",
                              "selected_for_runtime": True,
                              "readiness": helper_program.get("readiness"),
                              "report": helper_program.get("helper_report")}
        if SOURCE_PAYLOADS and helper_program.get("status") != "built":
            problems.append("selected helper has no source build receipt")
    else:
        problems.append("selected bootstrap missing")

    # 2) paired policy backend (a resource the helper loads from disk).
    if SOURCE_PAYLOADS:
        backend_record = helper_program.get("backend") or {}
        backend_source = backend_record.get("source")
        backends = [Path(backend_source)] if backend_source else []
        if not backends:
            problems.append("source helper has no paired backend input")
    else:
        backends = snapshot.backends
    for backend in backends:
        if not backend.is_absolute():
            backend = S.REPO_ROOT / backend
        if not backend.is_file():
            problems.append(f"paired backend is missing: {backend}")
            continue
        if SOURCE_PAYLOADS and (backend.stat().st_size, S.sha256_file(backend)) != (
                backend_record.get("bytes"), backend_record.get("sha256")):
            problems.append("paired backend differs from the source helper receipt")
            continue
        target = ASSETS_OUT / backend.name
        shutil.copyfile(backend, target)
        manifest["backend"].append({"source": rel(backend), "out": rel(target),
                                    "bytes": target.stat().st_size,
                                    "sha256": S.sha256_file(target)})

    # 3) embedded-program extraction from the archive we just packed. This is
    #    data-dependent: with a partial archive the four *_install.o members may
    #    be absent, and the extractor is another workstream's tool.
    install_names = ("maplesu_unsafe_su_install.o", "maplesu_unsafe_resetprop_install.o",
                     "maplesu_unsafe_webui_loader_install.o",
                     "maplesu_autorun_bootstrap_install.o")
    embedded_dir = ASSETS_OUT / "embedded"
    if ARCHIVE_OUT.is_file() and PAYLOAD_TOOL.is_file():
        names = set(S.read_archive(ARCHIVE_OUT).names)
        present = [name for name in install_names if name in names]
        if present:
            argv = [sys.executable, str(PAYLOAD_TOOL), "--archive", str(ARCHIVE_OUT),
                    "--out", str(embedded_dir), "--emit", "--quiet",
                    "--expected-assets", str(ASSETS_OUT)]
            completed = S.run(argv)
            S.write_text(LOG_DIR / "assets-embedded.log",
                         "$ " + fmt_cmd(argv) + f"\n\n[exit code] {completed.returncode}\n\n"
                         f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}\n")
            payloads_json = embedded_dir / "payloads.json"
            manifest["embedded"] = {
                "status": "ok" if completed.returncode == 0 and payloads_json.is_file() else "failed",
                "install_members_present": present,
                "exit": completed.returncode,
                "dir": rel(embedded_dir),
                "stderr_tail": (completed.stderr or "").strip().splitlines()[-5:],
            }
            if manifest["embedded"]["status"] != "ok":
                log("assets", f"WARNING embedded payload extraction failed "
                              f"(exit {completed.returncode}); see logs/assets-embedded.log")
                if len(present) == len(install_names):
                    problems.append("archive payloads do not match the selected assets")
        else:
            manifest["embedded"] = {"status": "skipped",
                                    "reason": "archive has none of the *_install.o members yet",
                                    "install_members_present": []}
    else:
        manifest["embedded"] = {"status": "skipped",
                                "reason": ("archive not built" if not ARCHIVE_OUT.is_file()
                                           else "extract_payloads.py absent")}

    S.write_json(ASSETS_OUT / "assets-manifest.json", manifest)
    report["assets"] = manifest
    if problems:
        for problem in problems[:12]:
            log("assets", f"  PROBLEM {problem}")
        raise StageError(f"{len(problems)} asset problem(s)", EXIT_ASSETS)
    log("assets", f"paired helper -> {rel(HELPER_OUT)}; "
                  f"{len(manifest['assets'])} declared asset(s), "
                  f"{len(manifest['backend'])} backend, embedded={manifest['embedded']['status']}")


def stage_source_validation_archive(tc: S.Toolchain, report: dict[str, Any]) -> None:
    """Capture a real full-archive link; reference comparison remains a separate result."""
    directory = LINK_DIR / "source-validation"
    directory.mkdir(parents=True, exist_ok=True)
    output, map_path = directory / "archive.so", directory / "archive.map"
    argv = [str(tc.tool("clang++")), "--target=aarch64-linux-android21", "-shared",
            "-Wl,--no-undefined", "-Wl,--no-gc-sections", "-Wl,-z,relro,-z,now",
            "-Wl,--whole-archive", str(ARCHIVE_OUT), "-Wl,--no-whole-archive",
            "-lc++_shared", "-llog", "-lz", "-ldl", "-lm", "-Wl,--trace",
            "-Wl,-Map=" + str(map_path), "-o", str(output)]
    archive_before = P.file_record(ARCHIVE_OUT, S.REPO_ROOT)
    tool_inputs = P.snapshot_inputs([(tc.tool("clang++"), "validation_tool"),
                                     (tc.tool("ld.lld"), "validation_tool"),
                                     (tc.tool("llvm-nm"), "validation_tool")], S.REPO_ROOT)
    completed = run_checked("link", "complete source archive", argv,
                            "source-validation-link.log", EXIT_ARCHIVE)
    trace = directory / "archive.trace"
    trace.write_text(completed.stdout, encoding="utf-8")
    providers = {}
    for line in completed.stdout.splitlines():
        candidate = Path(line.split("(", 1)[0]).resolve()
        if candidate == ARCHIVE_OUT.resolve() or not candidate.is_file():
            continue
        if not candidate.is_relative_to(tc.ndk.resolve()):
            raise StageError("source validation link selected an external provider", EXIT_ARCHIVE)
        providers[str(candidate)] = P.file_record(candidate, S.REPO_ROOT)
    if any(P.file_record(S.REPO_ROOT / item["path"], S.REPO_ROOT) !=
           {key: item[key] for key in ("path", "size", "sha256")} for item in tool_inputs):
        raise StageError("source validation linker tool changed", EXIT_ARCHIVE)
    if P.file_record(ARCHIVE_OUT, S.REPO_ROOT) != archive_before:
        raise StageError("source validation archive changed during link", EXIT_ARCHIVE)
    try:
        table = S.nm_symbols(tc, ARCHIVE_OUT)
    except S.ArchiveError as exc:
        raise StageError("source validation symbol capture failed: " + str(exc), EXIT_ARCHIVE) from exc
    symbols_path = directory / "archive-symbols.json"
    S.write_json(symbols_path, {"defined": sorted(table.defined), "undefined": sorted(table.undefined),
                                "weak_defined": sorted(table.weak_defined), "weak_undefined": sorted(table.weak_undefined)})
    if P.file_record(ARCHIVE_OUT, S.REPO_ROOT) != archive_before:
        raise StageError("source validation archive changed during symbol capture", EXIT_ARCHIVE)
    report["source_validation"] = {
        "schema": "maplesu-sdk-isolated-validation-inputs/1",
        "scope": "isolated-source-validation", "archive": archive_before,
        "legacy_sample": "replaced-by-complete-current-archive-no-undefined-no-gc-link",
        "symbols": P.file_record(symbols_path, S.REPO_ROOT),
        "symbol_tool": P.file_record(tc.tool("llvm-nm"), S.REPO_ROOT),
        "link": {"argv": argv, "exit_code": completed.returncode,
                 "tools_before": tool_inputs,
                 "output": P.file_record(output, S.REPO_ROOT),
                 "trace": P.file_record(trace, S.REPO_ROOT),
                 "map": P.file_record(map_path, S.REPO_ROOT),
                 "providers": list(providers.values()),
                 "compiler": P.file_record(tc.tool("clang++"), S.REPO_ROOT),
                 "linker": P.file_record(tc.tool("ld.lld"), S.REPO_ROOT)},
        "reference_equivalence": False, "runtime_acceptance": False,
        "final_source_acceptance": False}


# --------------------------------------------------------------------------- #
# Stage: gate
# --------------------------------------------------------------------------- #


def stage_explicit_legacy_abi(tc: S.Toolchain, report: dict[str, Any], required: list[str],
                              manifest_path: Path, signatures: dict[str, str]) -> dict[str, Any]:
    """Measure the source-selected explicit compatibility adapter, separately from keyless APIs."""
    directory = LINK_DIR / "explicit-legacy-abi"
    directory.mkdir(parents=True, exist_ok=True)
    contract_path = TOOLS_DIR / "explicit_legacy_abi.json"
    contract_identity = P.file_record(contract_path, S.REPO_ROOT)
    contract_bytes = contract_path.read_bytes()
    contract = json.loads(contract_bytes.decode("utf-8"))
    source = MAPLESU_SDK_ROOT / keyless_gate.EXPLICIT_LEGACY_SOURCE
    consumer = TOOLS_DIR / "explicit_legacy_public_abi.cpp"
    historical = MAPLESU_SDK_ROOT / keyless_gate.EXPLICIT_LEGACY_INCLUDE
    problems: list[str] = []
    if (len(contract_bytes) != contract_identity["size"] or
            S.sha256_bytes(contract_bytes) != contract_identity["sha256"] or
            P.file_record(contract_path, S.REPO_ROOT) != contract_identity):
        problems.append("explicit legacy ABI contract changed while reading")
    selected = [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    members = [row for row in selected if row["idx"] == 53]
    compiled = [row for row in (report.get("compile") or {}).get("rows", []) if row["idx"] == 53]
    composed = [row for row in (report.get("compose") or {}).get("rows", []) if row["idx"] == 53]
    archive_members = [member for member in S.read_archive(ARCHIVE_OUT).members
                       if member.idx == 53 and member.name == keyless_gate.EXPLICIT_LEGACY_MEMBER["name"]]
    unit = None
    if len(members) == len(compiled) == len(composed) == len(archive_members) == 1:
        member, compile_row, compose_row, archived = members[0], compiled[0], composed[0], archive_members[0]
        units = [item for item in compile_row.get("outputs", [])
                 if (S.REPO_ROOT / item["source"]).resolve() == source.resolve()]
        if (member["name"] != keyless_gate.EXPLICIT_LEGACY_MEMBER["name"] or
                member["sources"].count(keyless_gate.EXPLICIT_LEGACY_SOURCE.removeprefix("sdk/")) != 1 or
                compile_row.get("status") != "ok" or len(units) != 1 or
                compile_row.get("sources") != [rel(resolve_source(item)) for item in member["sources"]]):
            problems.append("explicit legacy source selection/compile receipt differs")
        else:
            unit = units[0]
            identity = P.file_record(S.REPO_ROOT / unit["object"], S.REPO_ROOT)
            if (identity != {"path": unit["object"], "size": unit["bytes"], "sha256": unit["sha256"]} or
                    identity not in compose_row.get("object_inputs", []) or
                    (archived.sha256, archived.size) != (compose_row.get("sha256"), compose_row.get("bytes")) or
                    P.file_record(S.REPO_ROOT / compose_row["object"], S.REPO_ROOT) !=
                    {"path": compose_row["object"], "size": archived.size, "sha256": archived.sha256} or
                    (S.REPO_ROOT / unit["build_source"]).resolve() != source.resolve() or
                    unit.get("source_sha256") != S.sha256_file(source) or
                    unit.get("build_source_sha256") != S.sha256_file(source) or
                    not unit.get("dependency_complete") or not unit.get("precompile_complete") or
                    P.file_record(source, S.REPO_ROOT) not in unit.get("dependencies", []) or
                    any(P.file_record(S.REPO_ROOT / item["path"], S.REPO_ROOT) != item
                        for item in unit.get("dependencies", []))):
                problems.append("explicit legacy compiled source/object/member pairing differs")
    else:
        problems.append("explicit legacy requires original m053 compile/compose/archive receipts")

    def capture(name: str, argv: list[str]) -> tuple[dict[str, Any], str]:
        completed = run_checked("gate", name, argv, name + ".log", EXIT_GATE)
        path = directory / (name + ".txt")
        S.write_text(path, completed.stdout)
        return dict(argv=argv, output=P.file_record(path, S.REPO_ROOT)), completed.stdout

    archive_capture, nm = capture("explicit-legacy-archive-nm", [str(tc.tool("llvm-nm")), "-A",
        "--defined-only", "--extern-only", "--format=posix", str(ARCHIVE_OUT)])
    providers = keyless_gate.archive_legacy_providers(nm, contract)
    definitions: dict[str, list[dict[str, str]]] = {}
    references: dict[str, dict[str, list[str]]] = {}
    probes = []
    units = []
    for abi, target in (("arm64", "aarch64-linux-android21"), ("armv7", "armv7a-linux-androideabi23")):
        references[abi] = {}
        for kind, input_source, includes in (("adapter", source, include_flags()),
                ("original", consumer, ["-I", str(historical)]), ("current", consumer, include_flags())):
            obj = directory / (abi + "-" + kind + ".o")
            argv = [str(tc.tool("clang++")), "--target=" + target, "-std=c++20", "-Oz", "-fPIC",
                    "-fexceptions", *includes, *P.dependency_flags(input_source, obj),
                    "-c", str(input_source), "-o", str(obj)]
            before = P.precompile_snapshot(argv, input_source, obj, Path.cwd(), S.REPO_ROOT)
            run_checked("gate", "compile explicit legacy " + abi + " " + kind, argv,
                        "explicit-legacy-" + abi + "-" + kind + ".log", EXIT_GATE)
            dependencies = P.dependency_receipt(input_source, obj, Path.cwd(), S.REPO_ROOT, precompile=before)
            probe_unit = dict(source=rel(input_source), build_source=rel(input_source), object=rel(obj),
                              bytes=obj.stat().st_size, sha256=S.sha256_file(obj), stage="explicit-legacy-abi", **dependencies)
            units.append(probe_unit)
            captured, nm = capture("explicit-legacy-" + abi + "-" + kind + "-nm",
                [str(tc.tool("llvm-nm")), "--extern-only", "--format=posix", str(obj)])
            rows = [line.split()[:2] for line in nm.splitlines() if line.strip()]
            if kind == "adapter":
                definitions[abi] = [dict(symbol=symbol, kind=tag) for symbol, tag in rows
                                    if tag in S.STRONG_DEFINED_KINDS]
            else:
                references[abi][kind] = sorted(symbol for symbol, tag in rows if tag in ("U", "w", "v")
                    and symbol.startswith(("_ZN10skroot_env", "_ZN7maplesu", "_ZN11kernel_root")))
            probe = dict(abi=abi, kind=kind, source=P.file_record(input_source, S.REPO_ROOT),
                         object=P.file_record(obj, S.REPO_ROOT), compile_argv=argv, unit=probe_unit, nm=captured)
            if abi == "arm64" and kind != "adapter":
                output = directory / (kind + "-public-abi.so")
                link_argv = [str(tc.tool("clang++")), "--target=" + target, "-shared", "-Wl,--no-undefined",
                    "-Wl,--no-gc-sections", str(obj), str(ARCHIVE_OUT), "-lc++_shared", "-llog", "-lz", "-ldl", "-lm", "-o", str(output)]
                run_checked("gate", "link explicit legacy " + kind, link_argv,
                            "explicit-legacy-" + kind + "-link.log", EXIT_GATE)
                probe["link"] = dict(argv=link_argv, output=P.file_record(output, S.REPO_ROOT))
            probes.append(probe)
    if unit:
        captured, nm = capture("explicit-legacy-archive-input-nm",
            [str(tc.tool("llvm-nm")), "--extern-only", "--defined-only", "--format=posix", str(S.REPO_ROOT / unit["object"])])
        actual = [line.split()[:2] for line in nm.splitlines() if line.strip()]
        if sorted((symbol, kind) for symbol, kind in actual if kind in S.STRONG_DEFINED_KINDS) != sorted(
                (item["symbol"], item["kind"]) for item in definitions["arm64"]):
            problems.append("explicit legacy original compile object exports differ from measured adapter")
    else:
        captured = None
    problems += keyless_gate.explicit_legacy_abi_problems(contract, archive_providers=providers,
        adapter_definitions=definitions, consumer_references=references,
        symbol_signatures=signatures, keyless_required=required)
    if P.file_record(contract_path, S.REPO_ROOT) != contract_identity:
        problems.append("explicit legacy ABI contract changed during validation")
    result = dict(schema="maplesu-sdk-explicit-legacy-abi/1", status="FAIL" if problems else "PASS", problems=problems,
        contract=contract_identity, source=P.file_record(source, S.REPO_ROOT),
        manifest=P.file_record(manifest_path, S.REPO_ROOT), compile_unit=unit,
        compose=composed[0] if len(composed) == 1 else None,
        archive_member=dict(idx=53, name=archive_members[0].name, size=archive_members[0].size,
                            sha256=archive_members[0].sha256) if len(archive_members) == 1 else None,
        archive_nm=archive_capture, archive_input_nm=captured, archive_providers=providers,
        adapter_definitions=definitions, consumer_references=references, probes=probes, units=units,
        symbol_signatures={row["symbol"]: signatures.get(row["symbol"]) for row in contract["symbols"]},
        runtime_acceptance=False)
    S.write_json(REPORT_DIR / "explicit-legacy-abi.json", result)
    return result


def stage_keyless_public_abi(tc: S.Toolchain, report: dict[str, Any],
                             manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    """Compile and link every public SDK API and a real module macro consumer."""
    source = TOOLS_DIR / "keyless_public_abi.cpp"
    directory = LINK_DIR / "keyless-public-abi"
    directory.mkdir(parents=True, exist_ok=True)
    obj, output = directory / "public-abi.o", directory / "public-abi.so"
    # Match the production WebUI module consumers and CivetWeb's no-RTTI ABI.
    compile_argv = [str(tc.tool("clang++")), "--target=aarch64-linux-android21", "-std=c++20",
                    "-fPIC", "-g0", "-Oz", "-fexceptions", "-fno-rtti", *include_flags(),
                    *P.dependency_flags(source, obj), "-c", str(source), "-o", str(obj)]
    tools_before = P.snapshot_inputs([(tc.tool(name), "validation_tool") for name in
        ("clang++", "ld.lld", "llvm-nm", "llvm-cxxfilt")], S.REPO_ROOT)
    precompile = P.precompile_snapshot(compile_argv, source, obj, Path.cwd(), S.REPO_ROOT)
    run_checked("gate", "compile keyless public API and module macros", compile_argv,
                "keyless-public-abi-compile.log", EXIT_GATE)
    dependencies = P.dependency_receipt(source, obj, Path.cwd(), S.REPO_ROOT, precompile=precompile)
    unit = dict(source=rel(source), build_source=rel(source), object=rel(obj),
                bytes=obj.stat().st_size, sha256=S.sha256_file(obj), stage="public-abi", **dependencies)
    archive_before = P.file_record(ARCHIVE_OUT, S.REPO_ROOT)
    link_argv = [str(tc.tool("clang++")), "--target=aarch64-linux-android21", "-shared",
                 "-Wl,--no-undefined", "-Wl,--no-gc-sections", "-Wl,-z,relro,-z,now",
                 str(obj), str(ARCHIVE_OUT), "-lc++_shared", "-llog", "-lz", "-ldl", "-lm",
                 "-o", str(output)]
    run_checked("gate", "link keyless public API and module macros", link_argv,
                "keyless-public-abi-link.log", EXIT_GATE)
    archive_symbols = S.nm_symbols(tc, ARCHIVE_OUT)
    probe_symbols = S.nm_symbols(tc, obj)
    linked_symbols = S.nm_symbols(tc, output, ("--dynamic", "--defined-only"))
    raw = sorted(archive_symbols.defined | archive_symbols.undefined |
                 archive_symbols.weak_defined | archive_symbols.weak_undefined)
    required = sorted(probe_symbols.undefined | probe_symbols.weak_undefined)
    all_symbols = list(dict.fromkeys([*raw, *required]))
    tool = tc.tool("llvm-cxxfilt")
    tool_before = P.file_record(tool, S.REPO_ROOT)
    completed = subprocess.run([str(tool)], input="\n".join(all_symbols) + "\n",
                               capture_output=True, text=True, encoding="utf-8")
    names = completed.stdout.splitlines()
    if completed.returncode or len(names) != len(all_symbols):
        raise StageError("keyless ABI signature capture failed", EXIT_GATE)
    signatures = dict(zip(all_symbols, names))
    capture_input = directory / "signature-input.txt"
    capture_output = directory / "signature-output.txt"
    S.write_text(capture_input, "\n".join(all_symbols) + "\n")
    S.write_text(capture_output, completed.stdout)
    explicit = stage_explicit_legacy_abi(tc, report, required, manifest_path, signatures)
    approved = explicit["symbol_signatures"] if not explicit["problems"] else None
    problems = explicit["problems"] + keyless_gate.retired_api_problems(raw, [signatures[name] for name in raw],
        [signatures[name] for name in required], explicit_legacy=approved)
    problems += keyless_gate.legacy_credential_problems(required)
    header = INCLUDE_DIR / "maplesu/compat/native_module_abi.h"
    module_symbols = keyless_gate.module_entry_symbols(header.read_text(encoding="utf-8-sig"))
    defined = linked_symbols.defined | linked_symbols.weak_defined
    problems += ["module macro export missing: " + name for name in module_symbols if name not in defined]
    problems += ["retired module export/reference: " + name.removesuffix("_keyless_v1")
                 for name in module_symbols if name.endswith("_keyless_v1") and
                 name.removesuffix("_keyless_v1") in raw]
    if P.file_record(ARCHIVE_OUT, S.REPO_ROOT) != archive_before or any(
            P.file_record(S.REPO_ROOT / item["path"], S.REPO_ROOT) !=
            {key: item[key] for key in ("path", "size", "sha256")} for item in tools_before):
        problems.append("keyless ABI archive/tool changed during validation")
    result = dict(schema="maplesu-sdk-keyless-public-abi/1", status="FAIL" if problems else "PASS",
                  source=P.file_record(source, S.REPO_ROOT), archive=archive_before,
                  object=P.file_record(obj, S.REPO_ROOT), output=P.file_record(output, S.REPO_ROOT),
                  compile_argv=compile_argv, link_argv=link_argv, dependencies=dependencies,
                  unit=unit, tools_before=tools_before, signature_tool=tool_before, required_symbols={name: signatures[name] for name in required},
                  module_symbols=module_symbols,
                  legacy_credential_symbols=sorted(set(raw).intersection(keyless_gate.LEGACY_CREDENTIAL_SYMBOLS)),
                  explicit_legacy_abi=explicit,
                  signature_input=P.file_record(capture_input, S.REPO_ROOT),
                  signature_output=P.file_record(capture_output, S.REPO_ROOT),
                  problems=problems, runtime_acceptance=False)
    S.write_json(REPORT_DIR / "keyless-public-abi.json", result)
    return result


def stage_gate(args: argparse.Namespace, report: dict[str, Any], tc: S.Toolchain) -> None:
    if not ARCHIVE_OUT.is_file():
        raise StageError(f"{rel(ARCHIVE_OUT)} not built; run --pack first", EXIT_GATE)
    gate = member_gate.run_gate(
        new_archive=ARCHIVE_OUT,
        ref_archive=args.archive,
        out_path=REPORT_DIR / "member-gate.json",
        allow_path=args.gate_allow if args.gate_allow else GATE_ALLOW_PATH,
        manifest_path=Path(args.manifest),
        scope=args.gate_scope,
        allow_partial=bool(args.allow_partial),
        jobs=max(1, min(int(args.jobs or 1), 16)),
        quiet=False,
        ndk=str(tc.ndk),
    )
    if SOURCE_PAYLOADS:
        if not report.get("source_validation"):
            stage_source_validation_archive(tc, report)
        report["source_validation"]["raw_gate"] = P.file_record(REPORT_DIR / "member-gate.json", S.REPO_ROOT)
    if getattr(args, "capture_source_validation", False):
        validation = report["source_validation"]
        symbols = sorted({symbol for row in gate["members"]
                          for field in ("raw_diffs", "w_diffs")
                          for values in row[field].values() for symbol in values})
        tool = tc.tool("llvm-cxxfilt")
        signature_tool_before = P.file_record(tool, S.REPO_ROOT)
        completed = subprocess.run([str(tool)], input="\n".join(symbols) + "\n",
                                   capture_output=True, text=True, encoding="utf-8")
        signatures = completed.stdout.splitlines()
        if completed.returncode or len(signatures) != len(symbols):
            raise StageError("source validation signature capture failed", EXIT_GATE)
        demangled = REPORT_DIR / "source-validation-signatures.json"
        S.write_json(demangled, dict(zip(symbols, signatures)))
        if P.file_record(tool, S.REPO_ROOT) != signature_tool_before:
            raise StageError("source validation signature tool changed", EXIT_GATE)
        validation["signatures"] = P.file_record(demangled, S.REPO_ROOT)
        validation["signature_tool"] = signature_tool_before
        validation["raw_gate"] = P.file_record(REPORT_DIR / "member-gate.json", S.REPO_ROOT)
    if SOURCE_PAYLOADS:
        if not report.get("source_validation"):
            stage_source_validation_archive(tc, report)
        problems = keyless_gate.structural_problems(gate)
        public_abi = stage_keyless_public_abi(tc, report, Path(args.manifest))
        problems += public_abi["problems"]
        report["keyless_public_abi"] = public_abi
        report["gate"] = dict(schema="maplesu-sdk-keyless-delivery-gate/1",
            status="FAIL" if problems else "PASS", exit_code=EXIT_GATE if problems else 0, problems=problems,
            historical_reference=dict(status=gate["status"], summary=gate.get("summary"),
                                      report=rel(REPORT_DIR / "member-gate.json")),
            reference_equivalence=False, complete_archive_link=report["source_validation"]["link"],
            public_abi=rel(REPORT_DIR / "keyless-public-abi.json"), runtime_acceptance=False)
        if problems:
            raise StageError("keyless delivery gate failed: " + "; ".join(problems[:12]), EXIT_GATE)
        log("gate", "current keyless ABI and complete archive link PASS; historical T/U migration recorded")
        return
    gate.pop("members", None)          # the JSON on disk keeps the per-member rows
    report["gate"] = gate
    if gate.get("status") != "PASS":
        raise StageError(f"member gate FAILED: {len(gate.get('problems') or [])} problem(s); "
                         f"see {rel(REPORT_DIR / 'member-gate.json')}", EXIT_GATE)


# --------------------------------------------------------------------------- #
# Legacy stage: substitution contract for the four sample members (--verify)
# --------------------------------------------------------------------------- #


def sysroot_symbol_providers(tc: S.Toolchain) -> dict[str, str]:
    sysroot = tc.ndk / "toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/lib/aarch64-linux-android"
    libraries = {
        "libc++_shared.so": "libc++_shared.so",
        "libc.so": "21/libc.so",
        "liblog.so": "21/liblog.so",
        "libm.so": "21/libm.so",
        "libdl.so": "21/libdl.so",
        "libz.so": "21/libz.so",
    }
    provider: dict[str, str] = {}
    for library, relative in libraries.items():
        path = sysroot / relative
        if not path.is_file():
            continue
        try:
            table = S.nm_symbols(tc, path, ("--dynamic", "--defined-only"))
        except S.ArchiveError:
            continue
        for name in table.defined:
            provider.setdefault(name.split("@", 1)[0], library)
    return provider


def classify_external(symbol: str) -> str:
    if symbol.startswith(("_ZN13kernel_module", "_ZNK13kernel_module", "unsafe_module",
                          "__maplesu_module", "maplesu", "maple_", "_ZN12maple_icache")):
        return "kit_internal"
    if symbol.startswith(("_ZN6asmjit", "_ZNSt", "_ZNKSt", "_ZdlPv", "_Znwm", "_ZdaPv", "_Znam")):
        return "cxx_runtime"
    if symbol.startswith(("__cxa", "__gxx", "_Unwind", "__aarch64_", "__dso", "__stack_chk")):
        return "compiler_runtime"
    if symbol in {"__cxa_atexit", "__cxa_finalize", "__stack_chk_fail", "abort", "memcpy",
                  "memset", "memmove", "memcmp", "malloc", "free", "strlen", "strcmp",
                  "strncmp", "strchr", "strstr", "snprintf", "vsnprintf", "syscall", "open",
                  "close", "read", "write", "ioctl", "mmap", "munmap", "lseek", "fstat",
                  "nanosleep", "prctl", "getpid"}:
        return "libc"
    return "other"


def stage_verify(entries: list[ManifestEntry], tc: S.Toolchain, args: argparse.Namespace,
                 report: dict[str, Any], shared_object: Path) -> None:
    sample = [entry for entry in entries if entry.idx in SAMPLE_LINK_IDX]
    if not sample:
        report["verify"] = {"skipped": "no sample member in the manifest"}
        log("verify", "skipped: no sample member declared")
        return
    snapshot = S.find_freeze(args.archive)
    reference = S.read_archive(snapshot.archive).by_idx()
    residual = LINK_DIR / "kit-residual.a"
    imported: set[str] = set()
    if residual.is_file():
        for member in S.read_archive(residual).members:
            imported |= set(S.nm_undefined_only(tc, _materialize(member, LINK_DIR / "residual-members")).undefined)
    problems: list[str] = []
    rows: list[dict[str, Any]] = []
    for entry in sample:
        base = reference.get(entry.idx)
        if base is None:
            problems.append(f"m{entry.idx:03d}: no frozen member")
            continue
        base_path = _materialize(base, BUILD_DIR / "baseline")
        base_syms = S.nm_defined_only(tc, base_path).defined
        new_syms = S.nm_defined_only(tc, entry.object_path).defined
        required = base_syms & imported
        missing = sorted(required - new_syms)
        row = {"member": entry.name, "required_by_other_members": len(required),
               "missing_from_object": missing, "defined_externals": len(new_syms),
               "baseline_externals": len(base_syms),
               "not_reproduced_vs_baseline": sorted(base_syms - new_syms)}
        rows.append(row)
        problems.extend(f"{entry.name}: required symbol missing: {sym}" for sym in missing)
    shared_defined: set[str] = set()
    if shared_object.is_file():
        shared_defined = set(S.nm_symbols(tc, shared_object, ("--defined-only",)).defined)
        if HARNESS_EXPORT not in shared_defined:
            problems.append(f"{shared_object.name}: {HARNESS_EXPORT} not defined")
    report["verify"] = {"contract": rows, "shared_object": rel(shared_object),
                        "shared_object_symbols": len(shared_defined), "problems": problems}
    for row in rows:
        log("verify", f"  contract {row['member']}: {row['required_by_other_members']} required, "
                      f"{row['defined_externals']}/{row['baseline_externals']} baseline externals")
    if problems:
        for problem in problems:
            log("verify", f"  PROBLEM {problem}")
        raise StageError(f"{len(problems)} verification problem(s)", EXIT_INTEGRITY)
    log("verify", "substitution contract holds")


def _materialize(member: S.ArchiveMember, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{member.idx:04d}__{member.name}"
    if not path.is_file():
        path.write_bytes(member.data)
    return path


# --------------------------------------------------------------------------- #
# Legacy stage: residual archive + harness shared object (--link-sample)
# --------------------------------------------------------------------------- #


def stage_link_sample(entries: list[ManifestEntry], tc: S.Toolchain, args: argparse.Namespace,
                      report: dict[str, Any]) -> Path:
    sample = [entry for entry in entries if entry.idx in SAMPLE_IDX]
    if len(sample) != 4:
        raise StageError("link-sample needs all four sample members declared", EXIT_ARCHIVE)
    sample = [entry for entry in entries if entry.idx in SAMPLE_LINK_IDX]
    snapshot = S.find_freeze(args.archive)
    LINK_DIR.mkdir(parents=True, exist_ok=True)
    residual = LINK_DIR / "kit-residual.a"
    shutil.copyfile(snapshot.archive, residual)
    names = [entry.name for entry in sample]
    before = S.llvm_ar_list(tc, residual)
    run_checked("link", f"llvm-ar d (remove {len(names)} sample members from the residual copy)",
                [tc.tool("llvm-ar"), "d", str(residual), *names], "ar-delete.log", EXIT_ARCHIVE)
    after = S.llvm_ar_list(tc, residual)
    leaked = sorted(set(names) & set(after))
    if leaked:
        raise StageError(f"residual archive still carries sample members: {leaked}", EXIT_ARCHIVE)
    if not HARNESS_SOURCE.is_file():
        raise StageError(f"harness source missing: {rel(HARNESS_SOURCE)}", EXIT_ARCHIVE)
    harness_object = OBJ_DIR / "sample_chain_harness.o"
    harness_argv = ([str(tc.tool("clang++")), *S.profile_flags("core-oz-elf", "cxx"),
                     *DIAGNOSTIC_FLAGS, *include_flags(),
                     *P.dependency_flags(HARNESS_SOURCE, harness_object),
                     "-c", str(HARNESS_SOURCE), "-o", str(harness_object)])
    harness_object.unlink(missing_ok=True)
    P.depfile_path(harness_object).unlink(missing_ok=True)
    harness_precompile = P.precompile_snapshot(harness_argv, HARNESS_SOURCE, harness_object,
                                               Path.cwd(), S.REPO_ROOT)
    run_checked("link", "compile harness", harness_argv, "compile-harness.log", EXIT_ARCHIVE)
    harness_receipt = {"source": rel(HARNESS_SOURCE), "build_source": rel(HARNESS_SOURCE),
                       "object": rel(harness_object), "stage": "link-sample",
                       "bytes": harness_object.stat().st_size,
                       "sha256": S.sha256_file(harness_object),
                       **P.dependency_receipt(HARNESS_SOURCE, harness_object,
                                              Path.cwd(), S.REPO_ROOT, precompile=harness_precompile)}
    report["link_sample"] = {"outputs": [harness_receipt]}
    output = LINK_DIR / "libmaplesu_sample_chain.so"
    link_argv = ([str(tc.tool("clang++")), "--target=aarch64-linux-android21", "-shared",
                  "-Wl,--no-undefined", "-Wl,--gc-sections", "-Wl,-z,relro,-z,now",
                  "-o", str(output), str(harness_object),
                  *[str(entry.object_path) for entry in sample], str(residual),
                  "-lc++_shared", "-llog", "-lz", "-ldl", "-lm"])
    run_checked("link", "clang++ -shared -Wl,--no-undefined", link_argv, "link-sample.log",
                EXIT_ARCHIVE)
    report["residual_archive"] = {"source": rel(snapshot.archive),
                                  "before": len(before), "after": len(after),
                                  "removed": names}
    report["link_sample"].update({"shared_object": rel(output), "bytes": output.stat().st_size,
                                  "sha256": S.sha256_file(output), "link_command": fmt_cmd(link_argv)})
    log("link", f"residual {len(after)} members; shared object {rel(output)} "
                f"({output.stat().st_size:,d} B)")
    return output


# --------------------------------------------------------------------------- #
# Stage: report
# --------------------------------------------------------------------------- #


def collect_build_provenance(args: argparse.Namespace, report: dict[str, Any],
                             tc: S.Toolchain | None) -> dict[str, Any]:
    """Describe this invocation's actual compiler inputs, not a repository scan."""
    inputs = [(Path(__file__), "build_script"), (Path(S.__file__), "build_script"),
              (Path(P.__file__), "build_script"), (Path(gen_manifest.__file__), "build_script"),
              (VENDOR_RULES_PATH, "build_rule")]
    stage_rows = {stage: {row["idx"]: row
                         for part in (report.get("bootstrap") or {}, report)
                         for row in (part.get(stage) or {}).get("rows") or []}.values()
                  for stage in ("compile", "compose")}
    units = [output for stage in ("compile", "compose")
             for row in stage_rows[stage]
             for output in row.get("outputs") or []]
    units += (report.get("link_sample") or {}).get("outputs") or []
    public_abi = report.get("keyless_public_abi")
    if public_abi:
        units.append(public_abi["unit"])
        units.extend(public_abi["explicit_legacy_abi"]["units"])
        inputs += [(TOOLS_DIR / "keyless_gate.py", "build_script"),
                   (TOOLS_DIR / "keyless_public_abi.cpp", "abi_contract"),
                   (TOOLS_DIR / "explicit_legacy_abi.json", "abi_contract"),
                   (TOOLS_DIR / "explicit_legacy_public_abi.cpp", "abi_contract"),
                   (REPORT_DIR / "keyless-public-abi.json", "validation_artifact"),
                   (REPORT_DIR / "explicit-legacy-abi.json", "validation_artifact"),
                   (S.REPO_ROOT / public_abi["output"]["path"], "validation_artifact")]
        explicit = public_abi["explicit_legacy_abi"]
        artifacts = [public_abi["signature_input"], public_abi["signature_output"],
                     explicit["archive_nm"]["output"]]
        if explicit["archive_input_nm"]:
            artifacts.append(explicit["archive_input_nm"]["output"])
        for probe in explicit["probes"]:
            artifacts.append(probe["nm"]["output"])
            if probe.get("link"):
                artifacts.append(probe["link"]["output"])
        inputs += [(S.REPO_ROOT / item["path"], "validation_artifact") for item in artifacts]
    selection = report.get("source_selection")
    if selection:
        inputs.append((S.REPO_ROOT / selection["manifest"]["path"], "source_selection"))
        inputs += [(S.REPO_ROOT / row["path"], "selected_source") for row in selection["files"]]
    reasons: list[str] = []
    children = []
    optional_inputs = []
    for row in stage_rows["compose"]:
        if row.get("mode") == "blocked":
            continue
        identities = list(row.get("object_inputs") or [])
        if row.get("object") and all(key in row for key in ("bytes", "sha256")):
            identities.append({"path": row["object"], "size": row["bytes"], "sha256": row["sha256"]})
        else:
            reasons.append(f"composed object receipt missing: m{row['idx']:04d}")
        for identity in identities:
            try:
                if P.file_record(S.REPO_ROOT / identity["path"], S.REPO_ROOT) != identity:
                    reasons.append(f"compose object changed since snapshot: {identity['path']}")
            except OSError as exc:
                reasons.append(f"compose object {identity['path']}: {exc}")
    stages = report.get("stages_run") or []
    manifest_path = Path(args.manifest)
    if manifest_path.is_file():
        inputs.append((manifest_path, "manifest"))
        try:
            for line in manifest_path.read_text(encoding="utf-8").splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("manifest record is not an object")
                    source_file = record.get("sourceFile")
                    if source_file:
                        inputs.append((Path(source_file), "manifest_reference"))
        except (OSError, ValueError) as exc:
            reasons.append(f"manifest provenance: {exc}")
    if "manifest" in stages:
        manifest_dir = Path(args.manifest_dir) if args.manifest_dir else MANIFEST_DIR
        inputs += [(path, "manifest") for path in sorted(manifest_dir.glob("*.json"))
                   if gen_manifest.MEMBER_FILE_RE.match(path.name) and not path.name.startswith("_")]
    if "compile" in stages or "compose" in stages:
        inputs += [(Path(PH.__file__), "build_script"), (ASSETS_SPEC_PATH, "manifest")]
    for row in (report.get("payload_inputs") or {}).get("members") or []:
        inputs += [(Path(row["asset_path"]), "asset"),
                   (SDK_DIR / "assets" / row["asset"], "asset")]
        inputs += [(Path(header["path"]), "generated_header")
                   for header in row.get("generated_headers") or []]
    payloads = report.get("payloads") or {}
    payload_manifest = ASSETS_OUT / PAYLOAD_MANIFEST_NAME
    if SOURCE_PAYLOADS and not payloads and payload_manifest.is_file():
        inputs += [(PAYLOAD_BUILD_TOOL, "build_script"), (payload_manifest, "manifest")]
        try:
            cached_payloads = json.loads(payload_manifest.read_text(encoding="utf-8"))
            if cached_payloads.get("provenance"):
                children.append(cached_payloads["provenance"])
            else:
                reasons.append("selected payload manifest has no dependency receipt")
        except (OSError, ValueError) as exc:
            reasons.append(f"selected payload provenance: {exc}")
    if payloads:
        inputs += [(PAYLOAD_BUILD_TOOL, "build_script"), (Path(payloads["manifest"]), "manifest")]
        child = payloads.get("provenance")
        if child:
            children.append(child)
        else:
            reasons.append("payload build has no dependency receipt")
    backend = report.get('source_backend')
    if backend:
        children.append(backend['provenance'])
    assets = report.get("assets") or {}
    if assets:
        inputs += [(Path(HB.__file__), "build_script"), (PAYLOAD_TOOL, "build_script"),
                   (ASSETS_SPEC_PATH, "manifest")]
        inputs += [(Path(row["source"]), "asset")
                   for row in assets.get("reference_assets") or [] if row.get("source")]
        inputs += [(Path(row["source"]), "asset")
                   for row in assets.get("backend") or [] if row.get("source")]
    if "gate" in stages:
        inputs.append((Path(member_gate.__file__), "build_script"))
        gate_allow = Path(args.gate_allow) if args.gate_allow else GATE_ALLOW_PATH
        if args.gate_allow and not gate_allow.is_file():
            reasons.append(f"selected gate allow file is missing: {P.canonical_path(gate_allow, S.REPO_ROOT)}")
        for path in (gate_allow, member_gate.DEFAULT_BASELINE):
            optional_inputs.append({"path": P.canonical_path(path, S.REPO_ROOT),
                                    "role": "build_rule", "present": path.is_file()})
            if path.is_file():
                inputs.append((path, "build_rule"))
    residual = report.get("residual_archive") or {}
    if residual.get("source"):
        inputs.append((Path(residual["source"]), "asset"))
    if ("pack" in stages or "compose" in stages) and "compile" not in stages:
        reasons.append("SDK objects were reused without compile receipts from this invocation")
    if not units and not any(child.get("translation_units") for child in children):
        reasons.append("no translation units were captured by this invocation")
    validation = report.get("source_validation")
    if validation:
        for key in ("archive", "raw_gate", "signatures", "symbols"):
            if key in validation:
                inputs.append((S.REPO_ROOT / validation[key]["path"], "validation_artifact"))
        for key in ("output", "trace", "map"):
            inputs.append((S.REPO_ROOT / validation["link"][key]["path"], "validation_artifact"))
    raw_only_failure = (validation is not None and "raw_gate" in validation and
                        report.get("failure", {}).get("exit_code") == EXIT_GATE and
                        report.get("gate", {}).get("status") == "FAIL" and
                        report.get("gate", {}).get("scope") == "full" and
                        report.get("gate", {}).get("summary", {}).get("compared") == 260 and
                        all(report["gate"]["summary"].get(key) == 0
                            for key in ("missing", "extra", "deferred")))
    if report.get("failure") and not raw_only_failure:
        reasons.append("build invocation failed; receipt covers only captured inputs")
    toolchain = None
    if tc is not None:
        try:
            toolchain = P.toolchain_record(tc, S.REPO_ROOT,
                                           (report.get("toolchain") or {}).get("versions"))
        except (OSError, subprocess.TimeoutExpired, S.ToolchainMissing) as exc:
            reasons.append(f"toolchain provenance: {exc}")
    else:
        reasons.append("toolchain was not resolved")
    receipt = P.build_receipt(units, inputs, S.REPO_ROOT, toolchain,
                              children=children, incomplete=reasons,
                              input_snapshots=report.get("input_snapshots") or [])
    if optional_inputs:
        receipt["optional_inputs"] = optional_inputs
    return receipt


def write_report(args: argparse.Namespace, report: dict[str, Any],
                 started: float, tc: S.Toolchain | None = None) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report.setdefault("schema", "maplesu-sdk-build/2")
    report["generated_by"] = "runtime/maplesu-sdk/sdk/build.py"
    report["generated_at_utc"] = S.utc_stamp()
    report["source_date_epoch"] = os.environ.get("SOURCE_DATE_EPOCH",
                                                S.DEFAULT_SOURCE_DATE_EPOCH)
    report["duration_seconds"] = round(time.monotonic() - started, 2)
    report["invocation"] = {"argv": sys.argv[1:], "python": sys.version.split()[0]}
    report["provenance"] = collect_build_provenance(args, report, tc)
    path = REPORT_DIR / "build-report.json"
    S.write_json(path, S.jsonable(report))
    return path


def print_summary(report: dict[str, Any], entries: list[ManifestEntry],
                  report_path: Path) -> None:
    print()
    print("=== MapleSU Ultra SDK build summary ===")
    meta = report.get("manifest_stage") or {}
    if meta:
        counts = meta.get("counts") or {}
        print(f"  manifest: {meta.get('members')}/{expected_members()} declared "
              f"(complete={counts.get('complete', 0)} partial={counts.get('partial', 0)} "
              f"vendor-copy={counts.get('vendor-copy', 0)}, "
              f"missing={len(meta.get('missing_idx') or [])})")
    blocked = (report.get("pack") or {}).get("blocked_members") or []
    if blocked:
        print(f"  blocked:  {len(blocked)} member(s) declared partial-no-source "
              f"(blockedBy), excluded from the archive")
    compile_info = report.get("compile") or {}
    if compile_info:
        print(f"  compile:  {compile_info.get('members')} member(s), "
              f"{sum(len(row.get('outputs') or []) for row in compile_info.get('rows') or [])} "
              f"TU object(s), {len(compile_info.get('failures') or [])} failure(s)")
    pack = report.get("pack") or {}
    if pack:
        print(f"  archive:  {pack.get('archive')} — {pack.get('members')} members, "
              f"{pack.get('bytes'):,d} B, sha256={str(pack.get('sha256'))[:16]}, "
              f"layouts={pack.get('layout_counts')}")
    payloads = report.get("payloads") or {}
    if payloads:
        summary = payloads.get("summary") or {}
        print(f"  payloads: {summary.get('programs', 0)} program(s) — "
              f"built={summary.get('built', 0)} "
              f"reference-copy={summary.get('reference_copy', 0)} "
              f"failed={summary.get('failed', 0)}")
    assets = report.get("assets") or {}
    if assets:
        print(f"  assets:   helper={assets.get('helper', {}).get('out', assets.get('helper', {}).get('path'))} "
              f"({len(assets.get('assets') or [])} payload(s), embedded="
              f"{(assets.get('embedded') or {}).get('status')})")
    gate = report.get("gate") or {}
    if gate:
        print(f"  gate:     {gate.get('status')} — compared={gate.get('summary', {}).get('compared')} "
              f"pass={gate.get('summary', {}).get('pass')} fail={gate.get('summary', {}).get('fail')} "
              f"missing={gate.get('summary', {}).get('missing')} "
              f"u_diff={gate.get('summary', {}).get('u_missing_total')}+"
              f"{gate.get('summary', {}).get('u_extra_total')}")
    if "link_sample" in report:
        print(f"  harness:  {report['link_sample']['shared_object']}")
    if "verify" in report and "problems" in (report.get("verify") or {}):
        print(f"  verify:   {'PASS' if not report['verify']['problems'] else 'FAIL'}")
    print(f"  report:   {rel(report_path)}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="build.py",
        description="Single build entry for the MapleSU Ultra SDK: 260-member archive from source.",
        epilog=(
            "exit codes: 0 ok, 2 environment/toolchain, 3 manifest, 4 compile/compose, "
            "5 archive/link, 6 member integrity (--verify), 7 member gate, 8 assets, "
            "9 payload build. With no stage flag, --all is assumed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    stages = parser.add_argument_group("stages")
    stages.add_argument("--all", action="store_true",
                        help="check-env + manifest + payloads + compile + compose + pack "
                             "+ assets + gate + report (+ link-sample/verify for the four "
                             "sample members)")
    stages.add_argument("--check", "--check-env", dest="check", action="store_true",
                        help="pinned toolchain and frozen snapshot identity")
    stages.add_argument("--gen-manifest", "--manifest-stage", dest="gen_manifest",
                        action="store_true",
                        help="collect sdk/manifest/*.json into manifest.jsonl + coverage")
    stages.add_argument("--compile", action="store_true", help="compile every declared member TU")
    stages.add_argument("--compose", "--partial-link", dest="compose", action="store_true",
                        help="fuse multi-TU members with ld.lld -r / llvm-link (legacy alias "
                             "--partial-link also writes build/link/sample-chain.partial.o)")
    stages.add_argument("--pack", "--archive-stage", dest="pack", action="store_true",
                        help="llvm-ar qc member-by-member in manifest order, then llvm-ar s")
    stages.add_argument("--payloads", action="store_true",
                        help="stage selected payloads into build/out/assets/*.bin")
    payload_mode = stages.add_mutually_exclusive_group()
    payload_mode.add_argument("--source-payloads", action="store_true", default=True,
                              help="build 4 source programs and paired backend/helper (default)")
    payload_mode.add_argument("--reference-payloads", dest="source_payloads", action="store_false",
                              help="explicit historical comparison with reference payload images")
    stages.add_argument("--assets", action="store_true",
                        help="stage helper + embedded payload assets under build/out")
    stages.add_argument("--gate", action="store_true",
                        help="per-member T/U/layout gate against the frozen epoch")
    stages.add_argument("--report", action="store_true", help="write build/report/build-report.json")
    stages.add_argument("--verify", action="store_true",
                        help="legacy substitution contract for the four sample members (exit 6)")
    stages.add_argument("--link-sample", action="store_true",
                        help="legacy harness shared object against the residual archive (exit 5)")
    stages.add_argument("--clean", action="store_true", help="remove the build directory and exit")

    inputs = parser.add_argument_group("inputs")
    inputs.add_argument("--manifest", default=str(MANIFEST_PATH), help="manifest.jsonl path")
    inputs.add_argument("--source-selection", type=Path, help="exact source/receipt identities for this isolated composition")
    inputs.add_argument("--capture-source-validation", action="store_true",
                        help="capture full source-archive link/review inputs; reference gate exit is unchanged")
    inputs.add_argument("--manifest-dir", default=None, help="member metadata dir (default sdk/manifest)")
    inputs.add_argument("--coverage", default=None, help="coverage markdown output path")
    inputs.add_argument("--catalog", default=None, help="member catalog markdown output path")
    inputs.add_argument("--archive", default=None,
                        help="frozen residual archive (default: the freeze snapshot; never the "
                             "live lib tree under runtime/maplesu-sdk)")
    inputs.add_argument("--build-dir", default=None, help="output directory (default sdk/build)")
    inputs.add_argument("--ndk", default=None, help="override the NDK root")
    inputs.add_argument("--policy-bundle-source", type=Path, default=None,
                        help="explicit source-generated policy bundle and Kbuild receipts; otherwise build all kernel families")
    inputs.add_argument("--kernel-source-618", type=Path, default=None,
                        help="prepared 6.18 kernel source passed to the maintained Kbuild tool")
    inputs.add_argument("--kernel-objtree-618", type=Path, default=None,
                        help="prepared 6.18 kernel object tree passed to the maintained Kbuild tool")
    inputs.add_argument("--kernel-toolchain-618", type=Path, default=None,
                        help="prepared 6.18 LLVM usr directory passed to the maintained Kbuild tool")
    inputs.add_argument("--cmake", type=Path, default=None,
                        help="CMake used for the source backend (default Android SDK 3.22.1)")
    inputs.add_argument("--gate-allow", default=None,
                        help="member gate allowlist (default sdk/notes/gate-allow.json)")
    inputs.add_argument("--gate-scope", choices=("auto", "full", "partial"), default="auto",
                        help="gate scope (auto: full only when the manifest declares 260)")
    inputs.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 4),
                        help="parallel compile / llvm-nm workers (default 8)")
    inputs.add_argument("--ar-chunk", type=int, default=64,
                        help="members appended per llvm-ar call (default 64; keeps the command "
                             "line short on Windows)")
    inputs.add_argument("--werror", action="store_true", help="treat compiler warnings as errors")

    manifest_opts = parser.add_argument_group("manifest collection")
    manifest_opts.add_argument("--allow-partial", action="store_true",
                               help="accept a manifest that covers <260 members (interim builds)")
    manifest_opts.add_argument("--idx-base", choices=("auto", "strict"), default="auto",
                               help="member idx resolution vs the freeze (default auto)")
    manifest_opts.add_argument("--skip-invalid", action="store_true",
                               help="exclude metadata records with errors from manifest.jsonl "
                                    "and list them (interim health check)")
    manifest_opts.add_argument("--require-normalized", action="store_true",
                               help="refuse manifest files with a non-canonical idx/file name")
    manifest_opts.add_argument("--no-legacy", action="store_true",
                               help="do not carry over entries from an existing manifest.jsonl")
    manifest_opts.add_argument("--allow-shrink", action="store_true",
                               help="allow the collected manifest to lose members")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--json", action="store_true", help="also print the build report JSON")
    misc.add_argument("--list-profiles", action="store_true",
                      help="print the flagsProfile table and exit")
    misc.add_argument("--version", action="version", version="build.py 2.0.0")
    return parser.parse_args(argv)


def _select_stages(args: argparse.Namespace) -> dict[str, bool]:
    selected = {
        "check": args.check,
        "manifest": args.gen_manifest,
        "payloads": args.payloads,
        "compile": args.compile,
        "compose": args.compose,
        "pack": args.pack,
        "assets": args.assets,
        "gate": args.gate,
        "report": args.report,
        "verify": args.verify,
        "link_sample": args.link_sample,
    }
    if args.all or not any(selected.values()):
        selected = {key: True for key in selected}
        # Current source archives use the complete archive and public API links.
        if args.source_payloads:
            selected["link_sample"] = selected["verify"] = False
    if args.source_payloads and selected['payloads']:
        for stage in ('manifest', 'compile', 'compose', 'pack'):
            selected[stage] = True
    return selected


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    selected = _select_stages(args)
    if args.source_payloads and args.all and not args.source_selection:
        raise SystemExit("complete source builds require --source-selection")
    if args.capture_source_validation and (not args.all or not args.source_payloads or
            args.allow_partial or args.gate_scope == "partial" or not args.source_selection):
        raise SystemExit("--capture-source-validation requires complete --all source payloads and source selection")
    if getattr(args, "capture_source_validation", False):
        # The complete current archive link replaces the old four-member/frozen-residual sample.
        selected["link_sample"] = selected["verify"] = False

    global BUILD_DIR, OBJ_DIR, PAYLOAD_GEN_DIR, TU_DIR, OUT_DIR, LINK_DIR, LOG_DIR, REPORT_DIR
    global ARCHIVE_OUT, HELPER_OUT, SOURCE_HELPER_OUT, ASSETS_OUT, SOURCE_PAYLOADS
    SOURCE_PAYLOADS = bool(args.source_payloads)
    if args.build_dir:
        BUILD_DIR = Path(args.build_dir).resolve()
        OBJ_DIR = BUILD_DIR / "obj"
        PAYLOAD_GEN_DIR = BUILD_DIR / "assets-gen"
        TU_DIR = OBJ_DIR / "tu"
        OUT_DIR = BUILD_DIR / "out"
        LINK_DIR = BUILD_DIR / "link"
        LOG_DIR = BUILD_DIR / "logs"
        REPORT_DIR = BUILD_DIR / "report"
        ARCHIVE_OUT = OUT_DIR / "libkernel_module_kit_static.a"   # residual: build output
        HELPER_OUT = OUT_DIR / "helper" / "autorun_bootstrap"
        SOURCE_HELPER_OUT = OUT_DIR / "source" / "helper" / "autorun_bootstrap"
        ASSETS_OUT = OUT_DIR / "assets"
        if selected["manifest"]:
            if Path(args.manifest).resolve() == MANIFEST_PATH.resolve():
                args.manifest = str(BUILD_DIR / "manifest.jsonl")
            args.coverage = args.coverage or str(REPORT_DIR / "MANIFEST-COVERAGE.md")
            args.catalog = args.catalog or str(REPORT_DIR / "MEMBER-CATALOG.md")

    if args.list_profiles:
        print("flagsProfile table (sdk_common.FLAG_PROFILES):")
        for name, spec in S.FLAG_PROFILES.items():
            print(f"  {name:32s} layout={'bitcode' if spec['emit_llvm'] else 'elf':7s} "
                  f"opt={spec['opt']:4s} std={spec.get('std') or '-':6s} "
                  f"exceptions={spec['exceptions']} rtti={spec['rtti']}")
            print(f"      {spec['description']}")
        vendor = VendorRules.load(VENDOR_RULES_PATH)
        if vendor.profiles:
            print("vendor profiles from third_party/build_rules.json:")
            for name, spec in sorted(vendor.profiles.items()):
                print(f"  {name:32s} language={spec.get('language')} layout={spec.get('layout')} "
                      f"emit={' '.join(spec.get('emit') or [])}")
        return EXIT_OK

    if args.clean:
        if BUILD_DIR.is_dir():
            shutil.rmtree(BUILD_DIR)
            print(f"[clean] removed {rel(BUILD_DIR)}")
        else:
            print(f"[clean] nothing to remove at {rel(BUILD_DIR)}")
        return EXIT_OK

    (BUILD_DIR / "report").mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    report: dict[str, Any] = {"stages_run": [name for name, on in selected.items() if on]}
    entries: list[ManifestEntry] = []
    tc: S.Toolchain | None = None

    try:
        build_inputs = [(Path(__file__), "build_script"), (Path(S.__file__), "build_script"),
                        (Path(P.__file__), "build_script"), (Path(gen_manifest.__file__), "build_script"),
                        (VENDOR_RULES_PATH, "build_rule")]
        if selected["payloads"] or selected["assets"]:
            build_inputs += [(Path(HB.__file__), "build_script"), (Path(SB.__file__), "build_script"),
                             (PAYLOAD_BUILD_TOOL, "build_script"), (PAYLOAD_TOOL, "build_script")]
        if selected["compile"] or selected["compose"] or selected["payloads"]:
            build_inputs += [(Path(PH.__file__), "build_script"), (ASSETS_SPEC_PATH, "manifest")]
        if selected["gate"]:
            gate_allow = Path(args.gate_allow) if args.gate_allow else GATE_ALLOW_PATH
            build_inputs += [(Path(member_gate.__file__), "build_script"),
                             (Path(keyless_gate.__file__), "build_script"),
                             (TOOLS_DIR / "keyless_public_abi.cpp", "abi_contract"),
                             (TOOLS_DIR / "explicit_legacy_abi.json", "abi_contract"),
                             (TOOLS_DIR / "explicit_legacy_public_abi.cpp", "abi_contract")]
            build_inputs += [(path, "build_rule") for path in (gate_allow, member_gate.DEFAULT_BASELINE)
                             if path.is_file()]
        report["input_snapshots"] = P.snapshot_inputs(build_inputs, S.REPO_ROOT)
        if args.source_selection:
            selection = capture_source_selection(args.source_selection, S.REPO_ROOT)
            report["source_selection"] = selection
            report["input_snapshots"] += [{**selection["manifest"], "roles": ["source_selection"]}]
            report["input_snapshots"] += [{**row, "roles": ["selected_source"]} for row in selection["files"]]
        tc = S.resolve_toolchain(args.ndk)
        vendor = VendorRules.load(VENDOR_RULES_PATH)

        if selected["check"]:
            stage_check_env(tc, args, report)
        if selected["manifest"]:
            stage_manifest(args, report)
        if selected["compile"] or selected["compose"] or selected["pack"] \
                or selected["assets"] or selected["gate"] or selected["verify"] \
                or selected["link_sample"] or selected['payloads']:
            report["input_snapshots"].extend(P.snapshot_inputs(
                [(Path(args.manifest), "manifest")], S.REPO_ROOT))
            entries, meta = load_manifest(Path(args.manifest), args.allow_partial)
            if SOURCE_PAYLOADS:
                report["keyless_selection"] = validate_keyless_sources(entries)
            report.setdefault("manifest", meta)
            log("manifest", f"{len(entries)} member(s) declared: "
                            f"{meta['status_counts']} (missing {len(meta['missing_idx'])})")
            if meta["missing_idx"]:
                log("manifest", f"PARTIAL: {len(meta['missing_idx'])}/{expected_members()} "
                                f"indices have no metadata (--allow-partial)")
        compile_entries = entries
        source_bootstrap = SOURCE_PAYLOADS and selected['payloads']
        if source_bootstrap:
            compile_entries = stage_source_bootstrap(entries, tc, args, report, vendor)
        if selected["payloads"]:
            # Payload programs are embedded by the *_install.o members, so they
            # must exist before the header generator and the compile stage run.
            # Source payloads are the default; only --reference-payloads selects
            # the historical comparison images.
            stage_payloads(args, report, tc)
        if selected["compile"] or selected["compose"]:
            if any(entry.name in {row[4] for row in PH.TABLE} for entry in entries):
                ensure_payload_headers(args)
                prepare_payload_sources(entries, report)
        if selected["compile"]:
            stage_compile(compile_entries, tc, args, report, vendor)
            if source_bootstrap:
                merge_bootstrap_rows(report, 'compile')
        if selected["compose"]:
            snapshot = None if SOURCE_PAYLOADS else S.find_freeze(args.archive)
            stage_compose(compile_entries, tc, args, report, snapshot)
            if source_bootstrap:
                merge_bootstrap_rows(report, 'compose')
        if selected["pack"]:
            stage_pack(entries, tc, args, report)
            if source_bootstrap:
                try:
                    report['final_archive_stability'] = SB.verify_final_archive(
                        tc, report['source_backend'], report['source_helper'], ARCHIVE_OUT,
                        {row[4] for row in PH.TABLE}, BUILD_DIR / 'final-archive-stability')
                except (OSError, ValueError, KeyError) as exc:
                    raise StageError(f'final archive pairing failed: {exc}', EXIT_ARCHIVE) from exc
        if SOURCE_PAYLOADS and selected["pack"]:
            stage_source_validation_archive(tc, report)
        if selected["assets"]:
            snapshot = S.find_freeze(args.archive)
            stage_assets(args, report, snapshot, tc)

        shared_object: Path | None = None
        declared_idx = {entry.idx for entry in entries}
        samples_present = all(idx in declared_idx for idx in SAMPLE_IDX)
        if selected["link_sample"]:
            if samples_present:
                shared_object = stage_link_sample(entries, tc, args, report)
            else:
                # --all must not die because a manifest snapshot is mid-write or the
                # sample members are not declared yet; the strict --link-sample stage
                # still refuses to run. The skip is recorded, never silent.
                missing_samples = [idx for idx in SAMPLE_IDX if idx not in declared_idx]
                report["link_sample"] = {"skipped": "sample members not declared",
                                         "missing_idx": missing_samples}
                log("link", f"skipped: sample member(s) not declared: {missing_samples}")
                selected["verify"] = False
        if selected["verify"]:
            if shared_object is None:
                shared_object = LINK_DIR / "libmaplesu_sample_chain.so"
            if shared_object.is_file():
                stage_verify(entries, tc, args, report, shared_object)
            else:
                report["verify"] = {"skipped": "no harness shared object"}
                log("verify", "skipped: no harness shared object")
        if selected["gate"]:
            stage_gate(args, report, tc)
        if selected["report"]:
            pass   # the report is always written below
    except StageError as exc:
        report["failure"] = {"message": str(exc), "exit_code": exc.code,
                             "meaning": S.EXIT_MEANING.get(exc.code, "?")}
        path = write_report(args, report, started, tc)
        print(f"\nbuild FAILED: {exc} (exit {exc.code}: "
              f"{S.EXIT_MEANING.get(exc.code, '?')})", file=sys.stderr)
        print(f"[report] {rel(path)}", file=sys.stderr)
        return exc.code
    except S.FreezeError as exc:
        report["failure"] = {"message": str(exc), "exit_code": EXIT_TOOLCHAIN}
        path = write_report(args, report, started, tc)
        print(f"\nbuild FAILED: {exc} (exit {EXIT_TOOLCHAIN})", file=sys.stderr)
        print(f"[report] {rel(path)}", file=sys.stderr)
        return EXIT_TOOLCHAIN

    path = write_report(args, report, started, tc)
    print()
    print(f"[done] {report['duration_seconds']:.2f}s, report: {rel(path)}")
    print_summary(report, entries, path)
    if args.json:
        print(json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
