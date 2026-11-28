"""Re-run the real ABI gate on unchanged completed source bytes for a development delivery."""
import argparse
import copy
import datetime
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback

from source_sdk_delivery import (checked, completed_keyless_gate_failure, record,
                                 source_inputs, verify_gate_revalidation)

ROOT = Path(__file__).resolve().parents[1]
TOOL_FILES = ('build.py', 'tools/keyless_gate.py', 'tools/explicit_legacy_abi.json',
              'tools/explicit_legacy_public_abi.cpp', 'tools/keyless_public_abi.cpp')


def load_builder(tool_root):
    # The new gate is an explicit, separately recorded tool input. Its runtime
    # support remains the original source build's tools and dependency closure.
    original = ROOT / 'runtime/maplesu-sdk/sdk/tools'
    sys.path.insert(0, str(original))
    sys.path.insert(0, str(tool_root / 'tools'))
    path = tool_root / 'build.py'
    spec = importlib.util.spec_from_file_location('maplesu_sdk_revalidation_build', path)
    builder = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = builder
    spec.loader.exec_module(builder)
    assert builder.S.REPO_ROOT.resolve() == ROOT, 'REVALIDATION_SUPPORT_ROOT'
    assert Path(builder.keyless_gate.__file__).resolve() == tool_root / 'tools/keyless_gate.py', 'REVALIDATION_GATE_SOURCE'
    sdk = ROOT / 'runtime/maplesu-sdk/sdk'
    builder.SDK_DIR = sdk
    builder.MAPLESU_SDK_ROOT = sdk.parent
    builder.REPO_ROOT = ROOT
    builder.INCLUDE_DIR = sdk.parent / 'include'
    builder.SDK_INCLUDE_DIR = sdk / 'include'
    builder.MANIFEST_PATH = sdk / 'manifest.jsonl'
    builder.MANIFEST_DIR = sdk / 'manifest'
    builder.VENDOR_RULES_PATH = sdk / 'third_party/build_rules.json'
    builder.GATE_ALLOW_PATH = sdk / 'notes/gate-allow.json'
    builder.SOURCE_PAYLOADS = True
    return builder


def revalidate(build_dir, output, gate_tool_dir, ndk, jobs):
    build_dir, output, gate_tool_dir = [Path(path).resolve() for path in (build_dir, output, gate_tool_dir)]
    assert (not output.exists() and output.is_relative_to(ROOT) and output != ROOT and
            not output.is_relative_to(build_dir) and gate_tool_dir.is_relative_to(ROOT) and
            not gate_tool_dir.is_relative_to(output)), 'REVALIDATION_NEW_OUTPUT_REQUIRED'
    report_path = build_dir / 'report/build-report.json'
    original_report = record(report_path, ROOT)
    build = json.loads(report_path.read_text(encoding='utf-8'))
    completed_keyless_gate_failure(build)
    before = source_inputs(build, ROOT, build_dir, allow_completed_gate_failure=True)
    archive = dict(path=build['pack']['archive'], size=build['pack']['bytes'], sha256=build['pack']['sha256'])
    checked(archive, ROOT, build_dir)
    tools = [record(gate_tool_dir / name, ROOT) for name in TOOL_FILES]
    output.mkdir(parents=True)
    receipt_path = output / 'GATE-REVALIDATION.json'
    result = dict(schema='maplesu-sdk-gate-revalidation/1', status='RUNNING',
        startedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope='original-compiled-bytes-new-gate-development-only',
        originalBuildReport=original_report, originalSourceSelection=build['source_selection']['manifest'],
        archive=archive, gateRoot=output.relative_to(ROOT).as_posix(),
        toolRoot=gate_tool_dir.relative_to(ROOT).as_posix(), toolFiles=tools,
        runner=record(Path(__file__), ROOT), validator=record(ROOT / 'scripts/source_sdk_delivery.py', ROOT),
        formalRelease=False, cleanReproducibility=False, freshClaim=False,
        jvmOperations=0, deviceOperations=0)
    started = time.monotonic()
    receipt_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    try:
        builder = load_builder(gate_tool_dir)
        builder.BUILD_DIR = build_dir
        builder.OBJ_DIR = build_dir / 'obj'
        builder.TU_DIR = build_dir / 'obj/tu'
        builder.ARCHIVE_OUT = checked(archive, ROOT, build_dir)
        builder.REPORT_DIR = output / 'report'
        builder.LINK_DIR = output / 'link'
        builder.LOG_DIR = output / 'logs'
        for directory in (builder.REPORT_DIR, builder.LINK_DIR, builder.LOG_DIR):
            directory.mkdir()
        args = builder.parse_args(['--gate', '--source-payloads', '--ndk', str(ndk),
            '--manifest', str(build_dir / 'manifest.jsonl'), '--jobs', str(jobs)])
        tc = builder.S.resolve_toolchain(args.ndk)
        current = copy.deepcopy(build)
        for field in ('failure', 'gate', 'keyless_public_abi', 'source_validation', 'provenance'):
            current.pop(field, None)
        # This executes the current producer: whole-archive link, historical
        # structural gate, keyless probe and both explicit compatibility ABIs.
        builder.stage_gate(args, current, tc)
        stage = dict(schema='maplesu-sdk-gate-revalidation-stage/1',
                     **{key: current[key] for key in ('gate', 'keyless_public_abi', 'source_validation')})
        stage_path = output / 'report/gate-result.json'
        stage_path.write_text(json.dumps(stage, indent=2) + '\n', encoding='utf-8')
        result['gateResult'] = record(stage_path, ROOT)
        assert record(report_path, ROOT) == original_report, 'REVALIDATION_ORIGINAL_REPORT_CHANGED'
        checked(archive, ROOT, build_dir)
        assert source_inputs(build, ROOT, build_dir, allow_completed_gate_failure=True) == before, 'REVALIDATION_SOURCE_CHANGED'
        assert [record(gate_tool_dir / name, ROOT) for name in TOOL_FILES] == tools, 'REVALIDATION_TOOL_CHANGED'
        result.update(status='PASS', originalReportUnchanged=True, archiveUnchanged=True,
                      sourceInputsUnchanged=True, originalSourceInputs=len(before))
        receipt_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        verify_gate_revalidation(build, report_path, record(receipt_path, ROOT), ROOT, build_dir)
    except Exception as error:
        result.update(status='FAIL', error=str(error), traceback=traceback.format_exc())
    result.update(finishedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  seconds=round(time.monotonic() - started, 3))
    receipt_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--gate-tool-dir', required=True, type=Path)
    parser.add_argument('--ndk', required=True, type=Path)
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=2)
    args = parser.parse_args()
    result = revalidate(args.build_dir, args.output, args.gate_tool_dir, args.ndk, args.jobs)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
