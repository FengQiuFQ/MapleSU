"""Replay real development-gate artifacts and reject altered ABI/provenance claims."""
import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import time
import unittest

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'build-dir', 'gate-root', 'gate-tools', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    root, build_dir, gate_root, tools = [path.resolve() for path in
        (args.root, args.build_dir, args.gate_root, args.gate_tools)]
    output = args.out.resolve()
    assert not output.exists()
    output.mkdir(parents=True)
    sys.path.insert(0, str(root / 'scripts'))
    import source_sdk_delivery as delivery
    spec = importlib.util.spec_from_file_location('revalidation_test_keyless', tools / 'keyless_gate.py')
    keyless = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(keyless)
    build_path = build_dir / 'report/build-report.json'
    gate_path = gate_root / 'report/gate-result.json'
    build = json.loads(build_path.read_text(encoding='utf-8'))
    gate = json.loads(gate_path.read_text(encoding='utf-8'))
    public = gate['keyless_public_abi']
    archive = delivery.checked(gate['source_validation']['archive'], root, build_dir)
    members = delivery.parse_ar(str(archive))['members']
    symbols = json.loads(delivery.checked(gate['source_validation']['symbols'], root, build_dir).read_text())
    raw = set().union(*(set(symbols[name]) for name in ('defined', 'undefined', 'weak_defined', 'weak_undefined')))
    ndk = (root / build['provenance']['toolchain']['ndk_root']).resolve()

    def tool_input(item):
        path = (root / item['path']).resolve()
        assert path.is_relative_to(ndk) and delivery.record(path, root) == {
            name: item[name] for name in ('path', 'size', 'sha256')}
        return path

    def validate(value):
        delivery.verify_explicit_legacy_abi(value, build, root, build_dir, tools,
            archive, members, keyless, raw, tool_input)

    class RealRevalidationTest(unittest.TestCase):
        def test_actual_source_objects_members_both_abis_and_signatures_pass(self):
            validate(public)

        def test_original_failed_full_build_is_rejected_without_separate_revalidation(self):
            with self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_BUILD_FAILED'):
                delivery.verify_source_build_status(build, build_path, root, build_dir)

        def test_only_the_finished_gate_failure_is_eligible(self):
            delivery.completed_keyless_gate_failure(build)
            for field, changed in (('failure', dict(exit_code=4, message='compile failed')),
                                   ('final_archive_stability', dict(passed=False))):
                candidate = copy.deepcopy(build)
                candidate[field] = changed
                with self.subTest(field=field), self.assertRaises(AssertionError):
                    delivery.completed_keyless_gate_failure(candidate)

        def test_default_provenance_stays_strict(self):
            with self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_PROVENANCE_INCOMPLETE'):
                delivery.verify_build_provenance(build, root, build_dir)

        def test_contract_bytes_must_match_the_measured_receipt(self):
            candidate = copy.deepcopy(public)
            candidate['explicit_legacy_abi']['contract']['sha256'] = '0' * 64
            with self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_STALE'):
                validate(candidate)

        def test_pass_status_does_not_replace_the_original_compile_object(self):
            candidate = copy.deepcopy(public)
            candidate['explicit_legacy_abi']['compile_unit']['bytes'] += 1
            with self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_EXPLICIT_ABI_ORIGINAL'):
                validate(candidate)

        def test_duplicate_or_missing_provider_claims_are_rejected(self):
            for duplicate in (False, True):
                candidate = copy.deepcopy(public)
                providers = candidate['explicit_legacy_abi']['archive_providers']
                symbol = next(iter(providers))
                providers[symbol] = providers[symbol] * 2 if duplicate else []
                with self.subTest(duplicate=duplicate), self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_EXPLICIT_ABI_PROVIDERS'):
                    validate(candidate)

        def test_both_arm_architectures_are_required(self):
            candidate = copy.deepcopy(public)
            candidate['explicit_legacy_abi']['probes'].pop()
            with self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_EXPLICIT_ABI_PROBE_COVERAGE'):
                validate(candidate)

        def test_claimed_demangled_signature_must_match_the_actual_capture(self):
            candidate = copy.deepcopy(public)
            signatures = candidate['explicit_legacy_abi']['symbol_signatures']
            signatures[next(iter(signatures))] = 'unmeasured::signature()'
            with self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_EXPLICIT_ABI_SIGNATURES'):
                validate(candidate)

        def test_standard_keyless_probe_does_not_gain_an_explicit_legacy_dependency(self):
            candidate = copy.deepcopy(public)
            symbol, signature = next(iter(candidate['explicit_legacy_abi']['symbol_signatures'].items()))
            candidate['required_symbols'][symbol] = signature
            with self.assertRaisesRegex(AssertionError, 'SOURCE_SDK_EXPLICIT_ABI_CONTRACT_FAILED'):
                validate(candidate)

    watched = [build_path, gate_path, archive, root / 'scripts/source_sdk_delivery.py', Path(__file__).resolve()]
    before = [delivery.record(path, root) for path in watched]
    started = time.monotonic()
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealRevalidationTest))
    stable = before == [delivery.record(path, root) for path in watched]
    (output / 'test.log').write_text(log.getvalue(), encoding='utf-8')
    receipt = dict(status='PASS' if result.wasSuccessful() and stable else 'FAIL', tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), seconds=round(time.monotonic() - started, 3),
        sourceAndArtifactsUnchanged=stable, inputs=before, jvmOperations=0, deviceOperations=0,
        qualification='Real immutable SDK/gate inputs; limited producer-consumer negative cases, no device or Release acceptance.')
    (output / 'RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({name: receipt[name] for name in ('status', 'tests', 'failures', 'errors', 'seconds')}, indent=2))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
