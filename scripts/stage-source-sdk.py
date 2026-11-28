"""Stage a fresh source build for isolated consumers, retaining truthful transition inputs."""
import argparse
import copy
import datetime
import importlib.util
import json
import os
import re
import shutil
import sys
from pathlib import Path

from source_sdk_delivery import checked, record, source_helper_identity, source_inputs, verify_source_build_status, verify_source_delivery
from policy_backend_identity import describe_backend

ROOT = Path(__file__).resolve().parents[1]


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    return target


def stage(build_dir, output, base, backend_bundle=None, source_validation_review=None,
          app_version=None, version_code=None, gate_revalidation=None):
    assert (app_version is None) == (version_code is None), 'Product version requires both app version and version code'
    if app_version is not None:
        assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', app_version) and version_code > 0, 'Invalid product version'
    build_dir, output, base = [Path(path).resolve() for path in (build_dir, output, base)]
    if not output.is_relative_to(ROOT) or output == ROOT or output.exists():
        raise AssertionError('Use a new candidate directory inside the repository')
    output.mkdir(parents=True)
    output_identity = None
    try:
        output_identity = output.stat(follow_symlinks=False)
        arguments = (build_dir, output, base, backend_bundle, source_validation_review, app_version, version_code)
        return (_stage_candidate(*arguments) if gate_revalidation is None else
                _stage_candidate(*arguments, gate_revalidation=gate_revalidation))
    except BaseException:
        try:
            current = output.stat(follow_symlinks=False)
            if (output.resolve().is_relative_to(ROOT) and output_identity is not None
                    and output_identity.st_ino and os.path.samestat(output_identity, current)):
                shutil.rmtree(output)
            else:
                print('SDK staging left an output with unknown or changed ownership: ' + str(output), file=sys.stderr)
        except FileNotFoundError:
            pass
        except Exception as cleanup_error:
            print('SDK staging cleanup failed: ' + str(cleanup_error), file=sys.stderr)
        raise


def _stage_candidate(build_dir, output, base, backend_bundle, source_validation_review=None,
                     app_version=None, version_code=None, gate_revalidation=None):
    report_path = build_dir / 'report/build-report.json'
    report = json.loads(report_path.read_text(encoding='utf-8'))
    assert report.get('provenance', {}).get('schema') == 'maplesu-sdk-source-provenance/2', 'New candidates require current compile-boundary provenance'
    validation = verify_source_build_status(report, report_path, ROOT, build_dir,
        record(Path(source_validation_review), ROOT) if source_validation_review is not None else None,
        record(Path(gate_revalidation), ROOT) if gate_revalidation is not None else None)
    inputs = source_inputs(report, ROOT, build_dir,
                           allow_completed_gate_failure=gate_revalidation is not None)
    baseline_path = base / 'SDK-RELEASE.json'
    baseline = json.loads(baseline_path.read_text(encoding='utf-8-sig'))
    member_manifest = build_dir / 'manifest.jsonl'
    assert member_manifest.is_file(), 'Fresh isolated build manifest is required'
    archive = copy_file(checked(dict(path=report['pack']['archive'], size=report['pack']['bytes'], sha256=report['pack']['sha256']), ROOT, build_dir),
                        output / 'lib/arm64-v8a/libkernel_module_kit_static.a')
    header_input = ROOT / report['compile']['include_dirs'][0]
    shutil.copytree(header_input, output / 'include')
    headers = [dict(input=record(path, ROOT), staged=record(output / 'include' / path.relative_to(header_input), ROOT))
               for path in sorted(header_input.rglob('*')) if path.is_file()]
    asset_manifest = json.loads((build_dir / 'out/assets/assets-manifest.json').read_text(encoding='utf-8'))
    names = {'su.bin': 'su', 'resetprop_file.bin': 'resetprop', 'webui_loader.bin': 'webui_loader', 'autorun_bootstrap.bin': 'autorun_bootstrap'}
    payloads = []
    for asset in asset_manifest['assets']:
        name = Path(asset['asset']).name
        if name not in names:
            continue
        source = checked(dict(path=asset['out'], size=asset['bytes'], sha256=asset['sha256']), ROOT, build_dir)
        target = copy_file(source, output / 'assets' / name)
        payloads.append(dict(name=names[name], origin=asset['origin'], file=record(target, ROOT)))
    helper = copy_file(output / 'assets/autorun_bootstrap.bin', output / 'helper/autorun_bootstrap')
    source_helper = report.get('source_helper')
    if source_helper:
        helper_report = asset_manifest['helper']['report']
        helper_receipt = json.loads(checked(helper_report, ROOT, build_dir).read_text(encoding='utf-8'))
        helper_info = dict(source_helper_identity(helper, helper_receipt), **record(helper, ROOT),
                           status='source-candidate-unvalidated-device')
        pair = helper_receipt['backend']
        backend_input = checked(dict(path=pair['source'], size=pair['bytes'], sha256=pair['sha256']), ROOT, build_dir)
        backend_info = describe_backend(backend_input)
        built_backend = report.get('source_backend')
        if built_backend:
            actual_bundle = (ROOT / built_backend['bundle']).with_suffix('.json').resolve()
            assert backend_bundle is None or Path(backend_bundle).resolve() == actual_bundle, 'Source backend bundle selection differs from build'
            backend_bundle = actual_bundle
        assert backend_bundle is not None, 'Source helper requires the actual compiled backend bundle manifest'
        bundle_input = Path(backend_bundle).resolve()
    else:
        raise AssertionError('Keyless delivery requires its same-generation source helper and backend')
    backend = copy_file(backend_input, output / 'backend' / backend_info['fileName'])
    bundle = copy_file(bundle_input, output / 'backend/policy-bundles.json')
    bundle_cpp = copy_file(bundle_input.with_suffix('.cpp'), output / 'backend/policy-bundles.cpp')
    retained_entry = []
    for path in sorted((base / 'maintenance/entry').rglob('*')):
        if path.is_file():
            retained_entry.append(record(copy_file(path, output / 'maintenance/entry' / path.relative_to(base / 'maintenance/entry')), ROOT))
    retained_release = copy_file(baseline_path, output / 'retained/SDK-RELEASE.json')
    version_source = ROOT / 'runtime/maplesu-sdk/sdk/src/maplesu/install/lifecycle.h'
    version_match = re.search(r'kSdkVersionText\s*\[\s*\]\s*=\s*"(\d+\.\d+\.\d+)"',
                              version_source.read_text(encoding='utf-8'))
    assert version_match, 'SDK version source was not found'
    release = dict(schemaVersion=1, appVersion=app_version or baseline['appVersion'],
                   versionCode=version_code if version_code is not None else baseline['versionCode'],
                   sdkVersion=version_match.group(1), rootKeyRequired=False,
                   sdkBuildId='maplesu-ultra-source-' + record(archive, ROOT)['sha256'][:16],
                   generatedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(), archive=record(archive, ROOT),
                   helper=helper_info, bootstrap=dict(helper_info),
                   environmentPolicyBoot=dict(status='candidate', backend=dict(backend_info, **record(backend, ROOT)),
                       entryHelperSha256=helper_info['sha256'], deviceAcceptance=False, complete=False, productionPackagingIntegrated=False,
                       delivery=dict(bundleManifest=record(bundle, ROOT))),
                   sourceBuild=dict(schemaVersion=1, buildReport=record(report_path, ROOT),
                       memberManifest=record(member_manifest, ROOT), inputs=inputs, headers=headers,
                       payloads=payloads, retainedEntry=retained_entry, retainedRelease=record(retained_release, ROOT),
                       retainedPolicyFiles=[] if source_helper else [record(bundle, ROOT), record(bundle_cpp, ROOT)],
                       deviceAcceptance=False, finalSourceAcceptance=False,
                       residuals=(['retained entry scripts'] if source_helper else ['retained bootstrap helper', 'retained policy backend and entry']) +
                           ['retained reference payload: ' + item['name'] for item in payloads if item['origin'] == 'reference-copy']),
                   statement='Isolated source archive candidate. Transition inputs remain; full source and device acceptance pending.')
    if validation is not None:
        release['sourceBuild']['sourceValidation'] = validation
        release['statement'] = 'Isolated source validation candidate; original reference comparison failed. Behavior and device acceptance pending.'
    if gate_revalidation is not None:
        release['sourceBuild']['gateRevalidation'] = record(Path(gate_revalidation), ROOT)
        release['statement'] = 'Development candidate: original compiled bytes with a separately revalidated ABI gate. Original full build failure retained; current full rebuild and device acceptance pending.'
    release['sourceBuild']['buildDirectory'] = build_dir.as_posix()
    if 'provenance' in report:
        release['sourceBuild']['provenanceSchema'] = report['provenance']['schema']
    saved_ir = sorted({row['idx'] for row in report['compile']['rows'] for item in row['outputs']
                       if Path(item['source']).suffix in ('.ll', '.bc')})
    release['sourceBuild']['residuals'][0:0] = ['saved IR member: m%03d' % index for index in saved_ir]
    release['sourceBuild']['helperOrigin'] = 'source-built' if source_helper else 'reference-copy'
    if source_helper:
        release['sourceBuild']['helperBuildReport'] = helper_report
        release['sourceBuild']['policyFiles'] = [record(bundle, ROOT), record(bundle_cpp, ROOT)]
    verify_source_delivery(release, ROOT)
    release_path = output / 'SDK-RELEASE.json'
    release_path.write_text(json.dumps(release, indent=2) + '\n', encoding='utf-8')
    identity_spec = importlib.util.spec_from_file_location('source_sdk_identity', ROOT / 'scripts/sync-ultra-sdk-identity.py')
    identity = importlib.util.module_from_spec(identity_spec)
    identity_spec.loader.exec_module(identity)
    (output / 'SDK-IDENTITY.cmake').write_text(identity.generated_identity(release_path), encoding='utf-8', newline='\n')
    return release_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base', type=Path, default=ROOT / 'runtime/maplesu-sdk')
    parser.add_argument('--backend-bundle', type=Path,
                        help='actual bundle manifest compiled into the source helper paired backend')
    parser.add_argument('--source-validation-review', type=Path,
                        help='independent full-generation source/provider/ABI review; original raw failure remains')
    parser.add_argument('--gate-revalidation', type=Path,
                        help='development-only independent real ABI gate on an unchanged completed source build')
    parser.add_argument('--app-version', help='product version paired with --version-code; SDK ABI version remains unchanged')
    parser.add_argument('--version-code', type=int)
    args = parser.parse_args()
    print(stage(args.build_dir, args.output, args.base, args.backend_bundle, args.source_validation_review,
                args.app_version, args.version_code, args.gate_revalidation).relative_to(ROOT))
