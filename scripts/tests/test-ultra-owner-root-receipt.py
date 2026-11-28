"""Run the actual private Owner Root worker across a modeled post-ROOT FD denial."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)
sources = ['runtime/ultra/bridge/manager_owner_root_probe.cpp',
           'runtime/ultra/bridge/manager_owner_root_probe.h',
           'runtime/tests/ultra_owner_root_receipt_test.cpp',
           'scripts/tests/test-ultra-owner-root-receipt.py']
sources += ['runtime/ultra/bridge/sdk_call_scope.cpp', 'runtime/ultra/bridge/sdk_call_scope.h',
            'runtime/tests/ultra_sdk_deadline_scope_host.cpp',
            'runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h',
            'runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h',
            'runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h']
before = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in sources}
docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
          '--tmpfs', '/tmp:rw,size=32m', '--mount', f'type=bind,source={root},target=/repo,readonly',
          '--mount', f'type=bind,source={out},target=/case', '-w', '/case',
          'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e']
records = []
for label, argv in [
    ('compile', ['g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                 '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
                 '-fsanitize=address,undefined', '-fno-pie', '-no-pie',
                 '-I/repo/runtime/maplesu-sdk/sdk/include', '-I/repo/runtime/maplesu-sdk/include',
                 '/repo/runtime/tests/ultra_owner_root_receipt_test.cpp',
                '/repo/runtime/tests/ultra_sdk_deadline_scope_host.cpp', '-Wl,--wrap=pipe2',
                 '-Wl,--wrap=write', '-Wl,--wrap=fork', '-pthread', '-lrt', '-o', 'owner-root-receipt']),
    *[(f'run-{case}', ['./owner-root-receipt', str(case)]) for case in range(15)]]:
    result = subprocess.run(docker + argv, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=55)
    output = result.stdout + result.stderr
    (out / f'{label}.log').write_text(output, encoding='utf-8')
    print(output, end='')
    records.append(dict(stage=label, argv=docker + argv, exitCode=result.returncode))
    if label == 'compile' and result.returncode:
        break
stable = all(hashlib.sha256((root / p).read_bytes()).hexdigest() == h for p, h in before.items())
passed = len(records) == 16 and all(r['exitCode'] == 0 for r in records) and stable
(out / 'RESULT.json').write_text(json.dumps(dict(passed=passed, stages=records,
    inputs=before, sourcesStable=stable, deviceOperations=0, formalBuild=False,
    scope='Actual complete Owner Root worker/parent and OS fork/pipe/poll/watchdog. Authentication and root effects are fixture seams; post-ROOT write on the inherited receipt FD yields EACCES. Not an Android SELinux or Root success claim.'), indent=2) + '\n', encoding='utf-8')
raise SystemExit(0 if passed else 1)
