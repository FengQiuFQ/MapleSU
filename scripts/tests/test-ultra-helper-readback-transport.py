"""Run the actual complete helper producer/consumer across post-Root pipe denial."""
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
sources = ['runtime/ultra/bridge/installed_helper_readback.cpp', 'runtime/ultra/bridge/installed_helper_readback.h',
           'runtime/ultra/bridge/manager_owner_root_probe.h', 'runtime/ultra/bridge/manager_owner_identity.h',
           'runtime/tests/ultra_helper_readback_transport_test.cpp', 'scripts/tests/test-ultra-helper-readback-transport.py']
sources += ['runtime/ultra/bridge/sdk_call_scope.cpp', 'runtime/ultra/bridge/sdk_call_scope.h',
            'runtime/tests/ultra_sdk_deadline_scope_host.cpp',
            'runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h',
            'runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h',
            'runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h']
before = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in sources}
(out / 'kernel_module_kit_umbrella.h').write_text('#pragma once\n#include "module_err_def.h"\n#include "module_base_kernel_mem.h"\nnamespace kernel_module { uint32_t get_page_size(); }\n')
docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
          '--tmpfs', '/tmp:rw,size=32m', '--mount', f'type=bind,source={root},target=/repo,readonly',
          '--mount', f'type=bind,source={out},target=/case', '-w', '/case',
          'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e']
compile_argv = ['g++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
                 '-fsanitize=address,undefined', '-fno-pie', '-no-pie', '-I/case',
                '-I/repo/runtime/maplesu-sdk/sdk/include', '-I/repo/runtime/maplesu-sdk/include',
                '/repo/runtime/tests/ultra_helper_readback_transport_test.cpp',
                '/repo/runtime/tests/ultra_sdk_deadline_scope_host.cpp', '-Wl,--wrap=pipe2',
                '-Wl,--wrap=write', '-Wl,--wrap=open', '-Wl,--wrap=fstat', '-Wl,--wrap=lstat',
                '-pthread', '-lrt', '-o', 'helper-transport']
records = []
for label, argv in [('compile', compile_argv), *[(f'run-{case}', ['./helper-transport', str(case)]) for case in range(10)]]:
    result = subprocess.run(docker + argv, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=55)
    output = result.stdout + result.stderr
    (out / f'{label}.log').write_text(output, encoding='utf-8')
    print(output, end='')
    records.append(dict(stage=label, argv=docker + argv, exitCode=result.returncode))
    if label == 'compile' and result.returncode:
        break
stable = all(hashlib.sha256((root / p).read_bytes()).hexdigest() == h for p, h in before.items())
captures = []
for case in (0, 1, 6):
    captured = out / f'captured-{case}.bin'
    expected = bytes((index * 13 + 7) & 255 for index in range((16 if case == 6 else 2) * 65536 + 13))
    captures.append(dict(case=case, bytes=captured.stat().st_size if captured.is_file() else None,
        sha256=hashlib.sha256(captured.read_bytes()).hexdigest() if captured.is_file() else None,
        expectedSha256=hashlib.sha256(expected).hexdigest()))
passed = len(records) == 11 and all(r['exitCode'] == 0 for r in records) and stable and all(
    c['sha256'] == c['expectedSha256'] for c in captures)
(out / 'RESULT.json').write_text(json.dumps(dict(passed=passed, stages=records,
    inputs=before, sourcesStable=stable, captures=captures, deviceOperations=0, formalBuild=False,
    scope='Complete actual installed helper worker, producer, framing, consumer and cleanup with real temporary files/fork/pipe/watchdog. Owner authentication/root are fixture seams; post-Root writes to inherited notification FD return EACCES. Metadata/path changes and sink cancellation are explicit faults. Independent Python SHA256 checks actual parent-consumed bytes; no Android SELinux, Root, official SDK or device qualification.'), indent=2) + '\n', encoding='utf-8')
raise SystemExit(0 if passed else 1)
