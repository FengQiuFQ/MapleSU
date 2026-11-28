"""Exercise both real JNI worker fork sites and real request TLS initialization."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--cold-control', action='store_true')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
build = args.build.resolve()
build.mkdir(parents=True, exist_ok=True)
(build / 'kernel_module_kit_umbrella.h').write_text(
    '#pragma once\n#include "module_err_def.h"\n#include "module_base_kernel_mem.h"\n'
    'namespace kernel_module { uint32_t get_page_size(); }\n', encoding='utf-8')
docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
          '--tmpfs', '/tmp:rw,size=64m', '--mount', f'type=bind,source={repo},target=/repo,readonly',
          '--mount', f'type=bind,source={build},target=/case', '-w', '/case',
          'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e']
sources = []
records = []
for name in ('installed_helper_readback.cpp', 'manager_owner_root_probe.cpp'):
    rel = 'runtime/ultra/bridge/' + name
    source = (repo / rel).read_text(encoding='utf-8')
    records.append(dict(path=rel, sha256=hashlib.sha256((repo / rel).read_bytes()).hexdigest()))
    if args.cold_control:
        call = '                maplesu_request_fork_prepare();\n'
        assert source.count(call) == 1
        source = source.replace(call, '')
        (build / name).write_text(source, encoding='utf-8')
        sources.append('/case/' + name)
    else:
        sources.append('/repo/' + rel)
dependencies = ['runtime/tests/ultra_raw_root_worker_tls_test.cpp', 'runtime/tests/ultra_sdk_deadline_scope_host.cpp',
                'runtime/ultra/bridge/sdk_call_scope.cpp', 'runtime/ultra/bridge/sdk_call_scope.h',
                'runtime/ultra/bridge/installed_helper_readback.h', 'runtime/ultra/bridge/manager_owner_root_probe.h',
                'runtime/ultra/bridge/manager_owner_identity.h',
                'runtime/maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp',
                'runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp',
                'runtime/ultra/authorization/request_context.cpp',
                'runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h',
                'runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h',
                'runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h',
                'scripts/tests/test-ultra-raw-root-worker-tls.py']
records += [dict(path=path, sha256=hashlib.sha256((repo / path).read_bytes()).hexdigest()) for path in dependencies]
command = ['g++', '-std=c++17', '-O2', '-ffunction-sections', '-fdata-sections', '-DFIXTURE_REAL_REQUEST_TLS',
           '-I/case', '-I/repo/runtime/ultra/bridge', '-I/repo/runtime/maplesu-sdk/sdk/include',
           '-I/repo/runtime/maplesu-sdk/include', *sources,
           '/repo/runtime/tests/ultra_raw_root_worker_tls_test.cpp',
           '/repo/runtime/tests/ultra_sdk_deadline_scope_host.cpp',
           '/repo/runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp',
           '/repo/runtime/ultra/authorization/request_context.cpp',
           '-Wl,--wrap=maplesu_prepare_kernel_request',
           '-Wl,--wrap=__cxa_thread_atexit',
           '-Wl,--wrap=_ZN13kernel_module29maplesu_request_set_auth_modeENS_15RequestAuthModeE',
           '-Wl,--wrap=_ZN13kernel_module32maplesu_request_worker_admissionEv',
           '-Wl,--wrap=pipe2', '-Wl,--wrap=fork',
           '-Wl,--gc-sections', '-pthread', '-lrt', '-o', 'raw-worker-tls']
compiled = subprocess.run(docker + command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
(build / 'compile.log').write_text(compiled.stdout + compiled.stderr, encoding='utf-8')
assert compiled.returncode == 0, compiled.stdout + compiled.stderr
result = subprocess.run(docker + ['./raw-worker-tls'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
output = result.stdout + result.stderr
(build / 'run.log').write_text(output, encoding='utf-8')
stable = all(hashlib.sha256((repo / item['path']).read_bytes()).hexdigest() == item['sha256'] for item in records)
receipt = dict(passed=result.returncode == 0 and stable, sourcesStable=stable, exitCode=result.returncode, coldControl=args.cold_control, coldThreads=6,
               workersPerThread=2, deviceOperations=0, sdkRebuilds=0, sources=records,
               scope='Actual parent/worker/framing/deadline and actual request TLS/mode setter; admission is a fixture seam: denied Manager/Helper callers have zero pipe/fork/ROOT and restore parent mode, admitted workers return auth error after child selection; real m023 operation deadline, parent exact restore, inherited child local bound and no post-fork TLS destructor registration; no ROOT or helper bytes.',
               output=output)
(build / 'RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
print(output, end='')
raise SystemExit(0 if receipt["passed"] else 1)
