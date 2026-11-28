"""Run selected SDK transport and fork/TLS regressions with explicit syscall seams."""
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
out.mkdir(parents=True, exist_ok=True)
inputs = [Path(__file__), root / 'runtime/tests/ultra_sdk_keyless_transport_test.cpp',
    root / 'runtime/tests/ultra_sdk_request_fork_tls_test.cpp',
    *[root / p for p in (
        'runtime/maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp',
        'runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp',
        'runtime/ultra/authorization/request_context.cpp',
        'runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp',
        'runtime/maplesu-sdk/sdk/src/maplesu/compat/fork_legacy_abi.h',
        'runtime/maplesu-sdk/sdk/src/maplesu/compat/fork_exports_legacy_abi.h',
        'runtime/maplesu-sdk/sdk/include/module_base_kernel_request.h',
        'runtime/maplesu-sdk/sdk/include/maplesu_request_private.h',
        'runtime/maplesu-sdk/sdk/include/maplesu_request_identity.h',
        'runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h',
        'runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h',
        'runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h',
        'runtime/ultra/authorization/kernel_read.cpp',
        'runtime/ultra/authorization/kernel_read_metadata.h',
        'runtime/ultra/authorization/request_protocol.h')]]
hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
(out / 'kernel_module_kit_umbrella.h').write_text('#pragma once\n#include "module_err_def.h"\n', encoding='utf-8')
(out / 'module_base_kernel_mem.h').write_text('#pragma once\n#include <cstdint>\nnamespace kernel_module {uint32_t get_page_size();}\n', encoding='utf-8')
(out / 'fork_stubs.cpp').write_text('#include <cstdint>\nnamespace kernel_module {uint32_t get_page_size(){return 4096;}}\n', encoding='utf-8')
docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
    '--tmpfs', '/tmp:rw,size=64m', '-e', 'ASAN_OPTIONS=detect_leaks=1',
    '-e', 'UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1',
    '--mount', f'type=bind,source={root},target=/repo,readonly',
    '--mount', f'type=bind,source={out},target=/work', '-w', '/work', '--entrypoint', '/bin/sh',
    'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e',
    '-c', 'exec "$@"', 'sh']
flags = ['-std=c++20', '-O1', '-g', '-pthread', '-fsanitize=address,undefined',
    '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
    '-I/work', '-I/repo/runtime/maplesu-sdk/sdk/include', '-I/repo/runtime/maplesu-sdk/include']
commands = [
    ('transport-compile', [*docker, 'g++', *flags, '-DMAPLESU_KERNEL_READ_CANONICAL',
        '/repo/runtime/tests/ultra_sdk_keyless_transport_test.cpp',
        '/repo/runtime/ultra/authorization/kernel_read.cpp',
        '/repo/runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp',
        '/repo/runtime/ultra/authorization/request_context.cpp',
        '-Wl,--wrap=syscall,--wrap=getuid,--wrap=geteuid', '-o', '/work/transport']),
    ('transport', [*docker, './transport']),
    ('fork-compile', [*docker, 'g++', *flags,
        '/repo/runtime/tests/ultra_sdk_request_fork_tls_test.cpp',
        '/repo/runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp',
        '/repo/runtime/ultra/authorization/request_context.cpp',
        '/repo/runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp', '/work/fork_stubs.cpp',
        '-Wl,--wrap=__cxa_thread_atexit', '-o', '/work/fork-tls']),
    ('fork', [*docker, './fork-tls']),
]
rows = []
for name, command in commands:
    done = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
    output = done.stdout + done.stderr
    (out / (name + '.log')).write_text(output, encoding='utf-8')
    print(name, done.returncode)
    print(output[-6000:], end='')
    rows.append({'name': name, 'argv': command, 'exit': done.returncode})
    if done.returncode:
        break
stable = all(hashlib.sha256((root / p).read_bytes()).hexdigest() == sha for p, sha in hashes.items())
passed = len(rows) == len(commands) and all(not row['exit'] for row in rows) and stable
(out / 'receipt.json').write_text(json.dumps({'passed': passed, 'sourceInputsStable': stable,
    'inputs': hashes, 'commands': rows,
    'scope': 'Selected production m023 and metadata READ; kernel replies are syscall fixtures; real Linux fork/pipe and TLS. No official SDK artifact or device evidence.'}, indent=2), encoding='utf-8')
raise SystemExit(0 if passed else 1)
