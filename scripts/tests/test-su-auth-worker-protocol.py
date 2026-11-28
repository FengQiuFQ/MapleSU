"""Run complete production SU workers and actual current process transport on Linux."""
import argparse,datetime,hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
names=['runtime/maplesu-sdk/sdk/src/maplesu_core/maplesu_su_auth.cpp','runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp','runtime/maplesu-sdk/sdk/include/maplesu_storage_worker_private.h','runtime/maplesu-sdk/sdk/include/maplesu_storage_private.h','runtime/maplesu-sdk/sdk/include/maplesu_request_private.h','runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/su_auth_result_private.h','runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/su_uid_profile_private.h','runtime/maplesu-sdk/sdk/src/maplesu_core/fixed_transfer_io.h','runtime/maplesu-sdk/sdk/include/maplesu_deadline_private.h','runtime/maplesu-sdk/sdk/include/maplesu_operation_wait_private.h','runtime/maplesu-sdk/sdk/include/maplesu_operation_fork_private.h','runtime/ultra/authorization/request_context.cpp','runtime/tests/ultra_su_auth_worker_protocol_test.cpp',__file__]
names=[str(Path(n).relative_to(ROOT)).replace('\\','/') if Path(n).is_absolute() else n for n in names]
names.append('runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/su_uid_read_result_private.h')
def snapshot():return {n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names}
before=snapshot();source=(ROOT/names[0]).read_text(encoding='utf-8-sig');source=re.sub(r'^#include [^\n]*\n','',source,flags=re.M);(out/'su-auth-production.inc').write_text(source,encoding='utf-8')
docker=['docker','run','--rm','--pull','never','--network','none','--read-only','--tmpfs','/tmp:rw,exec,size=64m','-e','ASAN_OPTIONS=detect_leaks=1','-e','UBSAN_OPTIONS=halt_on_error=1','--mount',f'type=bind,source={ROOT},target=/repo,readonly','--mount',f'type=bind,source={out},target=/work','-w','/work','sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e']
commands=[]
for label,argv in [('compile',['g++','-std=c++17','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie','-Wno-attributes','-I/work','-I/repo/runtime/maplesu-sdk/include','-I/repo/runtime/maplesu-sdk/sdk/include','-I/repo/runtime/maplesu-sdk/sdk','/repo/runtime/tests/ultra_su_auth_worker_protocol_test.cpp','/repo/runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp','/repo/runtime/ultra/authorization/request_context.cpp','-o','su-auth-test']),('run',['./su-auth-test'])]:
 done=subprocess.run(docker+argv,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=55);log=done.stdout+done.stderr;(out/(label+'.log')).write_text(log,encoding='utf-8');commands.append(dict(label=label,argv=docker+argv,exitCode=done.returncode));print(label,done.returncode,log[-9000:],flush=True)
 if done.returncode:break
stable=before==snapshot();passed=len(commands)==2 and all(c['exitCode']==0 for c in commands) and stable
(out/'RESULT.json').write_text(json.dumps(dict(passed=passed,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),inputsUnchanged=stable,sourceSha256=before,commands=commands,scope='Complete production m061 bodies, real current fork_pipe.cpp, inline WorkerScope, real Linux child and versioned result framing; auth Root/session/storage/body are boundary fixtures. No device effect.'),indent=2)+'\n',encoding='utf-8')
raise SystemExit(0 if passed else 1)
