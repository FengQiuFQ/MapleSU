// Actual m061 workers, WorkerScope and fork/pipe transport. Root/auth/storage are boundary fixtures.
#include "maplesu_storage_worker_private.h"
#include "maplesu_operation_wait_private.h"
#include "src/maplesu_core/closure_fork_pipe.h"
#include "src/maplesu/compat/su_auth_legacy_abi.h"
#include "src/module/su_redirect_tu/su_uid_profile_private.h"
#include <cerrno>
#include <cstdio>
#include <sys/mman.h>
#include <sys/wait.h>

namespace fixture {
struct Shared { unsigned roots, transactions, reads, closes, selects; pid_t worker; };
Shared* shared;
thread_local uint64_t auth=1;
uint64_t expected=1;
pid_t parent, session=0;
KModErr root_error=KModErr::OK, body_error=KModErr::OK, close_error=KModErr::OK, admission_error=KModErr::OK;
unsigned callbacks, checks, failures;
unsigned record_fault;
int blocked_read = -1;
thread_local kernel_module::RequestUidReadbackDiagnostic readback;
KModErr body() {
 if(getpid()==parent || auth!=expected)return KModErr::ERR_MODULE_TEST_CHANNEL;
 if(blocked_read>=0){shared->worker=getpid();char byte;const auto ignored=read(blocked_read,&byte,1);(void)ignored;}
 if(is_failed(body_error))errno=EIO;
 return body_error;
}
void check(bool value,const char* message) {++checks;if(!value){++failures;std::printf("FAIL %s\n",message);}}
}
namespace kernel_module {
uint64_t maplesu_request_auth_state(){return fixture::auth;}
KModErr maplesu_request_set_auth_mode(RequestAuthMode mode){++fixture::shared->selects;fixture::auth=((fixture::auth>>2)+1)*4+uint64_t(mode);return KModErr::OK;}
KModErr maplesu_request_worker_admission(){const auto e=maplesu_request_auth_usable(fixture::auth)?fixture::admission_error:KModErr::ERR_MODULE_ROOT_KEY;if(is_failed(e))errno=EPERM;return e;}
RequestManagementReply maplesu_request_management_reply(){return fixture::readback.reply;}
RequestUidReadbackDiagnostic maplesu_request_uid_readback_diagnostic(){return fixture::readback;}
bool maplesu_request_owner_lifetime_capture(RequestOwnerLifetimeToken&){return fixture::session==getpid();}
KModErr maplesu_request_owner_close(){++fixture::shared->closes;fixture::session=0;const auto e=fixture::shared->closes>1?fixture::close_error:KModErr::OK;if(is_failed(e))errno=ENOSPC;return e;}
KModErr maplesu_request_helper_open(){fixture::session=getpid();return KModErr::OK;}
KModErr maplesu_request_owner_deployment(RequestDeploymentNamespace& out){out.binding.actual_uid=0;std::memcpy(out.record.name,"0123456789abcdef",16);return KModErr::OK;}
bool maplesu_request_owner_binding_matches(const RequestOwnerBinding&){return fixture::session==getpid();}
CleanupReceiptScope::CleanupReceiptScope()noexcept:saved_errno_(errno),saved_process_(getpid()),saved_reply_{}{}
CleanupReceiptScope::~CleanupReceiptScope()noexcept{errno=saved_errno_;}
}
namespace maplesu::storage {
StorageScope::StorageScope(const StorageLocator&,const char*){error_=KModErr::OK;}
StorageScope::~StorageScope()=default;
KModErr StorageScope::select_module(const char*){return KModErr::OK;}
}
namespace default_modules::module_root {
KModErr set_current_root(bool manager){
 ++fixture::shared->roots;
 if(manager==kernel_module::maplesu_request_helper_mode()||fixture::auth!=fixture::expected)return KModErr::ERR_MODULE_TEST_CHANNEL;
 if(is_failed(fixture::root_error)){errno=EACCES;return fixture::root_error;}
 if(kernel_module::maplesu_request_owner_mode())fixture::session=getpid();
 return KModErr::OK;
}
}
namespace default_modules::module_su_redirect {
KModErr get_su_allowlist(void(*callback)(const maplesu::sdk::su_auth_item*)){
 ++fixture::shared->reads;const auto e=fixture::body();if(is_failed(e))return e;
 maplesu::sdk::su_auth_item item{};std::strcpy(item.app_package_name,"fixture.package");callback(&item);return KModErr::OK;
}
}
namespace maplesu::su_auth::detail {
KModErr transact_add(const char*,ResultV1& result){++fixture::shared->transactions;return finish(result,fixture::body());}
KModErr transact_remove(const char*,ResultV1& result){++fixture::shared->transactions;return finish(result,fixture::body());}
KModErr transact_clear(ResultV1& result){++fixture::shared->transactions;return finish(result,fixture::body());}
KModErr transact_set_uid_profile(uint32_t uid,const char*,bool,ResultV1& result){++fixture::shared->transactions;if(uid!=1012345)return fail(result,KModErr::ERR_MODULE_PARAM,Phase::ActionValidate);return finish(result,fixture::body());}
KModErr transact_get_uid_profiles(void(*callback)(const UidProfileV1*)){
 ++fixture::shared->reads;const auto e=fixture::body();fixture::readback={};
 fixture::readback.errorCode=to_num(e);fixture::readback.systemErrno=is_failed(e)?errno:0;
 fixture::readback.phase=is_failed(e)?kernel_module::RequestUidReadbackPhase::Metadata:kernel_module::RequestUidReadbackPhase::Complete;
 fixture::readback.capabilities=MAPLESU_CAP_UID_SNAPSHOT;fixture::readback.revision=19;
 fixture::readback.reply={is_failed(e)?-EIO:0,0,19,0,MAPLESU_REQUEST_UID_READBACK,true};
 if(is_failed(e))return e;
 UidProfileV1 item{};item.uid=1012345;item.allow=1;std::strcpy(item.package,"fixture.package");callback(&item);
 if(fixture::record_fault){
  if(fixture::record_fault==1)item.uid=0;
  if(fixture::record_fault==2)item.allow=2;
  if(fixture::record_fault==3)item.package[0]=0;
  if(fixture::record_fault==4)std::memset(item.package,'x',sizeof(item.package));
  callback(&item);
 }
 return KModErr::OK;
}
}
#include "su-auth-production.inc"
static void run(uint64_t source,unsigned operation,unsigned fault){
 using namespace fixture;
 std::memset(shared,0,sizeof(*shared));auth=expected=source;session=0;callbacks=0;readback={};
 root_error=fault==1?KModErr::ERR_MODULE_OPEN_FILE:KModErr::OK;
 body_error=fault==2||fault==5?KModErr::ERR_MODULE_READ_FILE:KModErr::OK;
 close_error=fault==3||fault==5?KModErr::ERR_MODULE_WRITE_FILE:KModErr::OK;
 admission_error=fault==4?KModErr::ERR_MODULE_ROOT_KEY:KModErr::OK;
 maplesu::su_auth::ResultV1 receipt(maplesu::su_auth::Operation::Add);
 maplesu::su_auth::ReadResultV1 read_receipt;
 KModErr error;
 switch(operation){
 case 0:error=maplesu::sdk::get_su_auth_list_with_cb([](const maplesu::sdk::su_auth_item* item){check(std::string(item->app_package_name)=="fixture.package","record bytes preserved");++callbacks;});break;
 case 1:error=maplesu::su_auth::get_uid_profiles_with_cb([](const maplesu::su_auth::UidProfileV1* item){check(item->uid==1012345,"fullUID preserved");++callbacks;},read_receipt);break;
 case 2:error=maplesu::su_auth::add("fixture.package",receipt);break;
 case 3:error=maplesu::su_auth::remove("fixture.package",receipt);break;
 case 4:error=maplesu::su_auth::clear(receipt);break;
 default:error=maplesu::su_auth::set_uid_profile(1012345,"fixture.package",true,receipt);break;
 }
 KModErr want=KModErr::OK;
 if(fault==4||!kernel_module::maplesu_request_auth_usable(source))want=KModErr::ERR_MODULE_ROOT_KEY;
 else if(fault==1)want=root_error;else if(fault==2||fault==5)want=body_error;
 else if(fault==3&&kernel_module::maplesu_request_auth_authenticated(source))want=close_error;
 check(error==want,"selected protocol and first error retained");
 check(auth==source,"parent protocol generation unchanged");
 check(shared->selects==0,"worker does not replace selected protocol");
 if(fault==4||!kernel_module::maplesu_request_auth_usable(source))check(shared->roots==0&&shared->transactions==0&&shared->reads==0,"admission failure never executes worker");
 else {check(shared->roots==1,"exactly one worker roots");if(fault==1)check(shared->transactions==0&&shared->reads==0,"failed root/session close never executes transaction");}
 if(operation<2)check(callbacks==(is_ok(want)?1u:0u),"failed read publishes zero callbacks");
 else if(fault!=4&&kernel_module::maplesu_request_auth_usable(source))check(receipt.childWaitStatusValid&&receipt.transportStatus==uint32_t(maplesu::su_auth::Transport::Complete),"real child transaction frame completed");
 if(operation==1){
  using namespace maplesu::su_auth;
  check(read_receipt.resultCode==to_num(want),"typed read returns original result code");
  if(fault==4||!kernel_module::maplesu_request_auth_usable(source))
   check(!read_receipt.flags&&read_receipt.primaryPhase==uint32_t(ReadPhase::Admission)&&!read_receipt.root.completed,"admission retains local error without inventing child facts");
  else {
   check(read_receipt.flags==kReadResultAvailable&&read_receipt.transportStatus==uint32_t(Transport::Complete)&&read_receipt.childWaitStatusValid,"read receipt belongs to completed real child exchange");
   check(read_receipt.root.completed&&read_receipt.root.code==to_num(root_error)&&read_receipt.root.systemErrno==(is_failed(root_error)?EACCES:0),"exact child Root result and errno retained");
   check(read_receipt.read.completed==is_ok(root_error)&&read_receipt.read.code==(is_ok(root_error)?to_num(body_error):0)&&read_receipt.read.systemErrno==(is_ok(root_error)&&is_failed(body_error)?EIO:0),"exact child UID read result retained");
   const bool close_failed=kernel_module::maplesu_request_auth_authenticated(source)&&is_failed(close_error);
   check(read_receipt.close.completed&&read_receipt.close.code==(close_failed?to_num(close_error):0)&&read_receipt.close.systemErrno==(close_failed?ENOSPC:0),"cleanup error is independent of the read first error");
   if(is_ok(root_error))check(read_receipt.readback.revision==19&&read_receipt.readback.managementCompleted&&read_receipt.readback.managementCommand==MAPLESU_REQUEST_UID_READBACK,"actual child UID management scalar receipt reaches parent");
  }
 }
}
int main(){
 using namespace fixture;parent=getpid();shared=static_cast<Shared*>(mmap(nullptr,sizeof(Shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0));if(shared==MAP_FAILED)return 80;
 for(uint64_t mode:{UINT64_C(1),UINT64_C(4),UINT64_C(7)})for(unsigned op=0;op<6;++op)for(unsigned fault=0;fault<5;++fault)run(mode,op,fault);
 for(uint64_t mode:{UINT64_C(0),UINT64_C(2),UINT64_MAX})for(unsigned op=0;op<6;++op)run(mode,op,0);
 for(uint64_t mode:{UINT64_C(1),UINT64_C(4),UINT64_C(7)})run(mode,1,5);
 for(record_fault=1;record_fault<=4;++record_fault){
  std::memset(shared,0,sizeof(*shared));auth=expected=1;session=0;callbacks=0;readback={};
  root_error=body_error=close_error=admission_error=KModErr::OK;
  maplesu::su_auth::ReadResultV1 result;
  const auto e=maplesu::su_auth::get_uid_profiles_with_cb([](const maplesu::su_auth::UidProfileV1*){++callbacks;},result);
  check(e==KModErr::ERR_READ_CHILD_DATA&&result.primaryPhase==uint32_t(maplesu::su_auth::ReadPhase::Records)&&result.primaryErrno==EBADMSG,"whole UID record validation keeps its original phase and errno");
  check(!callbacks&&result.flags==maplesu::su_auth::kReadResultAvailable&&result.read.completed,"malformed trailing UID record publishes no earlier callback");
 }
 record_fault=0;
 {
  using namespace maplesu::su_auth;
  ReadResultV1 original;original.flags=kReadResultAvailable;
  original.authMode=1;original.root.completed=original.read.completed=original.close.completed=1;
  original.readback.phase=10;
  original.readback.managementResult=UINT64_MAX;original.readback.capabilities=UINT64_MAX;
  const auto bytes=read_wire::encode(original);ReadResultV1 decoded;
  check(read_wire::decode(bytes.data(),bytes.size(),decoded)&&decoded.readback.managementResult==UINT64_MAX,"versioned UID receipt preserves full-width scalar facts");
  for(size_t offset:{size_t(0),size_t(4),size_t(6),size_t(8),size_t(12),size_t(24),size_t(28),size_t(44),size_t(148),size_t(160)}){
   auto bad=bytes;bad[offset]^=0x80;ReadResultV1 untouched;untouched.resultCode=900;
   check(!read_wire::decode(bad.data(),bad.size(),untouched)&&untouched.resultCode==900,"invalid UID receipt is rejected without changing output");
  }
  check(!read_wire::decode(bytes.data(),bytes.size()-1,decoded),"short UID receipt is rejected");
 }
 for(unsigned operation=0;operation<3;++operation){
  std::memset(shared,0,sizeof(*shared));auth=expected=1;session=0;callbacks=0;readback={};
  root_error=body_error=close_error=admission_error=KModErr::OK;
  int descriptors[2];if(pipe(descriptors))return 81;blocked_read=descriptors[0];
  timespec start{},end{};clock_gettime(CLOCK_MONOTONIC,&start);
  const auto began=int64_t(start.tv_sec)*1000000000+start.tv_nsec;
  maplesu_request_set_operation_deadline_nanos(began+100000000);
  maplesu::su_auth::ReadResultV1 read_result;
  maplesu::su_auth::ResultV1 write_result(maplesu::su_auth::Operation::Add);
  const auto error=operation==0?maplesu::su_auth::get_uid_profiles_with_cb([](const maplesu::su_auth::UidProfileV1*){++callbacks;},read_result):
   operation==1?maplesu::su_auth::set_uid_profile(1012345,"fixture.package",true,write_result):
   maplesu::sdk::get_su_auth_list_with_cb([](const maplesu::sdk::su_auth_item*){++callbacks;});
  clock_gettime(CLOCK_MONOTONIC,&end);maplesu_request_set_operation_deadline_nanos(0);
  check(error==KModErr::ERR_READ_CHILD_ERRCODE&&int64_t(end.tv_sec)*1000000000+end.tv_nsec-began<1000000000,
   "blocked UID read/write consumes the original deadline and returns promptly");
  check(shared->roots==1&&!callbacks,"deadline cancellation never creates a replacement worker or publishes records");
  if(operation==0)check(!read_result.flags&&read_result.primaryErrno==ETIMEDOUT,"missing child read receipt leaves Root facts unknown and keeps timeout");
  if(operation==1)check(!write_result.flags&&write_result.commitState==uint32_t(maplesu::su_auth::Commit::Unknown),"lost mutation completion retains unknown commit without replay");
  close(descriptors[0]);close(descriptors[1]);blocked_read=-1;
  int status=0;pid_t reaped;do{reaped=waitpid(shared->worker,&status,0);}while(reaped<0&&errno==EINTR);
  check((reaped==shared->worker&&WIFSIGNALED(status))||(reaped<0&&errno==ECHILD),"same timed-out worker terminates and can be fully reaped");
 }
 munmap(shared,sizeof(Shared));std::printf("SU worker protocol checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
