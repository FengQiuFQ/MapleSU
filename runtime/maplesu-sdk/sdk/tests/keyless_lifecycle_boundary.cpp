// Insert exact production identity/install/uninstall/version/state bodies. Worker, mutation, installers
// and process/result boundaries are fixtures; real file removal is confined to base.
#include "module_err_def.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <sys/wait.h>
namespace {
std::string base, system_directory, kernel_directory;
int root_error = 0, action_error = 0, launch_result = 0, removed_modules = 0;
int publishes = 0, commits = 0, revoked = 0, closes = 0, launches = 0, deletes = 0;
int channel_starts = 0, admission_error = 0;
bool installed = false, existing_current = false, helper_role = false, owner_mode = true;
int refresh_error = 0, refresh_errno = 0, commit_error = 0, refresh_calls = 0;
}
namespace kernel_module {
static bool maplesu_request_owner_mode() { return owner_mode; }
static uint64_t maplesu_request_auth_state() { return helper_role ? 3 : 1; }
static bool maplesu_request_auth_usable(uint64_t auth) { return auth == 1 || auth == 3; }
static bool maplesu_request_auth_helper(uint64_t auth) { return auth == 3; }
static KModErr maplesu_request_worker_admission() { return static_cast<KModErr>(admission_error); }
}
namespace maplesu::storage {
struct WorkerScope { KModErr root() { return static_cast<KModErr>(root_error); } };
static KModErr current_system_directory(std::string& out) { out=system_directory;return KModErr::OK; }
}
namespace maplesu::install::core { using err_t = long long; }
namespace maplesu::install::state {
struct Result { long long code = 0; };
struct Mutation {
 Result open() { return {}; } bool ready() { return true; } bool revocation_required() { return true; }
 Result revoke() { ++revoked;return {}; } void close() { ++closes; }
};
static void diagnose(const char*,Result) {}
static bool mutation_open_failed(Result r) { return r.code; }
}
namespace maplesu::compat {
using err_t = install::core::err_t;
constexpr err_t kInstallerOk=0,kInstallerIdentity=-20002,kInstallerBootSession=-20003,
 kInstallerEnvironmentAbsent=-20004,kInstallerFileAbsent=-20005,kInstallerWriteFile=-20006,
 kInstallerCreateFile=-20007,kInstallerSetLabel=-20008,kInstallerDeleteFile=-20009,
 kInstallerReadError=-20010,kInstallerReadText=-20011,kInstallerParseVersion=-20012;
struct InstallerChannel {
 bool start(){++channel_starts;return true;} void close(){} int child_pid(){return 123;}
 bool write_error(err_t){return true;} bool read_error(err_t&){return true;}
 bool write_text(const std::string&){return true;} bool read_text(std::string&){return true;}
 bool write_integer(int){return true;} bool read_integer(int&){return true;}
};
static err_t installer_clean_older(){return action_error;}
static err_t installer_create_directories(){return action_error;}
static err_t installer_su(){++publishes;return action_error;}
static err_t installer_webui(){++publishes;return action_error;}
static err_t installer_prepare_bootstrap(){++publishes;return action_error;}
static err_t installer_refresh_bootstrap(){++publishes;return action_error;}
static err_t installer_resetprop(){++publishes;return action_error;}
static err_t installer_refresh_authorization(){++refresh_calls;if(refresh_error)errno=refresh_errno;return refresh_error ? refresh_error : action_error;}
static err_t installer_commit_version(install::state::Mutation&){++commits;installed=true;return commit_error ? commit_error : action_error;}
static err_t installer_prepare_bootstrap_state(){return action_error;}
static err_t installer_reset_safe(){return action_error;}
static err_t installer_reset_duplicate(){return action_error;}
static err_t installer_restart_zygote(){return action_error;}
static bool installer_first_configuration(){return true;}
static err_t installer_delete_directories(){++deletes;std::filesystem::remove_all(base);return action_error;}
struct InstallerModules { err_t load(){return action_error;} size_t size(){return 2;} err_t remove(size_t){++removed_modules;return action_error;} };
}
namespace file_utils {
enum class SelinuxFileFlag { None };
static bool create_empty_file(const char*){return true;}
static bool write_text_file(const char*,const std::string&){return true;}
static bool set_file_selinux_access_mode(const char*,SelinuxFileFlag=SelinuxFileFlag::None,int=0600){return true;}
}
namespace boot_session_utils { static std::string read_boot_session(){return "12345678-1234-1234-1234-123456789abc";} }
static long maplesu_installer_launch_error(int,const char*){return -21002;}
static int maplesu_installer_reboot(const char*){assert(false);return 127;}
static pid_t maplesu_installer_wait_child(pid_t,int*,const char*){assert(false);return -1;}
static long maplesu_installer_result_open(int,int[2]){return 0;}
static void maplesu_installer_result_worker(int[2]){assert(false);}
static int maplesu_installer_result_complete(int[2],const char*,int){assert(false);return 0;}
static long maplesu_installer_result_parent(pid_t,int,int[2]){++launches;return launch_result;}
extern "C" uint32_t maplesu_environment_state(){assert(false);return 0;}
extern "C" pid_t maplesu_wait_environment_child(pid_t,int*){assert(false);return -1;}
extern "C" pid_t __wrap_fork(){return 123;}
extern "C" void __wrap_sync(){}
extern "C" KModErr maplesu_prepare_su_exec_directory(const char*){return KModErr::OK;}
namespace maplesu::install {
enum class DeploymentMode { Boot,HotLoad,Refresh };
enum class EnvironmentState { Unknown=0,Running=1 };
enum class ExploitPolicy { None,Magica,CVE2026_43499 };
struct InstallOptions { ExploitPolicy exploit=ExploitPolicy::CVE2026_43499; };
struct Version { uint32_t major=0,minor=0,patch=0; };
constexpr char kSdkVersionText[]="5.2.1";
static bool failed(core::err_t e){return e!=0;}
static bool succeeded(core::err_t e){return e==0;}
// @INSERT_IDENTITY@
static std::string get_kernel_file_dir_path(){return kernel_directory;}
static std::string get_autorun_bootstrap_path(){return kernel_directory+"init";}
static core::err_t read_installed_version(std::string& out){out=existing_current?kSdkVersionText:"5.2.0";return installed?0:compat::kInstallerEnvironmentAbsent;}
static core::err_t retire_environment_version(){installed=false;return 0;}
static core::err_t unsafe_installed_version(std::string&){assert(false);return -1;}
static bool parse_installed_environment_version(const std::string&,Version&){assert(false);return false;}
static void exec_bootstrap_command(const char*){assert(false);}
struct Completed { core::err_t error; };
static void finish_installation_child(compat::InstallerChannel&,state::Mutation&,std::optional<storage::WorkerScope>&,core::err_t e){throw Completed{e};}
static core::err_t collect_installation_result(compat::InstallerChannel&){assert(false);return -1;}
// @INSERT_INSTALL@
// @INSERT_UNINSTALL@
// @INSERT_VERSION@
// @INSERT_STATE@
}
static void reset(){
 static unsigned seq=0;
 base="/tmp/maplesu-lifecycle-"+std::to_string(getpid())+"-"+std::to_string(++seq);
 kernel_directory=base+"/kernel/";system_directory=base+"/system/";
 std::filesystem::create_directories(kernel_directory);std::filesystem::create_directories(system_directory);
 std::ofstream(kernel_directory+"init")<<"fixture-helper";
 root_error=action_error=launch_result=removed_modules=publishes=commits=revoked=closes=launches=deletes=0;
 channel_starts=admission_error=0;
 installed=existing_current=helper_role=false;owner_mode=true;refresh_error=refresh_errno=commit_error=refresh_calls=0;errno=0;
}
template<typename F> static long long invoke(F f){try{return f();}catch(const maplesu::install::Completed& c){return c.error;}}
int main(){
 using namespace maplesu::install;
 unsigned checks=0;
 reset();assert(invoke([&]{return install_environment(DeploymentMode::HotLoad,{});})==0);
 assert(publishes==4&&commits==1&&installed&&launches==1&&deletes==0);++checks;
 std::filesystem::remove_all(base);
 reset();admission_error=-19997;
 assert(invoke([&]{return install_environment(DeploymentMode::HotLoad,{});})==maplesu::compat::kInstallerIdentity);
 assert(channel_starts==0&&publishes==0&&commits==0&&launches==0);++checks;
 assert(invoke([&]{return uninstall_environment();})==maplesu::compat::kInstallerIdentity);
 assert(channel_starts==0&&removed_modules==0&&deletes==0);++checks;
 Version version{5,1,9};
 assert(installed_version(version)==maplesu::compat::kInstallerIdentity);
 assert(channel_starts==0&&version.major==5&&version.minor==1&&version.patch==9);++checks;
 assert(environment_state()==EnvironmentState::Unknown);
 assert(channel_starts==0);++checks;
 std::filesystem::remove_all(base);
 reset();installed=existing_current=true;
 assert(invoke([&]{return install_environment(DeploymentMode::HotLoad,{});})==0);
 assert(publishes==0&&commits==0&&launches==1&&deletes==0);++checks;
 std::filesystem::remove_all(base);
 reset();installed=true;
 assert(invoke([&]{return install_environment(DeploymentMode::Refresh,{});})==0);
 assert(publishes==4&&commits==1&&launches==0&&deletes==0);++checks;
 std::filesystem::remove_all(base);
 reset();assert(invoke([&]{return install_environment(DeploymentMode::Refresh,{});})==maplesu::compat::kInstallerEnvironmentAbsent);
 assert(publishes==0&&commits==0&&deletes==0);++checks;
 std::filesystem::remove_all(base);
 reset();launch_result=-21002;
 assert(invoke([&]{return install_environment(DeploymentMode::HotLoad,{});})==-21002);
 assert(commits==1&&installed&&deletes==0);++checks;
 std::filesystem::remove_all(base);
 reset();root_error=-20001;
 assert(invoke([&]{return install_environment(DeploymentMode::HotLoad,{});})==root_error);
 assert(publishes==0&&commits==0&&launches==0&&deletes==0);++checks;
 std::filesystem::remove_all(base);
 reset();helper_role=true;
 assert(invoke([&]{return install_environment(DeploymentMode::HotLoad,{});})==maplesu::compat::kInstallerIdentity);
 assert(publishes==0&&commits==0&&launches==0);++checks;
 std::filesystem::remove_all(base);
 reset();assert(invoke([&]{return uninstall_environment();})==0);
 assert(removed_modules==2&&revoked==1&&deletes==1&&!std::filesystem::exists(base));++checks;
 reset();root_error=-20001;
 assert(invoke([&]{return uninstall_environment();})==root_error);
 assert(removed_modules==0&&deletes==0&&std::filesystem::exists(kernel_directory+"init"));++checks;
 std::filesystem::remove_all(base);
 reset();action_error=-20021;
 assert(invoke([&]{return uninstall_environment();})==action_error);
 assert(removed_modules==0&&deletes==0);++checks;
 std::filesystem::remove_all(base);
 unsigned failures=0;
 const auto check = [&](bool ok,const char* name,long long code) {
  ++checks;if(!ok)++failures;
  std::printf("%s case=%s code=%lld refreshCalls=%d commits=%d launches=%d revoked=%d errno=%d\n",
    ok?"PASS":"FAIL",name,code,refresh_calls,commits,launches,revoked,errno);
 };
 for (const bool owner : {false,true}) {
  reset();installed=existing_current=true;owner_mode=owner;refresh_error=-19999;
  const auto code=invoke([&]{return install_environment(DeploymentMode::HotLoad,{});});
  check(code==0&&refresh_calls==0&&commits==0&&launches==1,
    owner?"owner-hotload-current-no-pre-refresh":"legacy-hotload-current-no-pre-refresh",code);
  std::filesystem::remove_all(base);
 }
 for (const int failure : {EAGAIN,ESTALE}) {
  reset();installed=true;refresh_error=-19999;refresh_errno=failure;
  const auto code=invoke([&]{return install_environment(DeploymentMode::Refresh,{});});
  check(code==0&&refresh_calls==0&&commits==1&&launches==0&&revoked==1,
    failure==EAGAIN?"owner-refresh-unstarted-factory":"owner-refresh-revoked-factory",code);
  std::filesystem::remove_all(base);
  reset();installed=true;owner_mode=false;refresh_error=-19999;refresh_errno=failure;
  const auto legacy=invoke([&]{return install_environment(DeploymentMode::Refresh,{});});
  check(legacy==-19999&&errno==failure&&refresh_calls==1&&commits==0&&launches==0&&revoked==1,
    failure==EAGAIN?"legacy-refresh-retains-eagain":"legacy-refresh-retains-estale",legacy);
  std::filesystem::remove_all(base);
 }
 reset();installed=true;owner_mode=false;
 const auto legacy=invoke([&]{return install_environment(DeploymentMode::Refresh,{});});
 check(legacy==0&&refresh_calls==1&&commits==1&&launches==0,"legacy-refresh-keeps-delivery",legacy);
 std::filesystem::remove_all(base);
 reset();installed=true;refresh_error=-19999;refresh_errno=EAGAIN;commit_error=-34567;
 const auto commit=invoke([&]{return install_environment(DeploymentMode::Refresh,{});});
 check(commit==commit_error&&refresh_calls==0&&commits==1&&launches==0,
   "owner-refresh-keeps-original-commit-failure",commit);
 std::filesystem::remove_all(base);
 std::printf("KEYLESS_LIFECYCLE_RESULT checks=%u failures=%u exact_install_uninstall=1 side_effect_endpoints=fixture device=0\n",checks,failures);
 return failures?1:0;
}
