#pragma once
#include <sys/types.h>

// Legacy callback and signed return ABI; independent of the Lite root kit.
namespace kernel_root {
enum AppDynlibStatus : int { Unknown = 0, Running = 1, NotRunning = 2 };
using ParasiteError = ssize_t;

constexpr ParasiteError PARASITE_OK = 0;
constexpr ParasiteError PARASITE_PARAM = -10000;
constexpr ParasiteError PARASITE_CHILD = -9998;
constexpr ParasiteError PARASITE_APP_DIR = -9987;
constexpr ParasiteError PARASITE_PROCESS = -9986;
constexpr ParasiteError PARASITE_32BIT = -9985;
constexpr ParasiteError PARASITE_ORIGINAL = -9984;
constexpr ParasiteError PARASITE_PAYLOAD = -9983;
constexpr ParasiteError PARASITE_CONTEXT = -9981;
constexpr ParasiteError PARASITE_LINK = -9980;
constexpr ParasiteError PARASITE_VERIFY = -9979;
constexpr ParasiteError PARASITE_IO = -9964;
constexpr ParasiteError PARASITE_NOT_ELF64 = -9962;
// Extension errors deliberately outside KRootErr / KModErr ranges.
constexpr ParasiteError PARASITE_RECOVERY_MISSING = -31001;
constexpr ParasiteError PARASITE_CONFLICT = -31002;

__attribute__((visibility("default"))) ParasiteError parasite_precheck_app_with_cb(
    const char* target_pid_cmdline,
    void (*callback)(const char*, AppDynlibStatus));
__attribute__((visibility("default"))) ParasiteError parasite_implant_app(
    const char* target_pid_cmdline, const char* original_so_full_path);
__attribute__((visibility("default"))) ParasiteError parasite_implant_su_env(
    const char* target_pid_cmdline, const char* original_so_full_path,
    const char* su_dir_path);
// Explicit 5.2.0 compatibility overloads; standard entries above remain keyless.
__attribute__((visibility("default"))) ParasiteError parasite_precheck_app_with_cb(
    const char* root_key, const char* target_pid_cmdline,
    void (*callback)(const char*, AppDynlibStatus));
__attribute__((visibility("default"))) ParasiteError parasite_implant_app(
    const char* root_key, const char* target_pid_cmdline, const char* original_so_full_path);
__attribute__((visibility("default"))) ParasiteError parasite_implant_su_env(
    const char* root_key, const char* target_pid_cmdline, const char* original_so_full_path,
    const char* su_dir_path);
}
