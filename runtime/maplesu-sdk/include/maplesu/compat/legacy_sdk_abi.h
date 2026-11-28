#pragma once

#include "module_err_def.h"
#include "maplesu_module_control.h"
#include "maplesu_parasite.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <tuple>
#include <vector>

// Internal natural-layout TUs rename the current public carrier while including
// the umbrella. The independent 5.2.0 public types keep their original names.
#pragma push_macro("module_desc")
#pragma push_macro("module_record")
#undef module_desc
#undef module_record

namespace skroot_env {
enum class InstallMode : uint32_t { Boot = 0, HotLoad = 1 };
enum class ExploitMethod : uint32_t { None = 0, Magica = 1, CVE2026_43499 = 2 };
struct InstallConfig { ExploitMethod exploit = ExploitMethod::None; };
enum class SkrootEnvState : uint32_t { NotInstalled = 0, Running = 1, Fault = 2, Unknown = 3 };
struct SkrootSdkVersion { uint32_t major = 0, minor = 0, patch = 0; };

struct module_desc {
    char name[1024] = {}, version[1024] = {}, desc[4096] = {}, author[1024] = {};
    char id32[1024] = {}, update_json[1024] = {};
    bool web_ui = false;
    SkrootSdkVersion min_sdk_ver = {};
} __attribute__((packed));
enum class ModuleRunState : uint32_t { NotRunning = 0, Running = 1, Abnormal = 2, RemovedPendingReboot = 3 };
struct module_record {
    module_desc desc;
    ModuleRunState state = ModuleRunState::NotRunning;
} __attribute__((packed));
struct su_auth_item { char app_package_name[256] = {}; };
enum class BasicItem : uint32_t { Channel, KernelBase, WriteTest, ReadTrampoline, WriteTrampoline, PhysAddrCalc };
enum class DeafultModuleName : uint32_t {
    RootBridgePrint, RootBridgeExec, SuRedirectPrint, SuRedirectExec, TombstonesPurgePrint
};

static_assert(sizeof(InstallMode) == 4 && sizeof(InstallConfig) == 4 && alignof(InstallConfig) == 4);
static_assert(sizeof(SkrootSdkVersion) == 12 && alignof(SkrootSdkVersion) == 4);
static_assert(offsetof(SkrootSdkVersion, major) == 0 && offsetof(SkrootSdkVersion, minor) == 4 &&
              offsetof(SkrootSdkVersion, patch) == 8);
// Match the frozen headers' measured ARM NDK layout: the non-POD version
// field keeps its alignment, while the outer record remains byte-aligned.
static_assert(offsetof(module_desc, name) == 0 && offsetof(module_desc, version) == 1024 &&
              offsetof(module_desc, desc) == 2048 && offsetof(module_desc, author) == 6144 &&
              offsetof(module_desc, id32) == 7168 && offsetof(module_desc, update_json) == 8192 &&
              offsetof(module_desc, web_ui) == 9216);
#if defined(__arm__) || defined(__aarch64__)
static_assert(sizeof(module_desc) == 9232 && alignof(module_desc) == 4 &&
              offsetof(module_desc, min_sdk_ver) == 9220);
static_assert(sizeof(module_record) == 9236 && alignof(module_record) == 1 &&
              offsetof(module_record, state) == 9232);
#endif
static_assert(sizeof(su_auth_item) == 256 && alignof(su_auth_item) == 1);
static_assert(sizeof(ModuleRunState) == 4 && sizeof(BasicItem) == 4 && sizeof(DeafultModuleName) == 4);

// Explicit historical credentials remain a separate compatibility entry. The
// current maplesu::sdk API continues to select the standard keyless protocol.
KModErr get_root(const char* root_key);
KModErr run_root_cmd(const char* root_key, const char* cmd, std::string& out_result);
KModErr install_skroot_environment(const char* root_key, InstallMode mode = InstallMode::Boot,
                                  const InstallConfig& config = InstallConfig());
KModErr uninstall_skroot_environment(const char* root_key);
SkrootEnvState get_skroot_environment_state(const char* root_key);
KModErr get_installed_skroot_environment_version(const char* root_key, SkrootSdkVersion& out_ver);
SkrootSdkVersion get_sdk_version();
KModErr set_boot_fail_protect_enabled(const char* root_key, bool enabled);
bool is_boot_fail_protect_enabled(const char* root_key);
KModErr set_adb_forced_disabled(const char* root_key, bool disabled);
bool is_adb_forced_disabled(const char* root_key);
const char* get_root_status_report(const char* root_key);
KModErr restart_zygote64(const char* root_key);
KModErr test_skroot_basics_with_cb(const char* root_key, BasicItem item, void (*callback)(const char*));
KModErr test_skroot_deafult_module_with_cb(const char* root_key, DeafultModuleName name,
                                        void (*callback)(const char*));
KModErr parse_module_desc_from_zip_file(const char* root_key, const char* path, module_desc& out_desc);
KModErr get_all_modules_with_cb(const char* root_key, void (*callback)(const module_record*));
KModErr install_module_with_cb(const char* root_key, const char* path, void (*callback)(const char*));
KModErr install_module_dev_run_once_with_cb(const char* root_key, const char* path,
                                         void (*callback)(const char*));
KModErr uninstall_module(const char* root_key, const char* id32);
KModErr read_skroot_log_cb(const char* root_key, void (*callback)(const char*));
KModErr set_skroot_log_enabled(const char* root_key, bool enable);
bool is_skroot_log_enabled(const char* root_key);
KModErr clear_skroot_log(const char* root_key);
KModErr get_su_auth_list_with_cb(const char* root_key, void (*callback)(const su_auth_item*));
KModErr add_su_auth_list(const char* root_key, const char* package);
KModErr remove_su_auth_list(const char* root_key, const char* package);
KModErr clear_su_auth_list(const char* root_key);
namespace features::web_ui {
KModErr start_module_web_ui_server_async(const char* root_key, const char* id32, int& out_port);
}

namespace legacy_detail {
template <class Output> class OutputScope {
public:
    explicit OutputScope(Output& output) : previous_(current) { current = &output; }
    ~OutputScope() { current = previous_; }
    OutputScope(const OutputScope&) = delete;
    OutputScope& operator=(const OutputScope&) = delete;
    inline static thread_local Output* current = nullptr;
private:
    Output* previous_;
};
inline void receive_text(const char* text) {
    if (text && OutputScope<std::string>::current) *OutputScope<std::string>::current = text;
}
template <class Item> void receive_item(const Item* item) {
    auto* output = OutputScope<std::vector<Item>>::current;
    if (item && output) output->push_back(*item);
}
}

inline KModErr read_skroot_log(const char* key, std::string& out) {
    legacy_detail::OutputScope<std::string> scope(out);
    return read_skroot_log_cb(key, legacy_detail::receive_text);
}
inline KModErr get_all_modules_list(const char* key, std::vector<module_record>& out) {
    legacy_detail::OutputScope<std::vector<module_record>> scope(out);
    return get_all_modules_with_cb(key, legacy_detail::receive_item<module_record>);
}
inline KModErr install_module(const char* key, const char* path, std::string& out) {
    legacy_detail::OutputScope<std::string> scope(out);
    return install_module_with_cb(key, path, legacy_detail::receive_text);
}
inline KModErr install_module_dev_run_once(const char* key, const char* path, std::string& out) {
    legacy_detail::OutputScope<std::string> scope(out);
    return install_module_dev_run_once_with_cb(key, path, legacy_detail::receive_text);
}
inline KModErr get_su_auth_list(const char* key, std::vector<su_auth_item>& out) {
    legacy_detail::OutputScope<std::vector<su_auth_item>> scope(out);
    return get_su_auth_list_with_cb(key, legacy_detail::receive_item<su_auth_item>);
}
inline KModErr test_skroot_basics(const char* key, BasicItem item, std::string& out) {
    legacy_detail::OutputScope<std::string> scope(out);
    return test_skroot_basics_with_cb(key, item, legacy_detail::receive_text);
}
inline KModErr test_skroot_deafult_module(const char* key, DeafultModuleName name, std::string& out) {
    legacy_detail::OutputScope<std::string> scope(out);
    return test_skroot_deafult_module_with_cb(key, name, legacy_detail::receive_text);
}
}

constexpr bool operator<(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return std::tie(a.major, a.minor, a.patch) < std::tie(b.major, b.minor, b.patch);
}
constexpr bool operator==(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) {
    return std::tie(a.major, a.minor, a.patch) == std::tie(b.major, b.minor, b.patch);
}
constexpr bool operator!=(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) { return !(a == b); }
constexpr bool operator>(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) { return b < a; }
constexpr bool operator<=(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) { return !(b < a); }
constexpr bool operator>=(const skroot_env::SkrootSdkVersion& a, const skroot_env::SkrootSdkVersion& b) { return !(a < b); }

#pragma pop_macro("module_record")
#pragma pop_macro("module_desc")
