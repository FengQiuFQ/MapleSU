#include "module_api_legacy_abi.h"
#include "module_carrier_conversion.h"
#include "maplesu/compat/legacy_sdk_abi.h"
#include "credential_scope_legacy_abi.h"

namespace maplesu::sdk {
KModErr get_all_modules_with_cb(void (*)(const module_record*));
KModErr install_module_with_cb(const char*, void (*)(const char*));
KModErr install_module_dev_run_once_with_cb(const char*, void (*)(const char*));
KModErr get_su_auth_list_with_cb(void (*)(const su_auth_item*));
KModErr read_maplesu_log_cb(void (*)(const char*));
KModErr test_maplesu_basics_with_cb(BasicItem, void (*)(const char*));
KModErr test_maplesu_deafult_module_with_cb(DeafultModuleName, void (*)(const char*));
}
namespace maplesu {
std::vector<ModuleControlResult> get_module_controls(const std::vector<sdk::module_record>&);
}

namespace {
using maplesu::compat::legacy_call;
using maplesu::compat::LegacyCredentialScope;
template <class Callback> class CallbackScope {
public:
    explicit CallbackScope(Callback callback) : previous_(current) { current = callback; }
    ~CallbackScope() { current = previous_; }
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;
    inline static thread_local Callback current = nullptr;
private:
    Callback previous_;
};
using ModuleCallback = CallbackScope<void (*)(const skroot_env::module_record*)>;
using SuCallback = CallbackScope<void (*)(const skroot_env::su_auth_item*)>;
void receive_module(const maplesu::sdk::module_record* record) {
    if (!record || !ModuleCallback::current) return;
    skroot_env::module_record converted;
    maplesu::compat::copy_module_record(converted, *record);
    ModuleCallback::current(&converted);
}
void receive_su(const maplesu::sdk::su_auth_item* item) {
    if (!item || !SuCallback::current) return;
    skroot_env::su_auth_item converted;
    std::memcpy(converted.app_package_name, item->app_package_name, sizeof(converted.app_package_name));
    SuCallback::current(&converted);
}
}

namespace skroot_env {
KModErr get_root(const char* key) {
    return legacy_call(key, [] { return maplesu::sdk::get_root(); });
}
KModErr run_root_cmd(const char* key, const char* cmd, std::string& out) {
    return legacy_call(key, [&] { return maplesu::sdk::run_root_cmd(cmd, out); });
}
KModErr install_skroot_environment(const char* key, InstallMode mode, const InstallConfig& config) {
    return legacy_call(key, [&] {
        maplesu::sdk::InstallConfig converted;
        converted.exploit = static_cast<maplesu::sdk::ExploitMethod>(config.exploit);
        return maplesu::sdk::install_maplesu_environment(static_cast<maplesu::sdk::InstallMode>(mode), converted);
    });
}
KModErr uninstall_skroot_environment(const char* key) {
    return legacy_call(key, [] { return maplesu::sdk::uninstall_maplesu_environment(); });
}
SkrootEnvState get_skroot_environment_state(const char* key) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return SkrootEnvState::Unknown;
    const auto state = maplesu::sdk::get_maplesu_environment_state();
    return is_ok(scope.restore()) ? static_cast<SkrootEnvState>(state) : SkrootEnvState::Unknown;
}
KModErr get_installed_skroot_environment_version(const char* key, SkrootSdkVersion& out) {
    return legacy_call(key, [&] {
        maplesu::sdk::MapleSUSdkVersion converted;
        const auto error = maplesu::sdk::get_installed_maplesu_environment_version(converted);
        if (is_ok(error)) out = {converted.major, converted.minor, converted.patch};
        return error;
    });
}
KModErr set_boot_fail_protect_enabled(const char* key, bool enabled) {
    return legacy_call(key, [&] { return maplesu::sdk::set_boot_fail_protect_enabled(enabled); });
}
bool is_boot_fail_protect_enabled(const char* key) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return false;
    const bool enabled = maplesu::sdk::is_boot_fail_protect_enabled();
    return is_ok(scope.restore()) && enabled;
}
KModErr set_adb_forced_disabled(const char* key, bool disabled) {
    return legacy_call(key, [&] { return maplesu::sdk::set_adb_forced_disabled(disabled); });
}
bool is_adb_forced_disabled(const char* key) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return false;
    const bool disabled = maplesu::sdk::is_adb_forced_disabled();
    return is_ok(scope.restore()) && disabled;
}
const char* get_root_status_report(const char* key) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return nullptr;
    const auto* report = maplesu::sdk::get_root_status_report();
    (void)scope.restore();
    return report;
}
KModErr restart_zygote64(const char* key) {
    return legacy_call(key, [] { return maplesu::sdk::restart_zygote64(); });
}
KModErr test_skroot_basics_with_cb(const char* key, BasicItem item, void (*callback)(const char*)) {
    return legacy_call(key, [&] {
        return maplesu::sdk::test_maplesu_basics_with_cb(static_cast<maplesu::sdk::BasicItem>(item), callback);
    });
}
KModErr test_skroot_deafult_module_with_cb(const char* key, DeafultModuleName name,
                                        void (*callback)(const char*)) {
    return legacy_call(key, [&] {
        return maplesu::sdk::test_maplesu_deafult_module_with_cb(
            static_cast<maplesu::sdk::DeafultModuleName>(name), callback);
    });
}
KModErr parse_module_desc_from_zip_file(const char* key, const char* path, module_desc& out) {
    return legacy_call(key, [&] {
        maplesu::sdk::module_desc converted;
        const auto error = maplesu::sdk::parse_module_desc_from_zip_file(path, converted);
        if (is_ok(error)) maplesu::compat::copy_module_descriptor(out, converted);
        return error;
    });
}
KModErr get_all_modules_with_cb(const char* key, void (*callback)(const module_record*)) {
    return legacy_call(key, [&] {
        if (!callback) return KModErr::ERR_MODULE_PARAM;
        ModuleCallback scope(callback);
        return maplesu::sdk::get_all_modules_with_cb(receive_module);
    });
}
KModErr install_module_with_cb(const char* key, const char* path, void (*callback)(const char*)) {
    return legacy_call(key, [&] { return maplesu::sdk::install_module_with_cb(path, callback); });
}
KModErr install_module_dev_run_once_with_cb(const char* key, const char* path, void (*callback)(const char*)) {
    return legacy_call(key, [&] { return maplesu::sdk::install_module_dev_run_once_with_cb(path, callback); });
}
KModErr uninstall_module(const char* key, const char* id32) {
    return legacy_call(key, [&] { return maplesu::sdk::uninstall_module(id32); });
}
KModErr read_skroot_log_cb(const char* key, void (*callback)(const char*)) {
    return legacy_call(key, [&] { return maplesu::sdk::read_maplesu_log_cb(callback); });
}
KModErr set_skroot_log_enabled(const char* key, bool enabled) {
    return legacy_call(key, [&] { return maplesu::sdk::set_maplesu_log_enabled(enabled); });
}
bool is_skroot_log_enabled(const char* key) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return false;
    const bool enabled = maplesu::sdk::is_maplesu_log_enabled();
    return is_ok(scope.restore()) && enabled;
}
KModErr clear_skroot_log(const char* key) {
    return legacy_call(key, [] { return maplesu::sdk::clear_maplesu_log(); });
}
KModErr get_su_auth_list_with_cb(const char* key, void (*callback)(const su_auth_item*)) {
    return legacy_call(key, [&] {
        if (!callback) return KModErr::ERR_MODULE_PARAM;
        SuCallback scope(callback);
        return maplesu::sdk::get_su_auth_list_with_cb(receive_su);
    });
}
KModErr add_su_auth_list(const char* key, const char* package) {
    return legacy_call(key, [&] { return maplesu::sdk::add_su_auth_list(package); });
}
KModErr remove_su_auth_list(const char* key, const char* package) {
    return legacy_call(key, [&] { return maplesu::sdk::remove_su_auth_list(package); });
}
KModErr clear_su_auth_list(const char* key) {
    return legacy_call(key, [] { return maplesu::sdk::clear_su_auth_list(); });
}
namespace features::web_ui {
KModErr start_module_web_ui_server_async(const char* key, const char* id32, int& port) {
    return legacy_call(key, [&] { return maplesu::sdk::features::web_ui::start_module_web_ui_server_async(id32, port); });
}
}
}

namespace maplesu {
int64_t module_control_capability(const char* key, bool& supported) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return to_num(scope.error());
    const auto result = module_control_capability(supported);
    const auto restored = scope.restore();
    return result ? result : to_num(restored);
}
int64_t get_module_control(const char* key, const char* id32, ModuleControlState& out) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return to_num(scope.error());
    const auto result = get_module_control(id32, out);
    const auto restored = scope.restore();
    return result ? result : to_num(restored);
}
int64_t set_module_enabled(const char* key, const char* id32, bool enabled, ModuleControlState& out) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return to_num(scope.error());
    const auto result = set_module_enabled(id32, enabled, out);
    const auto restored = scope.restore();
    return result ? result : to_num(restored);
}
std::vector<ModuleControlResult> get_module_controls(const char* key,
        const std::vector<skroot_env::module_record>& records) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) {
        std::vector<ModuleControlResult> failed(records.size());
        for (auto& item : failed) item.error = to_num(scope.error());
        return failed;
    }
    std::vector<sdk::module_record> converted(records.size());
    for (size_t i = 0; i < records.size(); ++i) compat::copy_module_record(converted[i], records[i]);
    auto result = get_module_controls(converted);
    const auto restored = scope.restore();
    if (is_failed(restored)) for (auto& item : result) if (!item.error) item.error = to_num(restored);
    return result;
}
}

namespace kernel_root {
ParasiteError parasite_precheck_app_with_cb(const char* key, const char* target,
        void (*callback)(const char*, AppDynlibStatus)) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return to_num(scope.error());
    const auto result = parasite_precheck_app_with_cb(target, callback);
    const auto restored = scope.restore();
    return result ? result : to_num(restored);
}
ParasiteError parasite_implant_app(const char* key, const char* target, const char* original) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return to_num(scope.error());
    const auto result = parasite_implant_app(target, original);
    const auto restored = scope.restore();
    return result ? result : to_num(restored);
}
ParasiteError parasite_implant_su_env(const char* key, const char* target, const char* original, const char* directory) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return to_num(scope.error());
    const auto result = parasite_implant_su_env(target, original, directory);
    const auto restored = scope.restore();
    return result ? result : to_num(restored);
}
}
