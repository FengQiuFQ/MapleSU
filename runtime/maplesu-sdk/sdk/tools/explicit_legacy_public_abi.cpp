#include "kernel_module_kit_umbrella.h"
#include "skroot_env/skroot_installer.h"
#include "skroot_env/skroot_module.h"
#include "skroot_env/skroot_root.h"
#include "skroot_env/skroot_su_auth.h"
#include "skroot_env/skroot_log.h"
#include "skroot_env/skroot_test.h"
#include "skroot_env/features/skroot_module_webui_loader.h"
#include "maplesu_module_control.h"
#include "maplesu_parasite.h"

// Link-only consumer. No entry in this file is executed on a host or device.
extern "C" void sdk_520_consumer(const char* key) {
    std::string text;
    skroot_env::get_root(key);
    skroot_env::run_root_cmd(key, "id", text);
    skroot_env::install_skroot_environment(key, skroot_env::InstallMode::HotLoad, {});
    skroot_env::uninstall_skroot_environment(key);
    skroot_env::get_skroot_environment_state(key);
    skroot_env::SkrootSdkVersion version;
    skroot_env::get_installed_skroot_environment_version(key, version);
    skroot_env::restart_zygote64(key);
    skroot_env::get_root_status_report(key);
    skroot_env::set_boot_fail_protect_enabled(key, true);
    skroot_env::is_boot_fail_protect_enabled(key);
    skroot_env::set_adb_forced_disabled(key, true);
    skroot_env::is_adb_forced_disabled(key);
    skroot_env::test_skroot_basics(key, skroot_env::BasicItem::Channel, text);
    skroot_env::test_skroot_deafult_module(key, skroot_env::DeafultModuleName::RootBridgePrint, text);
    skroot_env::module_desc desc;
    skroot_env::parse_module_desc_from_zip_file(key, "/fixture.zip", desc);
    std::vector<skroot_env::module_record> modules;
    skroot_env::get_all_modules_list(key, modules);
    skroot_env::install_module(key, "/fixture.zip", text);
    skroot_env::install_module_dev_run_once(key, "/fixture.zip", text);
    skroot_env::uninstall_module(key, "01234567890123456789012345678901");
    skroot_env::clear_skroot_log(key);
    skroot_env::read_skroot_log(key, text);
    skroot_env::is_skroot_log_enabled(key);
    skroot_env::set_skroot_log_enabled(key, true);
    std::vector<skroot_env::su_auth_item> packages;
    skroot_env::get_su_auth_list(key, packages);
    skroot_env::add_su_auth_list(key, "fixture.pkg");
    skroot_env::remove_su_auth_list(key, "fixture.pkg");
    skroot_env::clear_su_auth_list(key);
    int port = 0;
    skroot_env::features::web_ui::start_module_web_ui_server_async(key, "01234567890123456789012345678901", port);
    bool supported = false;
    maplesu::ModuleControlState control;
    maplesu::module_control_capability(key, supported);
    maplesu::get_module_control(key, "01234567890123456789012345678901", control);
    maplesu::set_module_enabled(key, "01234567890123456789012345678901", true, control);
    (void)maplesu::get_module_controls(key, modules);
    kernel_root::parasite_precheck_app_with_cb(key, "fixture.pkg", [](const char*, kernel_root::AppDynlibStatus) {});
    kernel_root::parasite_implant_app(key, "fixture.pkg", "/fixture.so");
    kernel_root::parasite_implant_su_env(key, "fixture.pkg", "/fixture.so", "/fixture");
}
