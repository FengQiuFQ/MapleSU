#pragma once

#include <cstddef>

namespace maplesu::compat::legacy_install {
// No-key aliases stay distinct from the keyed 5.2.0 thin exports in this member.
static_assert(sizeof(sdk::InstallMode) == 4 && alignof(sdk::InstallMode) == 4);
static_assert(static_cast<unsigned>(sdk::InstallMode::Boot) == 0 &&
              static_cast<unsigned>(sdk::InstallMode::HotLoad) == 1);
static_assert(sizeof(sdk::InstallConfig) == 4 && alignof(sdk::InstallConfig) == 4);
static_assert(offsetof(sdk::InstallConfig, exploit) == 0);
static_assert(sizeof(sdk::MapleSUSdkVersion) == 12 && alignof(sdk::MapleSUSdkVersion) == 4);
static_assert(offsetof(sdk::MapleSUSdkVersion, major) == 0 &&
              offsetof(sdk::MapleSUSdkVersion, minor) == 4 &&
              offsetof(sdk::MapleSUSdkVersion, patch) == 8);
extern decltype(sdk::install_maplesu_environment) install_environment
    asm("_ZN10skroot_env26install_skroot_environmentENS_11InstallModeERKNS_13InstallConfigE")
    __attribute__((alias("_ZN7maplesu3sdk27install_maplesu_environmentENS0_11InstallModeERKNS0_13InstallConfigE")));
extern decltype(sdk::uninstall_maplesu_environment) uninstall_environment
    asm("_ZN10skroot_env28uninstall_skroot_environmentEv")
    __attribute__((alias("_ZN7maplesu3sdk29uninstall_maplesu_environmentEv")));
extern decltype(sdk::get_installed_maplesu_environment_version) installed_version
    asm("_ZN10skroot_env40get_installed_skroot_environment_versionERNS_16SkrootSdkVersionE")
    __attribute__((alias("_ZN7maplesu3sdk41get_installed_maplesu_environment_versionERNS0_17MapleSUSdkVersionE")));
}
