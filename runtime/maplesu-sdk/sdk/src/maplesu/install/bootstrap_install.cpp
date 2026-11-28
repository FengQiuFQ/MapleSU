#include "maplesu/compat/persisted_inputs.h"
#include "kernel_module_kit_umbrella.h"

#include "../../maplesu_assets/maplesu_payload_assets.h"
#include "bootstrap_install.h"
#include "installation_state.h"
#include "core.h"
#include "environment.h"
#include "platform.h"
#include "lifecycle.h"
#include "maplesu_sdk/maplesu_installer.h"

#include <string>

namespace maplesu::compat {
namespace {

using maplesu::sdk::autorun_bootstrap_file_data;
using maplesu::sdk::kAutorunBootstrapPayloadSize;
using maplesu::sdk::kPayloadsReal;

KModErr enable_install_root() {
    return default_modules::module_root::set_current_root(true);
}

auto sdk_version() { return install::sdk_version(); }

std::string sdk_version_path() {
    return install::environment::kernel_file_path(maplesu::compat::kEnvironmentVersionFile);
}

}  // namespace
}  // namespace maplesu::compat

namespace maplesu::install {
namespace {

using compat::autorun_bootstrap_file_data;
using compat::kAutorunBootstrapPayloadSize;
using compat::kPayloadsReal;


using core::err_t;

static_assert(sizeof(autorun_bootstrap_file_data) == kAutorunBootstrapPayloadSize || !kPayloadsReal,
              "autorun_bootstrap_file_data must be the payload size pinned in ASSETS.json");

std::string get_autorun_bootstrap_path() { return environment::kernel_file_path("init"); }

err_t publish_bootstrap(const std::string& path) {
    return static_cast<err_t>(maplesu_publish_executable(
        path.c_str(), autorun_bootstrap_file_data, sizeof(autorun_bootstrap_file_data), core::kSelinuxKernel));
}

KModErr bootstrap() {
    const KModErr set_root_err = compat::enable_install_root();
    if (set_root_err != KModErr::OK) return set_root_err;

    const std::string path = get_autorun_bootstrap_path();
    if (path.empty()) return static_cast<KModErr>(core::kErrModuleParam);

    const err_t publish_err = publish_bootstrap(path);
    if (publish_err != core::kOk) return static_cast<KModErr>(publish_err);

    return KModErr::OK;
}

KModErr prepare_bootstrap_state() {
    const std::string path = get_autorun_bootstrap_path();
    if (path.empty()) return static_cast<KModErr>(core::kErrModuleParam);
    const std::string state_files[] = {path + ".running.lock", path + ".boot_session.work",
                                      path + ".log", path + ".log.last", path + ".log.crash",
                                      path + ".boot_session.completed"};
    constexpr char initial_log[] = "[FATAL] autorun_bootstrap: NEVER EXECUTED";
    for (unsigned i = 0; i < 6; ++i) {
        if (i >= 2 && i <= 4) {
            const KModErr error = platform::preserve_or_initialize_log(
                state_files[i].c_str(), i == 2 ? initial_log : "");
            if (error != KModErr::OK) return error;
        } else if (!platform::create_empty_file(state_files[i].c_str())) {
            return static_cast<KModErr>(core::kErrCreateEmptyFile);
        }
    }
    for (unsigned i = 0; i < 6; ++i) {
        if (i >= 2 && i <= 4) continue;
        if (!platform::set_file_selinux_access_mode(state_files[i].c_str(), core::kSelinuxKernel))
            return KModErr::ERR_SET_FILE_SELINUX;
    }
    const KModErr duplicate_err = sdk::unsafe_reset_autorun_bootstrap_duplicate_boot_session_flag();
    if (duplicate_err != KModErr::OK) return duplicate_err;
    return sdk::unsafe_reset_autorun_bootstrap_safe_flag();
}

}  // namespace

KModErr prepare_environment_bootstrap() {
    return bootstrap();
}

KModErr refresh_environment_bootstrap() {
    return bootstrap();
}

KModErr prepare_environment_bootstrap_state() {
    return prepare_bootstrap_state();
}

KModErr commit_environment_version(state::Mutation& mutation) {
    const std::string path = compat::sdk_version_path();
    if (path.empty()) return static_cast<KModErr>(core::kErrModuleParam);
    const auto version = compat::sdk_version();
    const std::string text = std::to_string(version.major) + "." +
                             std::to_string(version.minor) + "." +
                             std::to_string(version.patch);
    const auto publication = publish_version_result(path.c_str(), text.data(), text.size(), core::kSelinuxKernel);
    state::Result observation{};
    if (mutation.ready()) {
        observation = mutation.observe_version(publication);
        state::diagnose("commit", observation);
    }
    const auto published = project_publish_result(publication);
    if (published != KModErr::OK) return published;
    return observation.code ? KModErr::ERR_MODULE_WRITE_FILE : KModErr::OK;
}

KModErr commit_environment_version() {
    state::Mutation mutation;
    auto result = mutation.open();
    state::diagnose("open-commit", result);
    if (state::mutation_open_failed(result)) return KModErr::ERR_MODULE_WRITE_FILE;
    if (mutation.ready()) {
        const bool required = mutation.revocation_required();
        result = mutation.revoke();
        state::diagnose("revoke-commit", result);
        if (required && result.code) return KModErr::ERR_MODULE_WRITE_FILE;
    }
    return commit_environment_version(mutation);
}

}  // namespace maplesu::install

namespace maplesu::sdk {

__attribute__((visibility("hidden"))) KModErr unsafe_install_autorun_bootstrap() {
    const auto root = maplesu::compat::enable_install_root();
    if (root != KModErr::OK) return root;
    maplesu::install::state::Mutation mutation;
    auto result = mutation.open();
    maplesu::install::state::diagnose("open-bootstrap", result);
    if (maplesu::install::state::mutation_open_failed(result)) return KModErr::ERR_MODULE_WRITE_FILE;
    if (mutation.ready()) {
        const bool required = mutation.revocation_required();
        result = mutation.revoke();
        maplesu::install::state::diagnose("revoke-bootstrap", result);
        if (required && result.code) return KModErr::ERR_MODULE_WRITE_FILE;
    }
    const KModErr err = maplesu::install::prepare_environment_bootstrap();
    if (err != KModErr::OK) return err;
    const KModErr committed = maplesu::install::commit_environment_version(mutation);
    if (committed != KModErr::OK) return committed;
    return maplesu::install::prepare_environment_bootstrap_state();
}

}  // namespace maplesu::sdk

#include "../compat/install_bootstrap_exports_legacy_abi.h"
