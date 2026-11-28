#pragma once
#include <cstdint>
#include <vector>

namespace maplesu::sdk { struct module_record; }
namespace skroot_env { struct module_record; }

namespace maplesu {
// Extension ABI: legacy packed module_record and all legacy entrypoints stay intact.
struct ModuleControlState {
    uint32_t abiVersion = 1;
    uint32_t enabled = 1;
    uint32_t runtimeState = 0;
    uint32_t needsReboot = 0;
    uint32_t toggleSupported = 0;
};
constexpr int64_t MODULE_CONTROL_UNSUPPORTED = -20150;
constexpr int64_t MODULE_CONTROL_INVALID_ID = -20151;
constexpr int64_t MODULE_CONTROL_NOT_FOUND = -20152;
constexpr int64_t MODULE_CONTROL_IO = -20153;
constexpr int64_t MODULE_CONTROL_BUSY = -20154;
constexpr int64_t MODULE_CONTROL_ENVIRONMENT = -20155;
struct ModuleControlResult {
    int64_t error = MODULE_CONTROL_IO;
    ModuleControlState state;
};
// The installed helper must implement the gate, including in a later boot.
int64_t module_control_capability(bool& supported);
int64_t get_module_control(const char* id32, ModuleControlState& out);
// One authenticated read worker for the list; errors remain attached to each input row.
std::vector<ModuleControlResult> get_module_controls(
    const std::vector<maplesu::sdk::module_record>& records);
// Changes desired boot state only; never invokes install/uninstall or module entry.
int64_t set_module_enabled(const char* id32, bool enabled, ModuleControlState& out);
// Explicit 5.2.0 compatibility overloads authenticate the supplied legacy key.
int64_t module_control_capability(const char* rootKey, bool& supported);
int64_t get_module_control(const char* rootKey, const char* id32, ModuleControlState& out);
std::vector<ModuleControlResult> get_module_controls(
    const char* rootKey, const std::vector<skroot_env::module_record>& records);
int64_t set_module_enabled(const char* rootKey, const char* id32, bool enabled, ModuleControlState& out);
}
