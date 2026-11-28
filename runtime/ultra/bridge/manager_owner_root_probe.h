#pragma once

#include <cstdint>

namespace maplesu {

struct ManagerOwnerRootCommand {
    bool attempted = false;
    bool reply_observed = false;
    int64_t error = 0;
    uint32_t command = 0;
    int32_t status = 0;
    uint64_t result = 0;
    uint64_t handle = 0;
    uint32_t effects = 0;
    bool completed = false;
};

struct ManagerOwnerRootCredentials {
    uint32_t ruid = UINT32_MAX, euid = UINT32_MAX, suid = UINT32_MAX;
    uint32_t rgid = UINT32_MAX, egid = UINT32_MAX, sgid = UINT32_MAX;
    uint64_t inheritable = 0, permitted = 0, effective = 0, bounding = 0, ambient = 0;
    uint64_t capability_mask = 0;
    int32_t cap_last_cap = -1;
    int32_t securebits = -1;
    int32_t uid_error = 0, gid_error = 0;
    int64_t caps_error = 0;
    int32_t cap_limit_error = 0, securebits_error = 0;
    bool uid_observed = false, gid_observed = false, caps_observed = false;
    bool ambient_present = false, cap_limit_observed = false, securebits_observed = false;
    bool matches_root = false;
};

struct ManagerOwnerRootProbe {
    uint32_t abi_version = 1;
    int64_t mode_error = 0, channel_error = 0;
    bool mode_selected = false, owner_bound = false;
    uint32_t owner_full_uid = 0, owner_epoch = 0;
    uint64_t host_low = 0, host_high = 0, owner_capabilities = 0;
    ManagerOwnerRootCommand root;
    ManagerOwnerRootCredentials credentials;
    ManagerOwnerRootCommand close;
    bool root_committed = false, root_verified = false;
    int32_t watchdog_error = 0;
    bool watchdog_armed = false;
    uint32_t child_pid = 0;
    bool cleanup_pending = false, cleanup_scheduled = false;
    int32_t cleanup_error = 0, probe_admission_error = 0;
    bool child_exception = false;
    int32_t child_io_error = 0;
    bool root_checkpoint_received = false, receipt_complete = false;
    int32_t transport_error = 0, wait_error = 0;
    int32_t child_status = 0;
    bool child_status_valid = false, timed_out = false, termination_requested = false;
    int32_t termination_error = 0;
    uint64_t elapsed_us = 0;
};

// Call inside the bridge's isolated local transport scope. Facts describe only
// this forked child; they do not grant the parent Root or establish environment Ready.
__attribute__((visibility("hidden")))
ManagerOwnerRootProbe probe_manager_owner_root();

// The caller's absolute CLOCK_MONOTONIC deadline can shorten the independent
// 300 ms probe budget. Zero preserves the original standalone budget.
__attribute__((visibility("hidden")))
ManagerOwnerRootProbe probe_manager_owner_root(int64_t session_deadline_nanos);

} // namespace maplesu
