#pragma once
#include "maplesu_root_private.h"
#include <sys/types.h>

namespace maplesu::sdk {
enum class RootCommandPhase : int {
    None, Validate, Fork, WorkingDirectory, VendorMtk, VendorOplusGuard,
    VendorOplusInte, Root, Popen, Read, Pclose, Receipt, Output, Wait, Complete,
};

/* Local m060 diagnostics and the same call's complete Root transition snapshot.
 * root_process identifies the task's process that actually called m070; a
 * command child's Root facts do not describe this parent's credentials.
 * root_attempted records that call, root_returned only its normal return, and
 * root_report_received a complete snapshot. A validated original block keeps
 * its credential facts even if the appended task-state report is incomplete.
 * With root_report_received false, task_state fields are unknown, including
 * task_state_attempted=false; no false flag proves no attempt or rollback.
 * Missing credential reports leave commit state unknown and never permit replay.
 * Credential and task-state receipts remain separate even when later setup fails.
 * shell_status is the original pclose result (-1 included); child_status is a
 * separate waitpid status. Neither nonzero exit nor a signal invents errno.
 * vendor_child_status preserves the nested get_root prelude in run_root_cmd;
 * receipt_complete describes only this call's direct-child pipe transfer.
 * run_root_cmd publishes the fully received output frame after a shell started,
 * even on failure: Read errors may leave partial shell output; Pclose/CLOSE/Wait
 * errors do not erase captured bytes. Missing output frames leave the caller's output unchanged.
 * working_directory_error is best-effort diagnostics, never a Root gate.
 * A nullptr identity selects authenticated Manager Owner; an explicit empty or
 * malformed Key is an error, never an Owner request. Owner commands authenticate
 * and OPEN in their own fork child, run m070 without the Legacy vendor/name path,
 * and close that child's session after the shell. Direct get_root(nullptr)
 * retains this task's session for subsequent SDK operations and explicit close.
 * The Owner-only close tail never overwrites credential/task commit receipts;
 * a missing tail leaves cleanup unknown. No failed/unknown Root or shell replay.
 * There is no public cancellation handle. A private observation deadline bounds
 * pipe and child waits and can cancel its still-live worker/shell process group.
 * A pending reap or missing receipt remains unconfirmed; cancellation never
 * proves rollback. Deadline zero retains the original popen/pclose lifecycle.
 * Same thread/process only; a fork child sees an empty result until its call. */
struct RootCommandResult {
    KModErr error = KModErr::OK;
    RootCommandPhase phase = RootCommandPhase::None;
    int system_error = 0;
    int working_directory_error = 0;
    bool shell_close_attempted = false;
    int shell_status = -1;
    int shell_error = 0;
    RootCommandPhase transport_phase = RootCommandPhase::None;
    int transport_error = 0;
    int child_status = -1;
    bool child_status_valid = false;
    int vendor_child_status = -1;
    bool vendor_child_status_valid = false;
    bool receipt_complete = false;
    default_modules::module_root::RootTransitionResult root_transition{};
    pid_t root_process = 0;
    bool root_attempted = false;
    bool root_returned = false;
    bool root_report_received = false;
    bool owner_close_attempted = false;
    KModErr owner_close_error = KModErr::OK;
    kernel_module::RequestManagementReply owner_close{};
};
RootCommandResult current_root_command_result();
}
