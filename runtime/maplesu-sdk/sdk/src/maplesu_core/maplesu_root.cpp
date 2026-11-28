// MapleSU root implementation.
//
#include <maplesu_root_private.h>
#include "maplesu_root_command_private.h"
#include "maplesu_operation_wait_private.h"
#include "maplesu_operation_fork_private.h"
#include "../maplesu/compat/fork_legacy_abi.h"
#include "../maplesu/compat/root_legacy_abi.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

namespace default_modules::module_root { KModErr set_current_root(bool); }

namespace maplesu::sdk {

namespace {
thread_local RootCommandResult last_command;
thread_local pid_t last_command_process = 0;

RootCommandResult begin_command() {
    last_command = RootCommandResult{};
    last_command.phase = RootCommandPhase::Validate;
    last_command_process = getpid();
    return last_command;
}

KModErr finish_command(const RootCommandResult& result, int original_errno) {
    last_command = result;
    last_command_process = getpid();
    errno = is_failed(result.error) ? result.system_error : original_errno;
    return result.error;
}

void command_failure(RootCommandResult& result, KModErr error,
                     RootCommandPhase phase, int system_error = 0) {
    if (is_failed(result.error)) return;
    result.error = error;
    result.phase = phase;
    result.system_error = system_error;
}

void transport_failure(RootCommandResult& result, KModErr error,
                       RootCommandPhase phase, int system_error) {
    if (result.transport_phase == RootCommandPhase::None) {
        result.transport_phase = phase;
        result.transport_error = system_error;
    }
    command_failure(result, error, phase, system_error);
}

int pipe_terminal_error() {
    // m046 retries both errors internally; either may remain when EOF follows.
    const int error = errno;
    return error == EINTR || error == EAGAIN ? 0 : error;
}

bool open_deadline_shell(const char* command, int& output, pid_t& child) {
    if (!maplesu::deadline::available()) return false;
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC) != 0) return false;
    maplesu::deadline::ForkAdmission admission;
    if (fcntl(descriptors[0], F_SETFL, O_NONBLOCK) != 0 || !admission.prepare()) {
        const int error = errno;
        close(descriptors[0]); close(descriptors[1]);
        errno = error;
        return false;
    }
    child = fork();
    const int fork_error = errno;
    admission.complete();
    errno = fork_error;
    if (child < 0) {
        const int error = errno;
        close(descriptors[0]); close(descriptors[1]);
        errno = error;
        return false;
    }
    if (!child) {
        close(descriptors[0]);
        if (setpgid(0, 0) != 0 || dup2(descriptors[1], STDOUT_FILENO) < 0) _exit(127);
        if (descriptors[1] != STDOUT_FILENO) close(descriptors[1]);
        else if (fcntl(STDOUT_FILENO, F_SETFD, 0) != 0) _exit(127);
#ifdef __ANDROID__
        constexpr const char* shell = "/system/bin/sh";
#else
        constexpr const char* shell = "/bin/sh";
#endif
        execl(shell, "sh", "-c", command, static_cast<char*>(nullptr));
        _exit(127);
    }
    close(descriptors[1]);
    output = descriptors[0];
    return true;
}

pid_t wait_command_child(pid_t child, int* status, int& error) {
    const pid_t waited = maplesu::deadline::wait_child(child, status);
    error = waited < 0 ? errno : 0;
    if (waited >= 0 || !maplesu_request_operation_deadline_nanos()) return waited;
    if (error == ETIMEDOUT) {
        // Cancellation stops this same worker; it never proves rollback of
        // Root or shell work that has already been submitted.
        (void)kill(child, SIGKILL);
        if (waitpid(child, status, WNOHANG) == child) { errno = error; return child; }
    }
    errno = error;
    return -1;
}

int close_deadline_shell(int& output, pid_t child, int& error) {
    const int closed = close(output);
    output = -1;
    const int close_error = closed < 0 ? errno : 0;
    int status = -1;
    const pid_t waited = maplesu::deadline::wait_child(child, &status);
    error = waited < 0 ? errno : close_error;
    if (waited == child) return status;
    if (error == ETIMEDOUT) {
        // The shell owns a process group so its already-started descendants
        // are cancelled together. A missing reap remains an unknown status;
        // the worker's real exit transfers orphan reaping to init.
        if (kill(-child, SIGKILL) != 0) (void)kill(child, SIGKILL);
        if (waitpid(child, &status, WNOHANG) == child) return status;
    }
    return -1;
}

void snapshot_root_result(RootCommandResult& result) {
    result.root_transition = default_modules::module_root::current_root_transition();
    result.root_report_received = result.root_transition.phase != nullptr;
}

KModErr select_root_identity() {
    const auto state = kernel_module::maplesu_request_auth_state();
    if (!kernel_module::maplesu_request_auth_usable(state)) return KModErr::ERR_MODULE_ROOT_KEY;
    if (kernel_module::maplesu_request_auth_helper(state) ||
        kernel_module::maplesu_request_auth_manager(state) ||
        kernel_module::maplesu_request_auth_legacy(state)) return KModErr::OK;
    return kernel_module::maplesu_request_set_auth_mode(kernel_module::RequestAuthMode::ManagerOwner);
}

void transition_root(RootCommandResult& result) {
    result.phase = RootCommandPhase::Root;
    result.root_attempted = true;
    result.root_process = getpid();
    errno = 0;
    try {
        // The explicit legacy selection retains its existing Root environment.
        const bool legacy = kernel_module::maplesu_request_auth_legacy(
            kernel_module::maplesu_request_auth_state());
        const KModErr error = default_modules::module_root::set_current_root(legacy);
        const int system_error = errno;
        result.root_returned = true;
        snapshot_root_result(result);
        result.error = error;
        if (is_failed(error)) result.system_error = system_error;
        else result.phase = RootCommandPhase::Complete;
    } catch (const std::bad_alloc&) {
        snapshot_root_result(result);
        command_failure(result, KModErr::ERR_NO_MEM, result.phase);
    } catch (const std::length_error&) {
        snapshot_root_result(result);
        command_failure(result, KModErr::ERR_NO_MEM, result.phase);
    }
}

void close_command_owner(RootCommandResult& result) {
    result.owner_close_attempted = true;
    kernel_module::CleanupReceiptScope preserve_root_receipt;
    errno = 0;
    try {
        result.owner_close_error = kernel_module::maplesu_request_owner_close();
        result.owner_close = kernel_module::maplesu_request_management_reply();
        if (is_failed(result.owner_close_error))
            command_failure(result, result.owner_close_error, RootCommandPhase::Receipt, errno);
    } catch (const std::bad_alloc&) {
        result.owner_close_error = KModErr::ERR_NO_MEM;
        command_failure(result, result.owner_close_error, RootCommandPhase::Receipt);
    } catch (const std::length_error&) {
        result.owner_close_error = KModErr::ERR_NO_MEM;
        command_failure(result, result.owner_close_error, RootCommandPhase::Receipt);
    }
}

bool send_owner_close(const fork_pipe_info& pipe, const RootCommandResult& result) {
    const auto& reply = result.owner_close;
    return write_int_from_child(pipe, result.owner_close_attempted ? 1 : 0) &&
        write_errcode_from_child(pipe, result.owner_close_error) &&
        write_int_from_child(pipe, reply.status) && write_uint64_from_child(pipe, reply.effects) &&
        write_uint64_from_child(pipe, reply.result) && write_uint64_from_child(pipe, reply.handle) &&
        write_uint64_from_child(pipe, reply.command) && write_int_from_child(pipe, reply.completed ? 1 : 0);
}

bool receive_owner_close(const fork_pipe_info& pipe, RootCommandResult& result) {
    kernel_module::RequestManagementReply reply{};
    KModErr error = KModErr::OK;
    int attempted = 0, completed = 0;
    uint64_t effects = 0, command = 0;
    errno = 0;
    if (!(read_int_from_child(pipe, attempted) && read_errcode_from_child(pipe, error) &&
        read_int_from_child(pipe, reply.status) && read_uint64_from_child(pipe, effects) &&
        read_uint64_from_child(pipe, reply.result) && read_uint64_from_child(pipe, reply.handle) &&
        read_uint64_from_child(pipe, command) && read_int_from_child(pipe, completed))) {
        transport_failure(result, KModErr::ERR_READ_CHILD_DATA, RootCommandPhase::Receipt, pipe_terminal_error());
        return false;
    }
    const uint32_t allowed = MAPLESU_EFFECT_SESSION_CLOSED | MAPLESU_EFFECT_RELEASED |
        MAPLESU_EFFECT_QUARANTINED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED;
    if (attempted != 1 || (completed != 0 && completed != 1) ||
        static_cast<ssize_t>(error) > 0 || reply.status > 0 || reply.status < -4095 ||
        effects > UINT32_MAX || (effects & ~allowed) || reply.result || reply.handle ||
        (completed ? (!attempted || command != MAPLESU_REQUEST_SESSION_CLOSE) :
            (command || reply.status || effects)) ||
        (completed && !reply.status && !(effects & MAPLESU_EFFECT_SESSION_CLOSED)) ||
        (reply.status < 0 && !is_failed(error)) ||
        (is_ok(result.error) && (is_failed(error) || !completed || reply.status ||
            !(effects & MAPLESU_EFFECT_SESSION_CLOSED) || (effects & MAPLESU_EFFECT_QUARANTINED)))) {
        transport_failure(result, KModErr::ERR_READ_CHILD_DATA, RootCommandPhase::Receipt, 0);
        return false;
    }
    reply.effects = static_cast<uint32_t>(effects);
    reply.command = static_cast<uint32_t>(command);
    reply.completed = completed != 0;
    result.owner_close_attempted = attempted != 0;
    result.owner_close_error = error;
    result.owner_close = reply;
    return true;
}

bool send_root_result(const fork_pipe_info& pipe, const RootCommandResult& result) {
    const auto& root = result.root_transition;
    const auto& reply = root.credentials;
    const auto& task_state = root.task_state;
    return write_int_from_child(pipe, result.root_attempted ? 1 : 0) &&
        write_int_from_child(pipe, result.root_returned ? 1 : 0) &&
        write_int_from_child(pipe, result.root_report_received ? 1 : 0) &&
        write_int_from_child(pipe, static_cast<int>(result.root_process)) &&
        write_errcode_from_child(pipe, root.credentials_error) &&
        write_errcode_from_child(pipe, root.error) &&
        write_int_from_child(pipe, reply.status) &&
        write_uint64_from_child(pipe, reply.effects) &&
        write_uint64_from_child(pipe, reply.result) &&
        write_uint64_from_child(pipe, reply.handle) &&
        write_uint64_from_child(pipe, reply.command) &&
        write_int_from_child(pipe, reply.completed ? 1 : 0) &&
        write_int_from_child(pipe, static_cast<int>(
            default_modules::module_root::root_transition_phase_code(root.phase))) &&
        write_int_from_child(pipe, root.system_error) &&
        write_int_from_child(pipe, root.threads_total) &&
        write_int_from_child(pipe, root.cpuset_moved) &&
        write_int_from_child(pipe, root.stune_moved) &&
        write_int_from_child(pipe, root.cgroup_error) &&
        write_int_from_child(pipe, root.owner_mode ? 1 : 0) &&
        write_int_from_child(pipe, root.credentials_managed ? 1 : 0) &&
        write_int_from_child(pipe, root.credentials_attempted ? 1 : 0) &&
        write_int_from_child(pipe, root.credentials_committed ? 1 : 0) &&
        write_int_from_child(pipe, root.environment_completed ? 1 : 0) &&
        write_errcode_from_child(pipe, root.task_state_error) &&
        write_int_from_child(pipe, task_state.status) &&
        write_uint64_from_child(pipe, task_state.effects) &&
        write_uint64_from_child(pipe, task_state.result) &&
        write_uint64_from_child(pipe, task_state.handle) &&
        write_uint64_from_child(pipe, task_state.command) &&
        write_int_from_child(pipe, task_state.completed ? 1 : 0) &&
        write_int_from_child(pipe, root.task_state_attempted ? 1 : 0);
}

bool receive_root_result(const fork_pipe_info& pipe, RootCommandResult& result) {
    default_modules::module_root::RootTransitionResult root{};
    int attempted = 0, returned = 0, received = 0, process = 0;
    int completed = 0, phase = 0, owner = 0, managed = 0, credentials_attempted = 0,
        credentials_committed = 0, environment = 0;
    uint64_t effects = 0, command = 0, task_effects = 0, task_command = 0;
    int task_completed = 0, task_attempted = 0;
    const auto read_int = [&](int& value) {
        errno = 0;
        if (read_int_from_child(pipe, value)) return true;
        transport_failure(result, KModErr::ERR_READ_CHILD_INT, RootCommandPhase::Receipt, pipe_terminal_error());
        return false;
    };
    const auto read_u64 = [&](uint64_t& value) {
        errno = 0;
        if (read_uint64_from_child(pipe, value)) return true;
        transport_failure(result, KModErr::ERR_READ_CHILD_DATA, RootCommandPhase::Receipt, pipe_terminal_error());
        return false;
    };
    const auto read_error = [&](KModErr& value) {
        errno = 0;
        if (read_errcode_from_child(pipe, value) && static_cast<ssize_t>(value) <= 0) return true;
        transport_failure(result, KModErr::ERR_READ_CHILD_ERRCODE, RootCommandPhase::Receipt, pipe_terminal_error());
        return false;
    };
    if (!(read_int(attempted) && read_int(returned) && read_int(received) && read_int(process) &&
        read_error(root.credentials_error) && read_error(root.error) && read_int(root.credentials.status) &&
        read_u64(effects) && read_u64(root.credentials.result) && read_u64(root.credentials.handle) &&
        read_u64(command) && read_int(completed) && read_int(phase) && read_int(root.system_error) &&
        read_int(root.threads_total) && read_int(root.cpuset_moved) && read_int(root.stune_moved) &&
        read_int(root.cgroup_error) && read_int(owner) && read_int(managed) && read_int(credentials_attempted) &&
        read_int(credentials_committed) &&
        read_int(environment))) return false;
    const auto is_flag = [](int value) { return value == 0 || value == 1; };
    if (!is_flag(attempted) || !is_flag(returned) || !is_flag(received) || !is_flag(completed) ||
        !is_flag(owner) || !is_flag(managed) || !is_flag(credentials_attempted) ||
        !is_flag(credentials_committed) || !is_flag(environment) ||
        (returned && !attempted) || (received && !attempted) ||
        (credentials_attempted && !attempted) ||
        ((attempted || received) ? process != pipe.child_pid : process != 0) ||
        effects > UINT32_MAX || command > UINT32_MAX || phase < 0 || phase > 14) {
        transport_failure(result, KModErr::ERR_READ_CHILD_INT, RootCommandPhase::Receipt, 0);
        return false;
    }
    root.credentials.effects = static_cast<uint32_t>(effects);
    root.credentials.command = static_cast<uint32_t>(command);
    root.credentials.completed = completed != 0;
    root.phase = default_modules::module_root::root_transition_phase_name(static_cast<uint32_t>(phase));
    root.owner_mode = owner != 0;
    root.credentials_managed = managed != 0;
    root.credentials_attempted = credentials_attempted != 0;
    root.credentials_committed = credentials_committed != 0;
    const uint32_t credential_effects = MAPLESU_EFFECT_COMMITTED |
        MAPLESU_EFFECT_SESSION_CLOSED | MAPLESU_EFFECT_QUARANTINED;
    if (root.credentials.status > 0 || root.credentials.status < -4095 ||
        (root.credentials.completed ?
            (!credentials_attempted || !(owner || managed) || command != MAPLESU_REQUEST_CRED_ROOT ||
                (effects & ~credential_effects) || root.credentials.result || root.credentials.handle ||
                (!root.credentials.status && effects != MAPLESU_EFFECT_COMMITTED)) :
            (command || root.credentials.status || effects || root.credentials.result || root.credentials.handle)) ||
        root.credentials_committed != (root.credentials.completed &&
        root.credentials.command == MAPLESU_REQUEST_CRED_ROOT &&
        (root.credentials.effects & MAPLESU_EFFECT_COMMITTED))) {
        transport_failure(result, KModErr::ERR_READ_CHILD_INT, RootCommandPhase::Receipt, 0);
        return false;
    }
    root.environment_completed = environment != 0;
    // Preserve the validated original block before reading the appended tail.
    // A missing task report never erases known credential commit/effect facts.
    result.root_transition = root;
    result.root_process = process;
    result.root_attempted = attempted != 0;
    result.root_returned = returned != 0;
    result.root_report_received = false;
    if (!(read_error(root.task_state_error) && read_int(root.task_state.status) &&
        read_u64(task_effects) && read_u64(root.task_state.result) && read_u64(root.task_state.handle) &&
        read_u64(task_command) && read_int(task_completed) && read_int(task_attempted))) return false;
    if (!is_flag(task_completed) || !is_flag(task_attempted) || root.task_state.status > 0 ||
        root.task_state.status < -4095 ||
        task_effects > UINT32_MAX || task_command > UINT32_MAX ||
        (task_attempted && (!(owner || managed) || !credentials_attempted)) ||
        (task_completed && (!task_attempted || task_command != MAPLESU_REQUEST_TASK_STATE))) {
        transport_failure(result, KModErr::ERR_READ_CHILD_INT, RootCommandPhase::Receipt, 0);
        return false;
    }
    root.task_state.effects = static_cast<uint32_t>(task_effects);
    root.task_state.command = static_cast<uint32_t>(task_command);
    root.task_state.completed = task_completed != 0;
    root.task_state_attempted = task_attempted != 0;
    result.root_transition = root;
    result.root_report_received = received != 0;
    return true;
}

// Fixed same-image facts on the existing pipe, not a new public/kernel wire.
bool send_command_result(const fork_pipe_info& pipe, const RootCommandResult& result,
                         const std::string* output = nullptr) {
    if (!(write_errcode_from_child(pipe, result.error) &&
        write_int_from_child(pipe, static_cast<int>(result.phase)) &&
        write_int_from_child(pipe, result.system_error) &&
        write_int_from_child(pipe, result.working_directory_error) &&
        write_int_from_child(pipe, result.shell_close_attempted ? 1 : 0) &&
        write_int_from_child(pipe, result.shell_status) &&
        write_int_from_child(pipe, result.shell_error) &&
        write_int_from_child(pipe, static_cast<int>(result.transport_phase)) &&
        write_int_from_child(pipe, result.transport_error) &&
        write_int_from_child(pipe, result.vendor_child_status_valid ? 1 : 0) &&
        write_int_from_child(pipe, result.vendor_child_status) &&
        send_root_result(pipe, result))) return false;
    // Only managed channels append the explicit session-cleanup receipt.
    if ((result.root_transition.owner_mode || result.root_transition.credentials_managed) &&
        !send_owner_close(pipe, result)) return false;
    if (!output) return true;
    // A shell/read/cleanup failure does not erase bytes already captured.
    return write_string_from_child(pipe, *output);
}

void receive_command_result(fork_pipe_info& pipe, RootCommandResult& result,
                            std::string* output, int fork_error) {
    if (pipe.child_pid <= 0) {
        transport_failure(result, KModErr::ERR_READ_CHILD_ERRCODE, RootCommandPhase::Fork, fork_error);
        pipe.close_all();
        return;
    }
    try {
        KModErr child_error = KModErr::OK;
        errno = 0;
        if (pipe.fd_child_to_parent_read < 0 || !read_errcode_from_child(pipe, child_error)) {
            transport_failure(result, KModErr::ERR_READ_CHILD_ERRCODE, RootCommandPhase::Receipt, pipe_terminal_error());
        } else if (static_cast<ssize_t>(child_error) > 0) {
            transport_failure(result, KModErr::ERR_READ_CHILD_ERRCODE, RootCommandPhase::Receipt, 0);
        } else {
            result.error = child_error;
            result.phase = RootCommandPhase::Receipt;
            const auto read_fact = [&](int& value) {
                int candidate = 0;
                errno = 0;
                if (!read_int_from_child(pipe, candidate)) {
                    transport_failure(result, KModErr::ERR_READ_CHILD_INT, RootCommandPhase::Receipt, pipe_terminal_error());
                    return false;
                }
                value = candidate;
                return true;
            };
            int phase = 0, close_attempted = 0, transport_phase = 0, vendor_valid = 0;
            if (read_fact(phase) && phase >= static_cast<int>(RootCommandPhase::None) &&
                phase <= static_cast<int>(RootCommandPhase::Complete)) {
                result.phase = static_cast<RootCommandPhase>(phase);
                if (read_fact(result.system_error) && read_fact(result.working_directory_error) &&
                    read_fact(close_attempted) &&
                    (close_attempted == 0 || close_attempted == 1) &&
                    read_fact(result.shell_status) && read_fact(result.shell_error) &&
                    read_fact(transport_phase) && transport_phase >= static_cast<int>(RootCommandPhase::None) &&
                    transport_phase <= static_cast<int>(RootCommandPhase::Complete) &&
                    read_fact(result.transport_error) && read_fact(vendor_valid) &&
                    (vendor_valid == 0 || vendor_valid == 1) && read_fact(result.vendor_child_status)) {
                    result.shell_close_attempted = close_attempted != 0;
                    result.transport_phase = static_cast<RootCommandPhase>(transport_phase);
                    result.vendor_child_status_valid = vendor_valid != 0;
                    // A failed tail keeps validated credential facts; task
                    // fields remain unknown until the complete report arrives.
                    if (receive_root_result(pipe, result) &&
                        (!(result.root_transition.owner_mode || result.root_transition.credentials_managed) ||
                            receive_owner_close(pipe, result))) {
                        errno = 0;
                        if (output && !read_string_from_child(pipe, *output))
                            transport_failure(result, KModErr::ERR_READ_CHILD_STRING, RootCommandPhase::Output, pipe_terminal_error());
                        else result.receipt_complete = true;
                    }
                }
            }
            if (!result.receipt_complete && result.transport_phase == RootCommandPhase::None)
                transport_failure(result, KModErr::ERR_READ_CHILD_INT, RootCommandPhase::Receipt, 0);
        }
    } catch (const std::bad_alloc&) {
        transport_failure(result, KModErr::ERR_NO_MEM, RootCommandPhase::Output, 0);
    } catch (const std::length_error&) {
        transport_failure(result, KModErr::ERR_NO_MEM, RootCommandPhase::Output, 0);
    }
    // A failed read must not leave a child blocked while this parent waits.
    pipe.close_all();
    int status = 0;
    int wait_error = 0;
    const pid_t waited = wait_command_child(pipe.child_pid, &status, wait_error);
    if (waited == pipe.child_pid) {
        result.child_status = status;
        result.child_status_valid = true;
    }
    if (wait_error || waited != pipe.child_pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        transport_failure(result, KModErr::ERR_READ_CHILD_ERRCODE, RootCommandPhase::Wait, wait_error);
}
}

RootCommandResult current_root_command_result() {
    return last_command_process == getpid() ? last_command : RootCommandResult{};
}

KModErr get_root() {
    const int original_errno = errno;
    RootCommandResult result = begin_command();
    result.error = select_root_identity();
    if (is_ok(result.error)) transition_root(result);
    return finish_command(result, original_errno);
}

KModErr run_root_cmd(const char* cmd, std::string& out_result) {
    const int original_errno = errno;
    RootCommandResult result = begin_command();
    if (cmd == nullptr) {
        result.error = KModErr::ERR_MODULE_PARAM;
        return finish_command(result, original_errno);
    }
    if (strlen(cmd) == 0) {
        result.error = KModErr::ERR_MODULE_PARAM;
        return finish_command(result, original_errno);
    }
    result.error = kernel_module::maplesu_request_worker_admission();
    if (is_failed(result.error)) {
        result.system_error = errno;
        return finish_command(result, original_errno);
    }
    std::string shell_cmd;
    std::string cmd_output;
    try {
        shell_cmd.assign(cmd);
        shell_cmd.append(" 2>&1");
    } catch (const std::bad_alloc&) {
        result.error = KModErr::ERR_NO_MEM;
        return finish_command(result, original_errno);
    } catch (const std::length_error&) {
        result.error = KModErr::ERR_NO_MEM;
        return finish_command(result, original_errno);
    }

    fork_pipe_info pipe;
    if (fork_pipe_child_process(pipe)) {
        FILE* shell = nullptr;
        int shell_output = -1;
        pid_t shell_child = -1;
        bool sent = false;
        try {
            result.phase = RootCommandPhase::Root;
            errno = 0;
            // No parent session/token crosses fork. The request layer drops
            // its copied local view, then this child authenticates and OPENs.
            const KModErr root_error = get_root();
            result = current_root_command_result();
            result.error = root_error;
            result.vendor_child_status = result.child_status;
            result.vendor_child_status_valid = result.child_status_valid;
            if (is_ok(root_error) && result.root_transition.credentials_managed) {
                maplesu_metadata_owner_v3 metadata{};
                uint64_t descriptor = 0;
                kernel_module::RequestOwnerBinding binding{};
                errno = 0;
                const auto checked = kernel_module::maplesu_request_owner_channel(metadata, descriptor, binding);
                if (is_failed(checked)) command_failure(result, checked, RootCommandPhase::Root, errno);
            }
            if (is_ok(result.error)) {
                result.phase = RootCommandPhase::Popen;
                errno = 0;
                const bool bounded = maplesu_request_operation_deadline_nanos() != 0;
                if (bounded) (void)open_deadline_shell(shell_cmd.c_str(), shell_output, shell_child);
                else shell = popen(shell_cmd.c_str(), "r");
                if (!shell && shell_output < 0)
                    command_failure(result, KModErr::ERR_MODULE_OPEN_FILE, result.phase, errno);
                else {
                    result.phase = RootCommandPhase::Read;
                    errno = 0;
                    const int fd = shell ? fileno(shell) : shell_output;
                    if (fd < 0) command_failure(result, KModErr::ERR_MODULE_READ_FILE, result.phase, errno);
                    else for (;;) {
                        if (!maplesu::deadline::available()) {
                            command_failure(result, KModErr::ERR_MODULE_READ_FILE, result.phase, errno);
                            break;
                        }
                        char bytes[1024];
                        const ssize_t count = read(fd, bytes, sizeof(bytes));
                        if (count < 0) {
                            if (errno == EINTR) continue;
                            if (bounded && errno == EAGAIN) {
                                if (maplesu::deadline::wait_fd(fd, POLLIN)) continue;
                            }
                            // popen supplies a blocking descriptor; EAGAIN is
                            // an actual read failure, not an unbounded spin.
                            command_failure(result, KModErr::ERR_MODULE_READ_FILE, result.phase, errno);
                            break;
                        }
                        if (!count) break;
                        cmd_output.append(bytes, static_cast<size_t>(count));
                    }
                }
            }
        } catch (const std::bad_alloc&) {
            command_failure(result, KModErr::ERR_NO_MEM, result.phase);
        } catch (const std::length_error&) {
            command_failure(result, KModErr::ERR_NO_MEM, result.phase);
        }
        if (shell) {
            // Close even after read/append failure. Closing its read end may
            // stop a writer via SIGPIPE; preserve that real shell status.
            result.shell_close_attempted = true;
            errno = 0;
            result.shell_status = pclose(shell);
            result.shell_error = result.shell_status < 0 ? errno : 0;
            if (result.shell_status < 0 || !WIFEXITED(result.shell_status) ||
                WEXITSTATUS(result.shell_status) != 0)
                command_failure(result, KModErr::ERR_READ_CHILD_ERRCODE, RootCommandPhase::Pclose, result.shell_error);
        } else if (shell_child > 0) {
            result.shell_close_attempted = true;
            result.shell_status = close_deadline_shell(shell_output, shell_child, result.shell_error);
            if (result.shell_error || result.shell_status < 0 || !WIFEXITED(result.shell_status) ||
                WEXITSTATUS(result.shell_status) != 0)
                command_failure(result, KModErr::ERR_READ_CHILD_ERRCODE, RootCommandPhase::Pclose, result.shell_error);
        }
        if (result.root_transition.credentials_managed) close_command_owner(result);
        if (is_ok(result.error)) result.phase = RootCommandPhase::Complete;
        try { sent = send_command_result(pipe, result, &cmd_output); } catch (...) {}
        pipe.close_all();
        _exit(sent ? 0 : 1);
    }
    const int fork_error = errno;
    receive_command_result(pipe, result, &cmd_output, fork_error);
    // Only a fully received output frame from a started shell replaces the
    // caller's output. Read failures retain partial bytes and their original
    // phase/error; pclose, CLOSE and wait failures retain captured output too.
    if (result.receipt_complete && result.shell_close_attempted)
        out_result.swap(cmd_output);
    return finish_command(result, original_errno);
}

}  // namespace maplesu::sdk

namespace skroot_env {

KModErr get_root() {
    return maplesu::sdk::get_root();
}

KModErr run_root_cmd(const char* cmd, std::string& out_result) {
    return maplesu::sdk::run_root_cmd(cmd, out_result);
}

}  // namespace skroot_env
