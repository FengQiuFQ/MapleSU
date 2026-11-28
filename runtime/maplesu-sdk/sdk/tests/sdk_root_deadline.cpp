// Shared credential/session seams are followed by the complete selected m060 TU.
// EXACT_ROOT_FIXTURE_PREFIX

#include "maplesu_deadline_private.h"
#include <csignal>
#include <time.h>
namespace {
unsigned checks, failures;
int64_t monotonic_now() {
    timespec value{};
    clock_gettime(CLOCK_MONOTONIC, &value);
    return int64_t(value.tv_sec) * 1000000000 + value.tv_nsec;
}
void check(bool result, const char* label, int64_t elapsed = 0, int error = 0) {
    ++checks;
    if (!result) ++failures;
    std::printf("%s %s elapsed_us=%lld errno=%d\n", result ? "PASS" : "FAIL", label,
        static_cast<long long>(elapsed / 1000), error);
}
void prepare() {
    if (seteuid(0)) _exit(82);
    std::memset(fixture::shared, 0, sizeof(*fixture::shared));
    fixture::root_case = fixture::Root::Success;
    fixture::managed = true;
    fixture::auth_state = 1;
    fixture::root_report = {};
    fixture::current_reply = {};
    maplesu_request_set_operation_deadline_nanos(0);
    if (seteuid(10498)) _exit(83);
}
void complete_command() {
    prepare();
    maplesu_request_set_operation_deadline_nanos(monotonic_now() + 500000000);
    std::string output = "unchanged";
    const auto error = maplesu::sdk::run_root_cmd("printf complete", output);
    const auto result = maplesu::sdk::current_root_command_result();
    maplesu_request_set_operation_deadline_nanos(0);
    check(error == KModErr::OK && output == "complete" && result.receipt_complete &&
        result.root_report_received && result.root_transition.credentials_committed &&
        result.shell_close_attempted && result.shell_status == 0 && result.owner_close.completed &&
        result.child_status_valid, "real m060 bounded success keeps Root/shell/CLOSE receipts");
}
void stalled_command() {
    prepare();
    maplesu_request_set_operation_deadline_nanos(monotonic_now() + 25000000);
    std::string output = "unchanged";
    const auto start = monotonic_now();
    errno = 0;
    const auto error = maplesu::sdk::run_root_cmd("sleep 0.16; printf late", output);
    const auto elapsed = monotonic_now() - start;
    const int system_error = errno;
    const auto result = maplesu::sdk::current_root_command_result();
    maplesu_request_set_operation_deadline_nanos(0);
    check(is_failed(error) && result.system_error == ETIMEDOUT && elapsed < 100000000 &&
        output == "unchanged" && !result.receipt_complete && !result.root_report_received,
        "real m060 stalled command remains unconfirmed within shared budget", elapsed, system_error);
}
void completed_receipt_stalled_exit() {
    using namespace maplesu::sdk;
    prepare();
    maplesu_request_set_operation_deadline_nanos(monotonic_now() + 25000000);
    fork_pipe_info info;
    if (fork_pipe_child_process(info)) {
        RootCommandResult result;
        result.phase = RootCommandPhase::Complete;
        result.root_attempted = result.root_returned = result.root_report_received = true;
        result.root_process = getpid();
        result.root_transition.phase = "complete";
        result.root_transition.owner_mode = result.root_transition.credentials_managed = true;
        result.root_transition.credentials_attempted = result.root_transition.credentials_committed = true;
        result.root_transition.credentials = {0, MAPLESU_EFFECT_COMMITTED, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
        result.root_transition.task_state_attempted = result.root_transition.environment_completed = true;
        result.root_transition.task_state = {0, MAPLESU_EFFECT_TASK_STATE_COMPLETED, 0, 0, MAPLESU_REQUEST_TASK_STATE, true};
        result.shell_close_attempted = result.owner_close_attempted = true;
        result.shell_status = 0;
        result.owner_close = {0, MAPLESU_EFFECT_SESSION_CLOSED, 0, 0, MAPLESU_REQUEST_SESSION_CLOSE, true};
        const std::string output = "committed";
        if (!send_command_result(info, result, &output)) _exit(84);
        timespec delay{0, 160000000};
        while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        _exit(0);
    }
    RootCommandResult result;
    std::string output;
    const auto start = monotonic_now();
    receive_command_result(info, result, &output, 0);
    const auto elapsed = monotonic_now() - start;
    maplesu_request_set_operation_deadline_nanos(0);
    check(is_failed(result.error) && result.transport_phase == RootCommandPhase::Wait &&
        result.transport_error == ETIMEDOUT && result.receipt_complete &&
        result.root_report_received && result.root_transition.credentials_committed &&
        result.root_transition.credentials.completed &&
        (result.root_transition.credentials.effects & MAPLESU_EFFECT_COMMITTED) &&
        result.owner_close.completed && output == "committed" && elapsed < 100000000,
        "real m060 wait timeout retains received committed facts and output", elapsed, result.transport_error);
    if (!result.child_status_valid) {
        kill(info.child_pid, SIGKILL);
        int status;
        while (waitpid(info.child_pid, &status, 0) < 0 && errno == EINTR) {}
    }
}
#ifndef MAPLESU_DEADLINE_BASELINE
void explicit_shell_wait() {
    prepare();
    maplesu_request_set_operation_deadline_nanos(monotonic_now() + 25000000);
    int output = -1;
    pid_t child = -1;
    const auto start = monotonic_now();
    const bool started = maplesu::sdk::open_deadline_shell("sleep 0.16", output, child);
    int error = 0;
    const int status = started ? maplesu::sdk::close_deadline_shell(output, child, error) : -1;
    const auto elapsed = monotonic_now() - start;
    maplesu_request_set_operation_deadline_nanos(0);
    check(started && output == -1 && child > 0 && error == ETIMEDOUT &&
        (status == -1 || WIFSIGNALED(status)) && elapsed < 100000000,
        "real m060 shell cleanup keeps PID and shares original deadline", elapsed, error);
    if (status == -1 && child > 0) {
        int reaped;
        while (waitpid(child, &reaped, 0) < 0 && errno == EINTR) {}
    }
}
#endif
}
int main() {
    signal(SIGPIPE, SIG_IGN);
    fixture::shared = static_cast<fixture::Shared*>(mmap(nullptr, sizeof(fixture::Shared),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (fixture::shared == MAP_FAILED || geteuid() != 0) return 80;
    complete_command();
    stalled_command();
    completed_receipt_stalled_exit();
#ifndef MAPLESU_DEADLINE_BASELINE
    explicit_shell_wait();
#endif
    if (seteuid(0)) return 81;
    munmap(fixture::shared, sizeof(fixture::Shared));
    std::printf("sdk Root deadline checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
