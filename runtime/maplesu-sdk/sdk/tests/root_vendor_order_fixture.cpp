// Real keyless m060 entrypoints and m046 transport; credential/session/OEM boundaries are fixtures.
#include "maplesu_root_command_private.h"
#include "maplesu/compat/fork_legacy_abi.h"
#include "maplesu/compat/root_legacy_abi.h"
#include "maplesu_sdk/maplesu_root.h"
#include <type_traits>

static_assert(std::is_same_v<decltype(&maplesu::sdk::get_root), KModErr (*)()>);
static_assert(std::is_same_v<decltype(&maplesu::sdk::run_root_cmd), KModErr (*)(const char*, std::string&)>);
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" int __real_pipe2(int*, int);
extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return 0; }

namespace fixture {
struct Shared {
    int root_calls, vendor_calls[3], flag_ios, io_before_root, shells, closes, sequence, shell_reads;
    int root_sequence, vendor_sequence[3], shell_sequence, channels;
    uint64_t source_seen;
    pid_t channel_pid;
    pid_t root_pid, vendor_pid, shell_pid;
};
Shared* shared;
enum class Root { Success, Denied, PostCommitFailure };
Root root_case = Root::Success;
bool managed = true, fail_command_pipe = false;
bool fail_shell_read = false, fail_output_frame = false, fail_command_exit = false, fail_close = false, fail_channel = false;
uint64_t auth_state;
std::string directory;
thread_local default_modules::module_root::RootTransitionResult root_report;
kernel_module::RequestManagementReply current_reply{};
int pipe2(int* descriptors, int flags) {
    if (fail_command_pipe) { errno = EMFILE; return -1; }
    return __real_pipe2(descriptors, flags);
}
FILE* popen(const char* command, const char* mode) {
    ++shared->shells;
    shared->shell_pid = getpid();
    shared->shell_sequence = ++shared->sequence;
    return ::popen(command, mode);
}
ssize_t shell_read(int fd, void* output, size_t size) {
    if (fail_shell_read && shared->shell_reads++) { errno = EIO; return -1; }
    return ::read(fd, output, size);
}
bool output_frame(maplesu::sdk::fork_pipe_info& pipe, std::string& output) {
    if (fail_output_frame) { errno = EPIPE; return false; }
    return maplesu::sdk::read_string_from_child(pipe, output);
}
[[noreturn]] void command_exit(int status) { ::_exit(fail_command_exit && shared->shells ? 7 : status); }
KModErr vendor(int index) {
    ++shared->vendor_calls[index];
    shared->vendor_pid = getpid();
    shared->vendor_sequence[index] = ++shared->sequence;
    ++shared->flag_ios;
    if (geteuid() != 0 || !shared->root_calls) ++shared->io_before_root;
    // This models the already-observed 0711 directory, using actual host access checks.
    const std::string path = directory + "/workFlag";
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0777);
    if (fd < 0) return KModErr::ERR_MODULE_OPEN_FILE;
    if (write(fd, "1", 1) != 1) { const int error = errno; close(fd); errno = error; return KModErr::ERR_MODULE_WRITE_FILE; }
    close(fd);
    return KModErr::OK;
}
}

extern "C" int __wrap_pipe2(int* descriptors, int flags) { return fixture::pipe2(descriptors, flags); }

namespace kernel_module {
uint64_t maplesu_request_auth_state() { return fixture::auth_state; }
KModErr maplesu_request_worker_admission() { return KModErr::OK; } // Auth transport is this fixture's boundary.
KModErr maplesu_request_set_auth_mode(RequestAuthMode mode) { fixture::auth_state = static_cast<uint64_t>(mode); return KModErr::OK; }
KModErr maplesu_request_owner_channel(maplesu_metadata_owner_v3&, uint64_t&, RequestOwnerBinding&) {
    ++fixture::shared->channels; fixture::shared->channel_pid = getpid();
    errno = fixture::fail_channel ? ESTALE : 0;
    return fixture::fail_channel ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK;
}
CleanupReceiptScope::CleanupReceiptScope() noexcept : saved_errno_(errno), saved_process_(getpid()), saved_reply_(fixture::current_reply) {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {
    if (saved_process_ == static_cast<uint64_t>(getpid())) { fixture::current_reply = saved_reply_; errno = saved_errno_; }
}
KModErr maplesu_request_owner_close() {
    ++fixture::shared->closes;
    fixture::current_reply = {fixture::fail_close ? -EIO : 0, MAPLESU_EFFECT_SESSION_CLOSED,
        0, 0, MAPLESU_REQUEST_SESSION_CLOSE, true};
    errno = fixture::fail_close ? EIO : 0;
    return fixture::fail_close ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK;
}
RequestManagementReply maplesu_request_management_reply() { return fixture::current_reply; }
}

namespace default_modules {
struct module_bypass_mtk_mkp {
    static const char* get_module_eng_name() { return "fixture_mtk"; }
    static KModErr init() { return fixture::vendor(0); }
};
struct module_bypass_oplus_secure_guard {
    static const char* get_module_eng_name() { return "fixture_guard"; }
    static KModErr init() { return fixture::vendor(1); }
};
struct module_bypass_oplus_inte {
    static const char* get_module_eng_name() { return "fixture_inte"; }
    static KModErr init() { return fixture::vendor(2); }
};
namespace module_root {
RootTransitionResult current_root_transition() { return fixture::root_report; }
KModErr set_current_root(bool bypass_selinux) {
    if (bypass_selinux != kernel_module::maplesu_request_auth_legacy(fixture::auth_state)) _exit(92);
    ++fixture::shared->root_calls;
    fixture::shared->root_pid = getpid();
    fixture::shared->root_sequence = ++fixture::shared->sequence;
    auto& root = fixture::root_report;
    root = {};
    root.owner_mode = kernel_module::maplesu_request_owner_mode();
    root.credentials_managed = fixture::managed;
    fixture::shared->source_seen = fixture::auth_state;
    root.phase = "credentials";
    root.credentials_attempted = root.credentials_managed;
    if (fixture::root_case == fixture::Root::Denied) {
        root.error = root.credentials_error = KModErr::ERR_MODULE_TEST_CHANNEL;
        root.system_error = EACCES;
        if (root.credentials_managed) root.credentials = {-EACCES, 0, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
        errno = EACCES;
        return root.error;
    }
    if (seteuid(0) != 0) _exit(90);
    if (root.credentials_managed) {
        root.credentials_committed = true;
        root.credentials = {0, MAPLESU_EFFECT_COMMITTED, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
        root.task_state_attempted = true;
        root.task_state = {0, MAPLESU_EFFECT_TASK_STATE_COMPLETED, 0, 0, MAPLESU_REQUEST_TASK_STATE, true};
    }
    if (fixture::root_case == fixture::Root::PostCommitFailure) {
        root.error = KModErr::ERR_MODULE_CRED_DANGER;
        root.phase = "selinux_current";
        root.system_error = EIO;
        errno = EIO;
        return root.error;
    }
    root.phase = "complete";
    root.environment_completed = true;
    return KModErr::OK;
}
}
}

#define popen fixture::popen
#define read fixture::shell_read
#define read_string_from_child fixture::output_frame
#define _exit fixture::command_exit
// EXACT_ROOT_SOURCE
#undef _exit
#undef read_string_from_child
#undef read
#undef popen

namespace {
unsigned checks, failures, scenarios;
#define CHECK(value) do { ++checks; if (!(value)) { ++failures; \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #value); } } while (0)
void prepare(bool existing = false, uint64_t source = 1) {
    if (seteuid(0) != 0) _exit(91);
    std::memset(fixture::shared, 0, sizeof(*fixture::shared));
    fixture::root_case = fixture::Root::Success;
    fixture::managed = true; fixture::fail_command_pipe = false;
    fixture::fail_shell_read = fixture::fail_output_frame = fixture::fail_command_exit = fixture::fail_close = fixture::fail_channel = false;
    fixture::auth_state = source; fixture::root_report = {}; fixture::current_reply = {};
    const std::string flag = fixture::directory + "/workFlag";
    unlink(flag.c_str());
    if (existing) { const int fd = open(flag.c_str(), O_WRONLY | O_CREAT, 0777); CHECK(fd >= 0); if (fd >= 0) close(fd); CHECK(chmod(flag.c_str(), 0777) == 0); }
    CHECK(seteuid(10498) == 0);
    ++scenarios;
}
void no_vendor_effects(bool existing = false) {
    CHECK(fixture::shared->flag_ios == 0 && fixture::shared->io_before_root == 0);
    CHECK(fixture::shared->vendor_calls[0] == 0 && fixture::shared->vendor_calls[1] == 0 && fixture::shared->vendor_calls[2] == 0);
    struct stat flag{};
    const auto observed = stat((fixture::directory + "/workFlag").c_str(), &flag);
    CHECK(existing ? (observed == 0 && flag.st_uid == 0 && (flag.st_mode & 0777) == 0777 && flag.st_size == 0) :
        (observed == -1 && errno == ENOENT));
}
void check_root(const maplesu::sdk::RootCommandResult& result, bool command, uint64_t source, bool committed = true) {
    CHECK(fixture::shared->root_calls == 1);
    CHECK(result.root_attempted && result.root_returned && result.root_report_received);
    CHECK(result.root_process == fixture::shared->root_pid);
    CHECK(command ? result.root_process != getpid() : result.root_process == getpid());
    CHECK(result.root_transition.credentials_committed == (committed && fixture::managed));
    CHECK(result.root_transition.credentials_managed == fixture::managed);
    CHECK(result.root_transition.owner_mode);
    CHECK(fixture::shared->source_seen == source && fixture::auth_state == source);
}
void success(bool command, bool existing, uint64_t source) {
    prepare(existing, source);
    std::string output = "untouched";
    errno = EDOM;
    const auto error = command ? maplesu::sdk::run_root_cmd("printf fixture-command", output) : maplesu::sdk::get_root();
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(error == KModErr::OK && result.error == KModErr::OK && result.phase == maplesu::sdk::RootCommandPhase::Complete);
    CHECK(errno == EDOM);
    check_root(result, command, source);
    CHECK(result.transport_phase == maplesu::sdk::RootCommandPhase::None && result.transport_error == 0);
    CHECK(command ? (output == "fixture-command" && fixture::shared->shells == 1 && fixture::shared->shell_pid == result.root_process &&
        fixture::shared->shell_sequence > fixture::shared->root_sequence && result.shell_close_attempted && result.shell_status == 0 &&
        result.receipt_complete && result.child_status_valid && WIFEXITED(result.child_status) && WEXITSTATUS(result.child_status) == 0 &&
        !result.vendor_child_status_valid && fixture::shared->closes == 1 &&
        result.owner_close_attempted && fixture::shared->channels == 1 &&
        fixture::shared->channel_pid == result.root_process && geteuid() == 10498) :
        (output == "untouched" && fixture::shared->shells == 0 && !result.shell_close_attempted && fixture::shared->closes == 0 &&
        !result.receipt_complete && !result.child_status_valid && fixture::shared->channels == 0 && geteuid() == 0));
    no_vendor_effects(existing);
}
void root_failure(bool command, fixture::Root failure, uint64_t source) {
    prepare(false, source); fixture::root_case = failure;
    std::string output = "untouched";
    const auto error = command ? maplesu::sdk::run_root_cmd("printf unexpected", output) : maplesu::sdk::get_root();
    const auto result = maplesu::sdk::current_root_command_result();
    const auto expected = failure == fixture::Root::Denied ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::ERR_MODULE_CRED_DANGER;
    CHECK(error == expected && result.error == expected && result.phase == maplesu::sdk::RootCommandPhase::Root);
    CHECK(result.system_error == (failure == fixture::Root::Denied ? EACCES : EIO));
    check_root(result, command, source, failure == fixture::Root::PostCommitFailure);
    CHECK(fixture::shared->shells == 0 && fixture::shared->channels == 0);
    CHECK(output == "untouched" && !result.shell_close_attempted && !result.vendor_child_status_valid);
    CHECK(command ? (result.receipt_complete && result.child_status_valid && fixture::shared->closes == 1) :
        (!result.receipt_complete && !result.child_status_valid && fixture::shared->closes == 0));
    no_vendor_effects();
}
void rejected_source(bool command, uint64_t source) {
    prepare(false, source);
    std::string output = "untouched";
    const auto error = command ? maplesu::sdk::run_root_cmd("printf unexpected", output) : maplesu::sdk::get_root();
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(error == KModErr::ERR_MODULE_ROOT_KEY && result.error == error && result.phase == maplesu::sdk::RootCommandPhase::Validate);
    CHECK(!result.root_attempted && !result.root_returned && !result.root_report_received);
    CHECK(fixture::shared->root_calls == 0 && fixture::shared->shells == 0 && fixture::shared->closes == 0 && fixture::shared->channels == 0);
    CHECK(output == "untouched" && !result.owner_close_attempted && !result.shell_close_attempted);
    CHECK(command ? (result.receipt_complete && result.child_status_valid) : (!result.receipt_complete && !result.child_status_valid));
    CHECK(geteuid() == 10498 && fixture::auth_state == source);
    no_vendor_effects();
}
void command_launch_failure(uint64_t source) {
    prepare(false, source); fixture::fail_command_pipe = true;
    std::string output = "untouched";
    const auto error = maplesu::sdk::run_root_cmd("printf unexpected", output);
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(error == KModErr::ERR_READ_CHILD_ERRCODE && result.error == error);
    CHECK(result.phase == maplesu::sdk::RootCommandPhase::Fork && result.transport_phase == result.phase);
    CHECK(result.system_error == EMFILE && result.transport_error == EMFILE && !result.root_attempted);
    CHECK(fixture::shared->root_calls == 0 && fixture::shared->shells == 0 && fixture::shared->closes == 0);
    CHECK(!result.receipt_complete && output == "untouched");
    no_vendor_effects();
}
// The current credential-channel implementation always sets managed=true.
// A fabricated owner+unmanaged report therefore represents a broken boundary;
// its missing CLOSE must remain an uncertain receipt, never a successful replay.
void inconsistent_unmanaged_receipt(uint64_t source) {
    prepare(false, source); fixture::managed = false;
    std::string output = "untouched";
    const auto error = maplesu::sdk::run_root_cmd("printf captured", output);
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(error == KModErr::ERR_READ_CHILD_DATA && result.error == error);
    CHECK(result.phase == maplesu::sdk::RootCommandPhase::Receipt && result.transport_phase == result.phase);
    CHECK(result.root_transition.owner_mode && !result.root_transition.credentials_managed && result.root_report_received);
    CHECK(fixture::shared->root_calls == 1 && fixture::shared->shells == 1 && fixture::shared->closes == 0);
    CHECK(!result.owner_close_attempted && !result.receipt_complete && output == "untouched");
    no_vendor_effects();
}
void stale_session(uint64_t source) {
    prepare(false, source); fixture::fail_channel = fixture::fail_close = true;
    std::string output = "untouched";
    const auto error = maplesu::sdk::run_root_cmd("printf unexpected", output);
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(error == KModErr::ERR_MODULE_TEST_CHANNEL && result.error == error && result.system_error == ESTALE);
    check_root(result, true, source);
    CHECK(fixture::shared->channels == 1 && fixture::shared->channel_pid == result.root_process && fixture::shared->shells == 0);
    CHECK(result.owner_close_attempted && fixture::shared->closes == 1 && is_failed(result.owner_close_error));
    CHECK(result.phase == maplesu::sdk::RootCommandPhase::Root && result.receipt_complete && output == "untouched");
    no_vendor_effects();
}
void legacy_selected(bool command, bool denied) {
    const uint64_t source = 4; // Nonzero explicit LegacyKey generation.
    prepare(false, source); fixture::managed = false;
    if (denied) fixture::root_case = fixture::Root::Denied;
    std::string output = "untouched";
    const auto error = command ? maplesu::sdk::run_root_cmd("printf legacy", output) : maplesu::sdk::get_root();
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(error == (denied ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK));
    CHECK(fixture::shared->source_seen == source && fixture::auth_state == source);
    CHECK(fixture::shared->root_calls == 1 && result.root_attempted && result.root_returned && result.root_report_received);
    CHECK(!result.root_transition.owner_mode && !result.root_transition.credentials_managed);
    CHECK(fixture::shared->closes == 0 && fixture::shared->channels == 0 && !result.owner_close_attempted);
    CHECK(command ? (result.receipt_complete && result.child_status_valid && geteuid() == 10498) : !result.child_status_valid);
    CHECK(output == (command && !denied ? "legacy" : "untouched"));
    CHECK(fixture::shared->shells == int(command && !denied));
    no_vendor_effects();
}
void invalid_command(const char* command) {
    prepare();
    std::string output = "untouched";
    const auto error = maplesu::sdk::run_root_cmd(command, output);
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(error == KModErr::ERR_MODULE_PARAM && result.phase == maplesu::sdk::RootCommandPhase::Validate);
    CHECK(fixture::shared->root_calls == 0 && fixture::shared->shells == 0 && fixture::shared->closes == 0 && fixture::shared->channels == 0);
    CHECK(output == "untouched" && !result.root_attempted && !result.receipt_complete);
    no_vendor_effects();
}
void isolated_diagnostics() {
    prepare(); CHECK(maplesu::sdk::get_root() == KModErr::OK);
    CHECK(maplesu::sdk::current_root_command_result().root_attempted);
    const pid_t child = fork();
    if (child == 0) {
        const auto result = maplesu::sdk::current_root_command_result();
        _exit(result.phase == maplesu::sdk::RootCommandPhase::None && !result.root_attempted && !result.root_report_received ? 0 : 1);
    }
    int status = 0; CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(maplesu::sdk::current_root_command_result().root_attempted);
    no_vendor_effects();
}
void command_output_failure(uint64_t source, int failure) {
    prepare(false, source);
    fixture::fail_shell_read = failure == 1;
    fixture::fail_close = failure == 2;
    fixture::fail_output_frame = failure == 3;
    fixture::fail_command_exit = failure == 4;
    std::string output = "untouched";
    const auto error = maplesu::sdk::run_root_cmd(failure == 0 ? "printf captured; exit 7" : "printf captured", output);
    const auto result = maplesu::sdk::current_root_command_result();
    CHECK(is_failed(error) && result.error == error);
    CHECK(fixture::shared->shells == 1 && fixture::shared->root_calls == 1);
    CHECK(fixture::shared->closes == 1 && result.shell_close_attempted);
    CHECK(result.root_transition.credentials_committed && result.child_status_valid);
    CHECK(fixture::shared->source_seen == source && fixture::auth_state == source);
    if (failure == 3) {
        CHECK(!result.receipt_complete && output == "untouched");
        CHECK(result.transport_phase == maplesu::sdk::RootCommandPhase::Output && result.transport_error == EPIPE);
    } else {
        CHECK(result.receipt_complete && output == "captured");
        if (failure == 0) {
            CHECK(result.phase == maplesu::sdk::RootCommandPhase::Pclose && result.shell_status == (7 << 8));
            CHECK(result.system_error == 0 && result.shell_error == 0);
        } else if (failure == 1) {
            CHECK(result.phase == maplesu::sdk::RootCommandPhase::Read && result.system_error == EIO);
            CHECK(result.shell_status == 0);
        } else if (failure == 2) {
            CHECK(result.phase == maplesu::sdk::RootCommandPhase::Receipt && result.system_error == EIO);
            CHECK(result.owner_close_attempted && is_failed(result.owner_close_error) && result.shell_status == 0);
        } else {
            CHECK(result.phase == maplesu::sdk::RootCommandPhase::Wait && result.transport_phase == result.phase);
            CHECK(WIFEXITED(result.child_status) && WEXITSTATUS(result.child_status) == 7);
        }
    }
    no_vendor_effects();
}

}

int main() {
    fixture::shared = static_cast<fixture::Shared*>(mmap(nullptr, sizeof(fixture::Shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (fixture::shared == MAP_FAILED || geteuid() != 0) return 80;
    fixture::directory = "/tmp/root-vendor-order-" + std::to_string(getpid());
    if (mkdir(fixture::directory.c_str(), 0711) || chmod(fixture::directory.c_str(), 0711)) return 81;
    struct stat directory{};
    CHECK(stat(fixture::directory.c_str(), &directory) == 0 && directory.st_uid == 0 && directory.st_gid == 0 && (directory.st_mode & 0777) == 0711);
    for (uint64_t source : {uint64_t(1), uint64_t(3)}) {
        for (bool command : {false, true}) {
            success(command, false, source); success(command, true, source);
            root_failure(command, fixture::Root::Denied, source); root_failure(command, fixture::Root::PostCommitFailure, source);
        }
        stale_session(source); inconsistent_unmanaged_receipt(source); command_launch_failure(source);
        for (int failure = 0; failure < 5; ++failure) command_output_failure(source, failure);
    }
    for (uint64_t source : {uint64_t(0), uint64_t(2), UINT64_MAX})
        for (bool command : {false, true}) rejected_source(command, source);
    for (bool command : {false, true}) for (bool denied : {false, true}) legacy_selected(command, denied);
    invalid_command(nullptr); invalid_command(""); isolated_diagnostics();
    CHECK(seteuid(0) == 0);
    unlink((fixture::directory + "/workFlag").c_str());
    rmdir(fixture::directory.c_str());
    munmap(fixture::shared, sizeof(fixture::Shared));
    std::printf("Keyless Root lifecycle/order scenarios=%u checks=%u failures=%u\n", scenarios, checks, failures);
    return failures ? 1 : 0;
}
