// Exact m060 serializers and m046 pipe helpers; only kernel request APIs are seams.
#include "maplesu_root_command_private.h"
#include "maplesu/compat/fork_legacy_abi.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <vector>

extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return 0; }
namespace default_modules::module_root { KModErr set_current_root(bool); }

namespace kernel_module {
static RequestManagementReply current_reply{};
static KModErr close_error = KModErr::OK;
static unsigned closes = 0;
CleanupReceiptScope::CleanupReceiptScope() noexcept : saved_errno_(errno),
    saved_process_(getpid()), saved_reply_(current_reply) {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {
    if (saved_process_ == static_cast<uint64_t>(getpid())) {
        current_reply = saved_reply_;
        errno = saved_errno_;
    }
}
KModErr maplesu_request_owner_close() {
    ++closes;
    current_reply = {is_ok(close_error) ? 0 : -EIO,
        MAPLESU_EFFECT_SESSION_CLOSED, 0, 0, MAPLESU_REQUEST_SESSION_CLOSE, true};
    errno = is_ok(close_error) ? 0 : EIO;
    return close_error;
}
RequestManagementReply maplesu_request_management_reply() { return current_reply; }
}

// EXACT_ROOT_SOURCE

using namespace maplesu::sdk;
namespace {
unsigned checks = 0, failures = 0;
bool write_fixture_bytes(int fd, const void* data, size_t bytes) {
    auto* cursor = static_cast<const unsigned char*>(data);
    while (bytes) {
        const ssize_t count = write(fd, cursor, bytes);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        cursor += count;
        bytes -= static_cast<size_t>(count);
    }
    return true;
}
#define CHECK(value) do { ++checks; if (!(value)) { ++failures; \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #value); } } while (0)

RootCommandResult committed(bool managed = true, bool owner = false) {
    RootCommandResult result{};
    result.root_attempted = result.root_returned = result.root_report_received = true;
    result.root_process = getpid();
    auto& root = result.root_transition;
    root.owner_mode = owner;
    root.credentials_managed = managed;
    root.credentials_attempted = root.credentials_committed = true;
    root.credentials = {0, MAPLESU_EFFECT_COMMITTED, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
    root.task_state_attempted = true;
    root.task_state = {0, MAPLESU_EFFECT_TASK_STATE_COMPLETED, 0, 0, MAPLESU_REQUEST_TASK_STATE, true};
    root.phase = "complete";
    root.environment_completed = true;
    result.phase = RootCommandPhase::Complete;
    return result;
}

std::vector<unsigned char> encode_root(const RootCommandResult& result) {
    int fds[2];
    CHECK(pipe(fds) == 0);
    fork_pipe_info transfer;
    transfer.fd_child_to_parent_write = fds[1];
    CHECK(send_root_result(transfer, result));
    transfer.close_all();
    std::vector<unsigned char> bytes;
    unsigned char buffer[512];
    ssize_t got;
    while ((got = read(fds[0], buffer, sizeof(buffer))) > 0)
        bytes.insert(bytes.end(), buffer, buffer + got);
    close(fds[0]);
    return bytes;
}

bool decode_root(const std::vector<unsigned char>& bytes, RootCommandResult& result) {
    int fds[2];
    CHECK(pipe(fds) == 0);
    CHECK(write(fds[1], bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()));
    close(fds[1]);
    fork_pipe_info transfer;
    transfer.fd_child_to_parent_read = fds[0];
    transfer.child_pid = getpid();
    return receive_root_result(transfer, result);
}

void root_blocks() {
    auto source = committed();
    source.root_transition.credentials_error = KModErr::ERR_MODULE_ROOT_KEY;
    source.root_transition.error = source.root_transition.credentials_error;
    source.root_transition.credentials.status = -ESTALE;
    source.root_transition.phase = "credentials";
    source.root_transition.environment_completed = false;
    source.root_transition.task_state_attempted = false;
    source.root_transition.task_state = {};
    const auto encoded = encode_root(source);
    RootCommandResult result;
    CHECK(decode_root(encoded, result));
    CHECK(result.root_transition.credentials_committed && result.root_transition.credentials_managed);
    CHECK(!result.root_transition.owner_mode && result.root_transition.credentials.status == -ESTALE);
    CHECK(result.root_transition.credentials_error == KModErr::ERR_MODULE_ROOT_KEY);
    CHECK(result.root_report_received && !result.root_transition.task_state_attempted);

    constexpr size_t task_bytes = sizeof(KModErr) + 3 * sizeof(int) + 4 * sizeof(uint64_t);
    CHECK(encoded.size() > task_bytes);
    const size_t boundary = encoded.size() - task_bytes;
    for (size_t tail = 0; tail < task_bytes; ++tail) {
        std::vector<unsigned char> truncated(encoded.begin(), encoded.begin() + boundary + tail);
        RootCommandResult partial;
        CHECK(!decode_root(truncated, partial));
        CHECK(partial.root_transition.credentials_committed && partial.root_transition.credentials_managed);
        CHECK(partial.root_transition.credentials.status == -ESTALE && !partial.root_report_received);
        CHECK(!partial.root_transition.task_state_attempted && partial.root_transition.task_state.command == 0);
    }

    auto bad = encoded;
    int invalid = 2;
    std::memcpy(bad.data() + boundary - 4 * sizeof(int), &invalid, sizeof(invalid));
    result = {};
    CHECK(!decode_root(bad, result) && !result.root_transition.credentials_committed);
    bad = encoded;
    invalid = 1;
    std::memcpy(bad.data() + 4 * sizeof(int) + 2 * sizeof(KModErr), &invalid, sizeof(invalid));
    result = {};
    CHECK(!decode_root(bad, result) && !result.root_transition.credentials_committed);
    bad = encoded;
    invalid = -4096;
    std::memcpy(bad.data() + boundary + sizeof(KModErr), &invalid, sizeof(invalid));
    result = {};
    CHECK(!decode_root(bad, result) && result.root_transition.credentials_committed && !result.root_report_received);

    auto unrelated = source;
    unrelated.root_transition.credentials_managed = false;
    result = {};
    CHECK(!decode_root(encode_root(unrelated), result) && !result.root_transition.credentials_committed);
}

void kernel_close_seam() {
    auto result = committed();
    result.error = KModErr::ERR_MODULE_ROOT_KEY;
    result.root_transition.error = result.error;
    result.root_transition.credentials_error = result.error;
    const auto credentials = result.root_transition.credentials;
    kernel_module::current_reply = credentials;
    kernel_module::close_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    const auto before = kernel_module::closes;
    close_command_owner(result);
    CHECK(kernel_module::closes == before + 1 && result.owner_close_attempted);
    CHECK(result.owner_close_error == KModErr::ERR_MODULE_TEST_CHANNEL);
    CHECK(result.error == KModErr::ERR_MODULE_ROOT_KEY && result.root_transition.credentials_committed);
    CHECK(result.root_transition.credentials.command == MAPLESU_REQUEST_CRED_ROOT &&
        result.root_transition.credentials.effects == credentials.effects);
    CHECK(kernel_module::current_reply.command == MAPLESU_REQUEST_CRED_ROOT);
    kernel_module::close_error = KModErr::OK;
}

enum class Case { Key, Owner, Legacy, PostCommitError, TaskError, CloseTailMissing };
void command_pipe(Case test) {
    fork_pipe_info transfer;
    if (fork_pipe_child_process(transfer)) {
        auto result = committed(test != Case::Legacy, test == Case::Owner);
        if (test == Case::Legacy) {
            result.root_transition.credentials = {};
            result.root_transition.credentials_committed = false;
            result.root_transition.task_state_attempted = false;
            result.root_transition.task_state = {};
        }
        if (test == Case::PostCommitError) {
            result.error = result.root_transition.credentials_error =
                result.root_transition.error = KModErr::ERR_MODULE_ROOT_KEY;
            result.root_transition.credentials.status = -ESTALE;
            result.root_transition.environment_completed = false;
            result.root_transition.phase = "credentials";
            result.root_transition.task_state_attempted = false;
            result.root_transition.task_state = {};
        }
        if (test == Case::TaskError) {
            result.error = result.root_transition.task_state_error =
                result.root_transition.error = KModErr::ERR_MODULE_CRED_DANGER;
            result.root_transition.task_state.status = -EIO;
            result.root_transition.task_state.effects = MAPLESU_EFFECT_TASK_STATE_CHANGED;
            result.root_transition.environment_completed = false;
            result.root_transition.phase = "task_state";
        }
        if (result.root_transition.owner_mode || result.root_transition.credentials_managed)
            close_command_owner(result);
        bool sent;
        if (test == Case::CloseTailMissing) {
            // Root/task block and the outer prefix are actual production bytes.
            int fds[2];
            if (pipe(fds)) _exit(4);
            fork_pipe_info capture;
            capture.fd_child_to_parent_write = fds[1];
            if (!send_command_result(capture, result)) _exit(5);
            capture.close_all();
            std::vector<unsigned char> bytes;
            unsigned char buffer[512];
            ssize_t got;
            while ((got = read(fds[0], buffer, sizeof(buffer))) > 0)
                bytes.insert(bytes.end(), buffer, buffer + got);
            close(fds[0]);
            constexpr size_t close_bytes = sizeof(KModErr) + 3 * sizeof(int) + 4 * sizeof(uint64_t);
            if (bytes.size() <= close_bytes) _exit(6);
            sent = write_fixture_bytes(transfer.fd_child_to_parent_write, bytes.data(), bytes.size() - close_bytes);
        } else sent = send_command_result(transfer, result);
        transfer.close_all();
        _exit(sent ? 0 : 7);
    }
    CHECK(transfer.child_pid > 0);
    RootCommandResult result;
    receive_command_result(transfer, result, nullptr, errno);
    CHECK(result.child_status_valid && WIFEXITED(result.child_status) && WEXITSTATUS(result.child_status) == 0);
    CHECK(result.root_report_received);
    CHECK(result.root_transition.credentials_managed == (test != Case::Legacy));
    CHECK(result.root_transition.credentials_committed == (test != Case::Legacy));
    if (test == Case::CloseTailMissing) {
        CHECK(!result.receipt_complete && is_failed(result.error));
        CHECK(!result.owner_close_attempted && result.root_transition.task_state.completed);
    } else {
        CHECK(result.receipt_complete);
        CHECK(result.owner_close_attempted == (test != Case::Legacy));
        if (test == Case::PostCommitError) {
            CHECK(result.root_transition.credentials.status == -ESTALE &&
                result.root_transition.credentials_error == KModErr::ERR_MODULE_ROOT_KEY);
            CHECK(!result.root_transition.task_state_attempted && result.error == KModErr::ERR_MODULE_ROOT_KEY);
        } else if (test == Case::TaskError) {
            CHECK(result.root_transition.credentials.status == 0 &&
                result.root_transition.credentials_error == KModErr::OK);
            CHECK(result.root_transition.task_state.status == -EIO &&
                result.error == KModErr::ERR_MODULE_CRED_DANGER);
        } else CHECK(is_ok(result.error));
    }
}
}

int main() {
    root_blocks();
    kernel_close_seam();
    for (auto test : {Case::Key, Case::Owner, Case::Legacy, Case::PostCommitError,
        Case::TaskError, Case::CloseTailMissing}) command_pipe(test);
    std::printf("P4 root receipt checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
