#include "../ultra/bridge/manager_owner_root_probe.cpp"
#include "../ultra/bridge/sdk_call_scope.h"
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

namespace fixture {
enum class Case { Success, RootDenied, PostCommitError, CloseDenied, PipeDenied, ExitAfterRoot, CloseTimeout,
    ExpiredDeadline, ShortDeadline, InvalidReceipt, CloseException, AdmissionExpired, ForkPrepareExpired,
    TlsExpired, TlsShort };
Case scenario;
pid_t parent;
int receipt_fd = -1;
bool root_entered;
kernel_module::RequestManagementReply reply;
unsigned checks, failures;
unsigned admissions, pipes, forks;
void delay_admission() {
    const timespec duration{0, 60000000};
    nanosleep(&duration, nullptr);
}
}

extern "C" int __real_pipe2(int*, int);
extern "C" int __wrap_pipe2(int* fds, int flags) {
    ++fixture::pipes;
    const int result = __real_pipe2(fds, flags);
    if (!result) fixture::receipt_fd = fds[1];
    return result;
}
extern "C" pid_t __real_fork();
extern "C" pid_t __wrap_fork() { ++fixture::forks; return __real_fork(); }
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" ssize_t __wrap_write(int fd, const void* value, size_t bytes) {
    if (getpid() != fixture::parent && fd == fixture::receipt_fd && fixture::root_entered &&
        fixture::scenario == fixture::Case::PipeDenied) { errno = EACCES; return -1; }
    return __real_write(fd, value, bytes);
}
extern "C" void maplesu_request_fork_prepare() noexcept {
    if (fixture::scenario == fixture::Case::ForkPrepareExpired) fixture::delay_admission();
}
namespace kernel_module {
uint64_t maplesu_request_auth_state() { return 1; }
KModErr maplesu_request_worker_admission() {
    ++fixture::admissions;
    if (fixture::scenario == fixture::Case::AdmissionExpired) fixture::delay_admission();
    return KModErr::OK;
}
KModErr maplesu_request_set_auth_mode(RequestAuthMode) { return KModErr::OK; }
CleanupReceiptScope::CleanupReceiptScope() noexcept : saved_errno_(errno), saved_process_(getpid()), saved_reply_(fixture::reply) {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept { fixture::reply = saved_reply_; errno = saved_errno_; }
KModErr maplesu_request_owner_channel(maplesu_metadata_owner_v3& out, uint64_t&, RequestOwnerBinding&) {
    out.owner_full_uid = 10498; out.owner_epoch = 13; out.host = {17, 29};
    return KModErr::OK;
}
KModErr maplesu_request_owner_root() {
    using namespace fixture;
    root_entered = true;
    reply = {0, MAPLESU_EFFECT_COMMITTED, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
    if (scenario == Case::ExitAfterRoot) _exit(12);
    if (scenario == Case::RootDenied) {
        reply = {-EACCES, 0, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
        errno = EACCES;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (scenario == Case::PostCommitError) { errno = ESTALE; return KModErr::ERR_MODULE_ROOT_KEY; }
    return KModErr::OK;
}
KModErr maplesu_request_owner_close() {
    using namespace fixture;
    if (scenario == Case::CloseException) throw std::bad_alloc();
    if (scenario == Case::CloseTimeout || scenario == Case::ShortDeadline || scenario == Case::TlsShort) for (;;) pause();
    reply = {0, MAPLESU_EFFECT_SESSION_CLOSED, 0, 0, MAPLESU_REQUEST_SESSION_CLOSE, true};
    if (scenario == Case::CloseDenied) {
        reply.status = -EIO; errno = EIO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    return KModErr::OK;
}
RequestManagementReply maplesu_request_management_reply() { return fixture::reply; }
KModErr get_current_caps_snapshot(caps_info& out, bool& ambient) {
    const uint64_t mask = (UINT64_C(1) << 41) - 1;
    out = {mask, mask, mask, mask, mask}; ambient = true; return KModErr::OK;
}
}

#define CHECK(value) do { ++fixture::checks; if (!(value)) { ++fixture::failures; \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #value); } } while (0)
int main(int argc, char** argv) {
    using namespace fixture;
    parent = getpid();
    if (argc != 2) return 64;
    for (const auto test : {static_cast<Case>(std::atoi(argv[1]))}) {
        scenario = test; root_entered = false; reply = {};
        if (test == Case::InvalidReceipt) {
            maplesu::RootProbeReceipt receipt;
            const auto child = static_cast<pid_t>(41);
            maplesu::ManagerOwnerRootProbe observed;
            receipt.checkpoint.child_pid = child;
            receipt.checkpoint.root_checkpoint_received = true;
            receipt.final = receipt.checkpoint;
            receipt.final.receipt_complete = true;
            CHECK(maplesu::read_receipt(receipt, child, observed) == EPROTO);
            receipt.committed.store(3);
            CHECK(maplesu::read_receipt(receipt, child, observed) == 0);
            receipt.magic = 0;
            CHECK(maplesu::read_receipt(receipt, child, observed) == EPROTO);
            receipt.magic = 0x4d535250;
            receipt.version = 2;
            CHECK(maplesu::read_receipt(receipt, child, observed) == EPROTO);
            receipt.version = 1;
            CHECK(maplesu::read_receipt(receipt, child + 1, observed) == EPROTO);
            receipt.final.root_verified = true;
            CHECK(maplesu::read_receipt(receipt, child, observed) == EPROTO);
            CHECK(observed.root_checkpoint_received && !observed.receipt_complete && !observed.root_verified);
            std::printf("Root private receipt checks=%u failures=%u\n", checks, failures);
            return failures ? 1 : 0;
        }
        timespec now{};
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        const int64_t nanos = int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec;
        maplesu::SdkDeadlineScope outer(test == Case::TlsExpired ? nanos - 1 :
            test == Case::TlsShort ? nanos + 50000000 : 0);
        const auto prior = maplesu::sdk_call_deadline_nanos();
        const auto result = test == Case::ExpiredDeadline ? maplesu::probe_manager_owner_root(nanos - 1) :
            test == Case::AdmissionExpired || test == Case::ForkPrepareExpired ? maplesu::probe_manager_owner_root(nanos + 20000000) :
            test == Case::ShortDeadline ? maplesu::probe_manager_owner_root(nanos + 50000000) :
            maplesu::probe_manager_owner_root();
        CHECK(maplesu::sdk_call_deadline_nanos() == prior);
        CHECK(result.elapsed_us < 1000000);
        if (test == Case::ExpiredDeadline || test == Case::TlsExpired) {
            CHECK(admissions == 0 && !pipes && !forks && !result.child_pid && !result.root.attempted);
            CHECK(result.timed_out && result.transport_error == ETIMEDOUT);
            CHECK(!result.watchdog_armed && !result.cleanup_pending);
            std::printf("Root expired deadline checks=%u failures=%u\n", checks, failures);
            return failures ? 1 : 0;
        }
        if (test == Case::AdmissionExpired || test == Case::ForkPrepareExpired) {
            CHECK(admissions == 1 && !forks && !result.child_pid && !result.root.attempted);
            CHECK(pipes == (test == Case::ForkPrepareExpired ? 1u : 0u));
            CHECK(result.timed_out && result.transport_error == ETIMEDOUT);
            CHECK(!result.watchdog_armed && !result.cleanup_pending);
            std::printf("Root admission expiry case=%u checks=%u failures=%u pipe=%u fork=%u us=%llu\n",
                static_cast<unsigned>(test), checks, failures, pipes, forks, static_cast<unsigned long long>(result.elapsed_us));
            return failures ? 1 : 0;
        }
        CHECK(admissions == 1);
        if (test == Case::ExitAfterRoot) {
            CHECK(!result.root_checkpoint_received && !result.root_committed && !result.receipt_complete);
            CHECK(result.transport_error || result.wait_error);
        } else {
            CHECK(result.root_checkpoint_received && result.root.reply_observed);
            CHECK(result.root.command == MAPLESU_REQUEST_CRED_ROOT && result.root.completed);
            CHECK(result.root_committed == (test != Case::RootDenied));
            CHECK(result.root.error == (test == Case::RootDenied ? static_cast<int64_t>(KModErr::ERR_MODULE_TEST_CHANNEL) :
                test == Case::PostCommitError ? static_cast<int64_t>(KModErr::ERR_MODULE_ROOT_KEY) : 0));
            CHECK(result.root.status == (test == Case::RootDenied ? -EACCES : 0));
            if (test == Case::CloseTimeout || test == Case::ShortDeadline || test == Case::TlsShort) {
                CHECK(!result.receipt_complete && result.timed_out);
                if (test == Case::ShortDeadline || test == Case::TlsShort) CHECK(result.elapsed_us < 200000);
            } else {
                CHECK(result.receipt_complete && !result.transport_error);
                CHECK(result.close.attempted);
                if (test == Case::CloseException) {
                    CHECK(result.child_exception && result.root_verified);
                    CHECK(!result.close.completed && !result.close.reply_observed);
                } else CHECK(result.close.completed && result.close.command == MAPLESU_REQUEST_SESSION_CLOSE);
                CHECK(result.close.error == (test == Case::CloseDenied || test == Case::CloseException ?
                    static_cast<int64_t>(KModErr::ERR_MODULE_TEST_CHANNEL) : 0));
            }
        }
        std::printf("case=%u checkpoint=%d committed=%d complete=%d transport=%d wait=%d timeout=%d us=%llu\n",
            static_cast<unsigned>(test), result.root_checkpoint_received, result.root_committed, result.receipt_complete,
            result.transport_error, result.wait_error, result.timed_out, static_cast<unsigned long long>(result.elapsed_us));
        // Reap only this fixture's already terminated child if the production deferred reaper has not done it.
        if (result.cleanup_pending) {
            int status = 0;
            const auto child = static_cast<pid_t>(result.child_pid);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        }
    }
    std::printf("Root private receipt checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
