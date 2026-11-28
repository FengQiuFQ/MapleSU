#include "../ultra/bridge/installed_helper_readback.cpp"
#include "../ultra/bridge/sdk_call_scope.h"
#include <cstdio>
#include <cstdlib>

namespace fixture {
enum class Case { Expired, SharedShort, LocalShort, LegacyDefault, AdmissionDenied,
    AdmissionExpired, LayoutExpired, InvalidTimeout, OwnerDenied, ForkPrepareExpired,
    TlsExpired, TlsShort };
Case scenario;
unsigned checks, failures, admissions, pipes, forks, layout_entered, layout_left;
kernel_module::RequestManagementReply reply;
void delay_admission() {
    const timespec duration{0, 60000000};
    nanosleep(&duration, nullptr);
}
}

extern "C" int __real_pipe2(int*, int);
extern "C" int __wrap_pipe2(int* fds, int flags) {
    ++fixture::pipes;
    return __real_pipe2(fds, flags);
}
extern "C" pid_t __real_fork();
extern "C" pid_t __wrap_fork() {
    ++fixture::forks;
    return __real_fork();
}
extern "C" void maplesu_request_fork_prepare() noexcept {
    if (fixture::scenario == fixture::Case::ForkPrepareExpired) fixture::delay_admission();
}
extern "C" void maplesu_hook_fork_prepare() noexcept {
    ++fixture::layout_entered;
    if (fixture::scenario == fixture::Case::LayoutExpired) fixture::delay_admission();
}
extern "C" bool maplesu_hook_try_fork_prepare() noexcept { maplesu_hook_fork_prepare(); return true; }
extern "C" void maplesu_hook_fork_complete() noexcept { ++fixture::layout_left; }
extern "C" bool maplesu_btf_try_fork_prepare() noexcept { return true; }
extern "C" void maplesu_btf_fork_complete() noexcept {}
namespace kernel_module {
uint64_t maplesu_request_auth_state() { return 1; }
KModErr maplesu_request_worker_admission() {
    ++fixture::admissions;
    if (fixture::scenario == fixture::Case::AdmissionExpired) fixture::delay_admission();
    return fixture::scenario == fixture::Case::AdmissionDenied ? KModErr::ERR_MODULE_ROOT_KEY : KModErr::OK;
}
KModErr maplesu_request_set_auth_mode(RequestAuthMode) { return KModErr::OK; }
CleanupReceiptScope::CleanupReceiptScope() noexcept : saved_errno_(errno), saved_process_(getpid()), saved_reply_(fixture::reply) {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept { fixture::reply = saved_reply_; errno = saved_errno_; }
KModErr maplesu_request_owner_channel(maplesu_metadata_owner_v3& out, uint64_t&, RequestOwnerBinding&) {
    out.owner_full_uid = 10498; out.owner_epoch = 13; out.host = {17, 29};
    return fixture::scenario == fixture::Case::OwnerDenied ? KModErr::ERR_MODULE_ROOT_KEY : KModErr::OK;
}
bool maplesu_request_owner_binding_matches(const RequestOwnerBinding&) { return true; }
KModErr maplesu_request_owner_deployment(RequestDeploymentNamespace&) { return KModErr::ERR_MODULE_TEST_CHANNEL; }
KModErr maplesu_request_owner_root() { for (;;) pause(); }
KModErr maplesu_request_owner_close() {
    fixture::reply = {0, MAPLESU_EFFECT_SESSION_CLOSED, 0, 0, MAPLESU_REQUEST_SESSION_CLOSE, true};
    return KModErr::OK;
}
RequestManagementReply maplesu_request_management_reply() { return fixture::reply; }
}

#define CHECK(value) do { ++fixture::checks; if (!(value)) { ++fixture::failures; \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #value); } } while (0)
int main(int argc, char** argv) {
    using namespace fixture;
    if (argc != 2) return 64;
    scenario = static_cast<Case>(std::atoi(argv[1]));
    timespec now{};
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    const int64_t nanos = int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec;
    maplesu::SdkDeadlineScope outer(scenario == Case::TlsExpired ? nanos - 1 :
        scenario == Case::TlsShort ? nanos + 50000000 : 0);
    const auto prior = maplesu::sdk_call_deadline_nanos();
    const int64_t deadline = scenario == Case::Expired ? nanos - 1 :
        scenario == Case::SharedShort ? nanos + 50000000 :
        scenario == Case::AdmissionExpired || scenario == Case::LayoutExpired || scenario == Case::ForkPrepareExpired ?
            nanos + 20000000 : nanos + 2000000000;
    const uint32_t local_ms = scenario == Case::LocalShort ? 20 : scenario == Case::InvalidTimeout ? 5001 : 300;
    const auto consume = +[](void*, const uint8_t*, size_t) { return true; };
    const char* path = "/data/abcdefghijklmnop/init";
#if defined(FIXTURE_LEGACY_DEADLINE_API)
    (void)deadline;
    const auto out = maplesu::read_installed_helper(path, consume, nullptr, local_ms);
#else
    const auto out = scenario == Case::LegacyDefault ? maplesu::read_installed_helper(path, consume, nullptr) :
        maplesu::read_installed_helper(path, consume, nullptr, local_ms, deadline);
#endif
    CHECK(maplesu::sdk_call_deadline_nanos() == prior);
    CHECK(!out.complete && out.elapsed_us < 1000000);
    if (scenario == Case::Expired || scenario == Case::TlsExpired) {
        CHECK(!admissions && !pipes && !forks && !out.child_pid);
        CHECK(out.timed_out && out.system_error == ETIMEDOUT && out.admission_error == ETIMEDOUT);
    } else if (scenario == Case::InvalidTimeout) {
        CHECK(!admissions && !pipes && !forks && out.system_error == EINVAL && !out.timed_out);
    } else if (scenario == Case::AdmissionDenied) {
        CHECK(admissions == 1 && !pipes && !forks);
        CHECK(out.channel_error == static_cast<int64_t>(KModErr::ERR_MODULE_ROOT_KEY));
        CHECK(out.sdk_error == out.channel_error && !out.timed_out);
    } else if (scenario == Case::AdmissionExpired || scenario == Case::LayoutExpired || scenario == Case::ForkPrepareExpired) {
        CHECK(admissions == 1 && !forks && !out.child_pid);
        CHECK(pipes == (scenario == Case::AdmissionExpired ? 0u : 1u));
        CHECK(layout_entered == layout_left);
        CHECK(out.timed_out && out.admission_error == ETIMEDOUT && out.system_error == ETIMEDOUT);
    } else if (scenario == Case::OwnerDenied) {
        CHECK(admissions == 1 && pipes == 1 && forks == 1);
        CHECK(out.channel_error == static_cast<int64_t>(KModErr::ERR_MODULE_ROOT_KEY));
        CHECK(out.sdk_error == out.channel_error && out.root_checkpoint_received && out.receipt_complete);
        CHECK(!out.root.attempted && out.close.completed && !out.timed_out);
        CHECK(std::strcmp(maplesu::installed_helper_readback_failure_stage(out, false), "owner-channel") == 0);
    } else {
        CHECK(admissions == 1 && pipes == 1 && forks == 1 && out.child_pid);
        CHECK(out.timed_out && !out.receipt_complete && out.system_error);
        CHECK(std::strcmp(out.root_phase, "root-transition") == 0 && out.root.attempted);
        if (scenario == Case::SharedShort || scenario == Case::LocalShort || scenario == Case::TlsShort)
            CHECK(out.elapsed_us < 200000);
        if (scenario == Case::LegacyDefault) CHECK(out.elapsed_us >= 250000);
    }
    CHECK(!out.complete && !out.root_verified);
    std::printf("case=%u checks=%u failures=%u admission=%u pipe=%u fork=%u stage=%s transport=%d wait=%d timeout=%d us=%llu\n",
        static_cast<unsigned>(scenario), checks, failures, admissions, pipes, forks,
        maplesu::installed_helper_readback_failure_stage(out, false), out.transport_error, out.wait_error,
        out.timed_out, static_cast<unsigned long long>(out.elapsed_us));
    if (out.cleanup_pending) {
        int status = 0;
        while (waitpid(static_cast<pid_t>(out.child_pid), &status, 0) < 0 && errno == EINTR) {}
    }
    return failures ? 1 : 0;
}
