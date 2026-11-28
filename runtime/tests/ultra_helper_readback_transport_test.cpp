#include "../ultra/bridge/installed_helper_readback.cpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/mman.h>

namespace fixture {
enum class Case { Complete, PipeDenied, Cancel, MetadataChanged, PathReplaced, ExitInRoot,
    Large, CloseDenied, CloseTimeout, ShortDeadline };
struct Counters { unsigned roots = 0, denied_writes = 0, source_stats = 0; int64_t exit_started_ns = 0; };
Counters* counts;
Case scenario;
pid_t parent;
int receipt_fd = -1, source_fd = -1;
bool root_entered;
std::string source_path, received;
kernel_module::RequestManagementReply reply;
unsigned checks, failures, callbacks;
constexpr const char* requested_path = "/data/abcdefghijklmnop/init";
}

extern "C" int __real_pipe2(int*, int);
extern "C" int __wrap_pipe2(int* fds, int flags) {
    const int result = __real_pipe2(fds, flags);
    if (!result) fixture::receipt_fd = fds[1];
    return result;
}
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t bytes) {
    if (getpid() != fixture::parent && fd == fixture::receipt_fd && fixture::root_entered &&
        fixture::scenario == fixture::Case::PipeDenied) {
        ++fixture::counts->denied_writes;
        errno = EACCES;
        return -1;
    }
    return __real_write(fd, data, bytes);
}
extern "C" int __real_open(const char*, int, ...);
extern "C" int __wrap_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    const bool source = !std::strcmp(path, fixture::requested_path);
    const int fd = __real_open(source ? fixture::source_path.c_str() : path, flags, mode);
    if (source) fixture::source_fd = fd;
    return fd;
}
extern "C" int __real_fstat(int, struct stat*);
extern "C" int __wrap_fstat(int fd, struct stat* value) {
    const int result = __real_fstat(fd, value);
    if (!result && fd == fixture::source_fd && ++fixture::counts->source_stats == 2 &&
        fixture::scenario == fixture::Case::MetadataChanged) ++value->st_mtim.tv_nsec;
    return result;
}
extern "C" int __real_lstat(const char*, struct stat*);
extern "C" int __wrap_lstat(const char* path, struct stat* value) {
    const bool source = !std::strcmp(path, fixture::requested_path);
    const int result = __real_lstat(source ? fixture::source_path.c_str() : path, value);
    if (!result && source && fixture::scenario == fixture::Case::PathReplaced) ++value->st_ino;
    return result;
}
extern "C" void maplesu_request_fork_prepare() noexcept {}
extern "C" void maplesu_hook_fork_prepare() noexcept {}
extern "C" bool maplesu_hook_try_fork_prepare() noexcept { return true; }
extern "C" void maplesu_hook_fork_complete() noexcept {}
extern "C" bool maplesu_btf_try_fork_prepare() noexcept { return true; }
extern "C" void maplesu_btf_fork_complete() noexcept {}
namespace kernel_module {
uint64_t maplesu_request_auth_state() { return 1; }
KModErr maplesu_request_worker_admission() { return KModErr::OK; }
KModErr maplesu_request_set_auth_mode(RequestAuthMode) { return KModErr::OK; }
CleanupReceiptScope::CleanupReceiptScope() noexcept : saved_errno_(errno), saved_process_(getpid()), saved_reply_(fixture::reply) {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept { fixture::reply = saved_reply_; errno = saved_errno_; }
KModErr maplesu_request_owner_channel(maplesu_metadata_owner_v3& out, uint64_t&, RequestOwnerBinding&) {
    out.owner_full_uid = 10498; out.owner_epoch = 13; out.host = {17, 29}; return KModErr::OK;
}
bool maplesu_request_owner_binding_matches(const RequestOwnerBinding&) { return true; }
KModErr maplesu_request_owner_deployment(RequestDeploymentNamespace&) { return KModErr::ERR_MODULE_TEST_CHANNEL; }
KModErr maplesu_request_owner_root() {
    ++fixture::counts->roots;
    fixture::root_entered = true;
    if (fixture::scenario == fixture::Case::ExitInRoot) {
        timespec now{};
        if (!clock_gettime(CLOCK_MONOTONIC, &now))
            fixture::counts->exit_started_ns = int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec;
        _exit(12);
    }
    fixture::reply = {0, MAPLESU_EFFECT_COMMITTED, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
    return KModErr::OK;
}
KModErr maplesu_request_owner_close() {
    using namespace fixture;
    if (scenario == Case::CloseTimeout || scenario == Case::ShortDeadline) for (;;) pause();
    reply = {scenario == Case::CloseDenied ? -EIO : 0, MAPLESU_EFFECT_SESSION_CLOSED,
        0, 0, MAPLESU_REQUEST_SESSION_CLOSE, true};
    return scenario == Case::CloseDenied ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK;
}
RequestManagementReply maplesu_request_management_reply() { return fixture::reply; }
}

#define CHECK(value) do { ++fixture::checks; if (!(value)) { ++fixture::failures; \
    std::fprintf(stderr, "line %d: %s\n", __LINE__, #value); } } while (0)
int main(int argc, char** argv) {
    using namespace fixture;
    if (argc != 2) return 64;
    parent = getpid();
    scenario = static_cast<Case>(std::atoi(argv[1]));
    counts = static_cast<Counters*>(mmap(nullptr, sizeof(Counters), PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (counts == MAP_FAILED) return 70;
    char name[] = "/tmp/maplesu-helper-stream-XXXXXX";
    const int source = mkstemp(name);
    if (source < 0) return 71;
    source_path = name;
    std::string expected((scenario == Case::Large ? 16 : 2) * maplesu::kInstalledHelperReadbackChunkBytes + 13, '\0');
    for (size_t index = 0; index < expected.size(); ++index) expected[index] = static_cast<char>((index * 13 + 7) & 255);
    CHECK(__real_write(source, expected.data(), expected.size()) == static_cast<ssize_t>(expected.size()));
    CHECK(close(source) == 0);
    const auto consume = +[](void*, const uint8_t* bytes, size_t size) {
        CHECK(getpid() == parent);
        ++callbacks;
        if (scenario == Case::Cancel) return false;
        received.append(reinterpret_cast<const char*>(bytes), size);
        return true;
    };
    timespec now{};
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    const int64_t deadline = scenario == Case::ShortDeadline ?
        int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec + 50000000 : 0;
    const auto out = maplesu::read_installed_helper(requested_path, consume, nullptr, 300, deadline);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    const auto exit_return_us = counts->exit_started_ns ?
        (int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec - counts->exit_started_ns) / 1000 : 0;
    CHECK(out.elapsed_us < 1000000 && counts->roots == 1);
    const bool success = scenario == Case::Complete || scenario == Case::PipeDenied || scenario == Case::Large;
    CHECK(out.complete == success);
    if (scenario == Case::ExitInRoot) {
        CHECK(!out.root_checkpoint_received && !out.root_verified && !out.receipt_complete);
        CHECK(out.transport_error && out.wait_error);
        CHECK(out.transport_error == EPIPE && !out.timed_out && exit_return_us < 100000);
    } else {
        CHECK(out.root_checkpoint_received && out.root_committed && out.root_verified);
        CHECK(out.root.completed && out.root.command == MAPLESU_REQUEST_CRED_ROOT && !out.root.status);
        CHECK(out.root.effects & MAPLESU_EFFECT_COMMITTED);
        CHECK(out.owner_bound && out.owner_full_uid == 10498 && out.owner_epoch == 13);
        CHECK(counts->denied_writes == 0);
        if (scenario == Case::Cancel) {
            CHECK(callbacks == 1 && out.sink_error == ECANCELED && !out.receipt_complete);
        } else if (scenario == Case::CloseTimeout || scenario == Case::ShortDeadline) {
            CHECK(out.timed_out && !out.receipt_complete && out.received_bytes == expected.size());
            if (scenario == Case::ShortDeadline) CHECK(out.elapsed_us < 200000);
        } else {
            CHECK(out.receipt_complete && out.stream_eof && out.producer_end_received);
            CHECK(received == expected && out.actual_size == expected.size() && out.received_bytes == expected.size());
            if (scenario == Case::MetadataChanged || scenario == Case::PathReplaced) CHECK(out.producer_error == ESTALE);
            else CHECK(out.source_eof && out.metadata_stable && out.path_stable && !out.producer_error);
            if (scenario == Case::CloseDenied) CHECK(out.close.error && out.close.status == -EIO);
            if (success) {
                CHECK(!out.system_error && !out.transport_error && !out.wait_error && out.child_status_valid);
                const auto capture = "captured-" + std::to_string(static_cast<unsigned>(scenario)) + ".bin";
                const int fd = __real_open(capture.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
                CHECK(fd >= 0);
                if (fd >= 0) { CHECK(__real_write(fd, received.data(), received.size()) == static_cast<ssize_t>(received.size())); CHECK(!close(fd)); }
            }
        }
    }
    std::printf("case=%u checks=%u failures=%u complete=%d root=%d bytes=%llu callbacks=%u deniedWrites=%u producer=%d sink=%d transport=%d wait=%d timeout=%d us=%llu exitReturnUs=%lld\n",
        static_cast<unsigned>(scenario), checks, failures, out.complete, out.root_verified,
        static_cast<unsigned long long>(out.received_bytes), callbacks, counts->denied_writes,
        out.producer_error, out.sink_error, out.transport_error, out.wait_error, out.timed_out,
        static_cast<unsigned long long>(out.elapsed_us), static_cast<long long>(exit_return_us));
    if (out.cleanup_pending) {
        int status = 0;
        while (waitpid(static_cast<pid_t>(out.child_pid), &status, 0) < 0 && errno == EINTR) {}
    }
    CHECK(unlink(name) == 0);
    munmap(counts, sizeof(Counters));
    return failures ? 1 : 0;
}
