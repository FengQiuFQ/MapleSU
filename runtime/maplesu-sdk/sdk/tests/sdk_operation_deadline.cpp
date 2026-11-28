#include "../src/maplesu/compat/fork_legacy_abi.h"
#include "../src/maplesu_core/fixed_transfer_io.h"
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <time.h>

extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept;
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t) noexcept;
extern "C" long __real_syscall(long, ...);
static bool missing_pidfd;
extern "C" long __wrap_syscall(long number, ...) {
#ifdef SYS_pidfd_open
    if (number == SYS_pidfd_open) {
        if (missing_pidfd) { errno = ENOSYS; return -1; }
        va_list arguments;
        va_start(arguments, number);
        const pid_t child = va_arg(arguments, pid_t);
        const int flags = va_arg(arguments, int);
        va_end(arguments);
        return __real_syscall(number, child, flags);
    }
#endif
    _exit(20); // No other raw syscall is part of this pipe/TLS/wait fixture.
}
#ifdef MAPLESU_DEADLINE_BASELINE
static thread_local int64_t fixture_deadline;
extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept {
    return fixture_deadline;
}
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t value) noexcept {
    const auto old = fixture_deadline;
    fixture_deadline = value;
    return old;
}
#else
#include "maplesu_operation_wait_private.h"
#endif

// EXACT_ENVIRONMENT_WAIT

namespace {
unsigned checks, failures;
int64_t now() {
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
void pause_child() {
    timespec wait{0, 160000000};
    while (nanosleep(&wait, &wait) < 0 && errno == EINTR) {}
}
void reap(pid_t child) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
}
void read_timeout(bool interrupted) {
    int fds[2];
    if (pipe(fds)) _exit(10);
    const auto child = fork();
    if (!child) { close(fds[0]); pause_child(); close(fds[1]); _exit(0); }
    close(fds[1]);
    maplesu::sdk::fork_pipe_info info;
    info.fd_child_to_parent_read = fds[0];
    int value = 0;
    if (interrupted) {
        itimerval timer{{0, 1000}, {0, 1000}};
        setitimer(ITIMER_REAL, &timer, nullptr);
    }
    maplesu_request_set_operation_deadline_nanos(now() + 25000000);
    const auto start = now();
    errno = 0;
    const bool read = maplesu::sdk::read_int_from_child(info, value);
    const auto elapsed = now() - start;
    const int error = errno;
    if (interrupted) { itimerval timer{}; setitimer(ITIMER_REAL, &timer, nullptr); }
    maplesu_request_set_operation_deadline_nanos(0);
    check(!read && error == ETIMEDOUT && elapsed < 100000000,
        interrupted ? "real m046 EINTR read shares deadline" : "real m046 stalled read bounded",
        elapsed, error);
    check(!(fcntl(info.fd_child_to_parent_read, F_GETFL) & O_NONBLOCK),
        "caller blocking read descriptor flags restored");
    info.close_all();
    kill(child, SIGKILL);
    reap(child);
}
void partial_timeout() {
    int fds[2];
    if (pipe(fds)) _exit(11);
    const uint64_t size = 4;
    const char partial[2] = {'a', 'b'};
    if (write(fds[1], &size, sizeof(size)) != sizeof(size) ||
        write(fds[1], partial, sizeof(partial)) != sizeof(partial)) _exit(12);
    const auto child = fork();
    if (!child) { close(fds[0]); pause_child(); close(fds[1]); _exit(0); }
    close(fds[1]);
    maplesu::sdk::fork_pipe_info info;
    info.fd_child_to_parent_read = fds[0];
    char output[4]{};
    maplesu_request_set_operation_deadline_nanos(now() + 25000000);
    const auto start = now();
    const auto result = maplesu::sdk::read_fixed_transfer_data_from_child(info, output, 4);
    const auto elapsed = now() - start;
    maplesu_request_set_operation_deadline_nanos(0);
    check(result.status == maplesu::sdk::FixedTransferStatus::IoError &&
        result.systemErrno == ETIMEDOUT && result.transferredBytes == 10 &&
        !memcmp(output, partial, 2) && elapsed < 100000000,
        "real m046 partial receipt preserves bytes and timeout", elapsed, result.systemErrno);
    info.close_all();
    kill(child, SIGKILL);
    reap(child);
}
void write_timeout() {
    int fds[2];
    if (pipe2(fds, O_NONBLOCK)) _exit(13);
    char bytes[4096]{};
    while (write(fds[1], bytes, sizeof(bytes)) > 0) {}
    if (errno != EAGAIN) _exit(14);
    if (fcntl(fds[1], F_SETFL, 0) < 0) _exit(15);
    const auto child = fork();
    if (!child) {
        close(fds[1]); pause_child();
        const auto drained = read(fds[0], bytes, sizeof(bytes));
        close(fds[0]); _exit(drained > 0 ? 0 : 1);
    }
    close(fds[0]);
    maplesu::sdk::fork_pipe_info info;
    info.fd_child_to_parent_write = fds[1];
    maplesu_request_set_operation_deadline_nanos(now() + 25000000);
    const auto start = now();
    errno = 0;
    const bool written = maplesu::sdk::write_int_from_child(info, 7);
    const auto elapsed = now() - start;
    const int error = errno;
    maplesu_request_set_operation_deadline_nanos(0);
    check(!written && error == ETIMEDOUT && elapsed < 100000000,
        "real m046 full pipe write bounded", elapsed, error);
    check(!(fcntl(info.fd_child_to_parent_write, F_GETFL) & O_NONBLOCK),
        "caller blocking write descriptor flags restored");
    info.close_all();
    kill(child, SIGKILL);
    reap(child);
}
void expired_fork() {
    maplesu::sdk::fork_pipe_info info;
    maplesu_request_set_operation_deadline_nanos(now() - 1);
    errno = 0;
    const bool child = maplesu::sdk::fork_pipe_child_process(info);
    if (child) _exit(0);
    const int error = errno;
    maplesu_request_set_operation_deadline_nanos(0);
    check(info.child_pid <= 0 && error == ETIMEDOUT,
        "real m046 expired operation starts no worker", 0, error);
    if (info.child_pid > 0) reap(info.child_pid);
}
void wait_timeout(bool without_pidfd = false) {
    const auto child = fork();
    if (!child) { pause_child(); _exit(0); }
    maplesu_request_set_operation_deadline_nanos(now() + 25000000);
    missing_pidfd = without_pidfd;
    const auto start = now();
    int status = 0;
    errno = 0;
    const auto result = maplesu_wait_environment_child(child, &status);
    const auto elapsed = now() - start;
    const int error = errno;
    missing_pidfd = false;
    maplesu_request_set_operation_deadline_nanos(0);
    check((result < 0 || (result == child && WIFSIGNALED(status))) &&
        error == ETIMEDOUT && elapsed < 100000000,
        without_pidfd ? "actual m257 old-kernel fallback shares deadline" :
            "actual m257 wait body shares deadline", elapsed, error);
    if (result != child) { kill(child, SIGKILL); reap(child); }
}
void legacy_and_tls() {
    maplesu_request_set_operation_deadline_nanos(0);
    maplesu::sdk::fork_pipe_info info;
    if (maplesu::sdk::fork_pipe_child_process(info)) {
        const bool sent = maplesu::sdk::write_int_from_child(info, 42);
        _exit(sent ? 0 : 1);
    }
    int value = 0, status = 0;
    const bool read = maplesu::sdk::read_int_from_child(info, value);
    check(read && value == 42 && maplesu_wait_environment_child(info.child_pid, &status) == info.child_pid &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0, "deadline zero preserves legacy pipe and wait");
    info.close_all();
    const auto deadline = now() + 1000000000;
    check(maplesu_request_set_operation_deadline_nanos(deadline) == 0,
        "setter returns previous absolute deadline");
    bool isolated = false;
    std::thread worker([&] {
        isolated = maplesu_request_operation_deadline_nanos() == 0;
        maplesu_request_set_operation_deadline_nanos(17);
    });
    worker.join();
    check(isolated && maplesu_request_operation_deadline_nanos() == deadline,
        "m023 deadline TLS isolates threads");
    maplesu::sdk::fork_pipe_info child_info;
    if (maplesu::sdk::fork_pipe_child_process(child_info))
        _exit(maplesu_request_operation_deadline_nanos() == deadline ? 0 : 1);
    status = 0;
    const auto waited = maplesu_wait_environment_child(child_info.child_pid, &status);
    check(waited == child_info.child_pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "fork inherits identical absolute deadline");
    check(maplesu_request_set_operation_deadline_nanos(0) == deadline,
        "setter restores parent scope deadline");
    child_info.close_all();
}
}
int main() {
    signal(SIGPIPE, SIG_IGN);
    struct sigaction action{};
    action.sa_handler = +[](int) {};
    sigaction(SIGALRM, &action, nullptr);
    legacy_and_tls();
    read_timeout(false);
    read_timeout(true);
    partial_timeout();
    write_timeout();
    expired_fork();
    wait_timeout();
    wait_timeout(true);
    std::printf("sdk operation deadline checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
