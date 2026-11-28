#pragma once

#include "maplesu_deadline_private.h"
#include <cerrno>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace maplesu::deadline {

inline bool remaining(timespec& timeout) noexcept {
    const int64_t deadline = maplesu_request_operation_deadline_nanos();
    if (!deadline) { timeout = {}; return true; }
    timespec current{};
    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) return false;
    const int64_t now = int64_t(current.tv_sec) * 1000000000 + current.tv_nsec;
    if (now >= deadline) { errno = ETIMEDOUT; return false; }
    const int64_t left = deadline - now;
    timeout.tv_sec = static_cast<time_t>(left / 1000000000);
    timeout.tv_nsec = static_cast<long>(left % 1000000000);
    return true;
}

inline bool available() noexcept {
    timespec timeout{};
    return remaining(timeout);
}

inline bool wait_fd(int fd, short events) noexcept {
    for (;;) {
        timespec timeout{};
        if (!remaining(timeout)) return false;
        pollfd descriptor{fd, events, 0};
        const int result = ppoll(&descriptor, 1,
            maplesu_request_operation_deadline_nanos() ? &timeout : nullptr, nullptr);
        if (result > 0) {
            if (descriptor.revents & POLLNVAL) { errno = EBADF; return false; }
            return true; // Let the real read/write retain EOF, EPIPE and other errors.
        }
        if (result == 0) { errno = ETIMEDOUT; return false; }
        if (errno != EINTR) return false;
    }
}

inline pid_t wait_child(pid_t child, int* status) noexcept {
    if (child <= 0) { errno = ECHILD; return -1; }
    if (!maplesu_request_operation_deadline_nanos()) {
        pid_t result;
        do { result = waitpid(child, status, 0); } while (result < 0 && errno == EINTR);
        return result;
    }
    int descriptor = -1;
#ifdef SYS_pidfd_open
    descriptor = static_cast<int>(syscall(SYS_pidfd_open, child, 0));
#endif
    for (;;) {
        const pid_t result = waitpid(child, status, WNOHANG);
        if (result != 0) {
            if (result < 0 && errno == EINTR && available()) continue;
            const int error = errno;
            if (descriptor >= 0) close(descriptor);
            errno = error;
            return result;
        }
        timespec timeout{};
        if (!remaining(timeout)) {
            const int error = errno;
            if (descriptor >= 0) close(descriptor);
            errno = error;
            return -1;
        }
        pollfd event{descriptor, POLLIN, 0};
        // Kernels before pidfd support still wait for this same live child.
        // Each wait consumes the original budget; it never starts another query.
        if (descriptor < 0 && (timeout.tv_sec || timeout.tv_nsec > 1000000))
            timeout = {0, 1000000};
        const int ready = ppoll(descriptor >= 0 ? &event : nullptr,
            descriptor >= 0 ? 1 : 0, &timeout, nullptr);
        if (ready < 0 && errno != EINTR) {
            const int error = errno;
            if (descriptor >= 0) close(descriptor);
            errno = error;
            return -1;
        }
    }
}

} // namespace maplesu::deadline
