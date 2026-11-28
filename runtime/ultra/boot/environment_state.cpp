#include "module_err_def.h"
#include "maplesu_operation_wait_private.h"
#include "maplesu_storage_worker_private.h"
#include <tuple>
#include "maplesu_sdk/maplesu_installer.h"
#include <cerrno>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// The installer supplies paths from the worker's authenticated deployment namespace.
extern "C" void maplesu_environment_paths(std::string*, std::string*);
namespace default_modules::module_root { KModErr set_current_root(bool); }

namespace {
using State = maplesu::sdk::MapleSUEnvState;

int present(const std::string& path) {
    if (!maplesu::deadline::available()) return -1;
    struct stat st;
    if (lstat(path.c_str(), &st) == 0) return S_ISREG(st.st_mode) ? 1 : -1;
    return errno == ENOENT ? 0 : -1;
}

bool space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

bool read_text(const std::string& path, std::string& text) {
    if (!maplesu::deadline::available()) return false;
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
    char bytes[65];
    size_t size = 0;
    while (ok && size < sizeof(bytes)) {
        if (!maplesu::deadline::available()) { ok = false; break; }
        const auto count = read(fd, bytes + size, sizeof(bytes) - size);
        if (count < 0) { if (errno == EINTR) continue; ok = false; break; }
        if (!count) break;
        size += static_cast<size_t>(count);
    }
    if (close(fd) != 0 || size == sizeof(bytes)) ok = false;
    if (!ok) return false;
    size_t first = 0;
    while (first < size && space(bytes[first])) ++first;
    while (size > first && space(bytes[size - 1])) --size;
    text.assign(bytes + first, size - first);
    return true;
}

bool uuid(const std::string& text) {
    if (text.size() != 36) return false;
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return false; }
        else if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F')) return false;
    }
    return true;
}
}

extern "C" uint32_t maplesu_environment_state() noexcept {
    try {
        if (!maplesu::deadline::available()) return static_cast<uint32_t>(State::Unknown);
        maplesu::storage::WorkerScope worker;
        if (is_failed(worker.root())) return static_cast<uint32_t>(State::Unknown);
        std::string helper, version;
        maplesu_environment_paths(&helper, &version);
        if (helper.empty() || version.empty()) return static_cast<uint32_t>(State::Unknown);
        const int executable = present(helper), stamp = present(version);
        if (executable == 0 && stamp == 0) return static_cast<uint32_t>(State::NotInstalled);
        // A partial installation, unreadable file or boot in progress proves neither
        // absence nor a failed bootstrap. Queries never alter persistent protection.
        if (executable != 1) return static_cast<uint32_t>(State::Unknown);
        std::string boot, flag, receipt;
        if (!read_text("/proc/sys/kernel/random/boot_id", boot) || !uuid(boot) ||
            !read_text(helper + ".safe_flag", flag)) return static_cast<uint32_t>(State::Unknown);
        if (flag == "3") {
            // The bootstrap writes its current duplicate guard before taking the
            // protection branch. A previous boot's flag alone is insufficient.
            if (present(helper + ".boot_fail_protect") == 1 &&
                read_text(helper + ".boot_session.duplicate", receipt) && receipt == boot)
                return static_cast<uint32_t>(State::Fault);
            return static_cast<uint32_t>(State::Unknown);
        }
        if (stamp != 1) return static_cast<uint32_t>(State::Unknown);
        // The legacy native module installer/uninstaller clears safe_flag. Only
        // a separate receipt from successful bootstrap may survive that reset.
        const bool completed = flag == "2" || (flag.empty() &&
            read_text(helper + ".boot_session.completed", receipt) && receipt == boot);
        if (completed && read_text(helper + ".boot_session.work", receipt) && receipt == boot)
            return static_cast<uint32_t>(State::Running);
    } catch (...) {
        // This executes inside the SDK query worker; never unwind into the caller's
        // copied JVM/admission state or fabricate a successful observation.
    }
    return static_cast<uint32_t>(State::Unknown);
}

extern "C" pid_t maplesu_wait_environment_child(pid_t child, int* status) {
    const pid_t waited = maplesu::deadline::wait_child(child, status);
    if (waited >= 0 || !maplesu_request_operation_deadline_nanos()) return waited;
    const int error = errno;
    if (error == ETIMEDOUT) {
        (void)kill(child, SIGKILL);
        // Never extend the caller's budget for a grace period. A pending reap
        // remains an unconfirmed cleanup; task exit still retires its lease.
        if (waitpid(child, status, WNOHANG) == child) { errno = error; return child; }
    }
    errno = error;
    return -1;
}
