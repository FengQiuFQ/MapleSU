#include "manager_owner_root_probe.h"
#include "sdk_call_scope.h"
#include "manager_owner_identity.h"
#include "../../maplesu-sdk/sdk/include/maplesu_request_private.h"
#include "../../maplesu-sdk/sdk/include/maplesu_caps_private.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <poll.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <type_traits>
#include <unistd.h>

extern "C" __attribute__((visibility("hidden"))) void maplesu_request_fork_prepare() noexcept;

namespace maplesu {
namespace {
using Clock = std::chrono::steady_clock;
using namespace kernel_module;
static_assert(std::is_trivially_copyable_v<ManagerOwnerRootProbe>);
static_assert(std::atomic<uint32_t>::is_always_lock_free);

// A credential transition can revoke writes to an inherited app-labelled pipe.
// Keep fixed same-image receipts in this fork's anonymous mapping; the existing
// pipe only signals EOF and never needs a write from the elevated child.
struct RootProbeReceipt {
    uint32_t magic = 0x4d535250, version = 1;
    std::atomic<uint32_t> committed{0};
    ManagerOwnerRootProbe checkpoint, final;
};
static_assert(sizeof(RootProbeReceipt) <= 4096);

struct ReceiptMapping {
    RootProbeReceipt* value = nullptr;
    bool child_reaped = false;
    ReceiptMapping() {
        void* memory = mmap(nullptr, sizeof(RootProbeReceipt), PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (memory != MAP_FAILED) value = new (memory) RootProbeReceipt{};
    }
    ~ReceiptMapping() {
        if (!value) return;
        // A still-running child's mapping owns its own lifetime until _exit.
        if (child_reaped) {
            volatile unsigned char* bytes = reinterpret_cast<volatile unsigned char*>(value);
            for (size_t left = sizeof(*value); left; --left) *bytes++ = 0;
        }
        munmap(value, sizeof(*value));
    }
};

std::atomic<uint64_t> probe_slot{0};
std::atomic<uint64_t> wait_owner{0};
uint64_t slot_for(pid_t parent, pid_t child = 0) {
    return (uint64_t(static_cast<uint32_t>(parent)) << 32) | static_cast<uint32_t>(child);
}

int budget_ms(const timespec& deadline) {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -errno;
    const int64_t left = int64_t(deadline.tv_sec - now.tv_sec) * INT64_C(1000000000) +
        deadline.tv_nsec - now.tv_nsec;
    return left <= 0 ? 0 : static_cast<int>((left + 999999) / 1000000);
}

pid_t wait_nonblocking(pid_t child, int& status, const timespec& deadline, int& error) {
    for (;;) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited >= 0) { error = 0; return waited; }
        error = errno;
        if (error != EINTR) return -1;
        const int budget = budget_ms(deadline);
        if (budget <= 0) { error = budget ? -budget : ETIMEDOUT; return -1; }
    }
}

void pending_facts(ManagerOwnerRootProbe& result, uint64_t slot) {
    result.probe_admission_error = EINPROGRESS;
    if (static_cast<uint32_t>(slot)) {
        result.child_pid = static_cast<uint32_t>(slot);
        result.cleanup_pending = true;
        result.cleanup_scheduled = wait_owner.load(std::memory_order_acquire) == slot;
    }
}

bool admit_probe(ManagerOwnerRootProbe& result, const timespec& deadline, uint64_t& lease) {
    const auto parent = getpid();
    lease = slot_for(parent);
    auto owner = wait_owner.load(std::memory_order_acquire);
    if (owner && static_cast<uint32_t>(owner >> 32) != static_cast<uint32_t>(parent))
        wait_owner.compare_exchange_strong(owner, 0, std::memory_order_acq_rel);
    auto slot = probe_slot.load(std::memory_order_acquire);
    if (slot && static_cast<uint32_t>(slot >> 32) != static_cast<uint32_t>(parent)) {
        if (probe_slot.compare_exchange_strong(slot, lease, std::memory_order_acq_rel)) return true;
        pending_facts(result, slot); return false;
    }
    if (!slot) {
        if (!wait_owner.load(std::memory_order_acquire) &&
            probe_slot.compare_exchange_strong(slot, lease, std::memory_order_acq_rel)) return true;
        pending_facts(result, slot); return false;
    }
    if (!static_cast<uint32_t>(slot)) { pending_facts(result, slot); return false; }
    owner = 0;
    if (!wait_owner.compare_exchange_strong(owner, slot, std::memory_order_acq_rel)) {
        pending_facts(result, slot); return false;
    }
    if (probe_slot.load(std::memory_order_acquire) != slot) {
        auto expected = slot;
        wait_owner.compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
        pending_facts(result, probe_slot.load(std::memory_order_acquire)); return false;
    }
    int status = 0, error = 0;
    const pid_t waited = wait_nonblocking(static_cast<pid_t>(static_cast<uint32_t>(slot)), status, deadline, error);
    const bool reclaimed = waited > 0 || (waited < 0 && error == ECHILD);
    auto expected = slot;
    const bool admitted = reclaimed && probe_slot.compare_exchange_strong(expected, lease, std::memory_order_acq_rel);
    if (waited < 0) result.cleanup_error = error;
    if (!admitted) pending_facts(result, slot);
    expected = slot;
    wait_owner.compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
    if (!admitted) result.cleanup_scheduled = false;
    return admitted;
}

void* reap_probe(void* value) {
    const auto child = static_cast<pid_t>(reinterpret_cast<uintptr_t>(value));
    const auto slot = slot_for(getpid(), child);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited == child || (waited < 0 && errno == ECHILD)) {
        auto expected = slot;
        probe_slot.compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
    }
    auto expected = slot;
    wait_owner.compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
    return nullptr;
}

void defer_cleanup(pid_t child, ManagerOwnerRootProbe& result) {
    const auto slot = slot_for(getpid(), child);
    // Publish the wait owner first; entry probes never race a reaper for the PID.
    wait_owner.store(slot, std::memory_order_release);
    probe_slot.store(slot, std::memory_order_release);
    result.cleanup_pending = true;
    pthread_attr_t attributes;
    int error = pthread_attr_init(&attributes);
    if (!error) {
        error = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        if (!error) {
            pthread_t thread;
            error = pthread_create(&thread, &attributes, reap_probe,
                reinterpret_cast<void*>(static_cast<uintptr_t>(child)));
            result.cleanup_scheduled = !error;
        }
        const int destroy_error = pthread_attr_destroy(&attributes);
        if (!error) error = destroy_error;
    }
    if (error && !result.cleanup_error) result.cleanup_error = error;
    if (!result.cleanup_scheduled) {
        auto expected = slot;
        wait_owner.compare_exchange_strong(expected, 0, std::memory_order_acq_rel);
    }
}

int arm_watchdog(const timespec& deadline) {
    sigevent event{};
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGKILL;
    timer_t timer;
    if (timer_create(CLOCK_MONOTONIC, &event, &timer) != 0) return errno;
    itimerspec expiration{};
    expiration.it_value = deadline;
    if (timer_settime(timer, TIMER_ABSTIME, &expiration, nullptr) != 0) return errno;
    return 0;
}

void copy_reply(ManagerOwnerRootCommand& out, const RequestManagementReply& reply) {
    out.reply_observed = reply.command != 0;
    out.command = reply.command;
    out.status = reply.status;
    out.result = reply.result;
    out.handle = reply.handle;
    out.effects = reply.effects;
    out.completed = reply.completed;
}

int read_cap_limit(int32_t& last, uint64_t& mask) {
    const int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    char text[16]{};
    size_t used = 0;
    int error = 0;
    while (used < sizeof(text) - 1) {
        const ssize_t count = read(fd, text + used, sizeof(text) - 1 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { error = errno; break; }
        if (!count) break;
        used += static_cast<size_t>(count);
    }
    if (close(fd) < 0 && !error) error = errno;
    if (error) return error;
    if (!used || used == sizeof(text) - 1) return EPROTO;
    char* end = nullptr;
    errno = 0;
    const long value = strtol(text, &end, 10);
    if (errno || end == text || value < 0 || value > 63) return EPROTO;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') ++end;
    if (*end) return EPROTO;
    last = static_cast<int32_t>(value);
    mask = value == 63 ? UINT64_MAX : (UINT64_C(1) << (value + 1)) - 1;
    return 0;
}

void observe_credentials(ManagerOwnerRootCredentials& out) {
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) == 0) {
        out.ruid = ruid; out.euid = euid; out.suid = suid;
        out.uid_observed = true;
    } else out.uid_error = errno;
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) == 0) {
        out.rgid = rgid; out.egid = egid; out.sgid = sgid;
        out.gid_observed = true;
    } else out.gid_error = errno;
    caps_info caps{};
    out.caps_error = static_cast<int64_t>(get_current_caps_snapshot(caps, out.ambient_present));
    if (!out.caps_error) {
        out.inheritable = caps.inheritable; out.permitted = caps.permitted;
        out.effective = caps.effective; out.bounding = caps.bounding; out.ambient = caps.ambient;
        out.caps_observed = true;
    }
    out.cap_limit_error = read_cap_limit(out.cap_last_cap, out.capability_mask);
    out.cap_limit_observed = !out.cap_limit_error;
    const int bits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    if (bits >= 0) { out.securebits = bits; out.securebits_observed = true; }
    else out.securebits_error = errno;
    const uint64_t mask = out.capability_mask;
    out.matches_root = out.uid_observed && out.gid_observed &&
        !out.ruid && !out.euid && !out.suid && !out.rgid && !out.egid && !out.sgid &&
        out.caps_observed && out.ambient_present && out.cap_limit_observed &&
        out.inheritable == mask && out.permitted == mask && out.effective == mask &&
        out.bounding == mask && out.ambient == mask && out.securebits_observed && !out.securebits;
}

[[noreturn]] void probe_child(int input, int output, const timespec& deadline, RootProbeReceipt& receipt) {
    ManagerOwnerRootProbe result;
    result.child_pid = static_cast<uint32_t>(getpid());
    result.watchdog_error = arm_watchdog(deadline);
    result.watchdog_armed = !result.watchdog_error;
    if (close(input) < 0) result.child_io_error = errno;
    signal(SIGPIPE, SIG_IGN);
    if (result.watchdog_armed) try {
        result.mode_error = static_cast<int64_t>(maplesu_request_set_auth_mode(RequestAuthMode::ManagerOwner));
        result.mode_selected = !result.mode_error;
        if (result.mode_selected) {
            maplesu_metadata_owner_v3 metadata{};
            uint64_t descriptor = 0;
            RequestOwnerBinding binding{};
            result.channel_error = static_cast<int64_t>(maplesu_request_owner_channel(metadata, descriptor, binding));
            result.owner_bound = !result.channel_error;
            if (result.owner_bound) {
                result.owner_full_uid = metadata.owner_full_uid;
                result.owner_epoch = metadata.owner_epoch;
                result.host_low = metadata.host.low; result.host_high = metadata.host.high;
                result.owner_capabilities = metadata.common.capabilities;
                result.root.attempted = true;
                result.root.error = static_cast<int64_t>(maplesu_request_owner_root());
            }
        }
    } catch (...) {
        result.child_exception = true;
        if (result.root.attempted) result.root.error = static_cast<int64_t>(KModErr::ERR_MODULE_TEST_CHANNEL);
    }
    if (result.root.attempted) {
        copy_reply(result.root, maplesu_request_management_reply());
        result.root_committed = result.root.completed && result.root.command == MAPLESU_REQUEST_CRED_ROOT &&
            (result.root.effects & MAPLESU_EFFECT_COMMITTED);
        try { observe_credentials(result.credentials); }
        catch (...) { result.child_exception = true; }
        result.root_verified = result.root_committed && !result.root.error && !result.root.status &&
            !result.child_exception && result.credentials.matches_root;
    }
    // Publish confirmed Root facts before cleanup; a failed CLOSE cannot erase them.
    result.root_checkpoint_received = true;
    receipt.checkpoint = result;
    receipt.committed.store(1, std::memory_order_release);
    if (result.mode_selected) {
        result.close.attempted = true;
        try { result.close.error = static_cast<int64_t>(maplesu_request_owner_close()); }
        catch (...) {
            result.child_exception = true;
            result.close.error = static_cast<int64_t>(KModErr::ERR_MODULE_TEST_CHANNEL);
        }
        const auto reply = maplesu_request_management_reply();
        // A local no-op CLOSE leaves the prior getter value; it is not a new receipt.
        if (reply.command == MAPLESU_REQUEST_SESSION_CLOSE) copy_reply(result.close, reply);
    }
    result.receipt_complete = true;
    receipt.final = result;
    receipt.committed.store(3, std::memory_order_release);
    const bool delivered = close(output) == 0;
    _exit(delivered && !result.child_io_error ? 0 : 1);
}

int read_receipt(const RootProbeReceipt& receipt, pid_t child, ManagerOwnerRootProbe& result) {
    const uint32_t committed = receipt.committed.load(std::memory_order_acquire);
    if (receipt.magic != 0x4d535250 || receipt.version != 1 || (committed != 1 && committed != 3)) return EPROTO;
    for (unsigned frame = 0; frame < (committed == 3 ? 2u : 1u); ++frame) {
        const auto& snapshot = frame ? receipt.final : receipt.checkpoint;
        const auto& root = snapshot.root;
        const bool root_committed = root.completed && root.command == MAPLESU_REQUEST_CRED_ROOT &&
            (root.effects & MAPLESU_EFFECT_COMMITTED);
        if (snapshot.abi_version != 1 || snapshot.child_pid != static_cast<uint32_t>(child) ||
            !snapshot.root_checkpoint_received || snapshot.receipt_complete != (frame == 1) ||
            (snapshot.owner_bound && !snapshot.mode_selected) ||
            (root.attempted && !snapshot.owner_bound) ||
            (root.completed && (!root.attempted || !root.reply_observed || root.command != MAPLESU_REQUEST_CRED_ROOT)) ||
            snapshot.root_committed != root_committed ||
            (frame && snapshot.root_verified != receipt.checkpoint.root_verified) ||
            (snapshot.root_verified && (!root_committed || root.error || root.status ||
                (!frame && snapshot.child_exception) || !snapshot.credentials.matches_root))) return EPROTO;
        result = snapshot;
    }
    return committed == 3 ? 0 : EPIPE;
}

int read_eof(int fd, const timespec& deadline) {
    for (;;) {
        const int budget = budget_ms(deadline);
        if (budget <= 0) return budget ? -budget : ETIMEDOUT;
        pollfd watch{fd, POLLIN, 0};
        const int ready = poll(&watch, 1, budget);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return errno;
        if (!ready) return ETIMEDOUT;
        if (watch.revents & POLLNVAL) return EBADF;
        char extra;
        const ssize_t count = read(fd, &extra, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return errno;
        return count ? EPROTO : 0;
    }
}
} // namespace

ManagerOwnerRootProbe probe_manager_owner_root() { return probe_manager_owner_root(0); }

ManagerOwnerRootProbe probe_manager_owner_root(int64_t session_deadline_nanos) {
    ManagerOwnerRootProbe result;
    const auto start = Clock::now();
    timespec deadline{};
    uint64_t lease = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) result.watchdog_error = errno;
    else {
        deadline.tv_nsec += 300000000;
        if (deadline.tv_nsec >= 1000000000) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000; }
        if (session_deadline_nanos > 0 && session_deadline_nanos <
            int64_t(deadline.tv_sec) * INT64_C(1000000000) + deadline.tv_nsec) {
            deadline.tv_sec = static_cast<time_t>(session_deadline_nanos / INT64_C(1000000000));
            deadline.tv_nsec = static_cast<long>(session_deadline_nanos % INT64_C(1000000000));
        }
        SdkDeadlineScope sdk_deadline(int64_t(deadline.tv_sec) * INT64_C(1000000000) + deadline.tv_nsec);
        const int64_t operation_deadline = sdk_call_deadline_nanos();
        deadline.tv_sec = static_cast<time_t>(operation_deadline / INT64_C(1000000000));
        deadline.tv_nsec = static_cast<long>(operation_deadline % INT64_C(1000000000));
        const int budget = budget_ms(deadline);
        if (budget <= 0) {
            result.transport_error = budget ? -budget : ETIMEDOUT;
            result.timed_out = !budget;
        } else if (const auto admission = manager_worker_admission(); is_failed(admission)) {
            result.channel_error = static_cast<int64_t>(admission);
        } else if (const int remaining = budget_ms(deadline); remaining <= 0) {
            result.transport_error = remaining ? -remaining : ETIMEDOUT;
            result.timed_out = !remaining;
        } else if (admit_probe(result, deadline, lease)) {
            const int prior_cleanup_error = result.cleanup_error;
            ReceiptMapping receipt;
            int fds[2];
            if (!receipt.value || pipe2(fds, O_CLOEXEC) != 0) {
                result.transport_error = errno;
                probe_slot.compare_exchange_strong(lease, 0, std::memory_order_acq_rel);
            } else {
                maplesu_request_fork_prepare();
                const int remaining = budget_ms(deadline);
                const pid_t child = remaining > 0 ? fork() : -1;
                if (!child) probe_child(fds[0], fds[1], deadline, *receipt.value);
                if (child < 0) {
                    result.transport_error = remaining > 0 ? errno : remaining ? -remaining : ETIMEDOUT;
                    result.timed_out = !remaining;
                    receipt.child_reaped = true;
                    close(fds[0]); close(fds[1]);
                    probe_slot.compare_exchange_strong(lease, 0, std::memory_order_acq_rel);
                } else {
                    int transport_error = close(fds[1]) < 0 ? errno : 0;
                    bool receive_failed = false;
                    const int eof_error = read_eof(fds[0], deadline);
                    const int receipt_error = read_receipt(*receipt.value, child, result);
                    if (eof_error || receipt_error) {
                        if (!transport_error) transport_error = eof_error ? eof_error : receipt_error;
                        result.timed_out = eof_error == ETIMEDOUT || budget_ms(deadline) == 0;
                        receive_failed = true;
                    }
                    result.child_pid = static_cast<uint32_t>(child);
                    result.cleanup_error = prior_cleanup_error;
                    if (close(fds[0]) < 0 && !transport_error) transport_error = errno;
                    result.transport_error = transport_error;
                    if (receive_failed) {
                        result.termination_requested = true;
                        if (kill(child, SIGKILL) < 0 && errno != ESRCH) result.termination_error = errno;
                    }
                    int error = 0;
                    const pid_t waited = wait_nonblocking(child, result.child_status, deadline, error);
                    if (waited == child) result.child_status_valid = true;
                    else if (waited < 0) result.wait_error = error;
                    receipt.child_reaped = waited == child || (waited < 0 && error == ECHILD);
                    if (receipt.child_reaped)
                        probe_slot.compare_exchange_strong(lease, 0, std::memory_order_acq_rel);
                    else defer_cleanup(child, result);
                    if (result.child_status_valid && (!WIFEXITED(result.child_status) || WEXITSTATUS(result.child_status) != 0) &&
                        !result.wait_error) result.wait_error = EPROTO;
                }
            }
        }
    }
    result.elapsed_us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    return result;
}

} // namespace maplesu
