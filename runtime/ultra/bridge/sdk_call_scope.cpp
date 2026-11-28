#include "sdk_call_scope.h"
#include "../../maplesu-sdk/sdk/include/maplesu_deadline_private.h"
#include "../../maplesu-sdk/sdk/include/maplesu_operation_fork_private.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <new>
#include <pthread.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


extern "C" pid_t __real_fork();
extern "C" int __real_pipe2(int*, int);
extern "C" pid_t __real_waitpid(pid_t, int*, int);
extern "C" int __real_close(int);
extern "C" __attribute__((weak, visibility("hidden"))) void maplesu_hook_fork_prepare() noexcept;
extern "C" __attribute__((weak, visibility("hidden"))) void maplesu_hook_fork_complete() noexcept;

namespace maplesu {
struct SdkTransportOwner {
    std::atomic<unsigned> references{1};
    uint64_t generation = 0;
    pid_t pid = 0;
    bool owns_transport = true;
    unsigned reads = 0, writes = 0;
    std::atomic<uint32_t> fds{0};
    std::atomic<int> cleanup_error{0};
    std::atomic<bool> finalized{false}, admission_held{false};
    std::atomic<bool> queued{false}, worker_active{false};
    std::atomic<SdkTransportOwner*> pending_next{nullptr};
};
}

namespace {
thread_local maplesu::SdkCallContext* current_call = nullptr;
void record_process_error(int error) {
    if (current_call && !current_call->process_error) current_call->process_error = error;
}
enum Resource : unsigned {
    Environment = 1u << 0, Authorization = 1u << 1, Modules = 1u << 2,
    Policy = 1u << 3, Settings = 1u << 4, Log = 1u << 5,
    Execution = 1u << 6, WebUi = 1u << 7, Vendor = 1u << 8, Parasite = 1u << 9,
    All = (1u << 10) - 1,
};
constexpr unsigned resource_count = 10;
struct CallPolicy {
    maplesu::SdkCallAccess access;
    unsigned reads = 0, writes = 0;
    bool owned_transport = true;
};
bool named(const char* operation, std::initializer_list<const char*> names) {
    if (!operation) return false;
    for (const char* name : names) if (std::strcmp(operation, name) == 0) return true;
    return false;
}
CallPolicy call_policy(const char* operation) {
    using Access = maplesu::SdkCallAccess;
    if (named(operation, {"probe_manager_owner_root", "read_installed_helper"}))
        return {Access::Isolated};
    if (named(operation, {"get_sdk_version", "get_sdk_build_identity", "get_system_status",
                          "query_manager_owner_identity"}))
        return {Access::Local};
    if (named(operation, {"install_maplesu_environment", "uninstall_maplesu_environment", "restart_zygote64"}))
        return {Access::Exclusive, 0, All};
    if (named(operation, {"get_maplesu_environment_state", "get_installed_maplesu_environment_version",
                          "parse_module_desc_from_zip_file"}))
        return {Access::Read, Environment};
    if (named(operation, {"get_root_status_report", "run_root_cmd"}))
        // Each command owns its worker, credentials and output. Shell side effects
        // are not a process-global SDK transaction or an overview prerequisite.
        return {Access::Read, Environment | Execution};
    if (named(operation, {"get_su_auth_list", "get_su_uid_profiles", "get_su_runtime_status"}))
        return {Access::Read, Environment | Authorization};
    if (named(operation, {"add_su_auth_list", "refresh_su_auth_list", "remove_su_auth_list",
                          "clear_su_auth_list", "set_su_uid_profile"}))
        return {Access::Exclusive, Environment, Authorization};
    if (named(operation, {"get_all_modules_list", "get_module_control_capabilities", "get_module_control"}))
        return {Access::Read, Environment | Modules};
    if (named(operation, {"install_module", "install_module_dev_run_once", "uninstall_module", "set_module_enabled"}))
        return {Access::Exclusive, Environment, Modules | Policy | WebUi};
    if (named(operation, {"get_module_policy_settings"}))
        return {Access::Read, Environment | Policy};
    if (named(operation, {"publish_policy_backend", "set_module_policy_settings"}))
        return {Access::Exclusive, Environment | Modules, Policy};
    if (named(operation, {"start_module_web_ui_server_async"}))
        return {Access::Exclusive, Environment | Modules, WebUi};
    if (named(operation, {"is_boot_fail_protect_enabled", "is_adb_forced_disabled"}))
        return {Access::Read, Environment | Settings};
    if (named(operation, {"set_boot_fail_protect_enabled", "set_adb_forced_disabled"}))
        return {Access::Exclusive, Environment, Settings};
    if (named(operation, {"is_maplesu_log_enabled", "read_maplesu_log"}))
        return {Access::Read, Environment | Log};
    if (named(operation, {"set_maplesu_log_enabled", "clear_maplesu_log"}))
        return {Access::Exclusive, Environment, Log};
    if (named(operation, {"oneplus_bypass_is_work_normal"}))
        return {Access::Read, Environment | Vendor};
    if (named(operation, {"oneplus_bypass_stage1_and_2"}))
        return {Access::Exclusive, Environment, Vendor};
    if (named(operation, {"parasite_precheck_app"}))
        return {Access::Exclusive, Environment, Parasite};
    if (named(operation, {"parasite_implant_app", "parasite_implant_su_env"}))
        return {Access::Exclusive, Environment, Parasite};
    // Diagnostic item names include kernel writes; retain conservative exclusion.
    if (named(operation, {"test_maplesu_basics", "test_maplesu_default_module"}))
        return {Access::Exclusive, 0, All};
    return {Access::Exclusive, 0, All, false};
}
struct Admission {
    std::mutex mutex;
    std::condition_variable changed;
    unsigned readers[resource_count]{};
    unsigned writers_waiting[resource_count]{};
    unsigned writers = 0;
};
Admission*& admission_domain() {
    static Admission initial;
    static Admission* current = &initial;
    return current;
}
Admission& admission() { return *admission_domain(); }
using TransportOwner = maplesu::SdkTransportOwner;
enum class EndState { Open, Requested, Closing, Closed, Detached };
struct PipeEnd {
    int fd = -1;
    std::atomic<EndState> state{EndState::Closed};
    std::atomic<int> error{0};
};
struct QueryPipe {
    PipeEnd input, output;
    uint64_t generation = 0;
    TransportOwner* owner = nullptr;
    std::atomic<QueryPipe*> next{nullptr};
    QueryPipe* retired_next = nullptr;
};
struct QueryPipes {
    std::mutex mutex;
    std::atomic<QueryPipe*> entries{nullptr};
    std::atomic<unsigned> readers{0};
    QueryPipe* retired = nullptr;
};
QueryPipes& query_pipes() { static QueryPipes value; return value; }
std::atomic<uint64_t> next_generation{2};
std::atomic<TransportOwner*> pending_owners{nullptr};
// Odd means pthread_create is in progress; even means an actual worker exists.
std::atomic<uint64_t> cleanup_worker_state{0};
uint64_t new_generation() {
    auto value = next_generation.load();
    while (value <= UINT64_MAX - 2) {
        if (next_generation.compare_exchange_weak(value, value + 2)) return value;
    }
    errno = EOVERFLOW;
    return 0;
}
void retain_owner(TransportOwner* owner) { owner->references.fetch_add(1); }
void release_owner(TransportOwner* owner) {
    if (owner && owner->references.fetch_sub(1) == 1) delete owner;
}
void cleanup_error(TransportOwner* owner, int error) {
    int empty = 0;
    if (error) owner->cleanup_error.compare_exchange_strong(empty, error);
}
void reclaim_registry_locked(QueryPipes& pipes) {
    // Removal precedes this test. A later reader only sees the remaining list;
    // an older reader increments before loading head and keeps retired nodes alive.
    if (pipes.readers.load()) return;
    while (pipes.retired) {
        auto* entry = pipes.retired;
        pipes.retired = entry->retired_next;
        release_owner(entry->owner);
        delete entry;
    }
}
class RegistryRead final {
public:
    RegistryRead() : pipes_(query_pipes()), pid_(getpid()) { pipes_.readers.fetch_add(1); }
    ~RegistryRead() {
        if (pid_ != getpid()) return;
        if (pipes_.readers.fetch_sub(1) == 1) {
            const int error = errno;
            std::unique_lock lock(pipes_.mutex, std::try_to_lock);
            if (lock.owns_lock()) reclaim_registry_locked(pipes_);
            errno = error;
        }
    }
private:
    QueryPipes& pipes_;
    pid_t pid_;
};
class RegistryLock final {
public:
    RegistryLock() : pipes_(query_pipes()), lock_(pipes_.mutex, std::defer_lock) {}
    bool acquire(bool bounded) {
        if (bounded) {
            if (!maplesu::deadline::available()) return false;
            if (!lock_.try_lock()) {
                if (maplesu::deadline::available()) errno = EAGAIN;
                return false;
            }
            if (!maplesu::deadline::available()) return false;
        } else lock_.lock();
        return true;
    }
    ~RegistryLock() {
        const int error = errno;
        if (lock_.owns_lock()) reclaim_registry_locked(pipes_);
        errno = error;
    }
private:
    QueryPipes& pipes_;
    std::unique_lock<std::mutex> lock_;
};
bool terminal(const PipeEnd& end) {
    const auto state = end.state.load();
    return state == EndState::Closed || state == EndState::Detached;
}
void request_end(PipeEnd& end, TransportOwner* owner, bool close) {
    auto expected = EndState::Open;
    if (end.state.compare_exchange_strong(expected, close ? EndState::Requested : EndState::Detached) && !close)
        owner->fds.fetch_sub(1);
}
void close_requested_end(PipeEnd& end, TransportOwner* owner) {
    auto expected = EndState::Requested;
    if (!end.state.compare_exchange_strong(expected, EndState::Closing)) return;
    // The stable record, not an integer-only delayed request, owns this single
    // close. Never retry close: its FD number may already have been reused.
    const int result = __real_close(end.fd);
    const int error = result < 0 ? errno : 0;
    end.error.store(error);
    cleanup_error(owner, error);
    end.state.store(EndState::Closed);
    owner->fds.fetch_sub(1);
}
void drain_registry_locked() {
    auto& pipes = query_pipes();
    auto* link = &pipes.entries;
    for (auto* entry = link->load(); entry;) {
        if (entry->owner->finalized.load()) {
            request_end(entry->input, entry->owner, entry->owner->owns_transport);
            request_end(entry->output, entry->owner, entry->owner->owns_transport);
        }
        close_requested_end(entry->input, entry->owner);
        close_requested_end(entry->output, entry->owner);
        auto* next = entry->next.load();
        if (terminal(entry->input) && terminal(entry->output)) {
            link->store(next);
            entry->retired_next = pipes.retired;
            pipes.retired = entry;
        } else link = &entry->next;
        entry = next;
    }
}
bool release_admission(TransportOwner* owner, bool bounded) {
    if (!owner->admission_held.load() || owner->fds.load()) return !owner->admission_held.load();
    auto& state = admission();
    std::unique_lock lock(state.mutex, std::defer_lock);
    if (bounded) {
        if (!maplesu::deadline::available() || !lock.try_lock()) return false;
    } else lock.lock();
    if (owner->admission_held.exchange(false)) {
        for (unsigned i = 0; i < resource_count; ++i)
            if (owner->reads & (1u << i)) --state.readers[i];
        state.writers &= ~owner->writes;
    }
    lock.unlock();
    state.changed.notify_all();
    return true;
}
void queue_owner(TransportOwner* owner) {
    bool empty = false;
    if (!owner->queued.compare_exchange_strong(empty, true)) return;
    retain_owner(owner);
    auto* head = pending_owners.load();
    do { owner->pending_next.store(head); }
    while (!pending_owners.compare_exchange_weak(head, owner));
}
void* cleanup_worker(void*) {
    const auto token = cleanup_worker_state.load() & ~UINT64_C(1);
    auto starting = token | 1;
    cleanup_worker_state.compare_exchange_strong(starting, token);
    for (;;) {
        auto* batch = pending_owners.exchange(nullptr);
        if (!batch) {
            auto expected = cleanup_worker_state.load();
            while ((expected & ~UINT64_C(1)) == token &&
                !cleanup_worker_state.compare_exchange_weak(expected, 0)) {}
            if (!pending_owners.load()) return nullptr;
            expected = 0;
            if (!cleanup_worker_state.compare_exchange_strong(expected, token)) return nullptr;
            continue;
        }
        while (batch) {
            auto* owner = batch;
            batch = owner->pending_next.load();
            owner->worker_active.store(true);
            owner->queued.store(false);
            {
                RegistryLock lock;
                lock.acquire(false);
                drain_registry_locked();
            }
            if (owner->finalized.load()) release_admission(owner, false);
            owner->worker_active.store(false);
            release_owner(owner);
        }
    }
}
void start_cleanup_worker(TransportOwner* reporting_owner) {
    if (!pending_owners.load() || cleanup_worker_state.load()) return;
    const auto token = new_generation();
    if (!token) { if (reporting_owner) cleanup_error(reporting_owner, EOVERFLOW); return; }
    uint64_t empty = 0;
    if (!cleanup_worker_state.compare_exchange_strong(empty, token | 1)) return;
    pthread_attr_t attributes;
    int error = pthread_attr_init(&attributes);
    if (!error) {
        error = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        if (!error) {
            pthread_t thread;
            error = pthread_create(&thread, &attributes, cleanup_worker, nullptr);
            if (!error) {
                auto starting = token | 1;
                cleanup_worker_state.compare_exchange_strong(starting, token);
            }
        }
        const int destroyed = pthread_attr_destroy(&attributes);
        if (!error) error = destroyed;
    }
    if (error) {
        if (reporting_owner) cleanup_error(reporting_owner, error);
        auto starting = token | 1;
        cleanup_worker_state.compare_exchange_strong(starting, 0);
    }
}
void schedule_cleanup(TransportOwner* owner) {
    queue_owner(owner);
    start_cleanup_worker(owner);
}
void request_owner_cleanup(TransportOwner* owner) {
    RegistryRead read;
    for (auto* entry = query_pipes().entries.load(); entry; entry = entry->next.load()) {
        if (entry->owner == owner) {
            request_end(entry->input, owner, owner->owns_transport);
            request_end(entry->output, owner, owner->owns_transport);
        }
    }
}
bool transport_parent() { return current_call && current_call->owner_pid == getpid(); }
int64_t remaining_nanos(int64_t deadline) {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return std::max<int64_t>(0, deadline - (int64_t(now.tv_sec) * 1000000000 + now.tv_nsec));
}
}

namespace maplesu {
int64_t sdk_call_deadline_nanos() noexcept { return maplesu_request_operation_deadline_nanos(); }

SdkDeadlineScope::SdkDeadlineScope(int64_t deadline) noexcept : previous_(sdk_call_deadline_nanos()) {
    maplesu_request_set_operation_deadline_nanos(previous_ > 0 && deadline > 0
        ? std::min(previous_, deadline) : previous_ > 0 ? previous_ : deadline);
}

SdkDeadlineScope::~SdkDeadlineScope() { maplesu_request_set_operation_deadline_nanos(previous_); }

SdkCallAccess sdk_call_access(const char* operation) { return call_policy(operation).access; }

SdkCallScope::SdkCallScope(const char* operation) {
    // A new explicit SDK operation can resume a previously retained cleanup
    // whose worker creation failed. It never replays the original operation.
    start_cleanup_worker(nullptr);
    const auto policy = call_policy(operation);
    access_ = policy.access;
    read_mask_ = policy.reads & ~policy.writes;
    write_mask_ = policy.writes;
    owned_transport_ = policy.owned_transport;
    context_.owns_transport = owned_transport_;
    context_.owner_pid = getpid();
    const int64_t deadline = sdk_call_deadline_nanos();
    if (deadline > 0 && !remaining_nanos(deadline)) {
        deadline_exceeded_ = true;
        return;
    }
    if (access_ == SdkCallAccess::Local) { acquired_ = true; return; }
    std::unique_ptr<TransportOwner> owner(new TransportOwner);
    owner->generation = new_generation();
    if (!owner->generation) { context_.process_error = errno; return; }
    owner->pid = context_.owner_pid;
    owner->owns_transport = owned_transport_;
    owner->reads = read_mask_;
    owner->writes = write_mask_;
    if (access_ == SdkCallAccess::Isolated) {
        context_.retry_interrupted_wait = false;
    } else {
        auto& state = admission();
        std::unique_lock lock(state.mutex, std::defer_lock);
        if (deadline > 0 && !lock.try_lock()) {
            deadline_exceeded_ = !remaining_nanos(deadline);
            return;
        }
        if (deadline <= 0) lock.lock();
        const auto admissible = [&] {
            if (deadline > 0 && !remaining_nanos(deadline)) return false;
            if (state.writers & (read_mask_ | write_mask_)) return false;
            for (unsigned i = 0; i < resource_count; ++i) {
                if ((write_mask_ & (1u << i)) && state.readers[i]) return false;
                if ((read_mask_ & (1u << i)) && state.writers_waiting[i]) return false;
            }
            return true;
        };
        if (deadline > 0) acquired_ = admissible();
        else {
            for (unsigned i = 0; i < resource_count; ++i)
                if (write_mask_ & (1u << i)) ++state.writers_waiting[i];
            acquired_ = state.changed.wait_for(lock, std::chrono::nanoseconds(1500000000), admissible);
            for (unsigned i = 0; i < resource_count; ++i)
                if (write_mask_ & (1u << i)) --state.writers_waiting[i];
        }
        if (!acquired_) {
            deadline_exceeded_ = deadline > 0 && !remaining_nanos(deadline);
            state.changed.notify_all();
            return;
        }
        for (unsigned i = 0; i < resource_count; ++i)
            if (read_mask_ & (1u << i)) ++state.readers[i];
        state.writers |= write_mask_;
        owner->admission_held.store(true);
    }
    context_.transport_owner = owner.release();
    previous_call_ = current_call;
    current_call = &context_;
    acquired_ = true;
}

SdkCallScope::~SdkCallScope() {
    finalize();
    release_owner(context_.transport_owner);
}

SdkCallCompletion SdkCallScope::finalize() noexcept {
    SdkCallCompletion result;
    result.process_error = context_.process_error;
    auto* owner = context_.transport_owner;
    if (!acquired_ || access_ == SdkCallAccess::Local || !owner) return result;
    // SDK workers normally call _exit. Never unwind into copied admission/JNI.
    if (context_.owner_pid != getpid()) _exit(125);
    const int original_errno = errno;
    if (!finalized_) {
        finalized_ = true;
        owner->finalized.store(true);
        try {
            request_owner_cleanup(owner);
            {
                RegistryLock lock;
                if (lock.acquire(sdk_call_deadline_nanos() > 0)) drain_registry_locked();
            }
            release_admission(owner, sdk_call_deadline_nanos() > 0);
        } catch (...) {
            cleanup_error(owner, EIO);
        }
        if (owner->fds.load() || owner->admission_held.load()) schedule_cleanup(owner);
        current_call = previous_call_;
    }
    result.process_error = context_.process_error;
    result.cleanup_error = owner->cleanup_error.load();
    result.owner_generation = owner->generation;
    result.pending_fds = owner->fds.load();
    result.admission_release_pending = owner->admission_held.load();
    result.cleanup_pending = result.pending_fds || result.admission_release_pending;
    const auto worker = cleanup_worker_state.load();
    result.cleanup_scheduled = result.cleanup_pending && (owner->worker_active.load() ||
        (owner->queued.load() && worker && !(worker & 1)));
    errno = original_errno;
    return result;
}
}

// These are link-time wrappers inside this bridge only. Failed SDK setup leaves
// child_pid at zero; a group wait would otherwise consume another query's child.
extern "C" pid_t __wrap_fork() {
    // Publication precedes the pipe registry, including the real atfork callbacks.
    struct HookForkGuard {
        bool acquired = false, legacy = false;
        maplesu::deadline::ForkAdmission admission;
        HookForkGuard() {
            if (maplesu_request_operation_deadline_nanos()) acquired = admission.prepare();
            else {
                if (maplesu_hook_fork_prepare) { maplesu_hook_fork_prepare(); legacy = true; }
                acquired = true;
            }
        }
        ~HookForkGuard() {
            const int error = errno;
            if (legacy && maplesu_hook_fork_complete) maplesu_hook_fork_complete();
            errno = error;
        }
    } hook_fork_guard;
    if (!hook_fork_guard.acquired || !maplesu::deadline::available()) {
        record_process_error(errno);
        return -1;
    }
    // Keep this FD table stable across fork. Children release this same short lock,
    // then use only their own transport; they never touch the parent's registry.
    RegistryLock lock;
    if (!lock.acquire(maplesu_request_operation_deadline_nanos() > 0)) {
        record_process_error(errno);
        return -1;
    }
    auto& pipes = query_pipes();
    // Prepare an empty process domain in the parent. A child must never take
    // admission locks or reader/writer counts copied from vanished threads.
    (void)admission_domain();
    std::unique_ptr<Admission> child_admission(new (std::nothrow) Admission);
    if (!child_admission) { record_process_error(ENOMEM); errno = ENOMEM; return -1; }
    if (!maplesu::deadline::available()) { record_process_error(errno); return -1; }
    const pid_t result = __real_fork();
    if (result == 0) {
        for (auto* entry = pipes.entries.load(); entry; entry = entry->next.load()) {
            for (auto* end : {&entry->input, &entry->output})
                if (!terminal(*end) && (entry->owner != (current_call ? current_call->transport_owner : nullptr) ||
                    end->state.load() != EndState::Open)) __real_close(end->fd);
        }
        // Only this thread survives fork. Inherited readers, queue references
        // and worker flags belong to the parent; do not free copied heap state.
        pipes.entries.store(nullptr);
        pipes.retired = nullptr;
        pipes.readers.store(0);
        pending_owners.store(nullptr);
        cleanup_worker_state.store(0);
        admission_domain() = child_admission.release();
    } else if (result < 0) record_process_error(errno);
    return result;
}
extern "C" int __wrap_pipe2(int* fds, int flags) {
    if (!maplesu::deadline::available()) { record_process_error(errno); return -1; }
    if (!transport_parent()) {
        const int result = __real_pipe2(fds, flags);
        if (result < 0) record_process_error(errno);
        return result;
    }
    RegistryLock lock;
    if (!lock.acquire(maplesu_request_operation_deadline_nanos() > 0)) {
        record_process_error(errno);
        return -1;
    }
    std::unique_ptr<QueryPipe> entry(new (std::nothrow) QueryPipe);
    if (!entry) { record_process_error(ENOMEM); errno = ENOMEM; return -1; }
    entry->generation = new_generation();
    if (!entry->generation) { record_process_error(errno); return -1; }
    if (!maplesu::deadline::available()) { record_process_error(errno); return -1; }
    const int result = __real_pipe2(fds, flags);
    if (result == 0) {
        auto& pipes = query_pipes();
        entry->input.fd = fds[0];
        entry->output.fd = fds[1];
        entry->input.state.store(EndState::Open);
        entry->output.state.store(EndState::Open);
        entry->owner = current_call->transport_owner;
        retain_owner(entry->owner);
        entry->owner->fds.fetch_add(2);
        entry->next.store(pipes.entries.load());
        pipes.entries.store(entry.release());
    } else record_process_error(errno);
    return result;
}
extern "C" int __wrap_close(int fd) {
    if (current_call && current_call->owner_pid != getpid()) return __real_close(fd);
    RegistryRead read;
    for (auto* entry = query_pipes().entries.load(); entry; entry = entry->next.load()) {
        for (auto* end : {&entry->input, &entry->output}) {
            if (end->fd != fd || terminal(*end)) continue;
            auto expected = EndState::Open;
            if (!end->state.compare_exchange_strong(expected, EndState::Requested)) {
                // Another close already owns this generation. Never close its
                // numeric FD again, including after a later kernel reuse.
                errno = EBADF;
                return -1;
            }
            int admission_error = 0;
            {
                RegistryLock lock;
                if (lock.acquire(maplesu_request_operation_deadline_nanos() > 0)) drain_registry_locked();
                else admission_error = errno;
            }
            if (end->state.load() == EndState::Closed) {
                const int error = end->error.load();
                if (error) errno = error;
                return error ? -1 : 0;
            }
            schedule_cleanup(entry->owner);
            errno = admission_error ? admission_error : EAGAIN;
            return -1;
        }
    }
    return __real_close(fd);
}
extern "C" pid_t __wrap_waitpid(pid_t child, int* status, int flags) {
    if (!current_call) return __real_waitpid(child, status, flags);
    // Reads only wait for their own child. Preserve legacy group waits in
    // exclusive calls unless failed setup left the SDK's child PID at zero.
    if (child <= 0) {
        if (!current_call->owns_transport && !current_call->process_error) return __real_waitpid(child, status, flags);
        record_process_error(ECHILD);
        errno = ECHILD;
        return -1;
    }
    pid_t result;
    // Isolated workers own their deadline and finite EINTR retry budget.
    do { result = __real_waitpid(child, status, flags); } while (
        result < 0 && errno == EINTR && current_call->retry_interrupted_wait);
    if (result < 0 && (errno != EINTR || current_call->retry_interrupted_wait)) record_process_error(errno);
    return result;
}
