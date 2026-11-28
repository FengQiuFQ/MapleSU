#include <atomic>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fcntl.h>
#include <mutex>
#include <thread>
#include <unistd.h>

// Include the real wrappers so the event seam can hold their actual registry.
#include "../ultra/bridge/sdk_call_scope.cpp"

namespace fixture {
using Clock = std::chrono::steady_clock;
thread_local int64_t operation_deadline;
std::atomic<unsigned> pipe_calls{0}, close_calls{0}, fork_calls{0};
std::array<std::atomic<unsigned>, 4096> closes_by_fd{};
std::atomic<int> fail_close_fd{-1};
std::atomic<bool> fail_next_pipe{false};
std::atomic<bool> fail_cleanup_create{false};
std::atomic<unsigned> cleanup_starts{0}, cleanup_exits{0};
std::mutex observed_mutex;
std::condition_variable observed;
unsigned checks = 0, failures = 0;

int64_t now_nanos() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec;
}
void check(bool value, const char* expression, int line) {
    ++checks;
    if (!value) { ++failures; std::fprintf(stderr, "%d: %s\n", line, expression); }
}
#define CHECK(value) fixture::check((value), #value, __LINE__)

struct Event {
    std::mutex mutex;
    std::condition_variable changed;
    bool set = false;
    void signal() { std::lock_guard lock(mutex); set = true; changed.notify_all(); }
    void wait() { std::unique_lock lock(mutex); changed.wait(lock, [&] { return set; }); }
    bool until(Clock::time_point deadline) {
        std::unique_lock lock(mutex);
        return changed.wait_until(lock, deadline, [&] { return set; });
    }
};

bool closed(int fd) { errno = 0; return fcntl(fd, F_GETFD) == -1 && errno == EBADF; }
bool eventually_closed(int fd) {
    std::unique_lock lock(observed_mutex);
    return observed.wait_until(lock, Clock::now() + std::chrono::seconds(2), [&] { return closed(fd); });
}
bool workers_finished() {
    std::unique_lock lock(observed_mutex);
    return observed.wait_until(lock, Clock::now() + std::chrono::seconds(2), [&] {
        return cleanup_starts == cleanup_exits && !cleanup_worker_state.load();
    });
}

void expired_pipe() {
    operation_deadline = 0;
    maplesu::SdkCallScope scope("probe_manager_owner_root");
    CHECK(scope.acquired());
    operation_deadline = now_nanos() - 1;
    const auto before = pipe_calls.load();
    int fds[2] = {-1, -1};
    errno = 0;
    const int result = __wrap_pipe2(fds, O_CLOEXEC);
    const int error = errno;
    CHECK(result == -1 && error == ETIMEDOUT);
    CHECK(pipe_calls == before && fds[0] == -1 && fds[1] == -1);
    operation_deadline = 0;
    if (fds[0] >= 0) __wrap_close(fds[0]);
    if (fds[1] >= 0) __wrap_close(fds[1]);
}

enum class Contention { Pipe, Close, Destructor };
void contended(Contention kind) {
    Event ready, start, returned;
    int fds[2] = {-1, -1};
    int result = 0, error = 0;
    unsigned before = 0;
    std::thread caller([&] {
        operation_deadline = 0;
        {
            maplesu::SdkCallScope scope("probe_manager_owner_root");
            if (kind != Contention::Pipe) __wrap_pipe2(fds, O_CLOEXEC);
            ready.signal();
            start.wait();
            operation_deadline = now_nanos() + INT64_C(2000000000);
            if (kind == Contention::Pipe) {
                before = pipe_calls.load();
                result = __wrap_pipe2(fds, O_CLOEXEC);
                error = errno;
                returned.signal();
                operation_deadline = 0;
                if (fds[0] >= 0) __wrap_close(fds[0]);
                if (fds[1] >= 0) __wrap_close(fds[1]);
            } else if (kind == Contention::Close) {
                result = __wrap_close(fds[0]);
                error = errno;
                returned.signal();
            }
        }
        if (kind == Contention::Destructor) returned.signal();
    });
    ready.wait();
    bool before_unlock = false;
    {
        std::unique_lock lock(query_pipes().mutex);
        start.signal();
        before_unlock = returned.until(Clock::now() + std::chrono::milliseconds(100));
    }
    caller.join();
    CHECK(before_unlock);
    if (kind == Contention::Pipe) {
        CHECK(result == -1 && error == EAGAIN && pipe_calls == before);
    } else {
        if (kind == Contention::Close) CHECK(result == -1 && error == EAGAIN);
        CHECK(eventually_closed(fds[0]));
        CHECK(eventually_closed(fds[1]));
    }
    CHECK(workers_finished());
}

void completion_errors_and_idempotence() {
    operation_deadline = now_nanos() + INT64_C(2000000000);
    maplesu::SdkCallScope scope("get_su_auth_list");
    CHECK(scope.acquired());
    int fds[2];
    CHECK(__wrap_pipe2(fds, O_CLOEXEC) == 0);
    record_process_error(EPIPE);
    fail_close_fd = fds[0];
    errno = 0;
    CHECK(__wrap_close(fds[0]) == -1 && errno == EIO);
    errno = ENOENT;
    const auto completion = scope.finalize();
    CHECK(errno == ENOENT);
    CHECK(completion.process_error == EPIPE && completion.cleanup_error == EIO);
    CHECK(completion.owner_generation && !completion.pending_fds && !completion.cleanup_pending &&
        !completion.cleanup_scheduled && !completion.admission_release_pending);
    const auto count = close_calls.load();
    const auto again = scope.finalize();
    CHECK(again.owner_generation == completion.owner_generation && again.process_error == EPIPE &&
        again.cleanup_error == EIO && close_calls == count);
    CHECK(closed(fds[0]) && closed(fds[1]));
    CHECK(current_call == nullptr);
    CHECK(__real_close(-1) == -1 && errno == EBADF);
    operation_deadline = 0;
}

void partial_pipe_setup() {
    operation_deadline = now_nanos() + INT64_C(2000000000);
    maplesu::SdkCallScope scope("probe_manager_owner_root");
    CHECK(scope.acquired());
    int first[2], second[2] = {-1, -1};
    CHECK(__wrap_pipe2(first, O_CLOEXEC) == 0);
    const auto first_count = closes_by_fd[first[0]].load(), second_count = closes_by_fd[first[1]].load();
    const auto forks = fork_calls.load();
    fail_next_pipe = true;
    CHECK(__wrap_pipe2(second, O_CLOEXEC) == -1 && errno == EMFILE);
    CHECK(second[0] == -1 && second[1] == -1);
    const auto completion = scope.finalize();
    CHECK(completion.process_error == EMFILE && !completion.cleanup_error && !completion.cleanup_pending);
    CHECK(closed(first[0]) && closed(first[1]) && closes_by_fd[first[0]] == first_count + 1 &&
        closes_by_fd[first[1]] == second_count + 1);
    CHECK(fork_calls == forks);
    operation_deadline = 0;
}

void pending_owner_outlives_scope() {
    CHECK(workers_finished());
    operation_deadline = 0;
    auto scope = std::make_unique<maplesu::SdkCallScope>("probe_manager_owner_root");
    int fds[2];
    CHECK(__wrap_pipe2(fds, O_CLOEXEC) == 0);
    fail_cleanup_create = true;
    operation_deadline = now_nanos() - 1;
    maplesu::SdkCallCompletion completion;
    {
        std::unique_lock lock(query_pipes().mutex);
        completion = scope->finalize();
        scope.reset();
    }
    CHECK(completion.owner_generation && completion.pending_fds == 2 && completion.cleanup_pending &&
        !completion.cleanup_scheduled && !completion.admission_release_pending && completion.cleanup_error == EAGAIN);
    CHECK(!closed(fds[0]) && !closed(fds[1]));
    CHECK(current_call == nullptr && pending_owners.load() != nullptr);
    fail_cleanup_create = false;
    operation_deadline = 0;
    const auto calls = pipe_calls.load(), forks = fork_calls.load();
    { maplesu::SdkCallScope retry("get_system_status"); CHECK(retry.acquired()); }
    CHECK(eventually_closed(fds[0]) && eventually_closed(fds[1]));
    CHECK(workers_finished());
    CHECK(pipe_calls == calls && fork_calls == forks && !pending_owners.load());
}

void admission_release_and_admission_contention() {
    Event ready, start, returned;
    maplesu::SdkCallCompletion completion;
    std::thread caller([&] {
        operation_deadline = 0;
        maplesu::SdkCallScope scope("get_su_auth_list");
        ready.signal(); start.wait();
        operation_deadline = now_nanos() + INT64_C(2000000000);
        completion = scope.finalize();
        returned.signal();
    });
    ready.wait();
    bool promptly;
    {
        std::unique_lock lock(admission().mutex);
        start.signal();
        promptly = returned.until(Clock::now() + std::chrono::milliseconds(100));
    }
    caller.join();
    CHECK(promptly);
    CHECK(!completion.pending_fds && completion.admission_release_pending &&
        completion.cleanup_pending && completion.cleanup_scheduled && !completion.cleanup_error);
    CHECK(workers_finished());
    {
        std::lock_guard lock(admission().mutex);
        CHECK(!admission().readers[0] && !admission().readers[1]);
    }
    Event begin, done;
    bool acquired = true;
    std::thread blocked([&] {
        begin.wait();
        operation_deadline = now_nanos() + INT64_C(2000000000);
        maplesu::SdkCallScope scope("get_su_auth_list");
        acquired = scope.acquired();
        done.signal();
    });
    {
        std::unique_lock lock(admission().mutex);
        begin.signal();
        promptly = done.until(Clock::now() + std::chrono::milliseconds(100));
    }
    blocked.join();
    CHECK(promptly && !acquired);
}

void cross_owner_and_reused_number() {
    operation_deadline = now_nanos() + INT64_C(2000000000);
    maplesu::SdkCallScope outer("probe_manager_owner_root");
    int fds[2];
    CHECK(__wrap_pipe2(fds, O_CLOEXEC) == 0);
    const auto generation = current_call->transport_owner->generation;
    const auto first_close = closes_by_fd[fds[0]].load();
    {
        maplesu::SdkCallScope inner("read_installed_helper");
        CHECK(__wrap_close(fds[0]) == 0);
        const auto completion = inner.finalize();
        CHECK(completion.owner_generation != generation && !completion.pending_fds);
    }
    int replacement[2];
    CHECK(pipe2(replacement, O_CLOEXEC) == 0);
    // Reserve the old number as an unrelated, live object after the owned close.
    const int source = replacement[0] == fds[0] ? replacement[1] : replacement[0];
    CHECK(dup2(source, fds[0]) == fds[0]);
    const auto completion = outer.finalize();
    CHECK(completion.owner_generation == generation && !completion.cleanup_pending);
    CHECK(fcntl(fds[0], F_GETFD) >= 0);
    CHECK(closes_by_fd[fds[0]] == first_close + 1);
    close(fds[0]);
    if (replacement[0] != fds[0]) close(replacement[0]);
    if (replacement[1] != fds[0]) close(replacement[1]);
    operation_deadline = 0;
}

void legacy_async_ownership() {
    operation_deadline = 0;
    int fds[2];
    {
        maplesu::SdkCallScope scope("unknown-legacy-operation");
        CHECK(scope.acquired());
        CHECK(__wrap_pipe2(fds, O_CLOEXEC) == 0);
        const auto completion = scope.finalize();
        CHECK(!completion.cleanup_pending && !completion.pending_fds && !completion.admission_release_pending);
    }
    CHECK(fcntl(fds[0], F_GETFD) >= 0 && fcntl(fds[1], F_GETFD) >= 0);
    CHECK(__wrap_close(fds[0]) == 0 && __wrap_close(fds[1]) == 0);
}

void child_process_domain() {
    CHECK(workers_finished());
    operation_deadline = now_nanos() + INT64_C(2000000000);
    maplesu::SdkCallScope scope("probe_manager_owner_root");
    int inherited[2];
    CHECK(__wrap_pipe2(inherited, O_CLOEXEC) == 0);
    auto reader = std::make_unique<RegistryRead>();
    pid_t child;
    {
        std::unique_lock held_parent_admission(admission().mutex);
        child = __wrap_fork();
        if (!child) {
            reader.reset();
            bool ok = !query_pipes().readers.load() && !pending_owners.load() && !cleanup_worker_state.load();
            {
                maplesu::SdkCallScope nested("get_su_auth_list");
                int fds[2];
                ok = ok && nested.acquired() && __wrap_pipe2(fds, O_CLOEXEC) == 0;
                const auto completion = nested.finalize();
                ok = ok && !completion.cleanup_pending && !completion.cleanup_error;
            }
            __wrap_close(inherited[0]); __wrap_close(inherited[1]);
            _exit(ok ? 0 : 41);
        }
    }
    reader.reset();
    CHECK(child > 0);
    int status = -1;
    CHECK(__wrap_waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(!query_pipes().readers.load());
    CHECK(!scope.finalize().cleanup_pending);
    operation_deadline = 0;
}
} // namespace fixture

extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return fixture::operation_deadline; }
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t value) noexcept {
    const auto previous = fixture::operation_deadline; fixture::operation_deadline = value; return previous;
}
extern "C" int __real_pipe2(int* fds, int flags) {
    ++fixture::pipe_calls;
    if (fixture::fail_next_pipe.exchange(false)) { errno = EMFILE; return -1; }
    return pipe2(fds, flags);
}
extern "C" int __real_close(int fd) {
    ++fixture::close_calls;
    if (fd >= 0 && static_cast<size_t>(fd) < fixture::closes_by_fd.size()) ++fixture::closes_by_fd[fd];
    int result;
    {
        std::lock_guard lock(fixture::observed_mutex);
        result = close(fd);
    }
    int expected = fd;
    if (fd >= 0 && fixture::fail_close_fd.compare_exchange_strong(expected, -1)) { result = -1; errno = EIO; }
    fixture::observed.notify_all();
    return result;
}
extern "C" pid_t __real_fork() { ++fixture::fork_calls; return fork(); }
extern "C" pid_t __real_waitpid(pid_t child, int* status, int flags) { return waitpid(child, status, flags); }
extern "C" int __real_pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
void* observed_cleanup(void* argument) {
    const auto result = cleanup_worker(argument);
    {
        std::lock_guard lock(fixture::observed_mutex);
        ++fixture::cleanup_exits;
    }
    fixture::observed.notify_all();
    return result;
}
extern "C" int __wrap_pthread_create(pthread_t* thread, const pthread_attr_t* attributes,
    void* (*start)(void*), void* argument) {
    if (start != cleanup_worker) return __real_pthread_create(thread, attributes, start, argument);
    if (fixture::fail_cleanup_create) return EAGAIN;
    ++fixture::cleanup_starts;
    const int result = __real_pthread_create(thread, attributes, observed_cleanup, argument);
    if (result) --fixture::cleanup_starts;
    return result;
}

int main() {
    fixture::expired_pipe();
    fixture::contended(fixture::Contention::Pipe);
    fixture::contended(fixture::Contention::Close);
    fixture::contended(fixture::Contention::Destructor);
    fixture::completion_errors_and_idempotence();
    fixture::partial_pipe_setup();
    fixture::pending_owner_outlives_scope();
    fixture::admission_release_and_admission_contention();
    fixture::cross_owner_and_reused_number();
    fixture::legacy_async_ownership();
    fixture::child_process_domain();
    CHECK(fixture::workers_finished());
    std::printf("registry lifecycle checks=%u failures=%u pipe_calls=%u close_calls=%u fork_calls=%u\n",
        fixture::checks, fixture::failures, fixture::pipe_calls.load(), fixture::close_calls.load(), fixture::fork_calls.load());
    return fixture::failures ? 1 : 0;
}
