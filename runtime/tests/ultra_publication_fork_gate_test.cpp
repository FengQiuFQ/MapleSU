#include <algorithm>
#include "../maplesu-sdk/sdk/src/func_hook/module_base_kernel_func_hook.cpp"
#include "../maplesu-sdk/sdk/include/maplesu_deadline_private.h"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <thread>
#include <sys/wait.h>

extern "C" __attribute__((weak)) bool maplesu_hook_try_fork_prepare() noexcept;
extern "C" pid_t __real_fork();

namespace {
using Clock = std::chrono::steady_clock;
thread_local int64_t deadline_nanos;
unsigned checks, failures, forks;
unsigned managed_depth;
bool managed_busy;

int64_t now_nanos() {
    timespec value{};
    clock_gettime(CLOCK_MONOTONIC, &value);
    return int64_t(value.tv_sec) * INT64_C(1000000000) + value.tv_nsec;
}
void check(bool value, const char* expression, int line) {
    ++checks;
    if (!value) { ++failures; std::fprintf(stderr, "%d: %s\n", line, expression); }
}
#define CHECK(value) check((value), #value, __LINE__)
bool other_thread_can_lock() {
    bool acquired = false;
    std::thread thread([&] {
        acquired = kernel_module::publication_mutex.try_lock();
        if (acquired) kernel_module::publication_mutex.unlock();
    });
    thread.join();
    return acquired;
}
void finish_child(pid_t child) {
    if (!child) _exit(0);
    if (child < 0) return;
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
void expired() {
    deadline_nanos = now_nanos() - 1;
    const auto before = forks;
    errno = 0;
    const pid_t child = fork();
    const int error = errno;
    finish_child(child);
    CHECK(child == -1 && error == ETIMEDOUT && forks == before);
    CHECK(other_thread_can_lock());
}
void contended(bool bounded) {
    std::mutex mutex;
    std::condition_variable changed;
    bool entered = false, release = false;
    std::thread producer([&] {
        kernel_module::PublicationOperation operation;
        std::unique_lock lock(mutex);
        entered = true;
        changed.notify_one();
        changed.wait_for(lock, std::chrono::milliseconds(100), [&] { return release; });
    });
    {
        std::unique_lock lock(mutex);
        changed.wait(lock, [&] { return entered; });
    }
    deadline_nanos = bounded ? now_nanos() + 20000000 : 0;
    const auto before = forks;
    const auto began = Clock::now();
    errno = 0;
    const pid_t child = fork();
    const int error = errno;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - began).count();
    finish_child(child);
    {
        std::lock_guard lock(mutex);
        release = true;
    }
    changed.notify_one();
    producer.join();
    CHECK(bounded ? child == -1 && error == EAGAIN && forks == before && elapsed < 75 : child > 0 && forks == before + 1);
    CHECK(other_thread_can_lock());
}
void nested(bool reject) {
    maplesu_hook_fork_prepare();
    CHECK(!other_thread_can_lock());
    deadline_nanos = reject ? now_nanos() - 1 : now_nanos() + 1000000000;
    const auto before = forks;
    errno = 0;
    const pid_t child = fork();
    const int error = errno;
    finish_child(child);
    CHECK(reject ? child == -1 && error == ETIMEDOUT && forks == before : child > 0 && forks == before + 1);
    CHECK(!other_thread_can_lock());
    maplesu_hook_fork_complete();
    CHECK(other_thread_can_lock());
}
}

extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return deadline_nanos; }
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t value) noexcept {
    const auto previous = deadline_nanos; deadline_nanos = value; return previous;
}
extern "C" bool maplesu_request_try_fork_prepare() noexcept {
    if (managed_busy) { errno = EAGAIN; return false; }
    ++managed_depth; return true;
}
extern "C" void maplesu_request_fork_complete() noexcept { if (managed_depth) --managed_depth; }

int main() {
    CHECK(pthread_atfork(+[] { ++forks; }, nullptr, nullptr) == 0);
    expired();
    contended(true);
    contended(false);
    nested(false);
    nested(true);
    deadline_nanos = now_nanos() + 1000000000;
    managed_busy = true;
    const auto before = forks;
    errno = 0;
    const pid_t refused = fork();
    const int error = errno;
    finish_child(refused);
    CHECK(refused == -1 && error == EAGAIN && forks == before && !managed_depth);
    CHECK(other_thread_can_lock());
    managed_busy = false;
    {
        kernel_module::PublicationOperation operation;
        finish_child(fork());
        CHECK(!other_thread_can_lock());
    }
    CHECK(other_thread_can_lock() && !managed_depth);
    deadline_nanos = 0;
    finish_child(__real_fork());
    CHECK(other_thread_can_lock());
    std::printf("publication real-lock/atfork checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
