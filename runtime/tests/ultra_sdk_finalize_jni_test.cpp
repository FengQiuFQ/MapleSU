#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include "cJSON.h"
#include "sdk_error_receipt.h"
#include "su_authorization_receipt.h"
#include "../ultra/bridge/sdk_call_scope.cpp"

using jstring = const char*;
using jchar = uint16_t;
using jsize = int;
struct JNIEnv {
    std::string answer;
    unsigned publications = 0;
    jstring NewStringUTF(const char* text) { ++publications; answer = text; return answer.c_str(); }
    jstring NewString(const jchar* text, jsize size) {
        ++publications;
        answer.clear();
        for (int i = 0; i < size; ++i) answer += static_cast<char>(text[i]);
        return answer.c_str();
    }
};
constexpr int kSchemaVersion = 1, kBridgeVersion = 1;
constexpr int kBridgeException = -1001, kBridgeAlloc = -1003, kBridgeProcess = -1006;
#include "sdk_finalize_production.inc"

namespace fixture {
thread_local int64_t deadline;
std::atomic<int> fail_close_fd{-1};
std::mutex worker_mutex;
std::condition_variable worker_changed;
unsigned workers = 0;
unsigned checks = 0, failures = 0;
void check(bool passed, const char* expression, int line) {
    ++checks;
    if (!passed) { ++failures; std::fprintf(stderr, "%d: %s\n", line, expression); }
}
#define CHECK(value) fixture::check((value), #value, __LINE__)
cJSON* field(cJSON* object, const char* name) { return cJSON_GetObjectItemCaseSensitive(object, name); }
bool number(cJSON* object, const char* name, int value) {
    const auto* item = field(object, name);
    return cJSON_IsNumber(item) && item->valueint == value;
}
bool text(cJSON* object, const char* name, const char* value) {
    const auto* item = field(object, name);
    return cJSON_IsString(item) && std::strcmp(item->valuestring, value) == 0;
}
void begin_deadline() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    deadline = int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec + INT64_C(2000000000);
}
void body_receipt(cJSON* root, KModErr error) {
    if (is_failed(error)) mark_sdk_error(root, error, "original SDK reason"); else mark_ok(root);
    cJSON_AddBoolToObject(root, "operationCompleted", true);
    cJSON_AddBoolToObject(root, "cleanupPending", false);
    auto* data = cJSON_AddObjectToObject(root, "data");
    cJSON_AddStringToObject(data, "stage", "root_returned");
    cJSON_AddNumberToObject(data, "childPid", 73);
    cJSON_AddStringToObject(data, "receipt", "original-effect-receipt");
}
void check_body(cJSON* root) {
    CHECK(cJSON_IsTrue(field(root, "operationCompleted")));
    CHECK(cJSON_IsFalse(field(root, "cleanupPending")));
    const auto* data = field(root, "data");
    CHECK(data && text(const_cast<cJSON*>(data), "stage", "root_returned") &&
        number(const_cast<cJSON*>(data), "childPid", 73) &&
        text(const_cast<cJSON*>(data), "receipt", "original-effect-receipt"));
}
void cleanup_error_and_precision() {
    begin_deadline();
    constexpr uint64_t generation = UINT64_C(9007199254740994);
    next_generation.store(generation);
    JNIEnv env;
    int fds[2];
    const KModErr original = KModErr::ERR_MODULE_ROOT_KEY;
    const auto raw = guarded(&env, "get_su_auth_list", [&](cJSON* root) {
        CHECK(__wrap_pipe2(fds, O_CLOEXEC) == 0);
        fail_close_fd = fds[0];
        body_receipt(root, original);
    }, &original);
    auto* root = cJSON_Parse(raw);
    CHECK(root && env.publications == 1);
    CHECK(number(root, "sdkErrorCode", static_cast<int>(to_num(original))) &&
        text(root, "reason", "original SDK reason"));
    CHECK(text(root, "bridgeError", "MAPLESU_SDK_CLEANUP_ERROR") && number(root, "bridgeErrorCode", kBridgeProcess));
    CHECK(text(root, "sdkScopeCleanupOwnerGeneration", "9007199254740994"));
    CHECK(number(root, "sdkScopeCleanupError", EIO) && number(root, "sdkScopeCleanupPendingFds", 0) &&
        cJSON_IsFalse(field(root, "sdkScopeCleanupPending")));
    CHECK(!current_call && fcntl(fds[0], F_GETFD) == -1 && fcntl(fds[1], F_GETFD) == -1);
    check_body(root);
    cJSON_Delete(root);
}
void process_error_keeps_body_without_sdk_pointer() {
    begin_deadline();
    JNIEnv env;
    const KModErr original = KModErr::ERR_MODULE_OPEN_FILE;
    const auto raw = guarded(&env, "get_su_auth_list", [&](cJSON* root) {
        body_receipt(root, original);
        record_process_error(EPIPE);
    });
    auto* root = cJSON_Parse(raw);
    CHECK(root && env.publications == 1 && !cJSON_IsTrue(field(root, "ok")));
    CHECK(number(root, "sdkErrorCode", static_cast<int>(to_num(original))) &&
        text(root, "reason", "original SDK reason"));
    CHECK(number(root, "sdkScopeProcessError", EPIPE) && text(root, "bridgeError", "MAPLESU_SDK_PROCESS_ERROR"));
    check_body(root);
    cJSON_Delete(root);
}
void pending_cleanup_keeps_commit() {
    begin_deadline();
    std::mutex event_mutex;
    std::condition_variable changed;
    bool ready = false, held = false, release = false;
    std::thread holder([&] {
        std::unique_lock event(event_mutex);
        changed.wait(event, [&] { return ready; });
        std::unique_lock registry(query_pipes().mutex);
        held = true;
        changed.notify_all();
        changed.wait(event, [&] { return release; });
    });
    int fds[2];
    JNIEnv env;
    const auto raw = guarded(&env, "get_su_auth_list", [&](cJSON* root) {
        CHECK(__wrap_pipe2(fds, O_CLOEXEC) == 0);
        body_receipt(root, KModErr::OK);
        std::unique_lock event(event_mutex);
        ready = true;
        changed.notify_all();
        changed.wait(event, [&] { return held; });
    });
    auto* root = cJSON_Parse(raw);
    CHECK(root && env.publications == 1 && !cJSON_IsTrue(field(root, "ok")));
    CHECK(text(root, "sdkError", "MAPLESU_SDK_CLEANUP_PENDING") && number(root, "sdkErrorCode", kBridgeProcess));
    CHECK(cJSON_IsTrue(field(root, "sdkScopeCleanupPending")) && number(root, "sdkScopeCleanupPendingFds", 2));
    CHECK(cJSON_IsTrue(field(root, "sdkScopeCleanupScheduled")) &&
        cJSON_IsTrue(field(root, "sdkScopeCleanupAdmissionReleasePending")));
    check_body(root);
    cJSON_Delete(root);
    {
        std::lock_guard event(event_mutex);
        release = true;
    }
    changed.notify_all();
    holder.join();
    std::unique_lock worker(worker_mutex);
    CHECK(worker_changed.wait_for(worker, std::chrono::seconds(2), [] { return !workers; }));
    CHECK(fcntl(fds[0], F_GETFD) == -1 && fcntl(fds[1], F_GETFD) == -1 && !current_call);
}
void exception_finalizes_before_publication() {
    begin_deadline();
    JNIEnv env;
    int fds[2];
    const auto raw = guarded(&env, "get_su_auth_list", [&](cJSON* root) {
        CHECK(__wrap_pipe2(fds, O_CLOEXEC) == 0);
        fail_close_fd = fds[0];
        body_receipt(root, KModErr::ERR_MODULE_OPEN_FILE);
        throw std::runtime_error("body exception");
    });
    auto* root = cJSON_Parse(raw);
    CHECK(root && env.publications == 1);
    CHECK(number(root, "sdkErrorCode", static_cast<int>(to_num(KModErr::ERR_MODULE_OPEN_FILE))) &&
        text(root, "bridgeError", "MAPLESU_BRIDGE_EXCEPTION") && text(root, "bridgeReason", "body exception"));
    CHECK(number(root, "sdkScopeCleanupError", EIO) && cJSON_IsFalse(field(root, "sdkScopeCleanupPending")));
    check_body(root);
    cJSON_Delete(root);
}
void sdk_failure_after_zero_receipt() {
    begin_deadline();
    JNIEnv env;
    KModErr sdk_error = KModErr::OK;
    const auto raw = guarded(&env, "get_su_auth_list", [&](cJSON* root) {
        body_receipt(root, KModErr::OK);
        sdk_error = KModErr::ERR_MODULE_OPEN_FILE;
        throw std::runtime_error("later SDK failure");
    }, &sdk_error);
    auto* root = cJSON_Parse(raw);
    CHECK(root && env.publications == 1 && !cJSON_IsTrue(field(root, "ok")));
    CHECK(number(root, "sdkErrorCode", static_cast<int>(to_num(sdk_error))) &&
        text(root, "sdkError", maplesu::ultra::sdk_error_name(sdk_error).c_str()));
    CHECK(text(root, "bridgeError", "MAPLESU_BRIDGE_EXCEPTION") && text(root, "bridgeReason", "later SDK failure"));
    check_body(root);
    cJSON_Delete(root);
}
}

extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return fixture::deadline; }
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t value) noexcept {
    const auto previous = fixture::deadline; fixture::deadline = value; return previous;
}
extern "C" int __real_pipe2(int* fds, int flags) { return pipe2(fds, flags); }
extern "C" pid_t __real_fork() { return fork(); }
extern "C" pid_t __real_waitpid(pid_t child, int* status, int flags) { return waitpid(child, status, flags); }
extern "C" int __real_close(int fd) {
    int result = close(fd);
    int expected = fd;
    if (fd >= 0 && fixture::fail_close_fd.compare_exchange_strong(expected, -1)) { errno = EIO; result = -1; }
    return result;
}
extern "C" int __real_pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
void* observed_cleanup(void* argument) {
    cleanup_worker(argument);
    {
        std::lock_guard lock(fixture::worker_mutex);
        --fixture::workers;
    }
    fixture::worker_changed.notify_all();
    return nullptr;
}
extern "C" int __wrap_pthread_create(pthread_t* thread, const pthread_attr_t* attributes,
    void* (*start)(void*), void* argument) {
    if (start != cleanup_worker) return __real_pthread_create(thread, attributes, start, argument);
    {
        std::lock_guard lock(fixture::worker_mutex);
        ++fixture::workers;
    }
    const int result = __real_pthread_create(thread, attributes, observed_cleanup, argument);
    if (result) { std::lock_guard lock(fixture::worker_mutex); --fixture::workers; }
    return result;
}
int main() {
    fixture::cleanup_error_and_precision();
    fixture::process_error_keeps_body_without_sdk_pointer();
    fixture::pending_cleanup_keeps_commit();
    fixture::exception_finalizes_before_publication();
    fixture::sdk_failure_after_zero_receipt();
    std::printf("SDK finalize JNI checks=%u failures=%u\n", fixture::checks, fixture::failures);
    return fixture::failures ? 1 : 0;
}
