// Actual JNI wrapper and bridge scope; only the VM and SDK TLS storage are fixtures.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <time.h>
#include "cJSON.h"
#include "sdk_call_scope.h"

using jstring = const char*;
using jclass = void*;
using jobject = void*;
using jlong = int64_t;
using jchar = uint16_t;
using jsize = int;
#define JNIEXPORT
#define JNICALL

namespace {
thread_local int64_t stored_deadline;
int64_t now_nanos() {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now)) throw std::runtime_error("clock_gettime");
    return int64_t(now.tv_sec) * 1000000000 + now.tv_nsec;
}
}
extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return stored_deadline; }
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t value) noexcept {
    const auto previous = stored_deadline;
    stored_deadline = value;
    return previous;
}

struct JNIEnv {
    std::deque<std::string> strings;
    bool exception = false, clock_exception = false;
    int64_t java_now = 1000, clock_delay_nanos = 0;
    const char* GetStringUTFChars(jstring value, void*) { return value; }
    void ReleaseStringUTFChars(jstring, const char*) {}
    bool ExceptionCheck() const { return exception; }
    jstring NewStringUTF(const char* value) { strings.emplace_back(value); return strings.back().c_str(); }
    jstring NewString(const jchar* value, jsize size) {
        std::string text;
        for (int index = 0; index < size; ++index) text += static_cast<char>(value[index]);
        return NewStringUTF(text.c_str());
    }
    jclass FindClass(const char*) { return this; }
    void* GetStaticMethodID(jclass type, const char*, const char*) { return type; }
    jlong CallStaticLongMethod(jclass, void*) {
        if (clock_delay_nanos) std::this_thread::sleep_for(std::chrono::nanoseconds(clock_delay_nanos));
        exception = clock_exception;
        return java_now;
    }
    jclass GetObjectClass(jobject value) { return value; }
    void* GetMethodID(jclass type, const char*, const char*) { return type; }
    jstring CallObjectMethod(jobject callback, void*) { return (*static_cast<std::function<jstring()>*>(callback))(); }
    void DeleteLocalRef(jobject) {}
};
constexpr int kSchemaVersion = 1, kBridgeVersion = 1;
constexpr int kBridgeException = -1001, kBridgeAlloc = -1003, kBridgeProcess = -1006, kBridgeNullArgument = -1004;
#include "deadline_jni_production.inc"

int main() {
    JNIEnv env;
    int checks = 0, failures = 0, calls = 0;
    const auto check = [&](bool passed, const char* name) {
        ++checks;
        failures += !passed;
        std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
    };
    const auto invoke = [&](int64_t budget, std::function<jstring()>& callback) {
        return Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_invokeWithDeadline(
            &env, nullptr, "get_root_status_report", env.java_now + budget, &callback);
    };
    const auto code = [](jstring raw) {
        cJSON* root = cJSON_Parse(raw);
        const auto* value = cJSON_GetObjectItemCaseSensitive(root, "sdkErrorCode");
        const int result = cJSON_IsNumber(value) ? static_cast<int>(value->valuedouble) : 1;
        cJSON_Delete(root);
        return result;
    };
    const char* receipt = "{\"ok\":false,\"sdkErrorCode\":-19914,\"operationCompleted\":true,\"data\":{\"phase\":11,\"receiptComplete\":false}}";
    std::function<jstring()> business = [&] { ++calls; return receipt; };
    check(code(invoke(0, business)) == -1007 && calls == 0 && !stored_deadline,
        "expired-Java-deadline-does-not-submit-or-leak-TLS");
    const auto before = now_nanos();
    int64_t observed = 0;
    env.clock_delay_nanos = 2'000'000;
    std::function<jstring()> scoped = [&] { observed = stored_deadline; return business(); };
    const auto answer = invoke(25'000'000, scoped);
    check(answer == receipt && std::strcmp(answer, receipt) == 0 && calls == 1,
        "callback-receipt-keeps-original-code-stage-completion-and-payload");
    check(observed > before && observed <= before + 27'000'000 && observed < now_nanos() + 24'000'000,
        "Java-native-clock-translation-consumes-lookup-time-and-keeps-remaining-budget");
    check(!stored_deadline, "successful-callback-restores-unbounded-caller-TLS");
    env.clock_delay_nanos = 0;
    const auto outer = now_nanos() + 500'000'000;
    stored_deadline = outer;
    std::function<jstring()> nested = [&] {
        check(stored_deadline == outer, "later-Java-scope-keeps-earlier-native-parent");
        std::function<jstring()> inner = [&] {
            check(stored_deadline < outer && stored_deadline > now_nanos(), "earlier-Java-scope-shortens-native-parent");
            return receipt;
        };
        const auto result = invoke(25'000'000, inner);
        check(stored_deadline == outer, "inner-JNI-scope-restores-native-parent");
        return result;
    };
    check(invoke(1'000'000'000, nested) == receipt && stored_deadline == outer,
        "nested-JNI-receipt-and-parent-survive-outer-return");
    std::function<jstring()> cancelled = [&] { env.exception = true; return nullptr; };
    check(invoke(25'000'000, cancelled) == nullptr && env.exception && stored_deadline == outer,
        "Java-cancellation-stays-pending-and-restores-parent");
    env.exception = false;
    std::function<jstring()> throwing = []() -> jstring { throw std::runtime_error("fixture callback"); };
    check(code(invoke(25'000'000, throwing)) == -1001 && stored_deadline == outer,
        "native-exception-becomes-failure-receipt-and-restores-parent");
    std::function<jstring()> pending_throw = [&]() -> jstring { env.exception = true; throw 1; };
    check(invoke(25'000'000, pending_throw) == nullptr && env.exception && stored_deadline == outer,
        "native-unwind-keeps-original-pending-Java-exception");
    env.exception = false;
    env.clock_exception = true;
    const int submitted = calls;
    check(invoke(25'000'000, business) == nullptr && env.exception && calls == submitted && stored_deadline == outer,
        "clock-lookup-exception-does-not-enter-callback-or-change-parent");
    stored_deadline = 0;
    std::printf("CHECKS %d FAILURES %d\n", checks, failures);
    return failures ? 1 : 0;
}
