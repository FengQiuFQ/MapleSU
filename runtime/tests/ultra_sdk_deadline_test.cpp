#include "sdk_call_scope.h"
#include <chrono>
#include <cstdio>
#include <future>

namespace {
thread_local int64_t deadline_nanos = 0;
int64_t now_nanos() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}

extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept { return deadline_nanos; }
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t value) noexcept {
    const auto previous = deadline_nanos;
    deadline_nanos = value;
    return previous;
}

int main() {
    int failures = 0;
    const auto check = [&](bool passed, const char* name) {
        std::printf("%s %s\n", passed ? "PASS" : "FAIL", name);
        failures += !passed;
    };
    deadline_nanos = now_nanos() - 1;
    {
        maplesu::SdkCallScope expired("probe_manager_owner_root");
        check(!expired.acquired() && expired.deadline_exceeded(), "expired-isolated-call-does-not-submit");
    }
    check(std::async(std::launch::async, [] {
        maplesu::SdkCallScope other("get_system_status");
        return other.acquired() && !deadline_nanos;
    }).get(), "deadline-remains-local-to-the-calling-thread");
    deadline_nanos = 0;
    std::promise<void> entered, release;
    auto ready = entered.get_future();
    auto finished = release.get_future();
    auto writer = std::async(std::launch::async, [&] {
        maplesu::SdkCallScope operation("install_maplesu_environment");
        entered.set_value();
        finished.wait();
        return operation.acquired();
    });
    ready.wait();
    const auto start = now_nanos();
    deadline_nanos = start + 20'000'000;
    {
        maplesu::SdkCallScope reader("get_all_modules_list");
        check(!reader.acquired() && !reader.deadline_exceeded() && now_nanos() < deadline_nanos,
            "contended-admission-returns-busy-without-submission-or-waiting-for-deadline");
    }
    deadline_nanos = 0;
    release.set_value();
    check(writer.get(), "unrelated-existing-operation-keeps-its-lifetime");
    {
        const auto outer = now_nanos() + 1'000'000'000;
        maplesu::SdkDeadlineScope first(outer);
        check(maplesu::sdk_call_deadline_nanos() == outer, "observation-scope-publishes-the-original-deadline");
        {
            maplesu::SdkDeadlineScope later(outer + 1'000'000'000);
            check(maplesu::sdk_call_deadline_nanos() == outer, "nested-scope-does-not-extend-the-deadline");
        }
        check(maplesu::sdk_call_deadline_nanos() == outer, "nested-scope-restores-the-outer-deadline");
        try {
            maplesu::SdkDeadlineScope earlier(outer - 500'000'000);
            check(maplesu::sdk_call_deadline_nanos() == outer - 500'000'000,
                "nested-scope-selects-the-earlier-deadline");
            throw 1;
        } catch (int) {}
        check(maplesu::sdk_call_deadline_nanos() == outer, "exception-restores-the-outer-deadline");
    }
    check(!maplesu::sdk_call_deadline_nanos(), "scope-exit-restores-unbounded-business-calls");
    return failures ? 1 : 0;
}
