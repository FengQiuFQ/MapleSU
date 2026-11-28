// Production JNI upcall, receipt guards and m039 TLS; only VM and wire are fixtures.
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "cJSON.h"
#include "urlEncodeUtils.h"
#include "sdk_call_scope.h"
#include "sdk_error_receipt.h"
#include "manager_owner_identity.h"
#include "manager_owner_root_probe.h"
#include "maplesu_root_command_private.h"
#include "maplesu_sdk/maplesu_root.h"

using jstring = const char*;
using jclass = void*;
using jobject = void*;
using jchar = uint16_t;
using jsize = int;
#define JNIEXPORT
#define JNICALL
struct JNIEnv {
    std::deque<std::string> strings;
    bool exception = false;
    const char* GetStringUTFChars(jstring value, void*) { return value; }
    void ReleaseStringUTFChars(jstring, const char*) {}
    bool ExceptionCheck() const { return exception; }
    jstring NewStringUTF(const char* value) { strings.emplace_back(value); return strings.back().c_str(); }
    jstring NewString(const jchar* value, jsize size) {
        std::string text;
        for (int i = 0; i < size; ++i) text += static_cast<char>(value[i]);
        return NewStringUTF(text.c_str());
    }
    jclass GetObjectClass(jobject value) { return value; }
    void* GetMethodID(jclass type, const char*, const char*) { return type; }
    jstring CallObjectMethod(jobject callback, void*) { return (*static_cast<std::function<jstring()>*>(callback))(); }
    void DeleteLocalRef(jobject) {}
};
namespace fixture {
thread_local uint64_t state = 5;
thread_local bool live = false, fail_close = false;
thread_local KModErr sdk_error = KModErr::OK;
int checks, calls;
std::string observed_key;
kernel_module::RequestAuthMode observed_mode;
void check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
void reset() { state = 5; live = fail_close = false; sdk_error = KModErr::OK; calls = 0; observed_key.clear(); kernel_module::maplesu_request_clear_legacy(); }
}
namespace kernel_module {
uint64_t maplesu_request_auth_state() { return fixture::state; }
KModErr maplesu_request_set_auth_mode(RequestAuthMode value) {
    if (fixture::live) return KModErr::ERR_MODULE_TEST_CHANNEL;
    fixture::state = ((fixture::state & ~UINT64_C(3)) + 4) | static_cast<uint64_t>(value);
    return KModErr::OK;
}
KModErr maplesu_request_owner_close() {
    if (fixture::fail_close) return KModErr::ERR_MODULE_TEST_CHANNEL;
    fixture::live = false; return KModErr::OK;
}
CleanupReceiptScope::CleanupReceiptScope() noexcept {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {}
}
namespace maplesu {
SdkCallScope::SdkCallScope(const char*) { acquired_ = true; }
SdkCallScope::~SdkCallScope() = default;
SdkCallCompletion SdkCallScope::finalize() noexcept { return {}; }
namespace ultra { void retain_authorization_result_on_process_failure(cJSON*) {} }
namespace sdk {
KModErr run_root_cmd(const char*, std::string& output) {
    ++fixture::calls;
    fixture::observed_mode = kernel_module::maplesu_request_auth_mode(fixture::state);
    fixture::observed_key = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    output = "0\n"; return fixture::sdk_error;
}
RootCommandResult current_root_command_result() { return {}; }
}
}
constexpr int kSchemaVersion = 1, kBridgeVersion = 1;
constexpr int kBridgeException = -1001, kBridgeAlloc = -1003, kBridgeProcess = -1006, kBridgeNullArgument = -1004;
#include "legacy_manager_production.inc"

int main() {
    using namespace kernel_module;
    using fixture::check;
    const std::string first(48, 'A'), second(48, 'B');
    JNIEnv env;
    auto root = [&] { return Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_runRootCmd(&env, nullptr, "id -u"); };
    auto invoke = [&](const std::string& key, std::function<jstring()>& fn) {
        return Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_invokeWithLegacyCredential(
            &env, nullptr, "run_root_cmd", key.c_str(), &fn);
    };
    auto successful = [](jstring raw) { std::unique_ptr<cJSON, decltype(&cJSON_Delete)> value(cJSON_Parse(raw), cJSON_Delete); return cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(value.get(), "ok")); };
    fixture::reset();
    check(successful(root()) && fixture::observed_mode == RequestAuthMode::ManagerOwner && fixture::observed_key.empty(), "ordinary entry defaults to Owner");
    std::function<jstring()> business = root;
    check(successful(invoke(first, business)) && fixture::calls == 2 && fixture::observed_key == first && fixture::observed_mode == RequestAuthMode::LegacyKey, "actual JNI callback selects real old credential once");
    check(maplesu_request_auth_manager(fixture::state) && !maplesu::bridge_legacy_scope() && !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), "callback clears TLS and restores Owner");
    check(successful(root()) && fixture::observed_mode == RequestAuthMode::ManagerOwner && fixture::observed_key.empty(), "reused thread next request remains Owner");
    int callbacks = 0;
    std::function<jstring()> invalid = [&] { ++callbacks; return root(); };
    check(!successful(invoke("short", invalid)) && callbacks == 0, "invalid credential never submits");
    fixture::live = true;
    check(!successful(invoke(first, invalid)) && callbacks == 0 && fixture::live &&
        maplesu_request_auth_manager(fixture::state) &&
        !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(),
        "a live session rejects switching without changing or closing its context");
    fixture::reset();
    fixture::state = 0;
    check(!successful(invoke(first, invalid)) && callbacks == 0 && !maplesu::bridge_legacy_scope(),
        "invalid auth state never submits or selects legacy");
    fixture::reset();
    std::function<jstring()> nested = [&] {
        std::function<jstring()> inner = root;
        check(successful(invoke(second, inner)) && fixture::observed_key == second, "inner callback selects its credential");
        check(std::string(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW()) == first && maplesu::bridge_legacy_scope(), "inner callback restores outer credential and selection");
        { maplesu::RequestAuthModeScope owner(RequestAuthMode::ManagerOwner); check(is_ok(owner.error()) && maplesu_request_auth_manager(fixture::state), "Owner diagnostics stay Owner inside legacy callback"); }
        check(maplesu_request_auth_legacy(fixture::state) && std::string(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW()) == first, "Owner diagnostic restores genuine legacy credential");
        return root();
    };
    check(successful(invoke(first, nested)) && fixture::observed_key == first, "nested callback returns real outer result");
    bool cold_owner = false;
    std::function<jstring()> threaded = [&] {
        std::thread worker([&] { cold_owner = maplesu_request_auth_manager(maplesu_request_auth_state()) && !maplesu::bridge_legacy_scope() && !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(); }); worker.join(); return root();
    };
    check(successful(invoke(first, threaded)) && cold_owner, "new threads never inherit Java callback selection or key");
    std::function<jstring()> cancelled = [&] { env.exception = true; return nullptr; };
    check(invoke(first, cancelled) == nullptr && env.exception, "original Java cancellation stays pending");
    check(maplesu_request_auth_manager(fixture::state) && !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), "cancelled callback restores mode and wipes key"); env.exception = false;
    std::function<jstring()> throwing = [&]() -> jstring { throw std::runtime_error("fixture callback"); };
    check(!successful(invoke(first, throwing)) && maplesu_request_auth_manager(fixture::state) &&
        !maplesu::bridge_legacy_scope() && !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(),
        "native callback exception restores mode and erases credential");
    fixture::sdk_error = KModErr::ERR_MODULE_ROOT_KEY;
    const int before = fixture::calls;
    check(!successful(invoke(first, business)) && fixture::calls == before + 1, "legacy error is preserved without transport replay");
    fixture::reset();
    std::function<jstring()> completed_close_failure = [&] { const auto result = root(); fixture::live = true; fixture::fail_close = true; return result; };
    std::unique_ptr<cJSON, decltype(&cJSON_Delete)> close(cJSON_Parse(invoke(first, completed_close_failure)), cJSON_Delete);
    check(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(close.get(), "ok")) && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(close.get(), "operationCompleted")), "close failure preserves completion but rejects success");
    check(cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(close.get(), "authScopeCloseErrorCode")) && !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() && !maplesu::bridge_legacy_scope(), "close failure is visible and old key is erased");
    check(!successful(root()), "failed close cannot leak a successful next Owner request");
    fixture::reset(); fixture::sdk_error = KModErr::ERR_MODULE_ROOT_KEY;
    close.reset(cJSON_Parse(invoke(first, completed_close_failure)));
    check(cJSON_GetObjectItemCaseSensitive(close.get(), "sdkErrorCode")->valuedouble == static_cast<double>(to_num(KModErr::ERR_MODULE_ROOT_KEY)), "business failure remains primary after close failure");
    std::cout << "PASS: " << fixture::checks << " legacy Manager JNI scope checks\n";
}
