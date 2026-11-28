// Real JNI bodies/guards are extracted by test-ultra-uid-read-jni.py.
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include "cJSON.h"
#include "sdk_error_receipt.h"
#include "su_authorization_receipt.h"
#include "manager_owner_identity.h"
#include "maplesu_sdk/maplesu_su_auth.h"
#include "../maplesu-sdk/sdk/src/module/su_redirect_tu/su_uid_profile_private.h"
#include "urlEncodeUtils.h"
#include "../ultra/bridge/sdk_call_scope.cpp"

using jstring = const char*;
using jclass = void*;
using jchar = uint16_t;
using jsize = int;
#define JNIEXPORT
#define JNICALL
struct JNIEnv {
    std::string answer;
    unsigned publications = 0;
    jstring NewStringUTF(const char* text) { ++publications; answer = text; return answer.c_str(); }
    jstring NewString(const jchar* text, jsize size) {
        ++publications;
        answer.clear();
        for (int index = 0; index < size; ++index) answer += static_cast<char>(text[index]);
        return answer.c_str();
    }
};

namespace fixture {
thread_local int64_t deadline;
unsigned checks = 0, failures = 0, typed_calls = 0, legacy_calls = 0, package_calls = 0;
unsigned mode_sets = 0;
uint64_t auth_state = 1;

unsigned runtime_calls = 0, runtime_close_calls = 0, root_calls = 0;
bool runtime_available = true, runtime_borrowed = false;
bool runtime_throw_read = false, runtime_throw_close = false;
KModErr runtime_error = KModErr::OK, runtime_close_error = KModErr::OK;
kernel_module::RequestSuRuntimeStatus runtime_result;
kernel_module::RequestManagementReply runtime_reply;

KModErr sdk_error = KModErr::OK, restore_error = KModErr::OK;
maplesu::su_auth::ReadResultV1 result;
bool throw_sdk = false, process_failure = false, cleanup_failure = false;
int fail_close_fd = -1, cleanup_fds[2] = {-1, -1};
int allocation_after = -1, allocation_offset = -1;
void* allocate(size_t size) {
    if (!allocation_after) { allocation_after = -1; return nullptr; }
    if (allocation_after > 0) --allocation_after;
    return std::malloc(size);
}
void check(bool value, const char* expression, int line) {
    ++checks;
    if (!value) { ++failures; std::fprintf(stderr, "%d: %s\n", line, expression); }
}
#define CHECK(value) fixture::check((value), #value, __LINE__)
void reset() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    deadline = int64_t(now.tv_sec) * INT64_C(1000000000) + now.tv_nsec + INT64_C(2000000000);
    typed_calls = legacy_calls = package_calls = mode_sets = 0;
    auth_state = 1;

    runtime_calls = runtime_close_calls = root_calls = 0;
    runtime_available = true;
    runtime_borrowed = runtime_throw_read = runtime_throw_close = false;
    runtime_error = runtime_close_error = KModErr::OK;
    runtime_reply = {};
    runtime_result = {};
    runtime_result.record.schema = MAPLESU_SU_RUNTIME_STATUS_SCHEMA;
    runtime_result.record.bytes = sizeof(runtime_result.record);
    runtime_result.record.host = {UINT64_C(9007199254740993), UINT64_MAX};
    runtime_result.record.installation_fence = UINT64_MAX;
    runtime_result.record.flags = 15;
    runtime_result.record.hook_count = 3;
    runtime_result.record.users = 2;
    runtime_result.record.producers = 1;
    runtime_result.record.target_qualified = 1;
    for (unsigned i = 0; i < 16; ++i) {
        runtime_result.record.installation_generation[i] = i;
        runtime_result.record.runtime_generation[i] = 16 + i;
    }
    runtime_result.binding.host = runtime_result.record.host;
    runtime_result.binding.full_uid = runtime_result.binding.actual_uid = 1010123;
    runtime_result.binding.epoch = 7;
    runtime_result.binding.process = UINT64_C(9007199254740993);
    runtime_result.binding.auth_state = 1;

    sdk_error = restore_error = KModErr::OK;
    throw_sdk = process_failure = cleanup_failure = false;
    allocation_after = allocation_offset = fail_close_fd = -1;
    result = {};
    result.flags = maplesu::su_auth::kReadResultAvailable;
    result.authMode = 1;
    result.root.completed = result.read.completed = result.close.completed = 1;
    result.readback.phase = 10;
    result.readback.capabilities = UINT64_MAX;
    result.readback.revision = UINT64_C(9007199254740993);
    result.readback.count = result.recordCount = 2;
    result.readback.schema = 3;
    result.readback.managementResult = UINT64_MAX;
    result.readback.managementCommand = 30;
    result.readback.managementEffects = 8;
    result.readback.managementCompleted = result.readback.managementHasHandle = 1;
    result.transportStatus = static_cast<uint32_t>(maplesu::su_auth::Transport::Complete);
    result.childWaitStatusValid = 1;
}
void deliver(void (*callback)(const maplesu::su_auth::UidProfileV1*)) {
    if (process_failure) record_process_error(EPIPE);
    if (cleanup_failure) {
        CHECK(__wrap_pipe2(cleanup_fds, O_CLOEXEC) == 0);
        fail_close_fd = cleanup_fds[0];
    }
    allocation_after = allocation_offset;
    if (throw_sdk) throw std::runtime_error("UID fixture exception");
    if (is_failed(sdk_error)) return;
    maplesu::su_auth::UidProfileV1 profile;
    profile.uid = 1010123;
    profile.allow = 1;
    std::strcpy(profile.package, "com.example.allowed");
    callback(&profile);
    profile.uid = 1010124;
    profile.allow = 0;
    std::strcpy(profile.package, "com.example.denied");
    callback(&profile);
}
}

namespace kernel_module {
uint64_t maplesu_request_auth_state() { return fixture::auth_state; }
KModErr maplesu_request_set_auth_mode(RequestAuthMode mode) {
    ++fixture::mode_sets;
    if (mode == RequestAuthMode::EarlyHelper && is_failed(fixture::restore_error)) return fixture::restore_error;
    fixture::auth_state = static_cast<uint64_t>(mode);
    return KModErr::OK;
}
CleanupReceiptScope::CleanupReceiptScope() noexcept
    : saved_errno_(errno), saved_process_(getpid()), saved_reply_(fixture::runtime_reply) {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {
    fixture::runtime_reply = saved_reply_; errno = saved_errno_;
}

bool maplesu_request_owner_lifetime_capture(RequestOwnerLifetimeToken&) {
    return fixture::runtime_borrowed;
}
RequestManagementReply maplesu_request_management_reply() { return fixture::runtime_reply; }
KModErr maplesu_request_owner_su_runtime(RequestSuRuntimeStatus& output) {
    ++fixture::runtime_calls;
    fixture::runtime_reply = {fixture::runtime_result.record.status, 0, 104, UINT64_MAX, 30, true};
    if (fixture::runtime_available) output = fixture::runtime_result;
    errno = is_failed(fixture::runtime_error) ? -fixture::runtime_result.record.status : 0;
    fixture::allocation_after = fixture::allocation_offset;
    if (fixture::runtime_throw_read) throw std::runtime_error("runtime read fixture exception");
    return fixture::runtime_error;
}
KModErr maplesu_request_owner_close() {
    ++fixture::runtime_close_calls;
    fixture::runtime_reply = {is_failed(fixture::runtime_close_error) ? -EIO : 0,
        MAPLESU_EFFECT_SESSION_CLOSED, 0, 0, MAPLESU_REQUEST_SESSION_CLOSE, true};
    errno = is_failed(fixture::runtime_close_error) ? EIO : 0;
    if (fixture::runtime_throw_close) throw std::runtime_error("runtime close fixture exception");
    return fixture::runtime_close_error;
}

}
namespace maplesu::su_auth {
KModErr get_uid_profiles_with_cb(void (*callback)(const UidProfileV1*)) {
    ++fixture::legacy_calls;
    fixture::deliver(callback);
    return fixture::sdk_error;
}
KModErr get_uid_profiles_with_cb(void (*callback)(const UidProfileV1*), ReadResultV1& output) {
    ++fixture::typed_calls;
    output = fixture::result;
    fixture::deliver(callback);
    return fixture::sdk_error;
}
}
namespace maplesu::sdk {
KModErr get_root() { ++fixture::root_calls; return KModErr::OK; }
KModErr get_su_auth_list(std::vector<su_auth_item>& items) {
    ++fixture::package_calls;
    if (is_failed(fixture::sdk_error)) return fixture::sdk_error;
    su_auth_item item;
    std::strcpy(item.app_package_name, "com.example.allowed");
    items.push_back(item);
    return KModErr::OK;
}
}

constexpr int kSchemaVersion = 1, kBridgeVersion = 1;
constexpr int kBridgeException = -1001, kBridgeAlloc = -1003, kBridgeProcess = -1006;
#include "uid_read_production.inc"

namespace fixture {
using Tree = std::unique_ptr<cJSON, JsonDeleter>;
cJSON* field(cJSON* object, const char* name) { return cJSON_GetObjectItemCaseSensitive(object, name); }
bool number(cJSON* object, const char* name, int64_t value) {
    const auto* item = field(object, name);
    return cJSON_IsNumber(item) && item->valuedouble == static_cast<double>(value);
}
bool text(cJSON* object, const char* name, const char* value) {
    const auto* item = field(object, name);
    return cJSON_IsString(item) && !std::strcmp(item->valuestring, value);
}
Tree invoke(bool packages = false) {
    JNIEnv env;
    const auto raw = packages
        ? Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getSuAuthList(&env, nullptr)
        : Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getSuUidProfiles(&env, nullptr);
    allocation_after = -1;
    Tree tree(cJSON_Parse(raw));
    CHECK(tree && env.publications == 1 && !current_call);
    return tree;
}
cJSON* detail(cJSON* tree) { return field(field(tree, "data"), "uidReadResult"); }
void expect_typed(cJSON* tree) {
    CHECK(typed_calls == 1 && legacy_calls == 0 && package_calls == 0);
    CHECK(cJSON_IsObject(detail(tree)) && number(detail(tree), "schemaVersion", 1));
    CHECK(cJSON_IsTrue(field(detail(tree), "operationResultAvailable")));
    CHECK(number(detail(tree), "authMode", result.authMode));
    CHECK(text(detail(tree), "resultCode", std::to_string(result.resultCode).c_str()));
    CHECK(number(detail(tree), "primaryPhase", result.primaryPhase) && number(detail(tree), "primaryErrno", result.primaryErrno));
    auto* transport = field(detail(tree), "transport");
    CHECK(number(transport, "status", result.transportStatus) && number(transport, "errno", result.transportErrno));
    CHECK(number(transport, "childWaitStatus", result.childWaitStatus) &&
        cJSON_IsTrue(field(transport, "valid")) == bool(result.childWaitStatusValid));
}
void success_and_precision() {
    reset();
    auto tree = invoke();
    expect_typed(tree.get());
    CHECK(cJSON_IsTrue(field(tree.get(), "ok")) && number(tree.get(), "sdkErrorCode", 0));
    auto* data = field(tree.get(), "data");
    auto* profiles = field(data, "profiles");
    CHECK(number(data, "count", 2) && cJSON_IsTrue(field(data, "decisionsVerified")) && cJSON_GetArraySize(profiles) == 2);
    CHECK(number(cJSON_GetArrayItem(profiles, 0), "uid", 1010123) &&
        cJSON_IsFalse(field(cJSON_GetArrayItem(profiles, 1), "allow")));
    auto* readback = field(detail(tree.get()), "readback");
    CHECK(text(readback, "capabilities", "18446744073709551615") && text(readback, "revision", "9007199254740993"));
    auto* management = field(readback, "management");
    CHECK(text(management, "result", "18446744073709551615") && cJSON_IsTrue(field(management, "hasHandle")));
    CHECK(!field(management, "handle") && number(management, "effects", 8) && number(management, "command", 30));
    CHECK(cJSON_IsString(field(tree.get(), "sdkScopeCleanupOwnerGeneration")) && !mode_sets);
    auto* encoded = cJSON_PrintUnformatted(tree.get());
    if (encoded) { std::printf("UID_READ_SAMPLE_SUCCESS=%s\n", encoded); cJSON_free(encoded); }
    reset();
    result.resultCode = result.root.code = result.readback.code = INT64_C(-9007199254740993);
    sdk_error = static_cast<KModErr>(result.resultCode);
    result.primaryPhase = static_cast<uint32_t>(maplesu::su_auth::ReadPhase::Root);
    auto precise = invoke();
    CHECK(text(detail(precise.get()), "resultCode", "-9007199254740993") &&
        text(field(detail(precise.get()), "root"), "code", "-9007199254740993") &&
        text(field(detail(precise.get()), "readback"), "code", "-9007199254740993"));
}
void root_read_close_and_management_errors() {
    for (auto phase : {maplesu::su_auth::ReadPhase::Root, maplesu::su_auth::ReadPhase::Read, maplesu::su_auth::ReadPhase::Close}) {
        reset();
        sdk_error = KModErr::ERR_MODULE_OPEN_FILE;
        result.resultCode = to_num(sdk_error);
        result.primaryPhase = static_cast<uint32_t>(phase);
        result.primaryErrno = EACCES;
        auto& step = phase == maplesu::su_auth::ReadPhase::Root ? result.root :
            phase == maplesu::su_auth::ReadPhase::Read ? result.read : result.close;
        step.code = result.resultCode;
        step.systemErrno = EACCES;
        if (phase == maplesu::su_auth::ReadPhase::Root) {
            result.read = {};
            result.readback.phase = 0;
            result.readback.managementStatus = -EACCES;
            result.readback.managementCommand = 10;
        }
        result.close.code = to_num(KModErr::ERR_MODULE_TEST_CHANNEL);
        result.close.systemErrno = EIO;
        auto tree = invoke();
        expect_typed(tree.get());
        CHECK(!cJSON_IsTrue(field(tree.get(), "ok")) && number(tree.get(), "sdkErrorCode", to_num(sdk_error)));
        CHECK(!field(field(tree.get(), "data"), "profiles") && !field(field(tree.get(), "data"), "decisionsVerified"));
        CHECK(text(field(detail(tree.get()), "close"), "code", std::to_string(result.close.code).c_str()) &&
            number(field(detail(tree.get()), "close"), "systemErrno", EIO));
        auto* management = field(field(detail(tree.get()), "readback"), "management");
        CHECK(number(management, "status", result.readback.managementStatus) &&
            number(management, "command", result.readback.managementCommand));
    }
    for (uint32_t phase = 1; phase <= 10; ++phase) {
        reset();
        sdk_error = KModErr::ERR_READ_CHILD_DATA;
        result.resultCode = result.read.code = result.readback.code = to_num(sdk_error);
        result.primaryPhase = static_cast<uint32_t>(maplesu::su_auth::ReadPhase::Read);
        result.primaryErrno = result.read.systemErrno = result.readback.systemErrno = EBADMSG;
        result.readback.phase = phase;
        auto tree = invoke();
        auto* readback = field(detail(tree.get()), "readback");
        CHECK(number(readback, "phase", phase) && number(readback, "systemErrno", EBADMSG) &&
            text(readback, "code", std::to_string(to_num(sdk_error)).c_str()));
    }
}
void transport_and_unknown_child_facts() {
    reset();
    sdk_error = KModErr::ERR_READ_CHILD_ERRCODE;
    result.resultCode = to_num(sdk_error);
    result.primaryPhase = static_cast<uint32_t>(maplesu::su_auth::ReadPhase::Wait);
    result.primaryErrno = result.transportErrno = ETIMEDOUT;
    result.transportStatus = static_cast<uint32_t>(maplesu::su_auth::Transport::WaitFailed);
    result.childWaitStatusValid = 0;
    auto valid = invoke();
    expect_typed(valid.get());
    CHECK(cJSON_IsTrue(field(field(detail(valid.get()), "root"), "completed")) &&
        text(field(detail(valid.get()), "root"), "code", "0"));
    reset();
    sdk_error = KModErr::ERR_READ_CHILD_ERRCODE;
    result = {};
    result.authMode = 3;
    result.resultCode = to_num(sdk_error);
    result.primaryPhase = static_cast<uint32_t>(maplesu::su_auth::ReadPhase::Transfer);
    result.primaryErrno = result.transportErrno = EPIPE;
    result.transportStatus = static_cast<uint32_t>(maplesu::su_auth::Transport::Truncated);
    result.childWaitStatus = 256;
    result.childWaitStatusValid = 1;
    auto unknown = invoke();
    auto* diagnostic = detail(unknown.get());
    CHECK(typed_calls == 1 && cJSON_IsFalse(field(diagnostic, "operationResultAvailable")));
    CHECK(!field(diagnostic, "root") && !field(diagnostic, "read") && !field(diagnostic, "close") && !field(diagnostic, "readback"));
    CHECK(!field(diagnostic, "rootAttempted") && number(diagnostic, "authMode", 3));
    CHECK(number(field(diagnostic, "transport"), "childWaitStatus", 256) &&
        cJSON_IsTrue(field(field(diagnostic, "transport"), "valid")));
    auto* encoded = cJSON_PrintUnformatted(unknown.get());
    if (encoded) { std::printf("UID_READ_SAMPLE_UNKNOWN=%s\n", encoded); cJSON_free(encoded); }
}
void exception_restore_and_finalize() {
    reset();
    sdk_error = KModErr::ERR_MODULE_OPEN_FILE;
    result.resultCode = result.read.code = to_num(sdk_error);
    result.primaryPhase = static_cast<uint32_t>(maplesu::su_auth::ReadPhase::Read);
    result.primaryErrno = EIO;
    throw_sdk = true;
    cleanup_failure = true;
    auto thrown = invoke();
    expect_typed(thrown.get());
    CHECK(number(thrown.get(), "sdkErrorCode", to_num(sdk_error)) && text(thrown.get(), "bridgeError", "MAPLESU_BRIDGE_EXCEPTION"));
    CHECK(number(thrown.get(), "sdkScopeCleanupError", EIO) &&
        fcntl(cleanup_fds[0], F_GETFD) == -1 && fcntl(cleanup_fds[1], F_GETFD) == -1);
    reset();
    throw_sdk = true;
    auto callback_exception = invoke();
    CHECK(text(callback_exception.get(), "sdkError", "MAPLESU_BRIDGE_EXCEPTION") && detail(callback_exception.get()));
    reset();
    sdk_error = KModErr::ERR_MODULE_OPEN_FILE;
    result.resultCode = result.read.code = to_num(sdk_error);
    process_failure = true;
    auto process = invoke();
    CHECK(detail(process.get()) && text(process.get(), "bridgeError", "MAPLESU_SDK_PROCESS_ERROR") &&
        number(process.get(), "sdkErrorCode", to_num(sdk_error)));
    reset();
    auth_state = 3;
    restore_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    auto restore = invoke();
    CHECK(detail(restore.get()) && cJSON_IsTrue(field(restore.get(), "operationCompleted")) &&
        number(restore.get(), "authModeRestoreErrorCode", to_num(restore_error)));
    reset();
    auth_state = 2;
    auto invalid = invoke();
    CHECK(!typed_calls && !legacy_calls && !detail(invalid.get()) && !cJSON_IsTrue(field(invalid.get(), "ok")));
}
void package_list_stays_compatible() {
    reset();
    auto tree = invoke(true);
    CHECK(package_calls == 1 && !typed_calls && !legacy_calls && !detail(tree.get()));
    auto* data = field(tree.get(), "data");
    CHECK(cJSON_IsTrue(field(tree.get(), "ok")) && number(data, "count", 1) &&
        text(data, "encoding", "url") && cJSON_IsFalse(field(data, "authority")) &&
        cJSON_GetArraySize(field(data, "packages")) == 1);
    reset();
    sdk_error = KModErr::ERR_MODULE_OPEN_FILE;
    auto failed = invoke(true);
    CHECK(number(failed.get(), "sdkErrorCode", to_num(sdk_error)) && !field(failed.get(), "data"));
}
void allocation_failures_are_not_success() {
    unsigned failures_observed = 0;
    for (int offset = 0; offset < 240; ++offset) {
        reset();
        allocation_offset = offset;
        auto tree = invoke();
        if (cJSON_IsTrue(field(tree.get(), "ok"))) {
            CHECK(detail(tree.get()) && field(field(tree.get(), "data"), "profiles") &&
                cJSON_IsTrue(field(detail(tree.get()), "operationResultAvailable")));
            break;
        }
        ++failures_observed;
        if (!number(tree.get(), "sdkErrorCode", kBridgeAlloc)) {
            auto* encoded = cJSON_PrintUnformatted(tree.get());
            std::fprintf(stderr, "allocation offset=%d receipt=%s\n", offset, encoded ? encoded : "null");
            cJSON_free(encoded);
        }
        CHECK(number(tree.get(), "sdkErrorCode", kBridgeAlloc) && typed_calls == 1 && !legacy_calls);
    }
    CHECK(failures_observed > 50 && failures_observed < 240);
    std::printf("UID read JNI allocation cases=%u\n", failures_observed);
}
}


namespace fixture {
Tree runtime_invoke() {
    JNIEnv env;
    const auto raw = Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getSuRuntimeStatus(&env, nullptr);
    allocation_after = -1;
    Tree tree(cJSON_Parse(raw));
    CHECK(tree && env.publications == 1 && !current_call);
    CHECK(root_calls == 0 && typed_calls == 0 && legacy_calls == 0 && package_calls == 0);
    return tree;
}
cJSON* runtime_detail(cJSON* tree) { return field(field(tree, "data"), "suRuntimeResult"); }
void runtime_read_source_and_cleanup() {
    reset();
    CHECK(maplesu::sdk_call_access("get_su_runtime_status") == maplesu::SdkCallAccess::Read);
    auto success = runtime_invoke();
    CHECK(runtime_calls == 1 && runtime_close_calls == 1);
    auto* detail = runtime_detail(success.get());
    CHECK(cJSON_IsTrue(field(success.get(), "ok")) && cJSON_IsTrue(field(detail, "diagnosticAvailable")));
    auto* factory = field(detail, "factory");
    CHECK(number(factory, "bytes", 104) && number(factory, "flags", 15) && number(factory, "status", 0));
    CHECK(text(factory, "installationFence", "18446744073709551615") &&
        text(factory, "installationGeneration", "000102030405060708090a0b0c0d0e0f") &&
        text(factory, "runtimeGeneration", "101112131415161718191a1b1c1d1e1f"));
    CHECK(text(factory, "hostInstance", "ffffffffffffffff0020000000000001") &&
        text(field(detail, "binding"), "process", "9007199254740993"));
    auto* read = field(detail, "read");
    auto* close = field(detail, "close");
    CHECK(cJSON_IsTrue(field(read, "returned")) && text(field(read, "management"), "result", "104") &&
        number(field(read, "management"), "command", 30));
    CHECK(cJSON_IsTrue(field(field(read, "management"), "hasHandle")) && !field(field(read, "management"), "handle"));
    CHECK(cJSON_IsTrue(field(close, "attempted")) &&
        number(field(close, "management"), "command", MAPLESU_REQUEST_SESSION_CLOSE));
    CHECK(!field(detail, "ready") && !field(detail, "rootVerified") && !field(detail, "authorized"));

    reset();
    runtime_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    runtime_result.record.status = runtime_result.record.target_error = -EOPNOTSUPP;
    runtime_result.record.start_error = -EAGAIN;
    runtime_result.record.cleanup_error = -EIO;
    runtime_result.record.flags = 7;
    runtime_close_error = KModErr::ERR_MODULE_OPEN_FILE;
    auto negative = runtime_invoke();
    detail = runtime_detail(negative.get());
    factory = field(detail, "factory");
    CHECK(!cJSON_IsTrue(field(negative.get(), "ok")) && number(negative.get(), "sdkErrorCode", to_num(runtime_error)));
    CHECK(cJSON_IsTrue(field(detail, "diagnosticAvailable")) && number(factory, "targetError", -EOPNOTSUPP) &&
        number(factory, "startError", -EAGAIN) && number(factory, "cleanupError", -EIO));
    CHECK(text(field(detail, "read"), "code", "-19999") &&
        number(field(field(detail, "read"), "management"), "status", -EOPNOTSUPP));
    CHECK(number(field(detail, "close"), "systemErrno", EIO) && runtime_calls == 1 && runtime_close_calls == 1);
    CHECK(runtime_reply.command == 30 && runtime_reply.status == -EOPNOTSUPP);

    reset();
    runtime_close_error = KModErr::ERR_MODULE_OPEN_FILE;
    auto close_failed = runtime_invoke();
    detail = runtime_detail(close_failed.get());
    CHECK(number(close_failed.get(), "sdkErrorCode", to_num(runtime_close_error)) &&
        text(field(detail, "read"), "code", "0") && field(detail, "factory"));
    CHECK(runtime_calls == 1 && runtime_close_calls == 1 &&
        number(field(detail, "close"), "systemErrno", EIO));

    reset();
    runtime_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    runtime_result.record.status = -EOPNOTSUPP;
    allocation_offset = 0;
    auto negative_allocation = runtime_invoke();
    CHECK(number(negative_allocation.get(), "sdkErrorCode", to_num(runtime_error)) &&
        text(negative_allocation.get(), "bridgeError", "MAPLESU_BRIDGE_ALLOC"));
    CHECK(runtime_calls == 1 && runtime_close_calls == 1);

    reset();
    runtime_error = KModErr::ERR_MODULE_ROOT_KEY;
    runtime_result.record.status = -ESTALE;
    runtime_available = false;
    auto absent = runtime_invoke();
    detail = runtime_detail(absent.get());
    CHECK(cJSON_IsFalse(field(detail, "diagnosticAvailable")) && !field(detail, "factory") && !field(detail, "binding"));
    CHECK(runtime_calls == 1 && runtime_close_calls == 1 && number(absent.get(), "sdkErrorCode", to_num(runtime_error)));

    reset();
    runtime_borrowed = true;
    auto borrowed = runtime_invoke();
    detail = runtime_detail(borrowed.get());
    CHECK(cJSON_IsTrue(field(detail, "borrowedSession")) && runtime_calls == 1 && runtime_close_calls == 0);
    CHECK(cJSON_IsFalse(field(field(detail, "close"), "attempted")) &&
        cJSON_IsFalse(field(field(detail, "close"), "returned")));

    reset();
    runtime_throw_read = true;
    auto thrown = runtime_invoke();
    CHECK(runtime_calls == 1 && runtime_close_calls == 1 && text(thrown.get(), "sdkError", "MAPLESU_BRIDGE_EXCEPTION"));
    CHECK(cJSON_IsFalse(field(field(runtime_detail(thrown.get()), "read"), "returned")));
    reset();
    runtime_throw_close = true;
    auto close_thrown = runtime_invoke();
    CHECK(runtime_close_calls == 1 && text(close_thrown.get(), "sdkError", "MAPLESU_BRIDGE_EXCEPTION"));
    CHECK(cJSON_IsFalse(field(field(runtime_detail(close_thrown.get()), "close"), "returned")));
    reset();
    runtime_throw_read = runtime_throw_close = true;
    auto both_thrown = runtime_invoke();
    CHECK(text(both_thrown.get(), "sdkError", "MAPLESU_BRIDGE_EXCEPTION") &&
        text(both_thrown.get(), "reason", "runtime read fixture exception"));
    CHECK(runtime_calls == 1 && runtime_close_calls == 1);

    reset();
    deadline = 1;
    auto expired = runtime_invoke();
    CHECK(runtime_calls == 0 && runtime_close_calls == 0 && number(expired.get(), "sdkErrorCode", -1007));
    reset();
    auth_state = 2;
    auto invalid = runtime_invoke();
    CHECK(runtime_calls == 0 && runtime_close_calls == 0 && !field(invalid.get(), "data"));
}
void runtime_read_allocation_failures() {
    unsigned observed = 0;
    for (int offset = 0; offset < 260; ++offset) {
        reset();
        allocation_offset = offset;
        auto tree = runtime_invoke();
        CHECK(runtime_calls == 1 && runtime_close_calls == 1);
        if (cJSON_IsTrue(field(tree.get(), "ok"))) {
            CHECK(field(runtime_detail(tree.get()), "factory") && field(runtime_detail(tree.get()), "binding"));
            break;
        }
        ++observed;
        CHECK(number(tree.get(), "sdkErrorCode", kBridgeAlloc));
    }
    CHECK(observed > 50 && observed < 260);
    std::printf("SU runtime JNI allocation cases=%u\n", observed);
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
    const int answer = close(fd);
    if (fd >= 0 && fd == fixture::fail_close_fd) { fixture::fail_close_fd = -1; errno = EIO; return -1; }
    return answer;
}
int main() {
    cJSON_Hooks hooks{fixture::allocate, std::free};
    cJSON_InitHooks(&hooks);
    fixture::success_and_precision();
    fixture::root_read_close_and_management_errors();
    fixture::transport_and_unknown_child_facts();
    fixture::exception_restore_and_finalize();
    fixture::package_list_stays_compatible();
    fixture::allocation_failures_are_not_success();
    fixture::runtime_read_source_and_cleanup();
    fixture::runtime_read_allocation_failures();
    std::printf("UID read JNI checks=%u failures=%u\n", fixture::checks, fixture::failures);
    return fixture::failures ? 1 : 0;
}
