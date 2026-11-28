// Production JNI bodies/guards are extracted by test-root-command-identity.py.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <type_traits>
#include "cJSON.h"
#include "urlEncodeUtils.h"
#include "sdk_call_scope.h"
#include "sdk_error_receipt.h"
#include "manager_owner_identity.h"
#include "manager_owner_root_probe.h"
#include "maplesu_root_command_private.h"
#include "maplesu_sdk/maplesu_root.h"

static_assert(std::is_same_v<decltype(&maplesu::sdk::get_root), KModErr (*)()>);
static_assert(std::is_same_v<decltype(&maplesu::sdk::run_root_cmd), KModErr (*)(const char*, std::string&)>);

using jstring = const char*;
using jclass = void*;
using jchar = uint16_t;
using jsize = int;
#define JNIEXPORT
#define JNICALL
struct JNIEnv {
    std::string answer;
    bool exception = false;
    const char* GetStringUTFChars(jstring value, void*) { return value; }
    void ReleaseStringUTFChars(jstring, const char*) {}
    bool ExceptionCheck() const { return exception; }
    jstring NewStringUTF(const char* value) { answer = value; return answer.c_str(); }
    jstring NewString(const jchar* value, jsize size) {
        answer.clear();
        for (int index = 0; index < size; ++index) answer += static_cast<char>(value[index]);
        return answer.c_str();
    }
};

namespace fixture {
int failures, calls, mode_sets, restores, allocation_after = -1;
bool throw_sdk, acquired = true;
int process_error;
std::string command;
uint64_t auth_state = static_cast<uint64_t>(kernel_module::RequestAuthMode::ManagerOwner);
KModErr sdk_error = KModErr::OK, select_error = KModErr::OK, restore_error = KModErr::OK;
maplesu::sdk::RootCommandResult diagnostic;
void* allocate(size_t size) {
    if (allocation_after == 0) { allocation_after = -1; return nullptr; }
    if (allocation_after > 0) --allocation_after;
    return std::malloc(size);
}
char* print(cJSON* value) {
    // The allocation sweep targets JSON assembly, before VM/string serialization.
    allocation_after = -1;
    return cJSON_PrintUnformatted(value);
}
int allocation_offset = -1;
void reset() {
    calls = mode_sets = restores = process_error = 0;
    throw_sdk = false; acquired = true;
    command.clear(); auth_state = static_cast<uint64_t>(kernel_module::RequestAuthMode::ManagerOwner);
    sdk_error = select_error = restore_error = KModErr::OK;
    allocation_after = allocation_offset = -1;
    diagnostic = {};
    diagnostic.phase = maplesu::sdk::RootCommandPhase::Complete;
    diagnostic.error = KModErr::OK;
    diagnostic.system_error = 0;
    diagnostic.child_status = 0;
    diagnostic.child_status_valid = true;
    diagnostic.receipt_complete = true;
}
void check(bool value, const char* message) {
    if (!value) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}
}

namespace kernel_module {
uint64_t maplesu_request_auth_state() { return fixture::auth_state; }
KModErr maplesu_request_set_auth_mode(RequestAuthMode requested) {
    ++fixture::mode_sets;
    const bool restoring = requested == RequestAuthMode::EarlyHelper;
    if (restoring) ++fixture::restores;
    const auto result = restoring ? fixture::restore_error : fixture::select_error;
    if (is_ok(result)) fixture::auth_state = static_cast<uint64_t>(requested);
    return result;
}
CleanupReceiptScope::CleanupReceiptScope() noexcept {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {}
}
namespace maplesu {
SdkCallScope::SdkCallScope(const char*) { acquired_ = fixture::acquired; context_.process_error = fixture::process_error; }
SdkCallScope::~SdkCallScope() = default;
SdkCallCompletion SdkCallScope::finalize() noexcept { SdkCallCompletion result; result.process_error = context_.process_error; return result; }
namespace ultra { void retain_authorization_result_on_process_failure(cJSON*) {} }
namespace sdk {
KModErr run_root_cmd(const char* command, std::string& output) {
    ++fixture::calls;
    fixture::command = command;
    if (fixture::throw_sdk) throw std::runtime_error("SDK fixture exception");
    output = "root fixture\n";
    fixture::allocation_after = fixture::allocation_offset;
    return fixture::sdk_error;
}
RootCommandResult current_root_command_result() { return fixture::diagnostic; }
}
}

constexpr int kSchemaVersion = 1, kBridgeVersion = 1;
constexpr int kBridgeException = -1001, kBridgeAlloc = -1003, kBridgeProcess = -1006;
#define cJSON_PrintUnformatted fixture::print
#include "root_command_production.inc"
#undef cJSON_PrintUnformatted

using Tree = std::unique_ptr<cJSON, JsonDeleter>;
Tree invoke() {
    JNIEnv env;
    const auto raw = Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_runRootCmd(&env, nullptr, "id -u");
    Tree result(cJSON_Parse(raw));
    assert(result);
    return result;
}
cJSON* field(cJSON* object, const char* key) { return cJSON_GetObjectItemCaseSensitive(object, key); }
int number(cJSON* object, const char* key) { const auto* value = field(object, key); return value ? value->valueint : INT32_MIN; }
bool truth(cJSON* object, const char* key) { return cJSON_IsTrue(field(object, key)); }

int main() {
    cJSON_Hooks hooks{fixture::allocate, std::free};
    cJSON_InitHooks(&hooks);
    using fixture::check;
    using kernel_module::RequestAuthMode;
    fixture::reset();
    auto owner = invoke();
    check(fixture::calls == 1 && fixture::command == "id -u", "keyless JNI forwards the real command once");
    check(fixture::mode_sets == 0 && fixture::auth_state == static_cast<uint64_t>(RequestAuthMode::ManagerOwner),
        "an existing Manager scope stays in its actual mode without a redundant selection");
    check(truth(owner.get(), "ok") && truth(owner.get(), "operationCompleted"), "SDK success retains completion");
    auto* data = field(owner.get(), "data");
    check(number(data, "resultBytes") == 13 && std::string(field(data, "result")->valuestring) == "root+fixture%0A",
        "output bytes and URL encoding survive");
    auto* root = field(data, "rootCommand");
    check(number(root, "phase") == static_cast<int>(maplesu::sdk::RootCommandPhase::Complete) &&
        number(root, "systemError") == 0 && number(root, "childStatus") == 0 &&
        truth(root, "childStatusValid") && truth(root, "receiptComplete"), "original SDK diagnostics are retained");

    fixture::reset(); fixture::auth_state = static_cast<uint64_t>(RequestAuthMode::EarlyHelper);
    auto helper = invoke();
    check(truth(helper.get(), "ok") && fixture::calls == 1 && fixture::mode_sets == 2 && fixture::restores == 1 &&
        fixture::auth_state == static_cast<uint64_t>(RequestAuthMode::EarlyHelper),
        "JNI selects Manager and restores the exact EarlyHelper source once");
    fixture::reset(); fixture::auth_state = static_cast<uint64_t>(RequestAuthMode::EarlyHelper);
    {
        maplesu::RequestAuthModeScope manager(RequestAuthMode::ManagerOwner);
        check(is_ok(manager.error()) && fixture::auth_state == 1, "outer Manager scope selected");
        {
            maplesu::RequestAuthModeScope nested_helper(RequestAuthMode::EarlyHelper);
            check(is_ok(nested_helper.error()) && fixture::auth_state == 3, "nested helper scope selected");
            {
                maplesu::RequestAuthModeScope nested_manager(RequestAuthMode::ManagerOwner);
                check(is_ok(nested_manager.error()) && fixture::auth_state == 1, "nested Manager selected");
            }
            check(fixture::auth_state == 3, "nested Manager exit restores helper");
        }
        check(fixture::auth_state == 1, "nested helper exit restores Manager");
        check(is_ok(manager.restore()) && fixture::auth_state == 3, "explicit restore keeps exact original source");
        const auto sets = fixture::mode_sets;
        check(is_ok(manager.restore()) && fixture::mode_sets == sets, "scope restore is idempotent");
    }
    check(fixture::auth_state == 3 && fixture::mode_sets == 6, "destructor never restores an already-restored scope twice");
    for (uint64_t invalid : {uint64_t(0), uint64_t(2), UINT64_MAX}) {
        fixture::reset(); fixture::auth_state = invalid;
        auto denied = invoke();
        check(fixture::calls == 0 && fixture::mode_sets == 0 && !truth(denied.get(), "ok") &&
            number(denied.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_TEST_CHANNEL),
            "invalid/exhausted execution source never submits a command");
    }

    fixture::reset(); fixture::auth_state = 3;
    fixture::sdk_error = KModErr::ERR_MODULE_OPEN_FILE; fixture::restore_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    fixture::diagnostic.error = fixture::sdk_error; fixture::diagnostic.phase = maplesu::sdk::RootCommandPhase::Root;
    fixture::diagnostic.system_error = 13;
    auto denied = invoke();
    check(number(denied.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_OPEN_FILE), "SDK first failure survives restore failure");
    check(number(denied.get(), "authModeRestoreErrorCode") == to_num(KModErr::ERR_MODULE_TEST_CHANNEL) &&
        fixture::calls == 1 && fixture::restores == 1 && !truth(denied.get(), "operationCompleted"),
        "failed SDK call is never retried and restore is reported separately");
    root = field(field(denied.get(), "data"), "rootCommand");
    check(number(root, "phase") == static_cast<int>(maplesu::sdk::RootCommandPhase::Root) &&
        number(root, "systemError") == 13, "the primary permission failure keeps its Root diagnostics");

    fixture::reset(); fixture::auth_state = 3; fixture::restore_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    auto restored = invoke();
    check(number(restored.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_TEST_CHANNEL) &&
        !truth(restored.get(), "ok") && truth(restored.get(), "operationCompleted"),
        "successful operation with failed restore keeps its completed fact");
    fixture::reset(); fixture::auth_state = 3; fixture::select_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    auto select = invoke();
    check(fixture::calls == 0 && number(select.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_TEST_CHANNEL) &&
        fixture::auth_state == 3, "scope selection failure prevents submission and retains the old source");
    fixture::reset(); fixture::auth_state = 3; fixture::throw_sdk = true;
    auto exception = invoke();
    check(fixture::calls == 1 && fixture::restores == 1 && fixture::auth_state == 3 &&
        number(exception.get(), "sdkErrorCode") == kBridgeException,
        "SDK exception restores the exact source once without replay");
    fixture::reset(); fixture::acquired = false;
    auto busy = invoke();
    check(fixture::calls == 0 && fixture::mode_sets == 0 && number(busy.get(), "sdkErrorCode") == -1005,
        "failed SDK admission never executes or changes the source");
    fixture::reset(); fixture::process_error = 5; fixture::sdk_error = KModErr::ERR_MODULE_OPEN_FILE;
    auto process = invoke();
    check(number(process.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_OPEN_FILE) &&
        number(process.get(), "bridgeErrorCode") == kBridgeProcess, "SDK first failure survives process failure");

    fixture::reset();
    fixture::diagnostic.root_attempted = fixture::diagnostic.root_returned = fixture::diagnostic.root_report_received = true;
    auto& transition = fixture::diagnostic.root_transition;
    transition.phase = "task_state"; transition.owner_mode = true; transition.credentials_attempted = true;
    transition.credentials.command = 11; transition.credentials.effects = 4; transition.credentials.completed = true;
    transition.task_state_attempted = true; transition.task_state.command = 25; transition.task_state.completed = true;
    transition.threads_total = 8; transition.cpuset_moved = 7; transition.stune_moved = 6; transition.cgroup_error = 13;
    auto detailed = invoke();
    root = field(field(detailed.get(), "data"), "rootCommand");
    check(truth(root, "rootAttempted") && truth(root, "rootReturned") && truth(root, "rootReportReceived") &&
        truth(root, "ownerMode") && number(root, "threadsTotal") == 8 && number(root, "cgroupError") == 13 &&
        number(field(root, "credentials"), "command") == 11 && number(field(root, "taskState"), "command") == 25,
        "full current RootCommandResult JSON retains credential, task and environment details");

    int allocation_failures = 0;
    for (int offset = 0; offset < 160; ++offset) {
        fixture::reset(); fixture::auth_state = 3; fixture::allocation_offset = offset;
        auto result = invoke();
        check(fixture::calls == 1 && fixture::restores == 1 && fixture::auth_state == 3,
            "receipt allocation failure never replays SDK or skips exact source restore");
        check(truth(result.get(), "operationCompleted"), "all post-SDK receipt allocation failures preserve completion");
        if (number(result.get(), "sdkErrorCode") == kBridgeAlloc) ++allocation_failures;
    }
    check(allocation_failures > 15, "allocation sweep actually exercises receipt construction failures");
    fixture::reset(); fixture::sdk_error = KModErr::ERR_MODULE_OPEN_FILE; fixture::allocation_offset = 12;
    auto allocated = invoke();
    check(number(allocated.get(), "sdkErrorCode") == to_num(KModErr::ERR_MODULE_OPEN_FILE) && fixture::calls == 1,
        "SDK first failure survives receipt allocation failure");
    std::cout << "native assertions failures=" << fixture::failures << "; allocation failures=" << allocation_failures << '\n';
    return fixture::failures ? 1 : 0;
}
