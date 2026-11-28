// Execute the actual SDK query/transport against controlled boot files.
#include "module_err_def.h"
#include <tuple>
#include "maplesu_sdk/maplesu_installer.h"
#include "maplesu/compat/persisted_inputs.h"
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <signal.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#ifdef MAPLESU_TEST_JNI_RECEIPTS
#include "jni_test_utf8.h"
#include "../ultra/bridge/native_lib_ultra.cpp"
namespace maplesu {
SdkCallScope::SdkCallScope(const char*) : access_(SdkCallAccess::Read) { acquired_ = access_ == SdkCallAccess::Read; }
SdkCallScope::~SdkCallScope() { (void)previous_call_; }
SdkCallCompletion SdkCallScope::finalize() noexcept { return {}; }
}
namespace maplesu::sdk {
KModErr test_maplesu_basics_with_cb(const char*, BasicItem, void (*)(const char*)) { return KModErr::OK; }
}
#endif

static constexpr const char* key = "ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345";
static constexpr const char* boot = "11111111-2222-3333-4444-555555555555";
static const std::string directory = "/data/ABCDEFGHIJKLMNOP";
static const std::string helper = directory + "/init";
static std::string scenario;
static bool inject = false;
static pid_t child_pid = -1;
static pid_t parent_pid = 0;
static bool short_reply = false, read_interrupted = false;

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char* value) {
    assert(value && strcmp(value, key) == 0);
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return key; }
namespace default_modules::module_root {
KModErr set_current_root(bool) {
    if (scenario == "child_exit") _exit(17);
    if (scenario == "child_signal") raise(SIGKILL);
    return scenario == "root_error" ? KModErr::ERR_MODULE_ROOT_KEY : KModErr::OK;
}
}
extern "C" char* __strncpy_chk2(char* out, const char* in, size_t n, size_t capacity, size_t) {
    assert(n <= capacity);
    return strncpy(out, in, n);
}

extern "C" pid_t __real_fork();
extern "C" int __real_pipe2(int*, int);
extern "C" pid_t __real_waitpid(pid_t, int*, int);
extern "C" FILE* __real_fopen(const char*, const char*);
extern "C" int __real_open(const char*, int, ...);
extern "C" ssize_t __real_read(int, void*, size_t);
extern "C" pid_t __wrap_fork() {
    if (inject && scenario == "fork_error") { errno = EAGAIN; return -1; }
    const auto child = __real_fork();
    if (child > 0) child_pid = child;
    return child;
}
extern "C" int __wrap_pipe2(int* fds, int flags) {
    if (inject && scenario == "pipe_error") { errno = EMFILE; return -1; }
    return __real_pipe2(fds, flags);
}
extern "C" pid_t __wrap_waitpid(pid_t child, int* status, int flags) {
    // A failed fork must never wait for the process group.
    if (inject && child <= 0) { errno = ECHILD; return -1; }
    if (inject && scenario == "wait_error") { errno = ECHILD; return -1; }
    if (inject && scenario == "wait_eintr") { inject = false; errno = EINTR; return -1; }
    const auto result = __real_waitpid(child, status, flags);
    return inject && scenario == "wait_mismatch" && result > 0 ? result + 1 : result;
}
static const char* boot_path(const char* path) {
    return strcmp(path, "/proc/sys/kernel/random/boot_id") == 0 ? "/case/current-boot" : path;
}
extern "C" FILE* __wrap_fopen(const char* path, const char* mode) {
    if (inject && scenario == "boot_read_error" && strcmp(path, "/proc/sys/kernel/random/boot_id") == 0) {
        errno = EACCES; return nullptr;
    }
    return __real_fopen(boot_path(path), mode);
}
extern "C" int __wrap_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode = va_arg(args, mode_t); va_end(args);
    }
    if (inject && ((scenario == "boot_read_error" && strcmp(path, "/proc/sys/kernel/random/boot_id") == 0) ||
        (scenario == "work_read_error" && path == helper + ".boot_session.work"))) {
        errno = EACCES; return -1;
    }
    return __real_open(boot_path(path), flags, mode);
}
extern "C" ssize_t __wrap_read(int fd, void* data, size_t size) {
    if (inject && scenario == "read_eintr" && !read_interrupted) {
        read_interrupted = true; errno = EINTR; return -1;
    }
    const bool parent = inject && getpid() == parent_pid;
    if (parent && scenario == "reply_eof") return 0;
    if (parent && scenario == "reply_short") {
        if (short_reply) return 0;
        short_reply = true; size = 2;
    }
    const auto result = __real_read(fd, data, size);
    if (parent && scenario == "reply_corrupt" && result == 4) memset(data, 0x7f, 4);
    return result;
}
extern "C" ssize_t __read_chk(int fd, void* data, size_t size, size_t capacity) {
    assert(size <= capacity);
    return __wrap_read(fd, data, size);
}
static void put(const std::string& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary); output << text; assert(output.good());
}
static std::string get(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

int main(int argc, char** argv) {
    assert(argc == 3);
    scenario = argv[1]; const int expected = atoi(argv[2]);
    std::filesystem::create_directories(directory);
    put(helper, "fixture executable");
    put(directory + "/" + maplesu::compat::kEnvironmentVersionFile, "5.1.0");
    put("/case/current-boot", std::string(boot) + "\n");
    put(helper + ".safe_flag", "2");
    // The SDK enables protection by creating an empty file; absence disables it.
    put(helper + ".boot_fail_protect", "");
    put(helper + ".boot_session.duplicate", std::string(boot) + "\n");
    put(helper + ".boot_session.work", std::string(boot) + "\n");
    if (scenario == "missing_work" || scenario == "initializing" || scenario == "protection")
        std::filesystem::remove(helper + ".boot_session.work");
    if (scenario == "empty_work") put(helper + ".boot_session.work", "");
    if (scenario == "stale_work") put(helper + ".boot_session.work", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    if (scenario == "invalid_work") put(helper + ".boot_session.work", "not-a-boot-id");
    if (scenario == "initializing" || scenario == "legacy_early_receipt") put(helper + ".safe_flag", "1");
    if (scenario == "protection" || scenario == "disabled_protection" || scenario == "stale_protection")
        put(helper + ".safe_flag", "3");
    if (scenario == "disabled_protection") std::filesystem::remove(helper + ".boot_fail_protect");
    if (scenario == "stale_protection") put(helper + ".boot_session.duplicate", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n");
    if (scenario == "empty_boot") put("/case/current-boot", "");
    if (scenario == "invalid_boot") put("/case/current-boot", "x");
    if (scenario == "padded_receipt") put(helper + ".boot_session.work", std::string(" \t") + boot + "\r\n");
    if (scenario == "bad_flag") put(helper + ".safe_flag", "3junk");
    if (scenario == "missing_flag") std::filesystem::remove(helper + ".safe_flag");
    if (scenario == "oversize_work") put(helper + ".boot_session.work", std::string(10000, 'a'));
    if (scenario == "work_directory") {
        std::filesystem::remove(helper + ".boot_session.work");
        std::filesystem::create_directory(helper + ".boot_session.work");
    }
    if (scenario == "not_installed" || scenario == "missing_helper") std::filesystem::remove(helper);
    if (scenario == "not_installed" || scenario == "missing_version") std::filesystem::remove(directory + "/" + maplesu::compat::kEnvironmentVersionFile);
    std::map<std::string, std::string> before;
    for (const auto& entry : std::filesystem::directory_iterator(directory))
        if (entry.is_regular_file()) before[entry.path()] = get(entry.path());
    parent_pid = getpid(); inject = true;
#ifdef MAPLESU_TEST_JNI_RECEIPTS
    std::string output;
    static std::string* result = &output;
    JNINativeInterface table{};
    table.NewStringUTF = [](JNIEnv*, const char* text) -> jstring { *result = text; return nullptr; };
    table.NewString = [](JNIEnv*, const jchar* characters, jsize length) -> jstring {
        *result = jni_test_utf16_to_utf8(characters, length);
        return nullptr;
    };
    table.GetStringUTFChars = [](JNIEnv*, jstring text, jboolean*) -> const char* { return reinterpret_cast<const char*>(text); };
    table.ReleaseStringUTFChars = [](JNIEnv*, jstring, const char*) {};
    JNIEnv environment{&table};
    Java_dev_maplesu_manager_runtime_ultra_bridge_NativeBridge_getEnvironmentState(
        &environment, nullptr, reinterpret_cast<jstring>(const_cast<char*>(key)));
    auto receipt = cJSON_Parse(output.c_str()); assert(receipt);
    auto data = cJSON_GetObjectItemCaseSensitive(receipt, "data");
    auto state = cJSON_GetObjectItemCaseSensitive(data, "state");
    const char* names[] = {"NotInstalled", "Running", "Fault", "Unknown"};
    const auto actual = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(receipt, "ok")) &&
        cJSON_IsString(state) && strcmp(state->valuestring, names[expected]) == 0 ? expected : -1;
    if (expected == 2 || expected == 3) {
        auto reason = cJSON_GetObjectItemCaseSensitive(data, "stateReason");
        assert(cJSON_IsString(reason) && strcmp(reason->valuestring,
            expected == 2 ? "current_boot_protection" : "boot_state_unconfirmed") == 0);
    }
    cJSON_Delete(receipt);
#else
    const auto actual = static_cast<int>(maplesu::sdk::get_maplesu::sdkironment_state(key));
#endif
    inject = false;
    if (child_pid > 0) { int status; __real_waitpid(child_pid, &status, 0); }
    bool unchanged = true;
    for (const auto& [path, text] : before) unchanged &= get(path) == text;
    const bool ok = actual == expected && unchanged;
    printf("%s scenario=%s state=%d expected=%d filesUnchanged=%d\n", ok ? "PASS" : "FAIL", argv[1], actual, expected, unchanged);
    std::filesystem::remove_all(directory);
    return ok ? 0 : 1;
}
