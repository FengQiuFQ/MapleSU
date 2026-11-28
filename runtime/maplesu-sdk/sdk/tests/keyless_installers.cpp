#include "module_err_def.h"
#include "maplesu_storage_private.h"
#include "maplesu_payload_assets.h"
#include "../src/maplesu/install/bootstrap_install.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace maplesu::sdk {
KModErr unsafe_install_su();
KModErr unsafe_install_resetprop();
KModErr unsafe_install_webui_loader();
}
namespace {
std::string base, system_path, kernel_path;
KModErr root_error = KModErr::OK, storage_error = KModErr::OK;
bool rename_failure = false;
unsigned canonical_calls = 0;
std::string read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}
void put(const fs::path& path, const char* text) { std::ofstream(path) << text; }
void equal(const fs::path& path, const unsigned char* bytes, size_t size) {
    assert(read(path) == std::string(reinterpret_cast<const char*>(bytes), size));
}
void bootstrap_contract(const fs::path& path) {
    struct stat st {};
    assert(lstat(path.c_str(), &st) == 0);
    std::fprintf(stderr, "bootstrap contract mode=%04o uid=%u nlink=%lu\n",
        st.st_mode & 07777, st.st_uid, static_cast<unsigned long>(st.st_nlink));
    assert(S_ISREG(st.st_mode) && st.st_uid == 0 && st.st_nlink == 1);
    assert((st.st_mode & 07777) == 0700);
    constexpr char context[] = "u:object_r:kernel:s0";
    char actual[sizeof(context)] {};
    assert(getxattr(path.c_str(), "user.maplesu.selinux", actual, sizeof(actual)) == sizeof(context));
    assert(std::memcmp(actual, context, sizeof(context)) == 0);
}
}
namespace default_modules::module_root {
KModErr set_current_root(bool enabled) { assert(enabled); return root_error; }
}
namespace maplesu::storage {
KModErr current_kernel_directory(std::string& out) {
    if (storage_error != KModErr::OK) return storage_error;
    out = kernel_path; return KModErr::OK;
}
KModErr current_system_directory(std::string& out) {
    if (storage_error != KModErr::OK) return storage_error;
    out = system_path; return KModErr::OK;
}
}
extern "C" KModErr maplesu_prepare_su_exec_directory(const char* path) {
    assert(system_path == path); ++canonical_calls; return KModErr::OK;
}
extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" int __real_setxattr(const char*, const char*, const void*, size_t, int);
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    assert(!std::strcmp(name, "security.selinux"));
    return __real_fsetxattr(fd, "user.maplesu.selinux", value, size, flags);
}
extern "C" int __wrap_setxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
    assert(!std::strcmp(name, "security.selinux"));
    return __real_setxattr(path, "user.maplesu.selinux", value, size, flags);
}
extern "C" int __real_renameat(int, const char*, int, const char*);
extern "C" int __wrap_renameat(int from, const char* a, int to, const char* b) {
    if (rename_failure) { errno = EIO; return -1; }
    return __real_renameat(from, a, to, b);
}

int main() {
    base = "/tmp/maplesu-keyless-installer-" + std::to_string(getpid());
    kernel_path = base + "/ABCDEFGHIJKLMNOP/";
    system_path = base + "/ABCDEFGHIJKLMNOPA/";
    fs::create_directories(system_path + "modules");
    fs::create_directories(kernel_path);
    using namespace maplesu::sdk;
    struct Entry { KModErr (*run)(); const char* suffix; const unsigned char* bytes; size_t size; };
    const Entry entries[] = {
        {unsafe_install_su, "su", su_data, sizeof(su_data)},
        {unsafe_install_resetprop, "resetprop", resetprop_file_data, sizeof(resetprop_file_data)},
        {unsafe_install_webui_loader, "modules/webui_loader", webui_loader_data, sizeof(webui_loader_data)},
        {maplesu::install::prepare_environment_bootstrap, "init", autorun_bootstrap_file_data, sizeof(autorun_bootstrap_file_data)}
    };
    unsigned checks = 0;
    for (const auto& item : entries) {
        const auto path = std::string(item.suffix) == "init" ? kernel_path + item.suffix : system_path + item.suffix;
        assert(item.run() == KModErr::OK);
        equal(path, item.bytes, item.size); ++checks;
        if (std::string(item.suffix) == "init") bootstrap_contract(path);
        assert(item.run() == KModErr::OK);
        equal(path, item.bytes, item.size); ++checks;
        if (std::string(item.suffix) == "init") bootstrap_contract(path);
        put(path, "old-published");
        root_error = KModErr::ERR_MODULE_ROOT_KEY;
        assert(item.run() == root_error && read(path) == "old-published"); ++checks;
        root_error = KModErr::OK;
        storage_error = KModErr::ERR_MODULE_PARAM;
        assert(item.run() != KModErr::OK && read(path) == "old-published"); ++checks;
        storage_error = KModErr::OK;
        rename_failure = true;
        assert(item.run() != KModErr::OK && read(path) == "old-published"); ++checks;
        rename_failure = false;
        assert(item.run() == KModErr::OK);
        equal(path, item.bytes, item.size); ++checks;
        if (std::string(item.suffix) == "init") bootstrap_contract(path);
        for (const auto& dir : {kernel_path, system_path, system_path + "modules/"})
            for (const auto& file : fs::directory_iterator(dir))
                assert(file.path().filename().string().find(".maplesu-exec-") != 0);
    }
    equal(kernel_path + "su", su_data, sizeof(su_data));
    assert(canonical_calls == 3); ++checks;
    // Refresh must also replace a legacy 0777 helper with the gateway's private executable.
    assert(chmod((kernel_path + "init").c_str(), 0777) == 0);
    assert(maplesu::install::refresh_environment_bootstrap() == KModErr::OK);
    equal(kernel_path + "init", autorun_bootstrap_file_data, sizeof(autorun_bootstrap_file_data));
    bootstrap_contract(kernel_path + "init"); ++checks;
    // Explicitly selected public location still passes the real publisher's
    // owner/type checks; a symlink never becomes authority or gets followed.
    const auto loader = system_path + "modules/webui_loader";
    fs::remove(loader);
    put(base + "/victim", "untouched");
    fs::create_symlink(base + "/victim", loader);
    assert(unsafe_install_webui_loader() != KModErr::OK);
    assert(read(base + "/victim") == "untouched" && fs::is_symlink(loader)); ++checks;
    fs::remove_all(base);
    std::printf("KEYLESS_INSTALLERS_PASS checks=%u actual_installer_tus=4 atomic_publisher=real identity=fixture selinux=fixture payload=fixture\n", checks);
}
