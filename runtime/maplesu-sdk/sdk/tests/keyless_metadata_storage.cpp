// Real m035 and m041 implementations; only gateway/lifetime boundaries are fixtures.
#include "module_base_kernel_func_executor.h"
#include "module_base_kernel_mem.h"
#include "../src/module_base/module_base_disk_storage.cpp"
#include "../src/module/module_append_package_parser.cpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {
thread_local uint64_t auth = 1;
thread_local bool alive = true;
bool supported = true, stale_facts = false, stale_read = false;
KModErr metadata_error = KModErr::OK, read_error = KModErr::OK;
unsigned reads = 0;
constexpr uint64_t kernel_base = UINT64_C(0xffff800010000000);
constexpr uint64_t append_address = kernel_base + 0x1000;
unsigned char append[MAPLESU_APPEND64_BYTES]{};
uint32_t append_bytes = MAPLESU_APPEND64_BYTES;
uint64_t capabilities = 0;
template<typename T> void put(unsigned offset, T value) { std::memcpy(append + offset, &value, sizeof(value)); }
void reset() { auth = 1; alive = supported = true; stale_facts = stale_read = false; metadata_error = read_error = KModErr::OK; reads = 0; std::memset(append, 0, sizeof(append)); append_bytes = MAPLESU_APPEND64_BYTES; capabilities = 0; }
}
namespace kernel_module {
// Standard owner requests must never fall back to the legacy emitter or Key.
void maplesu_legacy_asm_func_start(asmjit::a64::Assembler*) { std::abort(); }
void maplesu_legacy_asm_func_end(asmjit::a64::Assembler*, asmjit::a64::GpX) { std::abort(); }
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&, uint64_t&) { std::abort(); }
KModErr read_kernel_mem(uint64_t, void*, uint32_t) { std::abort(); }
KModErr get_kernel_base_vaddr(uint64_t&) { std::abort(); }
uint64_t maplesu_request_auth_state() { return auth; }
bool maplesu_request_owner_lifetime_capture(RequestOwnerLifetimeToken&) { return alive; }
bool maplesu_request_owner_lifetime_matches(const RequestOwnerLifetimeToken&) { return alive; }
KModErr maplesu_kernel_metadata_facts(RequestMetadataFacts& facts, bool& out_supported) {
    facts = {}; facts.kernel_base = kernel_base; facts.append = append_address;
    facts.append_bytes = append_bytes; facts.capabilities = capabilities;
    out_supported = supported;
    if (stale_facts) ++auth;
    return metadata_error;
}
KModErr maplesu_request_owner_read(uint64_t source, void* out, uint32_t size, const RequestOwnerBinding&) {
    ++reads;
    if (read_error != KModErr::OK) return read_error;
    assert(source >= append_address && source - append_address + size <= sizeof(append));
    std::memcpy(out, append + source - append_address, size);
    if (stale_read) ++auth;
    return KModErr::OK;
}
}
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    std::abort();
}
extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c() {
    std::abort();
}
int main() {
    unsigned checks = 0;
    using namespace maplesu::storage;
    StorageLocator locator;
    std::memcpy(locator.kernel_component, "ABCDEFGHIJKLMNOP", 16);
    std::memcpy(locator.system_component, "ABCDEFGHIJKLMNOPA", 17);
    reset();
    StorageContext context;
    assert(current_context(context) != KModErr::OK); ++checks;
    {
        StorageScope selected(locator, "fixture_module");
        assert(selected.error() == KModErr::OK); ++checks;
        std::string path;
        assert(current_kernel_directory(path) == KModErr::OK && path == "/data/ABCDEFGHIJKLMNOP/"); ++checks;
        assert(current_system_directory(path) == KModErr::OK && path == "/data/ABCDEFGHIJKLMNOPA/"); ++checks;
        assert(current_context(context) == KModErr::OK && context.module_id == "fixture_module"); ++checks;
        bool other_failed = false;
        std::thread other([&] { StorageContext result; other_failed = current_context(result) != KModErr::OK; });
        other.join(); assert(other_failed); ++checks;
        {
            StorageScope nested(locator, "other_module");
            assert(current_context(context) == KModErr::OK && context.module_id == "other_module"); ++checks;
        }
        assert(current_context(context) == KModErr::OK && context.module_id == "fixture_module"); ++checks;
        alive = false;
        assert(current_context(context) != KModErr::OK && context.module_id.empty()); ++checks;
        alive = true;
    }
    assert(current_context(context) != KModErr::OK); ++checks;
    locator.system_component[16] = 'B';
    { StorageScope invalid(locator, nullptr); assert(invalid.error() != KModErr::OK); ++checks; }

    using namespace kernel_module;
    reset();
    uint64_t result = 123;
    put<uint32_t>(4, 0x2400);
    assert(get_append_package_kallsyms_kaddr(result) == KModErr::OK && result == kernel_base + 0x2400); ++checks;
    result = 123; supported = false;
    assert(get_append_package_kallsyms_kaddr(result) == KModErr::ERR_MODULE_TEST_CHANNEL && result == 123); ++checks;
    reset(); result = 123;
    assert(get_append_package_kallsyms_kaddr(result) == KModErr::ERR_MODULE_INTERNAL_APPEND && result == 123); ++checks;
    reset(); result = 123; stale_facts = true;
    assert(get_append_package_kallsyms_kaddr(result) != KModErr::OK && result == 123 && reads == 0); ++checks;
    reset(); result = 123; put<uint32_t>(4, 0x2400); stale_read = true;
    assert(get_append_package_kallsyms_kaddr(result) != KModErr::OK && result == 123); ++checks;
    reset(); result = 123; append_bytes = 54;
    assert(get_slow_avc_audit_addr(result) == KModErr::ERR_MODULE_INTERNAL_APPEND && result == 123 && reads == 0); ++checks;
    reset(); result = 123; metadata_error = KModErr::ERR_MODULE_ROOT_KEY;
    assert(get_append_package_kallsyms_kaddr(result) == metadata_error && result == 123); ++checks;
    reset(); capabilities = MAPLESU_CAP_APPEND64;
    put<uint32_t>(MAPLESU_APPEND64_HEADER, MAPLESU_APPEND64_MAGIC);
    put<uint16_t>(MAPLESU_APPEND64_HEADER + 4, MAPLESU_APPEND64_BYTES);
    put<int64_t>(MAPLESU_APPEND64_BASE, 0x1000);
    put<int64_t>(MAPLESU_APPEND64_LOOKUP, -0x4000);
    assert(get_append_package_kallsyms_kaddr(result) == KModErr::OK && result == kernel_base - 0x4000); ++checks;
    put<uint32_t>(0, 1); result = 123;
    assert(get_append_package_kallsyms_kaddr(result) == KModErr::ERR_MODULE_INTERNAL_APPEND && result == 123); ++checks;
    reset(); capabilities = MAPLESU_CAP_APPEND64; append_bytes = 87; result = 123;
    assert(get_append_package_kallsyms_kaddr(result) == KModErr::ERR_MODULE_INTERNAL_APPEND && result == 123); ++checks;
    assert(metadata_test::init_count == 0); ++checks;
    std::printf("KEYLESS_METADATA_STORAGE_PASS checks=%u actual_m035_m041=1 gateway=fixture legacy=not_invoked device=0\n", checks);
}
