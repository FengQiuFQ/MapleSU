// module append package parser implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <cstdint>
#include <cstring>

#include <exception>
#include <limits>
#include <functional>
#include <string>
#include <vector>

#include "private_module_base_kernel_func_executor.h"
#include "maplesu_request_identity.h"
#include "../../../../ultra/authorization/kernel_read_metadata.h"
#include <unistd.h>

namespace {
const std::string alphabet62 =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const int BASE62 = static_cast<int>(alphabet62.size());

// Position of one base62 digit; -1 when the character is not a digit.
int idx_of(char c) {
    const size_t position = alphabet62.find(c);
    return position == std::string::npos ? -1 : static_cast<int>(position);
}
}  // namespace

// Reverses the per-character rotation applied before the base62 encoding.
static std::string simple_decrypt_with_key(const std::string& cipher, char key) {
    const int key_index = idx_of(key);
    if (cipher.size() < 2 || key_index < 0) {
        return {};
    }
    const size_t length = cipher.size() - 1;
    std::string plain;
    plain.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        const int digit = idx_of(cipher[i + 1]);
        if (digit < 0) {
            return {};
        }
        int value = (digit - key_index - static_cast<int>(i % BASE62)) % BASE62;
        if (value < 0) {
            value += BASE62;
        }
        plain.push_back(alphabet62[static_cast<size_t>(value)]);
    }
    return plain;
}

static std::string simple_decrypt(const std::string& cipher) {
    if (cipher.size() < 2) {
        return {};
    }
    return simple_decrypt_with_key(cipher, cipher[0]);
}

// Decodes a base62 digit string into its integer value.
static bool from_base62(const std::string& text, uint64_t& value) {
    value = 0;
    if (text.empty()) {
        return false;
    }
    for (char character : text) {
        const int digit = idx_of(character);
        if (digit < 0 || value > (std::numeric_limits<uint64_t>::max() -
                                 static_cast<uint64_t>(digit)) / BASE62) {
            return false;
        }
        value = value * BASE62 + static_cast<uint64_t>(digit);
    }
    return true;
}

namespace kernel_module {

struct ExecveParam {
    uint32_t offset;
    char filename_reg;
    uint8_t is_single_char_ptr;
};

struct SymPack {
    uint32_t start_offset;
    int16_t ret_delta;
};

// The root key carries a signed offset: two leading base62 digits are the
// prefix length, the rest is the encrypted decimal magnitude; a trailing '0'
// marks a negative value.
void parser_root_key_info(const char* root_key, int& out_value) {
    out_value = 0;
    if (root_key == nullptr) {
        return;
    }
    try {
        std::string root_key_text(root_key);
        if (root_key_text.size() < 16) {
            return;
        }
        uint64_t prefix_length = 0;
        if (!from_base62(simple_decrypt(root_key_text.substr(0, 2)), prefix_length)) {
            return;
        }
        root_key_text.push_back(root_key_text[15]);
        root_key_text.push_back(root_key_text[2]);
        if (prefix_length < 3 || prefix_length > root_key_text.size()) {
            return;
        }
        const std::string tail = root_key_text.substr(root_key_text.size() - prefix_length);
        std::string tail_plain = simple_decrypt(tail);
        if (tail_plain.size() < 2) {
            return;
        }
        const bool negative = tail_plain.back() == '0';
        tail_plain.pop_back();
        uint64_t magnitude = 0;
        if (!from_base62(tail_plain, magnitude)) {
            return;
        }
        const uint64_t limit = static_cast<uint64_t>(std::numeric_limits<int>::max()) +
                               (negative ? 1 : 0);
        if (magnitude > limit) {
            return;
        }
        if (negative && magnitude == limit) {
            out_value = std::numeric_limits<int>::min();
        } else {
            out_value = negative ? -static_cast<int>(magnitude) : static_cast<int>(magnitude);
        }
    } catch (const std::exception&) {
        out_value = 0;
    }
}

// Executes one emitted routine in the kernel and returns its X0 result.
static KModErr run_legacy_kernel_u64_emitter(
    const std::function<KModErr(asmjit::a64::Assembler*, asmjit::a64::GpX&)>& emitter,
    uint64_t& out_result) {
    using namespace asmjit;
    using namespace asmjit::a64;
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    maplesu_legacy_asm_func_start(asm_ctx.assembler());
    GpX result_reg = regs::x0;
    KModErr err = emitter(asm_ctx.assembler(), result_reg);
    if (err == KModErr::OK) {
        maplesu_legacy_asm_func_end(asm_ctx.assembler(), result_reg);
        const std::vector<uint8_t> code = aarch64_asm_to_bytes(asm_ctx.assembler());
        err = execute_kernel_asm_func(code, out_result);
    }
    return err;
}

// The negotiated descriptor supplies the append address. Explicit legacy
// selection retains the original Key/return-address locator after untouched QUERY.
static KModErr get_append_package_addr(
    uint64_t& out_addr, uint32_t required_bytes = MAPLESU_LEGACY_METADATA_V2_BYTES) {
    RequestIdentity operation;
    if (!operation.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    RequestMetadataFacts facts{};
    bool supported = false;
    const auto metadata_error = maplesu_kernel_metadata_facts(facts, supported);
    if (is_failed(metadata_error)) return metadata_error;
    if (!operation.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (supported) {
        if (required_bytes > facts.append_bytes)
            return KModErr::ERR_MODULE_INTERNAL_APPEND;
        out_addr = facts.append;
        return KModErr::OK;
    }
    if (!maplesu_request_auth_legacy(operation.auth_state)) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (required_bytes > MAPLESU_LEGACY_METADATA_V2_BYTES)
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    struct LegacyLocator {
        pid_t pid = 0;
        uint64_t auth_state = 0;
        char key[1024] = {};
        uint64_t address = 0;
    };
    static thread_local LegacyLocator cache;
    const char* key = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    const auto length = key ? strnlen(key, sizeof(cache.key)) : 0;
    if (!length || length == sizeof(cache.key)) return KModErr::ERR_MODULE_ROOT_KEY;
    if (cache.pid != getpid() || cache.auth_state != operation.auth_state ||
        std::memcmp(cache.key, key, length + 1)) {
        cache = {};
        cache.pid = getpid();
        cache.auth_state = operation.auth_state;
        std::memcpy(cache.key, key, length + 1);
    }
    auto& result_cache = cache.address;
    if (result_cache != 0) {
        uint64_t address = 0;
        if (!maplesu_kernel_read::metadata_address(result_cache, 0, required_bytes, address))
            return KModErr::ERR_MODULE_INTERNAL_APPEND;
        out_addr = address;
        return KModErr::OK;
    }
    const pid_t identity_pid = cache.pid;
    char identity[sizeof(cache.key)];
    std::memcpy(identity, cache.key, sizeof(identity));
    int root_key_info = 0;
    parser_root_key_info(identity, root_key_info);
    uint64_t kernel_addr = 0;
    if (!operation.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    KModErr err = run_legacy_kernel_u64_emitter(
        [root_key_info](asmjit::a64::Assembler* a, asmjit::a64::GpX& out_reg) -> KModErr {
            using namespace asmjit;
            using namespace asmjit::a64;
            a->mov(x11, x30);
            a->sub(x11, x11, Imm(4));
            aarch64_asm_mov_x(a, x12, static_cast<uint64_t>(root_key_info));
            a->add(x11, x11, x12);
            out_reg = x11;
            return KModErr::OK;
        },
        kernel_addr);
    if (err != KModErr::OK) {
        return err;
    }
    const char* after = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    const auto after_length = after ? strnlen(after, sizeof(identity)) : 0;
    if (!operation.matches() || getpid() != identity_pid || after_length != length ||
        std::memcmp(identity, after, length + 1)) {
        cache = {};
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    uint64_t address = 0;
    if (!maplesu_kernel_read::metadata_address(kernel_addr, 0, required_bytes, address))
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    result_cache = address;
    out_addr = address;
    return KModErr::OK;
}

// Keep the field, base and final public result in one observed identity. Local
// output below remains unpublished when any constituent operation fails.
static KModErr read_append_field(uint32_t displacement, void* value, uint32_t size,
                                uint64_t* kernel_base = nullptr,
                                uint32_t required_bytes = MAPLESU_LEGACY_METADATA_V2_BYTES) {
    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (!maplesu_request_auth_legacy(identity.auth_state)) {
        RequestMetadataFacts facts{};
        bool supported = false;
        auto error = maplesu_kernel_metadata_facts(facts, supported);
        if (is_failed(error)) return error;
        if (!supported) return KModErr::ERR_MODULE_TEST_CHANNEL;
        if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
        if (required_bytes > facts.append_bytes || displacement > facts.append_bytes ||
            size > facts.append_bytes - displacement) return KModErr::ERR_MODULE_INTERNAL_APPEND;
        error = maplesu_request_owner_read(facts.append + displacement, value, size, facts.owner);
        if (is_failed(error)) return error;
        if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
        if (kernel_base) *kernel_base = facts.kernel_base;
        return KModErr::OK;
    }
    uint64_t append_addr = 0;
    auto error = get_append_package_addr(append_addr, required_bytes);
    if (is_failed(error)) return error;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    error = read_kernel_mem(append_addr + displacement, value, size);
    if (is_failed(error)) return error;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (kernel_base) {
        uint32_t offset = 0;
        std::memcpy(&offset, value, sizeof(offset));
        if (!offset) return KModErr::ERR_MODULE_INTERNAL_APPEND;
        error = get_kernel_base_vaddr(*kernel_base);
        if (is_failed(error)) return error;
        if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    }
    return KModErr::OK;
}

// Decode only after descriptor negotiation. A zero legacy u32 field never
// selects a guessed signed representation or performs a Key fallback.
static KModErr read_append64_address(uint32_t field, uint64_t& address, bool& extended) {
    extended = false;
    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    RequestMetadataFacts facts{};
    bool supported = false;
    auto error = maplesu_kernel_metadata_facts(facts, supported);
    if (is_failed(error)) return error;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (!supported || !(facts.capabilities & MAPLESU_CAP_APPEND64)) return KModErr::OK;
    if (facts.append_bytes != MAPLESU_APPEND64_BYTES ||
        (field != MAPLESU_APPEND64_BASE && field != MAPLESU_APPEND64_LOOKUP &&
         field != MAPLESU_APPEND64_AVC)) return KModErr::ERR_MODULE_INTERNAL_APPEND;
    uint8_t header[6]{};
    uint32_t sentinel = 1, magic = 0;
    uint16_t length = 0;
    int64_t base = 0, displacement = 0;
    error = read_append_field(0, &sentinel, sizeof(sentinel));
    if (is_failed(error)) return error;
    error = read_append_field(MAPLESU_APPEND64_HEADER, header, sizeof(header));
    if (is_failed(error)) return error;
    std::memcpy(&magic, header, sizeof(magic));
    std::memcpy(&length, header + 4, sizeof(length));
    error = read_append_field(MAPLESU_APPEND64_BASE, &base, sizeof(base));
    if (is_failed(error)) return error;
    uint64_t append = 0;
    if (sentinel || magic != MAPLESU_APPEND64_MAGIC || length != MAPLESU_APPEND64_BYTES ||
        !maplesu_kernel_read::metadata_address(facts.kernel_base, base, facts.append_bytes, append) ||
        append != facts.append) return KModErr::ERR_MODULE_INTERNAL_APPEND;
    error = read_append_field(field, &displacement, sizeof(displacement));
    if (is_failed(error)) return error;
    uint64_t candidate = 0;
    if (!displacement || !identity.matches() ||
        !maplesu_kernel_read::metadata_address(facts.kernel_base, displacement, 1, candidate))
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    address = candidate;
    extended = true;
    return KModErr::OK;
}

KModErr get_append_package_data_offset(uint32_t& out_offset) {
    uint32_t offset = 0;
    const auto err = read_append_field(0, &offset, 4);
    if (err != KModErr::OK) {
        return err;
    }
    if (offset == 0) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    out_offset = offset;
    return KModErr::OK;
}

KModErr get_append_package_kallsyms_kaddr(uint64_t& out_kaddr) {
    uint64_t extended_address = 0;
    bool extended = false;
    auto extended_error = read_append64_address(MAPLESU_APPEND64_LOOKUP, extended_address, extended);
    if (is_failed(extended_error)) return extended_error;
    if (extended) { out_kaddr = extended_address; return KModErr::OK; }
    uint32_t offset = 0;
    uint64_t kernel_base = 0;
    const auto err = read_append_field(4, &offset, 4, &kernel_base);
    if (err != KModErr::OK) {
        return err;
    }
    if (offset == 0) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    uint64_t kaddr = 0;
    if (!maplesu_kernel_read::metadata_address(kernel_base, offset, 1, kaddr)) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    out_kaddr = kaddr;
    return KModErr::OK;
}

KModErr get_append_package_run_fake_proc_path_addr(uint64_t& out_addr) {
    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    uint64_t append_addr = 0;
    KModErr err = get_append_package_addr(append_addr);
    if (err != KModErr::OK) {
        return err;
    }
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    out_addr = append_addr + 8;
    return KModErr::OK;
}

KModErr get_do_execve_info(uint64_t& out_addr, char& out_flag, bool& out_present) {
    ExecveParam param{};
    uint64_t kernel_base = 0;
    const auto err = read_append_field(36, &param, 6, &kernel_base);
    if (err != KModErr::OK) {
        return err;
    }
    if (param.offset == 0) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    uint64_t addr = 0;
    if (!maplesu_kernel_read::metadata_address(kernel_base, param.offset, 1, addr)) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    out_addr = addr;
    out_flag = param.filename_reg;
    out_present = param.is_single_char_ptr != 0;
    return KModErr::OK;
}

KModErr get_avc_denied_info(uint64_t& out_addr, uint64_t& out_extra) {
    uint64_t extended_address = 0;
    bool extended = false;
    auto extended_error = read_append64_address(MAPLESU_APPEND64_AVC, extended_address, extended);
    if (is_failed(extended_error)) return extended_error;
    if (extended) {
        int16_t ret_delta = 0;
        auto error = read_append_field(46, &ret_delta, sizeof(ret_delta));
        if (is_failed(error)) return error;
        uint64_t ret = 0;
        if (!ret_delta || !maplesu_kernel_read::metadata_address(extended_address,
                static_cast<int64_t>(ret_delta) * 4 - 4, 1, ret))
            return KModErr::ERR_MODULE_INTERNAL_APPEND;
        out_addr = extended_address;
        out_extra = ret;
        return KModErr::OK;
    }
    SymPack pack{};
    uint64_t kernel_base = 0;
    const auto err = read_append_field(42, &pack, 6, &kernel_base);
    if (err != KModErr::OK) {
        return err;
    }
    if (pack.start_offset == 0) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    uint64_t start_addr = 0, ret_addr = 0;
    if (!maplesu_kernel_read::metadata_address(kernel_base, pack.start_offset, 1, start_addr) ||
        !maplesu_kernel_read::metadata_address(start_addr,
            static_cast<int64_t>(pack.ret_delta) * 4 - 4, 1, ret_addr)) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    out_addr = start_addr;
    out_extra = ret_addr;
    return KModErr::OK;
}

KModErr get_filldir64_addr(uint64_t& out_addr) {
    uint32_t offset = 0;
    uint64_t kernel_base = 0;
    const auto err = read_append_field(48, &offset, 4, &kernel_base);
    if (err != KModErr::OK) {
        return err;
    }
    if (offset == 0) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    uint64_t addr = 0;
    if (!maplesu_kernel_read::metadata_address(kernel_base, offset, 1, addr)) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    out_addr = addr;
    return KModErr::OK;
}

KModErr get_seccomp_offset(uint32_t& out_offset) {
    int16_t value = 0;
    const auto err = read_append_field(52, &value, 2);
    if (err != KModErr::OK) {
        return err;
    }
    if (value == 0) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    const uint32_t offset = static_cast<uint32_t>(static_cast<int32_t>(value));
    out_offset = offset;
    return KModErr::OK;
}

KModErr get_slow_avc_audit_addr(uint64_t& out_addr) {
    uint32_t offset = 0;
    uint64_t kernel_base = 0;
    const auto err = read_append_field(54, &offset, 4, &kernel_base,
                                       MAPLESU_LEGACY_METADATA_AUDIT_BYTES);
    if (err != KModErr::OK) {
        return err;
    }
    if (offset == 0) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    uint64_t addr = 0;
    if (!maplesu_kernel_read::metadata_address(kernel_base, offset, 1, addr)) {
        return KModErr::ERR_MODULE_INTERNAL_APPEND;
    }
    out_addr = addr;
    return KModErr::OK;
}

}  // namespace kernel_module
