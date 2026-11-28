// module base kernel func hook implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <atomic>
#include <cstddef>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <new>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "maplesu_storage_private.h"
#include "module_base_kernel_request.h"

#include "module_base_kernel_func_hook.h"
#include "module_base_kernel_mem.h"
#include "../aarch64/branch_encoding.h"
#include "maplesu_hook_private.h"
#include "maplesu_request_identity.h"
#include "../../../../ultra/authorization/kernel_read_metadata.h"
#include "../../../../ultra/authorization/legacy_hook_private.h"
#include "maplesu_kernel_layout_private.h"
#include "owner_publication_gate.h"

extern "C" __attribute__((visibility("hidden"))) int maplesu_identity_fork_status() noexcept;

extern "C" __attribute__((visibility("hidden"))) int64_t maplesu_publish_hook_checked(
    uint64_t entry, const uint32_t* branch, uint32_t original, uint64_t trampoline,
    uint64_t size, uint64_t disable_flag, kernel_module::HookContext** output) noexcept;

// 冻结 mangling：read_brk_4_kprobe_original_insn 是 C++ 全局作用域 static
// （_ZL31read_brk_4_kprobe_original_insnmRj），不是 kernel_module 成员。
static KModErr read_brk_4_kprobe_original_insn(uint64_t kaddr, uint32_t& out_insn);

namespace kernel_module {

// 64 字节随机标记串：汇编生成时用它们当“占位锚点”，随后在生成的机器码里
static char kOriginKaddrSlotFlag[64] =
    "mAmLFv9WvjgL8PK5mhoJzEHFtFY44Q3uzngXEcUBTxk1QnBGjGS4Dea7jffSewf";
static char kRetModeSlotFlag[64] =
    "ntfvxVpMRtNPHCMH57mAikEvbAFNG6hgZhIwaf1ANev5CeCPbAHMplHW3DcUoVa";
static char kMyBeforeHookBeginFlag[64] =
    "QAvDvcKxoypwF7y0TpVp3Wb4FcJN2XOSvef04uJuMFfs3wO1EnMiOQuo4jutbxR";
static char kMyBeforeHookEndFlag[64] =
    "bITKPKyU0bLGhMXXjvIz42FjYd5oco9AyNm9HhaCJT4Tk7wYOvTUj2LNeCxhVMq";
static char kMyAfterHookBeginFlag[64] =
    "Tnyx6capYmmVCvDFrBe6QX7fDc4TLEEbyrC9VHyDZCv9qFJHeQ2LTDMldw58sDx";
static char kMyAfterHookEndFlag[64] =
    "kgHc5HPVSS7pBSCNJR1lcT5t9hZJfSM06tmlcTjFrdC8hjnGKKOh0fmNaPPfxbe";

// 锚点串实际参与匹配的前 56 字节（标记 56 字节 + 8 字节槽位）。
constexpr uint32_t kAnchorNeedleSize = 56;

// （`sub sp, sp, #80` 开、`add sp, sp, #80` 收）。
constexpr uint32_t kHookTrampolineFrame = 80;

// 注意：仓库内 include/module_err_def.h 是重构件，KMODERR_LIST_AUTO 共 96 条，
constexpr KModErr kErrHookFuncNotStandard = static_cast<KModErr>(-19972);
constexpr KModErr kErrAsmRetTooLong = static_cast<KModErr>(-19990);
constexpr KModErr kErrIdleRegionMismatch = static_cast<KModErr>(-19967);
constexpr KModErr kErrSimulateInsn = static_cast<KModErr>(-19971);
constexpr KModErr kErrAsmBranchEncode = static_cast<KModErr>(-19970);
constexpr KModErr kErrKprobeSlotNotFound = static_cast<KModErr>(-19955);

//   构造一条 B 指令字；把被 hook 覆盖掉的原指令在跳板里“模拟”出来；
//   申请一段空闲内核内存；申请 hook 的 disable 标志槽。
bool emit_simulate_aarch64_insn(asmjit::a64::Assembler* a, uint64_t insn_kaddr,
                                uint32_t insn, uint64_t emit_at);
KModErr acquire_kernel_idle_region(uint64_t near_kaddr, uint64_t& out_kaddr);
KModErr acquire_kernel_hook_disable_flag(uint64_t& out_kaddr);
KModErr icache_invalidate_all_cpus();

// 被 hook 覆盖的原指令记录：内核地址 + 4 字节原指令。
struct InsnRecord {
    uint64_t addr;
    uint32_t insn;
};
static_assert(sizeof(InsnRecord) == 16, "layout constraint violated");

// 在已生成机器码里定位“origin kaddr 槽”（kOriginKaddrSlotFlag 之后第 56 字节）。
// 找不到返回 -1。
[[gnu::used, maybe_unused]] static int64_t find_origin_kaddr_slot_offset(const void* buf,
                                                                 uint32_t size) {
    if (buf == nullptr || size < kAnchorNeedleSize) {
        return -1;
    }
    const auto* begin = static_cast<const char*>(buf);
    const auto* end = begin + size;
    const auto* found = std::search(begin, end, kOriginKaddrSlotFlag,
                                    kOriginKaddrSlotFlag + kAnchorNeedleSize);
    if (found == end) {
        return -1;
    }
    return static_cast<int64_t>(found - begin) + kAnchorNeedleSize;
}

// 生成“继续执行被覆盖的原指令，然后跳回原函数”的跳板序列。
// 参数: a         汇编器
//       back_kaddr 跳板在内核里的起始地址（用于换算相对跳转）
//       records    被覆盖的原指令列表
// 返回: OK / -19971（模拟某条原指令失败）/ -19970（B 编码失败）
//
//   L2654-2665  逐条 emit_simulate_aarch64_insn，任一失败 → -19971（L2687）
//   L2667-2683  跳回 last.addr + 4；位移 = (last.addr+4) - (back_kaddr + a->offset())
//   L2683       编码失败 → -19970；成功 → 0
// 与原对象的刻意差异（1 处）
//   这里补一条空判断返回 -19971：不改任何可达路径的行为（两个调用点都保证 ≥1 条），
//   只是把 UB 变成可判定的错误。
[[gnu::used, maybe_unused]] static KModErr emit_old_insn_and_jump_back(
    Assembler* a, uint64_t back_kaddr, const std::vector<InsnRecord>& records) {
    if (records.empty()) {
        return kErrSimulateInsn;
    }
    for (const InsnRecord& record : records) {
        if (!emit_simulate_aarch64_insn(a, back_kaddr, record.insn, record.addr)) {
            return kErrSimulateInsn;
        }
    }
    // 跳回“最后一条被覆盖指令之后”的原函数位置。
    const InsnRecord& last = records.back();
    uint32_t branch = 0;
    if (last.addr > UINT64_MAX - 4 || a->offset() > UINT64_MAX - back_kaddr ||
        !maplesu::aarch64::encode_b(back_kaddr + a->offset(), last.addr + 4, branch)) {
        return kErrAsmBranchEncode;
    }
    if (a->embed(&branch, sizeof(branch)) != asmjit::kErrorOk) return kErrAsmBranchEncode;
    return KModErr::OK;
}

// 公开头文件只暴露 `typedef struct HookContext* HookHandle`，结构体本体在
struct HookContext {
    uint64_t entry;         // 被 hook 的指令地址
    uint32_t original;      // 被替换掉的 4 字节原指令
    uint64_t trampoline;    // 跳板（继续执行原逻辑）
    uint64_t size;
    uint8_t enabled;
    uint64_t disable_flag;  // 内核侧 disable 标志地址
};
static_assert(sizeof(HookContext) == 48, "layout constraint violated");
static_assert(offsetof(HookContext, enabled) == 32, "enabled 偏移");
static_assert(offsetof(HookContext, disable_flag) == 40, "disable_flag 偏移");

// 在已生成的机器码里找 kRetModeSlotFlag 锚点，返回“锚点之后第 56 字节”
// （即返回地址槽）在 buf 内的字节偏移；找不到返回 -1。
static int64_t find_ret_insn_slot_offset(const void* buf, uint32_t size) {
    if (buf == nullptr || size < kAnchorNeedleSize) {
        return -1;
    }
    const auto* begin = static_cast<const char*>(buf);
    const auto* end = begin + size;
    const auto* found = std::search(begin, end, kRetModeSlotFlag,
                                   kRetModeSlotFlag + kAnchorNeedleSize);
    if (found == end) {
        return -1;
    }
    return static_cast<int64_t>(found - begin) + kAnchorNeedleSize;
}

// 入口指令被 hook 覆盖后，用“原入口指令 + RET”构造等价返回序列。
//   0xd503239f / 0xd50323bf / 0xd50323df / 0xd50323ff
// 其它指令只发 RET（不做语义承诺）。
static void emit_ret_by_entry_insn(Assembler* a, uint32_t entry_insn) {
    uint32_t replaced = 0;
    switch (entry_insn) {
        case 0xd503231fu:
        case 0xd503239fu:
            replaced = 0xd503239fu;
            break;
        case 0xd503233fu:
        case 0xd50323bfu:
            replaced = 0xd50323bfu;
            break;
        case 0xd503235fu:
        case 0xd50323dfu:
            replaced = 0xd50323dfu;
            break;
        case 0xd503237fu:
        case 0xd50323ffu:
            replaced = 0xd50323ffu;
            break;
        default:
            break;
    }
    if (replaced != 0) {
        a->embed(&replaced, sizeof(replaced));
    }
    a->ret(x30);
}

// arm64_before_hook_start：hook 处理函数开头。
//   BTI C
//   LDP X28, XZR, [SP], #16     ; 弹出调用方压入的 8 字节占位 + 对齐
//   B   <跳过锚点区>
//   <8 字节 0>
//   kOriginKaddrSlotFlag(64) kRetModeSlotFlag(64)
//   kMyBeforeHookBeginFlag(64)
//   <此处 bind>
void arm64_before_hook_start(asmjit::a64::Assembler* a) {
    aarch64_asm_bit_c(a);
    a->ldp(x28, xzr, ptr(sp).post(16));

    const Label body = a->newLabel();
    a->b(body);
    const uint64_t zero_slot = 0;
    a->embed(&zero_slot, sizeof(zero_slot));
    a->embed(kOriginKaddrSlotFlag, sizeof(kOriginKaddrSlotFlag));
    a->embed(kRetModeSlotFlag, sizeof(kRetModeSlotFlag));
    a->embed(kMyBeforeHookBeginFlag, sizeof(kMyBeforeHookBeginFlag));
    a->bind(body);
}

// arm64_before_hook_end：hook 处理函数结尾。
//   B <跳过锚点区>; kMyBeforeHookEndFlag(64); <bind>
//   continue_original == true  -> RET X30（直接返回调用者）
//   continue_original == false -> LDP X29,X30,[SP],#16 ; ADD SP,SP,#80 ;
//                                 回填一条 B 到“返回地址槽”
void arm64_before_hook_end(asmjit::a64::Assembler* a, bool continue_original) {
    const Label body = a->newLabel();
    a->b(body);
    a->embed(kMyBeforeHookEndFlag, sizeof(kMyBeforeHookEndFlag));
    a->bind(body);

    if (continue_original) {
        a->ret(x30);
        return;
    }

    a->ldp(x29, x30, ptr(sp).post(16));
    a->add(sp, sp, Imm(80));

    // 在已生成的机器码里定位返回地址槽，然后从这里补一条 B 跳过去。
    // 偏移 = 槽位在缓冲区内的偏移 - 当前已生成字节数。
    const std::vector<uint8_t> code = aarch64_asm_to_bytes(a);
    const int64_t slot = find_ret_insn_slot_offset(
        code.data(), static_cast<uint32_t>(code.size()));
    uint32_t branch = 0;
    if (slot < 0 || !maplesu::aarch64::encode_b(a->offset(), static_cast<uint64_t>(slot), branch)) {
        a->reportError(asmjit::kErrorInvalidDisplacement);
        return;
    }
    a->embed(&branch, sizeof(branch));
}

// arm64_after_hook_start：after-hook 处理函数开头（结构同 before，但只保留
// origin 与 after-begin 两个锚点）。
void arm64_after_hook_start(asmjit::a64::Assembler* a) {
    aarch64_asm_bit_c(a);
    a->ldp(x28, xzr, ptr(sp).post(16));

    const Label body = a->newLabel();
    a->b(body);
    const uint64_t zero_slot = 0;
    a->embed(&zero_slot, sizeof(zero_slot));
    a->embed(kOriginKaddrSlotFlag, sizeof(kOriginKaddrSlotFlag));
    a->embed(kMyAfterHookBeginFlag, sizeof(kMyAfterHookBeginFlag));
    a->bind(body);
}

// arm64_after_hook_end：after-hook 处理函数结尾。
//   B <跳过锚点区>; kMyAfterHookEndFlag(64); <bind>; RET X30
void arm64_after_hook_end(asmjit::a64::Assembler* a) {
    const Label body = a->newLabel();
    a->b(body);
    a->embed(kMyAfterHookEndFlag, sizeof(kMyAfterHookEndFlag));
    a->bind(body);
    a->ret(x30);
}

// arm64_emit_call_original —— 在 Hook 处理函数内部手动执行一次原函数（R3）
//
//
// 为什么这样写：安装器把“调用原函数”的实现放进了 idle region 的 origin 入口，
// 而那条入口的地址在编译期是未知的（要等 idle region 申请下来才知道），
// 所以它被回填进处理函数里的 origin-kaddr 槽（R1 的 I 段 / R2 的 I 段）。
// 本函数生成的代码在运行时做三件事：
//   ① 保存 x0/x1（原函数会覆盖它们）
//   ② 算出 origin-kaddr 槽的运行时地址，从槽里取出 origin 入口地址
//   ③ blr 过去；那条 origin 入口以 `bti c` 开头、紧跟 `ldp x0, x1, [sp], #16`
//      然后模拟被覆盖的原指令并跳回原函数体，原函数 ret 时回到 ③ 的下一条。
//
//                   （helper 里 adr_value=0 → 先 bind 再 adr，位移 0，取 4 字节发出）
//
// 与原对象一致的已知弱点（实测，不修）：若处理函数里没有 origin-kaddr 槽
// （例如没先调用 arm64_before_hook_start），find_origin_kaddr_slot_offset 返回 -1，
void arm64_emit_call_original(asmjit::a64::Assembler* a) {
    // Resolve the complete slot before emitting any runtime stack operation.
    const std::vector<uint8_t> code = aarch64_asm_to_bytes(a);
    const int64_t slot_off = find_origin_kaddr_slot_offset(
        code.data(), static_cast<uint32_t>(code.size()));
    if (slot_off < 0 || static_cast<uint64_t>(slot_off) + 8 > code.size()) {
        a->reportError(asmjit::kErrorInvalidDisplacement);
        return;
    }
    a->stp(x0, x1, ptr(sp).pre(-16));

    // 记录此刻偏移：下一条 adr 就落在这里，所以它等于 adr 的实际运行时地址偏移
    const int64_t here = static_cast<int64_t>(a->offset());

    // ③ `adr x0, .` —— 让 x0 等于本条 adr 的运行时地址
    aarch64_asm_adr_x(a, x0, 0);

    // x0 = (adr 地址) + (槽偏移 - adr 偏移) = 槽的运行时地址
    const int64_t slot_disp = slot_off - here;
    aarch64_asm_mov_x(a, x1, static_cast<uint64_t>(slot_disp));
    a->add(x0, x0, x1);
    a->ldr(x0, ptr(x0));
    a->blr(x0);
}

namespace {
std::mutex publication_mutex;
thread_local unsigned publication_depth = 0;
thread_local bool publication_fork_locked = false;
thread_local unsigned publication_fork_depth = 0;
struct PublicationOperation {
    bool acquired = false;
    PublicationOperation() {
        if (maplesu_identity_fork_status()) return;
        if (!publication_depth) publication_mutex.lock();
        ++publication_depth;
        acquired = true;
    }
    ~PublicationOperation() {
        if (acquired && !--publication_depth) publication_mutex.unlock();
    }
};
std::set<uint64_t> published_entries;
KModErr write_and_readback(uint64_t address, const void* data, uint32_t size,
                          KernMemProt protection) {
    const KModErr error = protection == KernMemProt::KMP_RW ? maplesu_hook_write(address, data, size) :
        write_kernel_mem(address, data, size, protection);
    if (error != KModErr::OK) return error;
    std::vector<uint8_t> actual(size);
    const KModErr read_error = read_kernel_mem(address, actual.data(), size);
    if (read_error != KModErr::OK) return read_error;
    return std::memcmp(actual.data(), data, size) == 0 ? KModErr::OK
                                                     : KModErr::ERR_MODULE_ASM;
}

} // namespace

#include "legacy_hook_publication.h"
#include "owner_hook_codegen.h"
#include "owner_hook_publication.h"
#include "legacy_boot_hook_publication.h"

// uninstall_kernel_hook：把 disable 标志写 1，让跳板直接退回原函数。
KModErr uninstall_kernel_hook(HookHandle handle) {
    PublicationOperation operation;
    if (!operation.acquired) return KModErr::ERR_MODULE_ASM;
    if (!handle) return KModErr::ERR_MODULE_PARAM;
    const auto boot = legacy_boot_hooks.find(handle);
    if (boot != legacy_boot_hooks.end()) return uninstall_legacy_boot_hook(*boot->second);
    if (!handle->disable_flag) return KModErr::ERR_MODULE_PARAM;
    const auto owned = find_owner_hook(handle);
    if (owned != owner_hooks.end()) {
        const auto error = uninstall_owner_hook(owned->second);
        if (handle != owned->second.context.get()) *handle = *owned->second.context;
        return error;
    }
    return KModErr::ERR_MODULE_PARAM;
}

KModErr maplesu_install_owned_hook_with_actor(uint64_t address,
    const void* instructions, uint32_t size, const OwnedHookActor& actor,
    bool& transferred, HookHandle* output) {
    transferred = false;
    if (output) *output = nullptr;
    PublicationOperation operation;
    if (!operation.acquired) return KModErr::ERR_MODULE_ASM;
    try { return install_owner_hook(address, instructions, size, false, output,
        nullptr, 0, &actor, &transferred); }
    catch (const std::bad_alloc&) { return KModErr::ERR_NO_MEM; }
    catch (...) { return KModErr::ERR_MODULE_ASM; }
}

KModErr maplesu_install_owned_hook_with_shared_bools(uint64_t address,
    const void* instructions, uint32_t size, bool after,
    const RequestSharedBool* dependencies, uint32_t count, HookHandle* output) {
    if (output) *output = nullptr;
    PublicationOperation operation;
    if (!operation.acquired) return KModErr::ERR_MODULE_ASM;
    try { return install_owner_hook(address, instructions, size, after, output, dependencies, count); }
    catch (const std::bad_alloc&) { return KModErr::ERR_NO_MEM; }
    catch (...) { return KModErr::ERR_MODULE_ASM; }
}

// Both public installers prepare the complete closure through the current
// authenticated backend; native publication alone exposes the entry.
KModErr install_kfunc_before_hook_with_buf(uint64_t kaddr, const void* insn_buf,
                                          uint32_t size, HookContext** out_handle) {
    if (out_handle) *out_handle = nullptr;
    PublicationOperation operation;
    if (!operation.acquired) return KModErr::ERR_MODULE_ASM;
    try {
        bool boot_backend = false;
        const auto error = legacy_boot_backend_selected(boot_backend);
        if (error != KModErr::OK) return error;
        if (boot_backend) return install_legacy_boot_before(kaddr, insn_buf, size, out_handle);
        return install_owner_hook(kaddr, insn_buf, size, false, out_handle);
    }
    catch (const std::bad_alloc&) { return KModErr::ERR_NO_MEM; }
    catch (...) { return KModErr::ERR_MODULE_ASM; }
}

KModErr maplesu_hook_legacy_boot_selected(bool& selected) {
    return legacy_boot_backend_selected(selected);
}

// The same per-task owner spans original, including sleep, and the after callback.
KModErr install_kfunc_after_hook_with_buf(uint64_t kaddr, const void* insn_buf,
                                         uint32_t size, HookContext** out_handle) {
    PublicationOperation operation;
    if (!operation.acquired) return KModErr::ERR_MODULE_ASM;
    try { return install_owner_hook(kaddr, insn_buf, size, true, out_handle); }
    catch (const std::bad_alloc&) { return KModErr::ERR_NO_MEM; }
    catch (...) { return KModErr::ERR_MODULE_ASM; }
}

}  // namespace kernel_module

// Current Legacy EXEC enters through the ordinary execve task frame. Keep lookup and
// exact-field copies under the native mutex; a returned probe pointer has no lifetime.
KModErr read_brk_4_kprobe_original_insn(uint64_t kaddr, uint32_t& out_insn) {
    kernel_module::KernelFieldDescription addr_field, opcode_field;
    bool blob_available = false;
    RETURN_IF_ERROR(kernel_module::maplesu_resolve_kprobe_fields(
        addr_field, opcode_field, blob_available));
    if (addr_field.owner_size_bytes != opcode_field.owner_size_bytes)
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    uint64_t mutex_kaddr = 0;
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name("kprobe_mutex", mutex_kaddr));
    if (mutex_kaddr < 0xffff000000000000ULL) return KModErr::ERR_MODULE_NOT_KADDR;

    const std::function<KModErr(Assembler*)> emit_snapshot =
        [=](Assembler* a) -> KModErr {
        KModErr call_err = KModErr::OK;
        const Label unlock = a->newLabel();
        a->sub(sp, sp, Imm(16));
        a->mov(x22, sp);
        aarch64_asm_mov_x(a, x19, kaddr);
        aarch64_asm_mov_x(a, x20, mutex_kaddr);
        a->mov(x23, xzr);
        kernel_module::export_symbol::mutex_lock(a, call_err, x20);
        RETURN_IF_ERROR(call_err);
        kernel_module::export_symbol::get_kprobe(a, call_err, x19);
        RETURN_IF_ERROR(call_err);
        a->cbz(x0, unlock);
        a->mov(x21, x0);

        aarch64_asm_mov_x(a, x10, addr_field.offset_bytes);
        a->add(x10, x21, x10);
        kernel_module::export_symbol::copy_from_kernel_nofault(a, call_err, x22, x10, uint64_t(8));
        RETURN_IF_ERROR(call_err);
        a->cbnz(x0, unlock);
        a->ldr(x10, ptr(x22));
        a->cmp(x10, x19);
        a->b(CondCode::kNE, unlock);

        aarch64_asm_mov_x(a, x10, opcode_field.offset_bytes);
        a->add(x10, x21, x10);
        a->add(x11, x22, Imm(8));
        kernel_module::export_symbol::copy_from_kernel_nofault(a, call_err, x11, x10, uint64_t(4));
        RETURN_IF_ERROR(call_err);
        a->cbnz(x0, unlock);
        a->ldr(w23, ptr(x22, 8));
        aarch64_asm_mov_x(a, x10, uint64_t(1) << 32);
        a->orr(x23, x23, x10);

        a->bind(unlock);
        kernel_module::export_symbol::mutex_unlock(a, call_err, x20);
        a->add(sp, sp, Imm(16));
        return call_err;
    };

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    RETURN_IF_ERROR(emit_snapshot(a));
    kernel_module::arm64_module_asm_func_end(a, x23);
    const auto bytes = aarch64_asm_to_bytes(a);
    if (asm_ctx.has_error() || bytes.empty()) return KModErr::ERR_MODULE_ASM;
    uint64_t snapshot = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(bytes, snapshot));
    if ((snapshot >> 32) != 1) return kernel_module::kErrKprobeSlotNotFound;
    out_insn = static_cast<uint32_t>(snapshot);
    return KModErr::OK;
}


// Frozen external publication symbols share the same transaction as all installers.
extern "C" __attribute__((visibility("hidden"))) int maplesu_get_pending_hook(
    kernel_module::HookContext* out) noexcept {
    using namespace kernel_module;
    PublicationOperation operation;
    if (!operation.acquired) return 0;
    if (!out) return 0;
    for (const auto& item : owner_hooks) {
        if (item.second.pending && !item.second.retired) {
            *out = *item.second.context;
            return 1;
        }
    }
    return 0;
}

// The private return provider owns its 64-slot pool and overflow records.
// The old raw-pool diagnostics have no address/count to expose on this backend.
extern "C" __attribute__((visibility("hidden"))) int maplesu_get_after_hook_missed(
    kernel_module::HookHandle, uint64_t*) noexcept { return 0; }
extern "C" __attribute__((visibility("hidden"))) int maplesu_get_after_hook_pool(
    kernel_module::HookContext*, uint64_t*, uint32_t*) noexcept { return 0; }

extern "C" __attribute__((visibility("hidden"))) int64_t maplesu_publish_hook_checked(
    uint64_t entry, const uint32_t* branch, uint32_t original, uint64_t trampoline,
    uint64_t size, uint64_t disable_flag, kernel_module::HookContext** output) noexcept {
    using namespace kernel_module;
    PublicationOperation operation;
    if (!operation.acquired) return to_num(KModErr::ERR_MODULE_ASM);
    if (output) *output = nullptr;
    // This private compatibility entry has no publication ownership token.
    // Raw bytes alone never establish the closure's in-flight lifetime.
    errno = EOPNOTSUPP;
    return to_num(KModErr::ERR_MODULE_TEST_CHANNEL);
}

// The identity module invokes these in the same atfork lock order as Root keys.
extern "C" __attribute__((visibility("hidden"))) void maplesu_hook_fork_prepare() noexcept {
    using namespace kernel_module;
    if (!publication_depth && !publication_fork_locked) {
        publication_mutex.lock();
        publication_fork_locked = true;
    }
    ++publication_fork_depth;
}
extern "C" __attribute__((visibility("hidden"))) bool maplesu_hook_try_fork_prepare() noexcept {
    using namespace kernel_module;
    if (!publication_depth && !publication_fork_locked) {
        if (!publication_mutex.try_lock()) { errno = EAGAIN; return false; }
        publication_fork_locked = true;
    }
    ++publication_fork_depth;
    return true;
}
extern "C" __attribute__((visibility("hidden"))) void maplesu_hook_fork_complete() noexcept {
    using namespace kernel_module;
    if (!publication_fork_depth || --publication_fork_depth) return;
    if (publication_fork_locked) {
        publication_fork_locked = false;
        publication_mutex.unlock();
    }
}
