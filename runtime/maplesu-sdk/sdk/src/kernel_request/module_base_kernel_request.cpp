// module base kernel request implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

#include <pthread.h>
#include <unistd.h>

#include "module_base_kernel_request.h"
#include "module_base_kernel_mem.h"
#include "maplesu_request_private.h"
#include "maplesu_request_identity.h"
#include "maplesu_operation_wait_private.h"
#include "../../../../ultra/authorization/kernel_read_metadata.h"
#include "../../../../ultra/authorization/legacy_hook_private.h"

namespace kernel_module {
namespace {

constexpr size_t kFrameSize = 18;
// 掩码表与请求帧等长，逐字节记录该字节的还原方式。
constexpr size_t kMaskSize = 18;
// ROOT 密钥长度上界（不含此值，也是 strnlen 的扫描上限）。
constexpr size_t kRootKeyMaxLen = 1024;
// 允许进入请求包的密钥长度下限。
constexpr size_t kRootKeyMinLen = 16;
constexpr long kKernelRequestSyscall = 221;
constexpr size_t kPacketTrailer = 1;

//   * -19999                              64 位补码
//   * 0xfffeffffb1e1                      32 位错误码被原样回显进 64 位槽
constexpr int64_t kExecFailedDecoded = -19999;
constexpr uint64_t kExecFailedRaw = 0xfffeffffb1e1ull;

uint32_t align_to_page(uint32_t size, uint32_t page_size) {
    if (size == 0 || page_size == 0 || (page_size & (page_size - 1)) != 0 ||
        size > std::numeric_limits<uint32_t>::max() - (page_size - 1)) return 0;
    return (size + page_size - 1) & ~(page_size - 1);
}

bool valid_memory_range(uint64_t kaddr, const void* buffer, uint32_t size) {
    const auto user = reinterpret_cast<uintptr_t>(buffer);
    return kaddr != 0 && buffer != nullptr && size != 0 &&
        kaddr <= std::numeric_limits<uint64_t>::max() - (size - 1) &&
        user <= std::numeric_limits<uintptr_t>::max() - (size - 1);
}

}  // namespace

// 共享请求帧编码与传输；回执由各协议分别读取。
// 参数: flag      命令字 KernelCmdFlag
//       sub       子命令 / 单字节数据（写内存时就是要写的那个字节）
//       addr      目标内核地址，或被塞进帧的两个 32 位值
//       v0/v1     帧偏移 10 / 14 处的 32 位实参
// 返回: 0 成功；负值为 KModErr
static int64_t dispatch_kernel_request(KernelCmdFlag flag, uint8_t sub, uint64_t addr,
                                       uint32_t v0, uint32_t v1, const char* key_snapshot = nullptr) {
    if (!maplesu::deadline::available()) return to_num(KModErr::ERR_MODULE_TEST_CHANNEL);
    std::array<uint8_t, kFrameSize> request{};
    std::array<uint8_t, kMaskSize> mask{};

    request[0] = static_cast<uint8_t>(flag);
    request[1] = sub;
    std::memcpy(&request[2], &addr, sizeof(addr));
    std::memcpy(&request[10], &v0, sizeof(v0));
    std::memcpy(&request[14], &v1, sizeof(v1));

    // 逐字节编码，保证帧里不出现明文 0x00 / 0x01：
    //   0 -> 0xFF, mask=1      （0xFF + mask=1 还原成 0）
    //   1 -> 0xFF, mask=2      （0xFF + mask=2 还原成 1）
    //   n -> n-1, mask=1       （其它值减 1）
    for (size_t i = 0; i < kFrameSize; ++i) {
        switch (request[i]) {
            case 0:
                mask[i] = 1;
                request[i] = 0xFF;
                break;
            case 1:
                mask[i] = 2;
                request[i] = 0xFF;
                break;
            default:
                mask[i] = 1;
                request[i] = static_cast<uint8_t>(request[i] - 1);
                break;
        }
    }

    const char* root_key = maplesu_request_auth_legacy(maplesu_request_auth_state())
        ? (key_snapshot ? key_snapshot : current_module_root_key()) : MAPLESU_OWNER_ENVELOPE_PREFIX;
    if (root_key == nullptr) {
        return to_num(KModErr::ERR_MODULE_ROOT_KEY);
    }
    const size_t root_key_len = strnlen(root_key, kRootKeyMaxLen);
    if (root_key_len < kRootKeyMinLen || root_key_len >= kRootKeyMaxLen) {
        return to_num(KModErr::ERR_MODULE_ROOT_KEY);
    }
    const size_t key_len = root_key_len;

    try {
        std::vector<uint8_t> packet(key_len + kMaskSize + kFrameSize + kPacketTrailer);
        uint8_t* const base = packet.data();
        std::memcpy(base, root_key, key_len);
        std::memcpy(base + key_len, mask.data(), kMaskSize);
        std::memcpy(base + key_len + kMaskSize, request.data(), kFrameSize);

        if (!maplesu::deadline::available()) return to_num(KModErr::ERR_MODULE_TEST_CHANNEL);
        ::syscall(kKernelRequestSyscall, base, nullptr, nullptr);
    } catch (const std::bad_alloc&) {
        return to_num(KModErr::ERR_NO_MEM);
    }
    return 0;
}

// 旧协议内部符号保持 namespace 级静态链接（见 PROTOCOL §5）。
static int64_t send_kernel_request(KernelCmdFlag flag, uint8_t sub, uint64_t addr,
                                  uint32_t v0, uint32_t v1, uint64_t* out_reply,
                                  const char* key_snapshot = nullptr) {
    if (maplesu_request_owner_mode()) return to_num(KModErr::ERR_MODULE_TEST_CHANNEL);
    // Only the legacy receipt path needs credential privatization.
    if (const int64_t error = maplesu_prepare_kernel_request()) return error;
    if (const int64_t error = dispatch_kernel_request(flag, sub, addr, v0, v1, key_snapshot)) return error;

    if (out_reply == nullptr) {
        return 0;
    }

    // 回执 = (sgid << 32) | suid，由通道经 cred 回写后在此读回。
    uint32_t suid = 0, sgid = 0;
    const KModErr snapshot_error = SuidSgidGuard::snapshot(suid, sgid);
    if (is_failed(snapshot_error)) return to_num(snapshot_error);
    const uint64_t reply = (static_cast<uint64_t>(sgid) << 32) | suid;

    // r13 修订：执行请求失败时把回执翻译成返回码，避免上层把
    // “页已 stage 但未执行”误判为成功。
    if ((flag == KernelCmdFlag::EXEC_MEM || flag == KernelCmdFlag::ALLOC_MEM ||
         flag == KernelCmdFlag::READ_MEM) &&
        (reply == static_cast<uint64_t>(kExecFailedDecoded) || reply == kExecFailedRaw)) {
        return kExecFailedDecoded;
    }
    *out_reply = reply;
    return 0;
}

namespace {
std::atomic<uint64_t> request_sequence{0};
// Selection belongs to the calling task/thread, like its current credentials.
// A worker switching modes must not strand another thread's legacy receipt guard.
thread_local std::atomic<uint64_t> request_auth_state{0};
// Unique across threads and their lifetimes; allocation occurs only on selection
// or invalidation. Keep the all-ones owner sentinel permanently closed.
std::atomic<uint64_t> request_auth_sequence{0};

uint64_t next_auth_state(RequestAuthMode mode) {
    constexpr auto last = std::numeric_limits<uint64_t>::max() - 7;
    auto previous = request_auth_sequence.load(std::memory_order_relaxed);
    for (;;) {
        if (previous >= last) return std::numeric_limits<uint64_t>::max();
        const auto next = previous + 4;
        if (request_auth_sequence.compare_exchange_weak(previous, next,
                std::memory_order_relaxed, std::memory_order_relaxed))
            return next | static_cast<uint64_t>(mode);
    }
}

KModErr exchange_v2(uint32_t command, uint64_t arg0, uint64_t arg1, bool probe,
                   maplesu_response_v2& response, bool& supported, bool retain_completed = false) {
    response = {};
    supported = false;
    if (maplesu_request_owner_mode()) return KModErr::ERR_MODULE_TEST_CHANNEL;
    // The installed gateway's authenticated envelope is exactly 48 bytes.
    RequestIdentity identity;
    if (!identity.capture() || identity.length != 48) return KModErr::ERR_MODULE_ROOT_KEY;
    uint64_t saved = 0;
    if (probe) {
        if (const int64_t error = maplesu_prepare_kernel_request()) return static_cast<KModErr>(error);
        uid_t uid = 0, euid = 0, suid = 0;
        gid_t gid = 0, egid = 0, sgid = 0;
        // Only the compatibility probe may reach the legacy setter.
        // A negotiated exchange uses the independent response exclusively.
        if (getresuid(&uid, &euid, &suid) || getresgid(&gid, &egid, &sgid))
            return KModErr::ERR_MODULE_CRED_DANGER;
        saved = (static_cast<uint64_t>(sgid) << 32) | static_cast<uint32_t>(suid);
    }
    maplesu_response_v2 candidate{};
    maplesu_request_v2 request{};
    request.magic = MAPLESU_REQUEST_MAGIC;
    request.version = MAPLESU_REQUEST_PROTOCOL_VERSION;
    request.length = sizeof(request);
    request.command = command;
    request.request_id = request_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    request.response_user = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&candidate));
    request.arg0 = arg0;
    request.arg1 = arg1;
    const uint64_t address = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&request));
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    std::atomic_thread_fence(std::memory_order_release);
    const int64_t error = dispatch_kernel_request(KernelCmdFlag::SET_SUID_SGID,
        MAPLESU_REQUEST_SELECTOR_SUB, saved, static_cast<uint32_t>(address), static_cast<uint32_t>(address >> 32),
        identity.key.data());
    std::atomic_thread_fence(std::memory_order_acquire);
    if (error) return static_cast<KModErr>(error);
    if (!retain_completed && !identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    const maplesu_response_v2 empty{};
    if (probe && !std::memcmp(&candidate, &empty, sizeof(candidate))) return KModErr::OK;
    if (candidate.completion_magic != MAPLESU_RESPONSE_MAGIC ||
        candidate.version != MAPLESU_REQUEST_PROTOCOL_VERSION || candidate.length != sizeof(candidate) ||
        candidate.command != command || candidate.request_id != request.request_id)
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    response = candidate;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (command == MAPLESU_REQUEST_QUERY && candidate.status == MAPLESU_REQUEST_STATUS_OK) {
        if (!(candidate.result & MAPLESU_CAP_QUERY) || !candidate.metadata_address ||
            candidate.metadata_length != MAPLESU_METADATA_WIRE_BYTES ||
            candidate.metadata_version != MAPLESU_METADATA_VERSION) {
            response = {};
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        supported = true;
    }
    return KModErr::OK;
}
}

namespace { bool management_session_open(); }

uint64_t maplesu_request_auth_state() {
    auto state = request_auth_state.load(std::memory_order_acquire);
    if (!state) {
        state = next_auth_state(RequestAuthMode::ManagerOwner);
        request_auth_state.store(state, std::memory_order_release);
    }
    return state;
}

KModErr maplesu_request_set_auth_mode(RequestAuthMode mode) {
    if (mode != RequestAuthMode::LegacyKey && mode != RequestAuthMode::ManagerOwner &&
        mode != RequestAuthMode::EarlyHelper)
        return KModErr::ERR_MODULE_PARAM;
    if (management_session_open()) return KModErr::ERR_MODULE_TEST_CHANNEL;
    const auto next = next_auth_state(mode);
    request_auth_state.store(next, std::memory_order_release);
    return maplesu_request_auth_usable(next) ? KModErr::OK : KModErr::ERR_MODULE_TEST_CHANNEL;
}

namespace {
struct OwnerChannel {
    bool ready = false;
    uint64_t descriptor = 0;
    maplesu_metadata_owner_v3 metadata{};
    RequestOwnerBinding binding{};
};
thread_local OwnerChannel owner_channel;
struct OwnerAllocation { uint64_t address, handle; uint32_t length; };
struct OwnerPublication {
    uint64_t id = 0;
    uint32_t count = 0;
    std::array<uint64_t, 64> handles{};
};
struct OwnerManagement {
    uint64_t session = 0;
    RequestOwnerBinding binding{};
    bool uncertain = false;
    std::vector<OwnerAllocation> allocations;
    std::vector<OwnerPublication> publications;
};
thread_local OwnerManagement owner_management;
thread_local RequestIdentity key_management_identity;
thread_local bool key_management_unavailable = false;
// An address issued by the managed allocator must never become a legacy raw
// request after EXEC, CLOSE, fork or transfer to another thread. Keep merged
// provenance ranges separately from live, task-owned handles.
struct ManagedAddressRange { uint64_t first, last; };
std::vector<ManagedAddressRange> managed_address_ranges;
thread_local std::vector<ManagedAddressRange> legacy_address_ranges;
pthread_mutex_t managed_address_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_once_t managed_address_once = PTHREAD_ONCE_INIT;
int managed_address_fork_error = 0;
thread_local unsigned managed_address_fork_depth = 0;
void managed_address_before_fork() {
    if (!managed_address_fork_depth) pthread_mutex_lock(&managed_address_mutex);
    ++managed_address_fork_depth;
}
void managed_address_after_fork() {
    if (managed_address_fork_depth && !--managed_address_fork_depth)
        pthread_mutex_unlock(&managed_address_mutex);
}
void managed_address_initialize() {
    managed_address_fork_error = pthread_atfork(managed_address_before_fork,
        managed_address_after_fork, managed_address_after_fork);
}
bool remember_managed_address(uint64_t address, uint32_t length) {
    pthread_once(&managed_address_once, managed_address_initialize);
    if (managed_address_fork_error) { errno = managed_address_fork_error; return false; }
    const uint64_t last = address + length - 1;
    pthread_mutex_lock(&managed_address_mutex);
    auto first = address, end = last;
    for (const auto& range : managed_address_ranges) {
        if (address >= range.first && last <= range.last) {
            pthread_mutex_unlock(&managed_address_mutex);
            return true;
        }
        if ((range.last >= first || range.last + 1 == first) &&
            (range.first <= end || (end != UINT64_MAX && range.first == end + 1))) {
            first = std::min(first, range.first);
            end = std::max(end, range.last);
        }
    }
    try { managed_address_ranges.push_back({first, end}); }
    catch (const std::bad_alloc&) {
        pthread_mutex_unlock(&managed_address_mutex);
        errno = ENOMEM;
        return false;
    }
    // Only the new final record survives overlapping/adjacent old records.
    auto& ranges = managed_address_ranges;
    ranges.erase(std::remove_if(ranges.begin(), ranges.end() - 1,
        [first, end](const ManagedAddressRange& range) {
            return range.first >= first && range.last <= end;
        }), ranges.end() - 1);
    pthread_mutex_unlock(&managed_address_mutex);
    return true;
}
bool known_managed_address(uint64_t address) {
    pthread_mutex_lock(&managed_address_mutex);
    const bool known = std::any_of(managed_address_ranges.begin(), managed_address_ranges.end(),
        [address](const ManagedAddressRange& range) { return address >= range.first && address <= range.last; });
    pthread_mutex_unlock(&managed_address_mutex);
    return known;
}
struct HelperChannel {
    uint64_t auth_state = 0;
    pid_t process = 0;
    uid_t uid = 0, euid = 0;
    bool uncertain = true;
    maplesu_host_instance host{};
    uint64_t revision = 0;
    bool matches() const {
        return maplesu_request_auth_usable(auth_state) &&
            auth_state == maplesu_request_auth_state() && process == getpid() &&
            uid == getuid() && euid == geteuid() && auth_state == maplesu_request_auth_state();
    }
};
thread_local HelperChannel helper_channel;
thread_local RequestManagementReply management_reply;
thread_local RequestUidReadbackDiagnostic uid_readback_diagnostic;
thread_local pid_t management_process = 0;
void management_reset_after_fork() {
    const pid_t process = getpid();
    if (management_process != process) {
        // The kernel never transfers a task session at fork. Drop this child's
        // copied local view without releasing or closing the parent's handles.
        owner_management = {};
        key_management_identity = {};
        key_management_unavailable = false;
        legacy_address_ranges.clear();
        owner_channel = {};
        helper_channel = {};
        management_reply = {};
        uid_readback_diagnostic = {};
        management_process = process;
    }
}
bool management_session_open() {
    management_reset_after_fork();
    return owner_management.session != 0 || owner_management.uncertain;
}

bool owner_identity_matches(const RequestOwnerBinding& binding) {
    return maplesu_request_auth_usable(binding.auth_state) &&
        (maplesu_request_auth_authenticated(binding.auth_state) ||
            (maplesu_request_auth_legacy(binding.auth_state) && key_management_identity.matches())) &&
        binding.auth_state == maplesu_request_auth_state() &&
        binding.process == static_cast<uint64_t>(getpid()) && binding.actual_uid == getuid() &&
        binding.auth_state == maplesu_request_auth_state();
}

KModErr owner_failed(KModErr error, uint64_t failed_auth_state) {
    owner_channel = {};
    if (owner_management.session) owner_management.uncertain = true;
    // Invalidate identity-bound ordinary caches. Preserve the first error.
    if (maplesu_request_auth_authenticated(failed_auth_state) &&
        failed_auth_state == maplesu_request_auth_state()) {
        const auto next = next_auth_state(maplesu_request_auth_mode(failed_auth_state));
        request_auth_state.compare_exchange_strong(failed_auth_state, next,
            std::memory_order_acq_rel, std::memory_order_acquire);
    }
    return error;
}

KModErr owner_raw_exchange(uint32_t command, uint64_t arg0, uint64_t arg1,
                           const RequestOwnerBinding& binding, maplesu_response_owner_v3& response,
                           bool management = false, bool* query_rejected = nullptr) {
    response = {};
    if (query_rejected) *query_rejected = false;
    if (command != MAPLESU_REQUEST_QUERY && command != MAPLESU_REQUEST_ECHO64 &&
        command != MAPLESU_REQUEST_READ &&
        !(management && command >= MAPLESU_REQUEST_SESSION_OPEN && command <= MAPLESU_REQUEST_SU_RUNTIME_READ &&
          command != MAPLESU_REQUEST_VENDOR_STATE))
        return KModErr::ERR_MODULE_PARAM;
    if (!owner_identity_matches(binding)) { errno = ESTALE; return KModErr::ERR_MODULE_ROOT_KEY; }
    if (maplesu_request_auth_helper(binding.auth_state) && command == MAPLESU_REQUEST_QUERY) {
        errno = EPERM;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    maplesu_response_owner_v3 candidate{};
    const bool key_management = maplesu_request_auth_legacy(binding.auth_state);
    KModErr transport_error = KModErr::OK;
    maplesu_request_owner_v3 request{};
    request.magic = MAPLESU_REQUEST_MAGIC;
    request.version = MAPLESU_OWNER_PROTOCOL_VERSION;
    request.length = sizeof(request);
    request.command = command;
    request.expected_epoch = binding.epoch;
    request.request_id = request_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    request.response_user = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&candidate));
    request.arg0 = arg0;
    request.arg1 = arg1;
    if (key_management) {
        if (!management || !((command >= MAPLESU_REQUEST_SESSION_OPEN && command <= MAPLESU_REQUEST_RELEASE) ||
            command == MAPLESU_REQUEST_CRED_ROOT || command == MAPLESU_REQUEST_CRED_CAPS ||
            command == MAPLESU_REQUEST_CRED_PROCATTR || command == MAPLESU_REQUEST_TASK_STATE))
            return KModErr::ERR_MODULE_PARAM;
        bool ignored = false;
        transport_error = exchange_v2(command, arg0, arg1, false, candidate, ignored, true);
        if (is_failed(transport_error) && !candidate.completion_magic) return transport_error;
    } else {
        const auto pointer = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&request));
        std::atomic_thread_fence(std::memory_order_release);
        const auto error = dispatch_kernel_request(KernelCmdFlag::SET_SUID_SGID,
            MAPLESU_REQUEST_SELECTOR_SUB, 0, static_cast<uint32_t>(pointer),
            static_cast<uint32_t>(pointer >> 32), MAPLESU_OWNER_ENVELOPE_PREFIX);
        std::atomic_thread_fence(std::memory_order_acquire);
        if (error) return static_cast<KModErr>(error);
    }
    if (!key_management && (candidate.completion_magic != MAPLESU_RESPONSE_MAGIC ||
        candidate.version != MAPLESU_OWNER_PROTOCOL_VERSION || candidate.length != sizeof(candidate) ||
        candidate.command != command || candidate.request_id != request.request_id)) {
        errno = EPROTO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (management) {
        uint32_t effects = MAPLESU_EFFECT_QUARANTINED | MAPLESU_EFFECT_SESSION_CLOSED;
        if (command == MAPLESU_REQUEST_SESSION_OPEN && maplesu_request_auth_helper(binding.auth_state) &&
            !binding.epoch) effects |= MAPLESU_INSTALLATION_LIFECYCLE_EFFECTS;
        if (command == MAPLESU_REQUEST_SESSION_CLOSE) effects |= MAPLESU_EFFECT_SESSION_CLOSED |
            MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED;
        if (command == MAPLESU_REQUEST_ALLOC) effects |= MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_RELEASED |
            MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED;
        if (command == MAPLESU_REQUEST_WRITE) effects |= MAPLESU_EFFECT_WRITTEN | MAPLESU_EFFECT_TEXT_ATTEMPTED;
        if (command == MAPLESU_REQUEST_EXEC) effects |= MAPLESU_EFFECT_EXECUTED | MAPLESU_EFFECT_RELEASED;
        if (command == MAPLESU_REQUEST_RELEASE) effects |= MAPLESU_EFFECT_RELEASED;
        if (key_management && (candidate.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED))
            effects |= MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED;
        if (command == MAPLESU_REQUEST_CRED_ROOT || command == MAPLESU_REQUEST_CRED_CAPS)
            effects |= MAPLESU_EFFECT_COMMITTED;
        if (command >= MAPLESU_REQUEST_PUBLICATION_PREPARE && command <= MAPLESU_REQUEST_PUBLICATION_RETIRE)
            effects |= MAPLESU_EFFECT_PUBLICATION_PREPARED | MAPLESU_EFFECT_PUBLICATION_PUBLISHED |
                MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_GATE_PINNED |
                MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_TEXT_ATTEMPTED |
                MAPLESU_EFFECT_WRITTEN | MAPLESU_EFFECT_RELEASED;
        if (command == MAPLESU_REQUEST_SHARED_BOOL_CREATE) effects |= MAPLESU_EFFECT_ALLOCATED |
            MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED;
        if (command == MAPLESU_REQUEST_SHARED_BOOL_STORE) effects |= MAPLESU_EFFECT_WRITTEN;
        if (command == MAPLESU_REQUEST_SHARED_BOOL_RELEASE) effects |= MAPLESU_EFFECT_REFERENCE_DROPPED |
            MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_SHARED_RETAINED;
        if (command == MAPLESU_REQUEST_UID_CREATE) effects |= MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_COMMITTED;
        if (command == MAPLESU_REQUEST_UID_PREPARE) effects |= MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_REFERENCE_DROPPED;
        if (command == MAPLESU_REQUEST_UID_COMMIT) effects |= MAPLESU_EFFECT_COMMITTED |
            MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_PENDING;
        if (command == MAPLESU_REQUEST_UID_CANCEL) effects |= MAPLESU_EFFECT_REFERENCE_DROPPED;
        if (command == MAPLESU_REQUEST_UID_SHUTDOWN) effects |= MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_PENDING;
        if (command == MAPLESU_REQUEST_CRED_PROCATTR)
            effects |= MAPLESU_EFFECT_PROC_WRITE_ATTEMPTED | MAPLESU_EFFECT_CRED_CHANGED;
        if (command == MAPLESU_REQUEST_TASK_STATE)
            effects = MAPLESU_EFFECT_SESSION_CLOSED | MAPLESU_EFFECT_TASK_STATE_CHANGED |
                MAPLESU_EFFECT_TASK_STATE_COMPLETED;
        if (command == MAPLESU_REQUEST_DEPLOYMENT_READ || command == MAPLESU_REQUEST_SU_RUNTIME_READ)
            effects = MAPLESU_EFFECT_SESSION_CLOSED;
        if (command == MAPLESU_REQUEST_INSTALLATION_STATE)
            effects = MAPLESU_EFFECT_SESSION_CLOSED | MAPLESU_INSTALLATION_LIFECYCLE_EFFECTS;
        if (candidate.status > 0 || candidate.status < -4095 || candidate.metadata_version || (candidate.metadata_length & ~effects) ||
            (command != MAPLESU_REQUEST_ALLOC && command < MAPLESU_REQUEST_PUBLICATION_PREPARE &&
                !(command == MAPLESU_REQUEST_SESSION_OPEN && maplesu_request_auth_helper(binding.auth_state) &&
                  !binding.epoch) && candidate.metadata_address)) {
            errno = EPROTO;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        // Retain this call's validated wire facts if its authority changed
        // afterwards. The caller still validates command shape and fails closed.
        response = candidate;
        if (is_failed(transport_error)) return transport_error;
        // Only typed ROOT may rotate the recorded caller UID. Other completed
        // effects never adopt a new identity or retain mutation authority.
        if (command == MAPLESU_REQUEST_CRED_ROOT && (candidate.metadata_length & MAPLESU_EFFECT_COMMITTED)) {
            if (binding.process != static_cast<uint64_t>(getpid()) || getuid() != 0 ||
                binding.auth_state != maplesu_request_auth_state()) return KModErr::ERR_MODULE_ROOT_KEY;
            owner_channel.binding.actual_uid = 0;
            owner_management.binding.actual_uid = 0;
        } else if (!owner_identity_matches(binding)) return KModErr::ERR_MODULE_ROOT_KEY;
        return KModErr::OK;
    }
    if (query_rejected && command == MAPLESU_REQUEST_QUERY &&
        (arg0 == MAPLESU_OWNER_OPTIONAL_CAPABILITIES || arg0 == MAPLESU_OWNER_UID_QUERY ||
         arg0 == MAPLESU_OWNER_PROCATTR_QUERY || arg0 == MAPLESU_OWNER_TASK_QUERY) &&
        !arg1 && !binding.epoch &&
        (candidate.status == MAPLESU_REQUEST_STATUS_INVALID || candidate.status == MAPLESU_REQUEST_STATUS_UNSUPPORTED) &&
        !candidate.result && !candidate.metadata_address && !candidate.metadata_length && !candidate.metadata_version) {
        if (!owner_identity_matches(binding)) return KModErr::ERR_MODULE_ROOT_KEY;
        *query_rejected = true;
    }
    if (candidate.status > 0 || candidate.status < -4095) {
        errno = EPROTO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (candidate.status) {
        errno = -candidate.status;
        if (candidate.status == MAPLESU_REQUEST_STATUS_INVALID) return KModErr::ERR_MODULE_PARAM;
        if (candidate.status == MAPLESU_REQUEST_STATUS_FAULT) return KModErr::ERR_MODULE_NOT_KADDR;
        if (candidate.status == MAPLESU_REQUEST_STATUS_NOMEM) return KModErr::ERR_NO_MEM;
        if (candidate.status == MAPLESU_REQUEST_STATUS_DENIED || candidate.status == MAPLESU_REQUEST_STATUS_STALE)
            return KModErr::ERR_MODULE_ROOT_KEY;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (!owner_identity_matches(binding)) return KModErr::ERR_MODULE_ROOT_KEY;
    response = candidate;
    return KModErr::OK;
}

KModErr owner_read_batch(uint64_t source, void* destination, uint32_t size,
                         const RequestOwnerBinding& binding) {
    maplesu_read_owner_v3 read{};
    read.destination_user = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(destination));
    read.length = size;
    read.host = binding.host;
    maplesu_response_owner_v3 response{};
    const auto error = owner_raw_exchange(MAPLESU_REQUEST_READ, source,
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&read)), binding, response);
    if (is_failed(error)) return error;
    return response.result == size ? KModErr::OK : KModErr::ERR_MODULE_TEST_CHANNEL;
}

bool valid_owner_metadata(const maplesu_metadata_owner_v3& metadata, uint64_t descriptor,
                           uint64_t capabilities, const RequestOwnerBinding& identity) {
    const auto known = MAPLESU_OWNER_CAPABILITIES | MAPLESU_CAP_APPEND_AUDIT | MAPLESU_CAP_APPEND64;
    return !(capabilities & ~known) && (capabilities & (MAPLESU_CAP_QUERY | MAPLESU_CAP_READ)) ==
        (MAPLESU_CAP_QUERY | MAPLESU_CAP_READ) &&
        maplesu_kernel_read::valid_metadata_fields(metadata.common, descriptor, capabilities,
            MAPLESU_OWNER_METADATA_VERSION, sizeof(metadata)) &&
        metadata.owner_schema == MAPLESU_OWNER_SCHEMA && metadata.owner_state == MAPLESU_OWNER_STATE_BOUND &&
        metadata.owner_epoch && (metadata.host.low || metadata.host.high) &&
        metadata.owner_full_uid == identity.full_uid;
}
KModErr helper_management_channel(maplesu_metadata_owner_v3& metadata,
    uint64_t& descriptor, RequestOwnerBinding& binding);
}

// A fork child must not register these non-trivial TLS destructors with the
// dynamic loader for the first time. Initialize the calling thread's local
// request storage before fork; this performs no request and transfers no session.
extern "C" __attribute__((visibility("hidden"))) void maplesu_request_fork_prepare() noexcept {
    management_reset_after_fork();
}

extern "C" __attribute__((visibility("hidden"))) bool maplesu_request_try_fork_prepare() noexcept {
    if (!maplesu::deadline::available()) return false;
    if (!managed_address_fork_depth) {
        const int error = pthread_mutex_trylock(&managed_address_mutex);
        if (error) { errno = error == EBUSY ? EAGAIN : error; return false; }
    }
    ++managed_address_fork_depth;
    if (maplesu::deadline::available()) return true;
    const int error = errno;
    managed_address_after_fork();
    errno = error;
    return false;
}

extern "C" __attribute__((visibility("hidden"))) void maplesu_request_fork_complete() noexcept {
    managed_address_after_fork();
}

bool maplesu_request_owner_binding_matches(const RequestOwnerBinding& binding) {
    management_reset_after_fork();
    return !owner_management.uncertain && binding.epoch && (binding.host.low || binding.host.high) && owner_identity_matches(binding);
}

bool maplesu_request_owner_lifetime_capture(RequestOwnerLifetimeToken& token) {
    token = {};
    management_reset_after_fork();
    if (!owner_management.session ||
        !maplesu_request_owner_binding_matches(owner_management.binding)) return false;
    token.binding_ = owner_management.binding;
    token.session_ = owner_management.session;
    return true;
}

bool maplesu_request_owner_lifetime_matches(const RequestOwnerLifetimeToken& token) {
    management_reset_after_fork();
    if (!token.session_ || token.session_ != owner_management.session ||
        !maplesu_request_owner_binding_matches(token.binding_)) return false;
    const auto& current = owner_management.binding;
    const auto& saved = token.binding_;
    return current.auth_state == saved.auth_state && current.process == saved.process &&
        current.full_uid == saved.full_uid && current.actual_uid == saved.actual_uid &&
        current.epoch == saved.epoch && current.host.low == saved.host.low &&
        current.host.high == saved.host.high;
}

KModErr maplesu_request_owner_channel(maplesu_metadata_owner_v3& metadata,
    uint64_t& descriptor, RequestOwnerBinding& binding) {
    metadata = {};
    descriptor = 0;
    binding = {};
    management_reset_after_fork();
    if (!maplesu_request_owner_mode()) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (owner_management.uncertain) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (maplesu_request_helper_mode()) return helper_management_channel(metadata, descriptor, binding);
    if (owner_channel.ready && !maplesu_request_owner_binding_matches(owner_channel.binding))
        owner_channel = {};
    RequestOwnerBinding identity{};
    identity.auth_state = maplesu_request_auth_state();
    identity.process = static_cast<uint64_t>(getpid());
    identity.full_uid = getuid();
    identity.actual_uid = identity.full_uid;
    uint64_t address = owner_channel.descriptor;
    uint64_t capabilities = owner_channel.metadata.common.capabilities;
    if (!owner_channel.ready) {
        maplesu_response_owner_v3 query{};
        bool query_rejected = false;
        auto error = owner_raw_exchange(MAPLESU_REQUEST_QUERY, MAPLESU_OWNER_TASK_QUERY,
            0, identity, query, false, &query_rejected);
        if (query_rejected) error = owner_raw_exchange(MAPLESU_REQUEST_QUERY, MAPLESU_OWNER_PROCATTR_QUERY,
            0, identity, query, false, &query_rejected);
        if (query_rejected) {
            error = owner_raw_exchange(MAPLESU_REQUEST_QUERY, MAPLESU_OWNER_UID_QUERY,
                0, identity, query, false, &query_rejected);
            if (query_rejected) {
                error = owner_raw_exchange(MAPLESU_REQUEST_QUERY, MAPLESU_OWNER_OPTIONAL_CAPABILITIES,
                    0, identity, query, false, &query_rejected);
                if (query_rejected) error = owner_raw_exchange(MAPLESU_REQUEST_QUERY, 0, 0, identity, query);
            }
        }
        if (is_failed(error)) return owner_failed(error, identity.auth_state);
        uint64_t checked = 0;
        if (query.metadata_length != sizeof(metadata) || query.metadata_version != MAPLESU_OWNER_METADATA_VERSION ||
            (query.metadata_address & 7) || !maplesu_kernel_read::metadata_address(query.metadata_address,
                0, sizeof(metadata), checked)) return owner_failed(KModErr::ERR_MODULE_TEST_CHANNEL, identity.auth_state);
        address = query.metadata_address;
        capabilities = query.result;
    } else {
        identity = owner_channel.binding;
    }
    maplesu_metadata_owner_v3 candidate{};
    auto error = owner_read_batch(address, &candidate, sizeof(candidate), identity);
    if (is_failed(error)) return owner_failed(error, identity.auth_state);
    if (!valid_owner_metadata(candidate, address, capabilities, identity) ||
        (owner_channel.ready && std::memcmp(&candidate, &owner_channel.metadata, sizeof(candidate))))
        return owner_failed(KModErr::ERR_MODULE_INTERNAL_APPEND, identity.auth_state);
    if (!owner_identity_matches(identity)) return owner_failed(KModErr::ERR_MODULE_ROOT_KEY, identity.auth_state);
    identity.epoch = candidate.owner_epoch;
    identity.host = candidate.host;
    owner_channel.descriptor = address;
    owner_channel.metadata = candidate;
    owner_channel.binding = identity;
    owner_channel.ready = true;
    metadata = candidate;
    descriptor = address;
    binding = identity;
    return KModErr::OK;
}

KModErr maplesu_request_worker_admission() {
    const auto state = maplesu_request_auth_state();
    if (maplesu_request_auth_legacy(state)) {
        RequestIdentity identity;
        return identity.capture() ? KModErr::OK : KModErr::ERR_MODULE_ROOT_KEY;
    }
    if (maplesu_request_auth_manager(state)) {
        maplesu_metadata_owner_v3 metadata{};
        uint64_t descriptor = 0;
        RequestOwnerBinding binding{};
        return maplesu_request_owner_channel(metadata, descriptor, binding);
    }
    if (maplesu_request_auth_helper(state) && !getuid() && !geteuid()) {
        // Existing native init-user-ns/exact-helper verification; never OPEN a
        // parent session. Normal helper startup has already observed this state.
        maplesu_installation_state_v3 installation{};
        return maplesu_request_helper_vendor(MAPLESU_INSTALLATION_READ, 0, installation);
    }
    errno = EPERM;
    return KModErr::ERR_MODULE_ROOT_KEY;
}

KModErr maplesu_request_owner_read(uint64_t source, void* destination, uint32_t size,
    const RequestOwnerBinding& binding) {
    if (!valid_memory_range(source, destination, size) ||
        source < UINT64_C(0xffff000000000000)) return KModErr::ERR_MODULE_PARAM;
    const auto identity = binding;
    if (!maplesu_request_owner_binding_matches(identity)) return owner_failed(KModErr::ERR_MODULE_ROOT_KEY, identity.auth_state);
    if (maplesu_request_auth_helper(identity.auth_state) &&
        (!owner_channel.ready || source != owner_channel.descriptor || size != sizeof(maplesu_metadata_owner_v3))) {
        errno = EPERM;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    for (uint32_t done = 0; done < size;) {
        const auto count = std::min(MAPLESU_READ_MAX_BYTES, size - done);
        const auto error = owner_read_batch(source + done, static_cast<uint8_t*>(destination) + done, count, identity);
        if (is_failed(error)) return owner_failed(error, identity.auth_state);
        done += count;
    }
    return KModErr::OK;
}

KModErr maplesu_request_owner_echo(uint64_t value, uint64_t& result) {
    maplesu_metadata_owner_v3 metadata{};
    RequestOwnerBinding binding{};
    uint64_t address = 0;
    auto error = maplesu_request_owner_channel(metadata, address, binding);
    if (is_failed(error)) return error;
    if (!(metadata.common.capabilities & MAPLESU_CAP_ECHO64)) return KModErr::ERR_MODULE_TEST_CHANNEL;
    maplesu_response_owner_v3 response{};
    error = owner_raw_exchange(MAPLESU_REQUEST_ECHO64, value,
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&binding.host)), binding, response);
    if (is_failed(error)) return owner_failed(error, binding.auth_state);
    if (response.result != value) return owner_failed(KModErr::ERR_MODULE_TEST_CHANNEL, binding.auth_state);
    result = response.result;
    return KModErr::OK;
}

namespace {
KModErr management_status(int32_t status) {
    if (!status) return KModErr::OK;
    errno = -status;
    if (status == MAPLESU_REQUEST_STATUS_INVALID) return KModErr::ERR_MODULE_PARAM;
    if (status == MAPLESU_REQUEST_STATUS_FAULT) return KModErr::ERR_MODULE_NOT_KADDR;
    if (status == MAPLESU_REQUEST_STATUS_NOMEM) return KModErr::ERR_NO_MEM;
    if (status == MAPLESU_REQUEST_STATUS_DENIED || status == MAPLESU_REQUEST_STATUS_STALE)
        return KModErr::ERR_MODULE_ROOT_KEY;
    return KModErr::ERR_MODULE_TEST_CHANNEL;
}
uint32_t early_fixed_effect_mask(uint32_t operation) {
    if (operation >= MAPLESU_EARLY_FIXED_OEM_MTK &&
        operation <= MAPLESU_EARLY_FIXED_OEM_OPLUS_INTE)
        return MAPLESU_EARLY_FIXED_EFFECT_COMMON_MASK;
    if (operation == MAPLESU_EARLY_FIXED_ROOT_ENV)
        return MAPLESU_EARLY_FIXED_EFFECT_ROOT_MASK;
    if (operation >= MAPLESU_EARLY_FIXED_SELINUX_PREPARE &&
        operation <= MAPLESU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE)
        return MAPLESU_EARLY_FIXED_EFFECT_SELINUX_MASK;
    return 0;
}

bool management_error_shape(uint32_t command, const maplesu_management_v3& operation,
                            const maplesu_response_owner_v3& response) {
    const auto effects = response.metadata_length & ~MAPLESU_EFFECT_SESSION_CLOSED;
    const bool closed = response.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED;
    const bool zero = !response.result && !response.metadata_address;
    const bool same_handle = response.metadata_address == operation.handle;
    const auto only = [effects](uint32_t mask) { return !(effects & ~mask); };
    const auto kernel_range = [](uint64_t address, uint32_t size) {
        return size && address >= UINT64_C(0xffff000000000000) &&
            size - 1 <= std::numeric_limits<uint64_t>::max() - address;
    };
    // END or delivery cleanup can close the whole Key session after this
    // command completed. Its cleanup effects describe every owned resource,
    // including earlier allocations, so keep them without attributing them to
    // the current WRITE/EXEC. Output publication still requires status == 0.
    if (closed && maplesu_request_auth_legacy(maplesu_request_auth_state()) &&
        command >= MAPLESU_REQUEST_SESSION_OPEN && command <= MAPLESU_REQUEST_RELEASE) {
        const uint32_t cleanup = MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED |
            MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED;
        if ((effects & MAPLESU_EFFECT_SHARED_RETAINED) && !(effects & MAPLESU_EFFECT_REFERENCE_DROPPED)) return false;
        switch (command) {
        case MAPLESU_REQUEST_SESSION_OPEN:
            return !response.metadata_address && only(cleanup);
        case MAPLESU_REQUEST_SESSION_CLOSE:
            return zero && only(cleanup);
        case MAPLESU_REQUEST_ALLOC:
            return only(cleanup | MAPLESU_EFFECT_ALLOCATED) &&
                (zero || (response.metadata_address && kernel_range(response.result, operation.length) &&
                    (effects & MAPLESU_EFFECT_ALLOCATED)));
        case MAPLESU_REQUEST_WRITE:
            return !response.metadata_address && response.result <= operation.length &&
                only(cleanup | MAPLESU_EFFECT_WRITTEN) &&
                (!!response.result == !!(effects & MAPLESU_EFFECT_WRITTEN)) &&
                (!operation.handle || !response.result || response.result == operation.length);
        case MAPLESU_REQUEST_EXEC:
            return !response.metadata_address && only(cleanup | MAPLESU_EFFECT_EXECUTED) &&
                ((effects & MAPLESU_EFFECT_EXECUTED) ?
                    !!(effects & (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED)) : !response.result);
        case MAPLESU_REQUEST_RELEASE:
            return zero && only(cleanup);
        }
    }
    const bool text_prefix = (response.result == 0 || response.result == 4) &&
        (!(effects & MAPLESU_EFFECT_WRITTEN) || (effects & MAPLESU_EFFECT_TEXT_ATTEMPTED)) &&
        (!response.result || (effects & MAPLESU_EFFECT_WRITTEN));
    switch (command) {
    case MAPLESU_REQUEST_SESSION_OPEN:
        if (maplesu_request_helper_mode() && !operation.session &&
            operation.length == sizeof(maplesu_metadata_owner_v3)) {
            const bool invalidated = effects & MAPLESU_EFFECT_COMMITTED;
            return !response.metadata_address && (!response.result || closed) &&
                only(MAPLESU_INSTALLATION_LIFECYCLE_EFFECTS) &&
                (!effects || (invalidated && (effects & MAPLESU_EFFECT_PENDING)));
        }
        return !response.metadata_address && !effects && (!response.result || closed);
    case MAPLESU_REQUEST_SESSION_CLOSE:
        return zero && (!effects || (closed && only(MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED |
            MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED)));
    case MAPLESU_REQUEST_ALLOC:
        if (!zero) return closed && effects == MAPLESU_EFFECT_ALLOCATED && response.metadata_address &&
            kernel_range(response.result, operation.length);
        if (!closed) return effects == 0 ||
            effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_RELEASED) ||
            effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_QUARANTINED);
        return only(MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED |
            MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED) &&
            (!(effects & MAPLESU_EFFECT_ALLOCATED) ||
                (effects & (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED))) &&
            (!(effects & MAPLESU_EFFECT_SHARED_RETAINED) || (effects & MAPLESU_EFFECT_REFERENCE_DROPPED));
    case MAPLESU_REQUEST_WRITE:
        if (response.metadata_address || response.result > operation.length) return false;
        if (operation.flags & MAPLESU_MANAGEMENT_WRITE_TEXT)
            return only(MAPLESU_EFFECT_WRITTEN | MAPLESU_EFFECT_TEXT_ATTEMPTED) &&
                (!(effects & MAPLESU_EFFECT_WRITTEN) || (effects & MAPLESU_EFFECT_TEXT_ATTEMPTED)) &&
                (!response.result || (effects & MAPLESU_EFFECT_WRITTEN)) &&
                (!(response.result & 3) || response.result == operation.length);
        return only(MAPLESU_EFFECT_WRITTEN) &&
            (!!response.result == !!(effects & MAPLESU_EFFECT_WRITTEN)) &&
            (!operation.handle || !response.result || response.result == operation.length);
    case MAPLESU_REQUEST_EXEC:
        return !response.metadata_address && only(MAPLESU_EFFECT_EXECUTED | MAPLESU_EFFECT_RELEASED |
            MAPLESU_EFFECT_QUARANTINED) &&
            (!(effects & MAPLESU_EFFECT_EXECUTED) ? !response.result :
                !!(effects & (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED))) &&
            (effects & (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED)) !=
                (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED);
    case MAPLESU_REQUEST_RELEASE:
        return zero && (effects == 0 || effects == MAPLESU_EFFECT_RELEASED ||
            effects == MAPLESU_EFFECT_QUARANTINED);
    case MAPLESU_REQUEST_CRED_ROOT:
    case MAPLESU_REQUEST_CRED_CAPS:
        return zero && only(MAPLESU_EFFECT_COMMITTED);
    case MAPLESU_REQUEST_DEPLOYMENT_READ:
        return !response.metadata_address && !effects &&
            (!response.result || response.result == sizeof(maplesu_deployment_namespace_v3));
    case MAPLESU_REQUEST_SU_RUNTIME_READ:
        return !response.metadata_address && !effects &&
            (!response.result || response.result == sizeof(maplesu_su_runtime_status_v3));
    case MAPLESU_REQUEST_EARLY_FIXED:
        return !response.metadata_address &&
            (!response.result || response.result == sizeof(RequestEarlyFixedResult)) &&
            !effects;
    case MAPLESU_REQUEST_INSTALLATION_STATE:
        return !response.metadata_address &&
            (operation.address == MAPLESU_INSTALLATION_READ ?
                !effects && (!response.result || response.result == sizeof(maplesu_installation_state_v3)) :
                !response.result && only(MAPLESU_INSTALLATION_LIFECYCLE_EFFECTS));
    case MAPLESU_REQUEST_PUBLICATION_PREPARE:
        if (!zero) return closed && response.result && !(response.metadata_address & 7) &&
            effects == MAPLESU_EFFECT_PUBLICATION_PREPARED &&
            kernel_range(response.metadata_address, sizeof(maplesu_publication_control_v3));
        return only(MAPLESU_EFFECT_PUBLICATION_PREPARED | MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED);
    case MAPLESU_REQUEST_PUBLICATION_PUBLISH:
        if (!same_handle) return zero && !effects;
        if (!(effects & MAPLESU_EFFECT_PUBLICATION_RETAINED))
            return !response.result && only(MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED);
        return text_prefix && only(MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_PUBLICATION_PUBLISHED |
            MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_TEXT_ATTEMPTED | MAPLESU_EFFECT_WRITTEN) &&
            (!response.result || (effects & MAPLESU_EFFECT_PUBLICATION_PUBLISHED)) &&
            (closed || (effects & MAPLESU_EFFECT_PENDING));
    case MAPLESU_REQUEST_PUBLICATION_DISABLE:
    case MAPLESU_REQUEST_PUBLICATION_RETIRE:
        if (!same_handle) return zero && !effects;
        if (!effects) return !response.result;
        if (command == MAPLESU_REQUEST_PUBLICATION_DISABLE && !(effects & MAPLESU_EFFECT_PUBLICATION_RETAINED))
            return !response.result && (effects & MAPLESU_EFFECT_RELEASED) &&
                only(MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED | MAPLESU_EFFECT_PENDING) &&
                (!(effects & MAPLESU_EFFECT_QUARANTINED) || (effects & MAPLESU_EFFECT_PENDING));
        if (!(effects & MAPLESU_EFFECT_PUBLICATION_RETAINED))
            return command == MAPLESU_REQUEST_PUBLICATION_RETIRE && text_prefix &&
                only(MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED |
                    MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_TEXT_ATTEMPTED | MAPLESU_EFFECT_WRITTEN |
                    MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED) &&
                (!(effects & MAPLESU_EFFECT_SHARED_RETAINED) || (effects & MAPLESU_EFFECT_REFERENCE_DROPPED));
        return text_prefix && (effects & MAPLESU_EFFECT_GATE_PINNED) &&
            only(MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_GATE_PINNED | MAPLESU_EFFECT_PENDING |
                MAPLESU_EFFECT_QUARANTINED | MAPLESU_EFFECT_TEXT_ATTEMPTED | MAPLESU_EFFECT_WRITTEN |
                (command == MAPLESU_REQUEST_PUBLICATION_RETIRE ?
                    MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED : 0)) &&
            (!(effects & MAPLESU_EFFECT_SHARED_RETAINED) || (effects & MAPLESU_EFFECT_REFERENCE_DROPPED)) &&
            (!(effects & MAPLESU_EFFECT_QUARANTINED) || (effects & MAPLESU_EFFECT_PENDING));
    case MAPLESU_REQUEST_SHARED_BOOL_CREATE:
        if (!zero) return closed && effects == MAPLESU_EFFECT_ALLOCATED && response.metadata_address &&
            kernel_range(response.result, 1);
        return effects == 0 || effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_RELEASED) ||
            effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_QUARANTINED) ||
            (closed && (effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_RELEASED) ||
                effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_QUARANTINED) ||
                effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED)));
    case MAPLESU_REQUEST_SHARED_BOOL_STORE:
        if (!same_handle) return zero && !effects;
        return only(MAPLESU_EFFECT_WRITTEN) && response.result <= 1 &&
            (!response.result || (effects & MAPLESU_EFFECT_WRITTEN));
    case MAPLESU_REQUEST_SHARED_BOOL_RELEASE:
        if (!same_handle) return zero && !effects;
        return !response.result && (effects == 0 ||
            effects == (MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_RELEASED) ||
            effects == (MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_QUARANTINED) ||
            effects == (MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED));
    default:
        // UID and procattr have their typed validators immediately below.
        return true;
    }
}
bool runtime_uid_sync_receipt_valid(const maplesu_response_owner_v3& response) {
    const auto effects = response.metadata_length & ~MAPLESU_EFFECT_SESSION_CLOSED;
    constexpr uint32_t known = MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_COMMITTED |
        MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_QUARANTINED;
    if (response.metadata_address || (effects & ~known) ||
        ((effects & MAPLESU_EFFECT_QUARANTINED) && !(effects & MAPLESU_EFFECT_PENDING))) return false;
    const bool committed = effects & MAPLESU_EFFECT_COMMITTED;
    const bool consumed = effects & MAPLESU_EFFECT_REFERENCE_DROPPED;
    // Private candidate/controller IDs stay with HOST. A successful unchanged
    // sync returns its held revision, including after a completed cancel.
    // ALLOCATED/PENDING never fabricates a committed revision.
    if (committed && (!consumed || !response.result)) return false;
    if (response.status && !committed && response.result &&
        (!(response.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED) ||
         (effects & ~MAPLESU_EFFECT_REFERENCE_DROPPED))) return false;
    if (!response.status) return response.result && (!(effects & ~MAPLESU_EFFECT_REFERENCE_DROPPED) || (committed && consumed)) &&
        !(effects & (MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_QUARANTINED)) &&
        !(response.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED);
    return true;
}
KModErr management_exchange(uint32_t command, const maplesu_management_v3& operation,
                           const RequestOwnerBinding& binding) {
    management_reply = {};
    maplesu_response_owner_v3 response{};
    const auto error = owner_raw_exchange(command, 0,
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&operation)), binding, response, true);
    if (is_failed(error)) {
        owner_management.uncertain = true;
        if (!response.completion_magic) return error;
    }
    if (response.status < 0 && !management_error_shape(command, operation, response)) {
        owner_management.uncertain = true;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (command == MAPLESU_REQUEST_WRITE && !(operation.flags & MAPLESU_MANAGEMENT_WRITE_TEXT) &&
        (response.metadata_length & MAPLESU_EFFECT_TEXT_ATTEMPTED)) {
        owner_management.uncertain = true;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (command == MAPLESU_REQUEST_CRED_PROCATTR) {
        const auto effects = response.metadata_length;
        const bool attempted = effects & MAPLESU_EFFECT_PROC_WRITE_ATTEMPTED;
        const bool changed = effects & MAPLESU_EFFECT_CRED_CHANGED;
        const bool closed = effects & MAPLESU_EFFECT_SESSION_CLOSED;
        if ((effects & ~(MAPLESU_EFFECT_PROC_WRITE_ATTEMPTED | MAPLESU_EFFECT_CRED_CHANGED |
                MAPLESU_EFFECT_SESSION_CLOSED)) || response.metadata_address || response.result > INT64_MAX ||
            (!attempted && response.result) ||
            (response.status < 0 && (attempted || changed) && !closed) ||
            (!response.status && (!attempted || closed || response.result != operation.length))) {
            owner_management.uncertain = true;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
    }
    if (command == MAPLESU_REQUEST_TASK_STATE) {
        const auto effects = response.metadata_length;
        const bool completed = effects & MAPLESU_EFFECT_TASK_STATE_COMPLETED;
        const bool changed = effects & MAPLESU_EFFECT_TASK_STATE_CHANGED;
        if (response.metadata_address || response.result > 2 ||
            (changed && (!completed || !response.result)) ||
            (completed && (!!response.result != changed)) ||
            (!completed && response.result) ||
            (!response.status && (!completed || (effects & MAPLESU_EFFECT_SESSION_CLOSED)))) {
            owner_management.uncertain = true;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
    }
    if (command >= MAPLESU_REQUEST_UID_CREATE && command <= MAPLESU_REQUEST_UID_SHUTDOWN) {
        const auto effects = response.metadata_length & ~MAPLESU_EFFECT_SESSION_CLOSED;
        const auto completed_effects = effects & ~(MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_QUARANTINED);
        const bool negative_pending = response.status < 0 && (effects & MAPLESU_EFFECT_PENDING);
        bool valid = false;
        switch (command) {
        case MAPLESU_REQUEST_UID_CREATE:
            valid = (!effects && !response.result && !response.metadata_address) ||
                (effects == MAPLESU_EFFECT_ALLOCATED && !response.result && response.metadata_address) ||
                (effects == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_COMMITTED) &&
                    response.result == 1 && response.metadata_address);
            break;
        case MAPLESU_REQUEST_UID_PREPARE:
            valid = (!effects && !response.result && !response.metadata_address) ||
                (effects == MAPLESU_EFFECT_ALLOCATED && response.result && response.metadata_address == operation.handle);
            break;
        case MAPLESU_REQUEST_UID_COMMIT:
            if (!operation.handle) {
                valid = runtime_uid_sync_receipt_valid(response);
                break;
            }
            valid = (!effects && !response.result && !response.metadata_address) ||
                (negative_pending && !completed_effects &&
                    !response.result && response.metadata_address == operation.address) ||
                (completed_effects == (MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_REFERENCE_DROPPED) &&
                    (effects == completed_effects || negative_pending) &&
                    response.result && response.metadata_address == operation.address);
            break;
        case MAPLESU_REQUEST_UID_CANCEL:
            valid = (!effects && !response.result && !response.metadata_address) ||
                (effects == MAPLESU_EFFECT_REFERENCE_DROPPED && !response.result && response.metadata_address == operation.handle);
            break;
        case MAPLESU_REQUEST_UID_READBACK:
            if (!operation.handle) valid = !response.metadata_address &&
                (response.status == -EINPROGRESS ?
                    (!response.result && effects == MAPLESU_EFFECT_PENDING) : !effects);
            else valid = !effects && ((!response.result && !response.metadata_address) ||
                    (response.result && response.metadata_address == operation.handle));
            break;
        case MAPLESU_REQUEST_UID_SHUTDOWN:
            valid = (!effects && !response.result && !response.metadata_address) ||
                (negative_pending && !completed_effects &&
                    !response.result && response.metadata_address == operation.handle) ||
                (completed_effects == MAPLESU_EFFECT_RELEASED &&
                    (effects == completed_effects || negative_pending) &&
                    !response.result && response.metadata_address == operation.handle);
            break;
        }
        if (!valid) {
            owner_management.uncertain = true;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
    }
    management_reply = {response.status, response.metadata_length, response.result,
                        response.metadata_address, command, true};
    if (command != MAPLESU_REQUEST_SESSION_CLOSE &&
        (response.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED)) owner_management.uncertain = true;
    if (!response.status) {
        bool valid = false;
        switch (command) {
        case MAPLESU_REQUEST_SESSION_OPEN:
            if (maplesu_request_auth_helper(binding.auth_state) && !binding.epoch) {
                uint64_t checked = 0;
                valid = response.result && !response.metadata_length &&
                    !(response.metadata_address & 7) && maplesu_kernel_read::metadata_address(
                        response.metadata_address, 0, sizeof(maplesu_metadata_owner_v3), checked);
            } else valid = response.result && !response.metadata_address && !response.metadata_length;
            break;
        case MAPLESU_REQUEST_SESSION_CLOSE:
            valid = !response.result && !response.metadata_address &&
                (response.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED) &&
                !(response.metadata_length & MAPLESU_EFFECT_QUARANTINED);
            break;
        case MAPLESU_REQUEST_ALLOC:
            valid = response.result >= UINT64_C(0xffff000000000000) && response.metadata_address &&
                operation.length - 1 <= std::numeric_limits<uint64_t>::max() - response.result &&
                response.metadata_length == MAPLESU_EFFECT_ALLOCATED;
            break;
        case MAPLESU_REQUEST_WRITE:
            valid = response.result == operation.length && response.metadata_length ==
                (MAPLESU_EFFECT_WRITTEN | ((operation.flags & MAPLESU_MANAGEMENT_WRITE_TEXT)
                    ? MAPLESU_EFFECT_TEXT_ATTEMPTED : 0));
            break;
        case MAPLESU_REQUEST_EXEC:
            valid = response.metadata_length == (MAPLESU_EFFECT_EXECUTED | MAPLESU_EFFECT_RELEASED);
            break;
        case MAPLESU_REQUEST_RELEASE:
            valid = !response.result && response.metadata_length == MAPLESU_EFFECT_RELEASED;
            break;
        case MAPLESU_REQUEST_CRED_ROOT:
        case MAPLESU_REQUEST_CRED_CAPS:
            valid = !response.result && response.metadata_length == MAPLESU_EFFECT_COMMITTED;
            break;
        case MAPLESU_REQUEST_SHARED_BOOL_CREATE:
            valid = response.result >= UINT64_C(0xffff000000000000) && response.metadata_address &&
                response.metadata_length == MAPLESU_EFFECT_ALLOCATED;
            break;
        case MAPLESU_REQUEST_SHARED_BOOL_STORE:
            valid = response.metadata_address == operation.handle && response.result == 1 &&
                response.metadata_length == MAPLESU_EFFECT_WRITTEN;
            break;
        case MAPLESU_REQUEST_SHARED_BOOL_RELEASE:
            valid = response.metadata_address == operation.handle && !response.result &&
                (response.metadata_length == (MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_RELEASED) ||
                 response.metadata_length == (MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED));
            break;
        case MAPLESU_REQUEST_UID_CREATE:
            valid = response.result == 1 && response.metadata_address &&
                response.metadata_length == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_COMMITTED);
            break;
        case MAPLESU_REQUEST_UID_PREPARE:
            valid = response.result && response.metadata_address == operation.handle &&
                response.metadata_length == MAPLESU_EFFECT_ALLOCATED;
            break;
        case MAPLESU_REQUEST_UID_COMMIT:
            if (!operation.handle) {
                valid = runtime_uid_sync_receipt_valid(response);
                break;
            }
            valid = response.result && response.metadata_address == operation.address &&
                response.metadata_length == (MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_REFERENCE_DROPPED);
            break;
        case MAPLESU_REQUEST_UID_CANCEL:
            valid = !response.result && response.metadata_address == operation.handle &&
                response.metadata_length == MAPLESU_EFFECT_REFERENCE_DROPPED;
            break;
        case MAPLESU_REQUEST_UID_READBACK:
            valid = response.result && response.metadata_address == operation.handle && !response.metadata_length;
            break;
        case MAPLESU_REQUEST_UID_SHUTDOWN:
            valid = !response.result && response.metadata_address == operation.handle &&
                response.metadata_length == MAPLESU_EFFECT_RELEASED;
            break;
        case MAPLESU_REQUEST_CRED_PROCATTR:
            valid = !response.metadata_address && response.result == operation.length &&
                (response.metadata_length == MAPLESU_EFFECT_PROC_WRITE_ATTEMPTED ||
                 response.metadata_length == (MAPLESU_EFFECT_PROC_WRITE_ATTEMPTED | MAPLESU_EFFECT_CRED_CHANGED));
            break;
        case MAPLESU_REQUEST_TASK_STATE:
            valid = !response.metadata_address && response.result <= 2 &&
                (response.metadata_length == MAPLESU_EFFECT_TASK_STATE_COMPLETED ||
                 response.metadata_length == (MAPLESU_EFFECT_TASK_STATE_COMPLETED |
                    MAPLESU_EFFECT_TASK_STATE_CHANGED));
            break;
        case MAPLESU_REQUEST_DEPLOYMENT_READ:
            valid = response.result == sizeof(maplesu_deployment_namespace_v3) &&
                !response.metadata_address && !response.metadata_length;
            break;
        case MAPLESU_REQUEST_SU_RUNTIME_READ:
            valid = response.result == sizeof(maplesu_su_runtime_status_v3) &&
                !response.metadata_address && !response.metadata_length;
            break;
        case MAPLESU_REQUEST_EARLY_FIXED:
            valid = response.result == sizeof(RequestEarlyFixedResult) && !response.metadata_address &&
                !response.metadata_length;
            break;
        case MAPLESU_REQUEST_INSTALLATION_STATE:
            valid = !response.metadata_address &&
                (operation.address == MAPLESU_INSTALLATION_READ ?
                    response.result == sizeof(maplesu_installation_state_v3) && !response.metadata_length :
                    !response.result && !(response.metadata_length &
                        (MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_QUARANTINED | MAPLESU_EFFECT_SESSION_CLOSED)) &&
                    (operation.address != MAPLESU_INSTALLATION_COMMIT ||
                     response.metadata_length == MAPLESU_EFFECT_COMMITTED));
            break;
        case MAPLESU_REQUEST_PUBLICATION_PREPARE:
            valid = response.result && response.metadata_address >= UINT64_C(0xffff000000000000) &&
                !(response.metadata_address & 7) && response.metadata_address <= UINT64_MAX -
                    (sizeof(maplesu_publication_control_v3) - 1) &&
                response.metadata_length == MAPLESU_EFFECT_PUBLICATION_PREPARED;
            break;
        case MAPLESU_REQUEST_PUBLICATION_PUBLISH:
            valid = response.metadata_address == operation.handle &&
                ((response.result == 0 && response.metadata_length ==
                    (MAPLESU_EFFECT_PUBLICATION_PUBLISHED | MAPLESU_EFFECT_PUBLICATION_RETAINED)) ||
                 (response.result == 4 && response.metadata_length ==
                    (MAPLESU_EFFECT_PUBLICATION_PUBLISHED | MAPLESU_EFFECT_PUBLICATION_RETAINED |
                        MAPLESU_EFFECT_TEXT_ATTEMPTED | MAPLESU_EFFECT_WRITTEN)));
            break;
        case MAPLESU_REQUEST_PUBLICATION_DISABLE:
            valid = response.metadata_address == operation.handle &&
                ((response.result == 0 && response.metadata_length ==
                    (MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_GATE_PINNED)) ||
                 (response.result == 0 && response.metadata_length == MAPLESU_EFFECT_RELEASED) ||
                 (response.result == 4 && response.metadata_length ==
                    (MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_GATE_PINNED |
                        MAPLESU_EFFECT_TEXT_ATTEMPTED | MAPLESU_EFFECT_WRITTEN)));
            break;
        case MAPLESU_REQUEST_PUBLICATION_RETIRE: {
            const uint32_t effects = response.metadata_length;
            const uint32_t retained = MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_GATE_PINNED;
            const uint32_t text = MAPLESU_EFFECT_TEXT_ATTEMPTED | MAPLESU_EFFECT_WRITTEN;
            const uint32_t shared = MAPLESU_EFFECT_REFERENCE_DROPPED | MAPLESU_EFFECT_SHARED_RETAINED;
            valid = response.metadata_address == operation.handle &&
                (effects & MAPLESU_EFFECT_RELEASED) &&
                !(effects & ~(MAPLESU_EFFECT_RELEASED | retained | text | shared)) &&
                (!(effects & retained) || (effects & retained) == retained) &&
                (!(effects & MAPLESU_EFFECT_SHARED_RETAINED) || (effects & MAPLESU_EFFECT_REFERENCE_DROPPED)) &&
                ((response.result == 0 && !(effects & text)) ||
                 (response.result == 4 && (effects & text) == text));
            break;
        }
        }
        if (!valid) {
            const bool closed_readback = command == MAPLESU_REQUEST_UID_READBACK && !operation.handle &&
                (response.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED);
            if (!closed_readback) management_reply = {};
            owner_management.uncertain = true;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
    }
    return is_failed(error) ? error : management_status(response.status);
}
bool valid_helper_metadata(const maplesu_metadata_owner_v3& metadata, uint64_t descriptor,
    const RequestOwnerBinding& identity) {
    const uint64_t required = MAPLESU_CAP_ECHO64 | MAPLESU_CAP_READ |
        MAPLESU_CAP_SESSION | MAPLESU_CAP_CREDENTIAL;
    const uint64_t known = required | MAPLESU_CAP_PROCATTR | MAPLESU_CAP_TASK_STATE |
        MAPLESU_CAP_APPEND_AUDIT | MAPLESU_CAP_APPEND64;
    const auto capabilities = metadata.common.capabilities;
    return (capabilities & required) == required && !(capabilities & ~known) &&
        maplesu_kernel_read::valid_metadata_fields(metadata.common, descriptor, capabilities,
            MAPLESU_OWNER_METADATA_VERSION, sizeof(metadata)) &&
        metadata.owner_schema == MAPLESU_OWNER_SCHEMA && metadata.owner_state == MAPLESU_OWNER_STATE_HELPER &&
        metadata.owner_epoch && (metadata.host.low || metadata.host.high) &&
        metadata.owner_full_uid == identity.full_uid;
}
KModErr helper_management_channel(maplesu_metadata_owner_v3& metadata,
    uint64_t& descriptor, RequestOwnerBinding& binding) {
    if (!maplesu_request_helper_mode() || owner_management.uncertain) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (owner_management.session) {
        const auto identity = owner_management.binding;
        if (!owner_channel.ready || !maplesu_request_owner_binding_matches(identity))
            return owner_failed(KModErr::ERR_MODULE_ROOT_KEY, identity.auth_state);
        maplesu_response_owner_v3 response{};
        const auto error = owner_raw_exchange(MAPLESU_REQUEST_ECHO64, owner_management.session,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&identity.host)), identity, response);
        if (is_failed(error)) return owner_failed(error, identity.auth_state);
        if (response.result != owner_management.session || response.metadata_address ||
            response.metadata_length || response.metadata_version)
            return owner_failed(KModErr::ERR_MODULE_TEST_CHANNEL, identity.auth_state);
        metadata = owner_channel.metadata;
        descriptor = owner_channel.descriptor;
        binding = identity;
        return KModErr::OK;
    }
    RequestOwnerBinding identity{};
    identity.auth_state = maplesu_request_auth_state();
    identity.process = static_cast<uint64_t>(getpid());
    identity.full_uid = getuid();
    identity.actual_uid = identity.full_uid;
    if (!owner_identity_matches(identity)) return KModErr::ERR_MODULE_ROOT_KEY;
    maplesu_metadata_owner_v3 candidate{};
    maplesu_management_v3 operation{};
    operation.data_user = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&candidate));
    operation.length = sizeof(candidate);
    // Keep this execution identity for explicit CLOSE(0) if OPEN completion is lost.
    owner_management.binding = identity;
    const auto error = management_exchange(MAPLESU_REQUEST_SESSION_OPEN, operation, identity);
    if (is_failed(error)) {
        owner_management.uncertain = true;
        if (management_reply.completed && management_reply.status < 0) errno = -management_reply.status;
        return owner_failed(error, identity.auth_state);
    }
    owner_management.session = management_reply.result;
    if (!valid_helper_metadata(candidate, management_reply.handle, identity) ||
        !owner_identity_matches(identity)) {
        owner_management.uncertain = true;
        errno = EPROTO;
        return owner_failed(KModErr::ERR_MODULE_TEST_CHANNEL, identity.auth_state);
    }
    identity.epoch = candidate.owner_epoch;
    identity.host = candidate.host;
    owner_management.binding = identity;
    owner_channel.metadata = candidate;
    owner_channel.descriptor = management_reply.handle;
    owner_channel.binding = identity;
    owner_channel.ready = true;
    metadata = candidate;
    descriptor = owner_channel.descriptor;
    binding = identity;
    return KModErr::OK;
}
KModErr key_management_session(bool& supported) {
    supported = true;
    management_reset_after_fork();
    if (!maplesu_request_auth_legacy(maplesu_request_auth_state())) return KModErr::ERR_MODULE_PARAM;
    if (owner_management.uncertain) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (owner_management.session)
        return owner_identity_matches(owner_management.binding) ? KModErr::OK : KModErr::ERR_MODULE_ROOT_KEY;
    if (!key_management_identity.matches()) {
        key_management_unavailable = false;
        if (!key_management_identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    }
    if (key_management_identity.length != 48) { supported = false; return KModErr::OK; }
    if (key_management_unavailable) { supported = false; return KModErr::OK; }
    // An old image has no v2 descriptor. Keep its sole compatibility adapter;
    // an incomplete management OPEN is never evidence for this choice.
    maplesu_response_v2 query{};
    bool v2 = false;
    auto error = maplesu_request_v2_channel(query, v2);
    if (is_failed(error)) return error;
    if (!v2) { supported = false; return KModErr::OK; }
    RequestOwnerBinding binding{};
    binding.auth_state = maplesu_request_auth_state();
    binding.process = getpid();
    binding.full_uid = binding.actual_uid = getuid();
    owner_management.binding = binding; // CLOSE(0) also recovers a lost OPEN.
    maplesu_host_instance host{};
    maplesu_management_v3 operation{};
    operation.data_user = reinterpret_cast<uintptr_t>(&host);
    operation.length = sizeof(host);
    error = management_exchange(MAPLESU_REQUEST_SESSION_OPEN, operation, binding);
    if (management_reply.completed && management_reply.status == MAPLESU_REQUEST_STATUS_UNSUPPORTED &&
        !management_reply.effects && !management_reply.result && !management_reply.handle &&
        key_management_identity.matches() && !owner_management.uncertain) {
        key_management_unavailable = true;
        supported = false;
        return KModErr::OK;
    }
    if (is_failed(error)) { owner_management.uncertain = true; return error; }
    if (!(host.low | host.high) || !owner_identity_matches(binding)) {
        owner_management.uncertain = true;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    owner_management.binding.host = host;
    owner_management.session = management_reply.result;
    return KModErr::OK;
}
KModErr management_session() {
    management_reset_after_fork();
    if (owner_management.uncertain) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (owner_management.session) {
        if (owner_management.uncertain ||
            !(maplesu_request_auth_legacy(owner_management.binding.auth_state)
                ? owner_identity_matches(owner_management.binding)
                : maplesu_request_owner_binding_matches(owner_management.binding)))
            return KModErr::ERR_MODULE_ROOT_KEY;
        return KModErr::OK;
    }
    if (maplesu_request_auth_legacy(maplesu_request_auth_state())) {
        bool supported = false;
        const auto error = key_management_session(supported);
        if (!supported) errno = EOPNOTSUPP;
        return is_failed(error) ? error : supported ? KModErr::OK : KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    maplesu_metadata_owner_v3 metadata{};
    uint64_t descriptor = 0;
    RequestOwnerBinding binding{};
    if (maplesu_request_helper_mode()) return helper_management_channel(metadata, descriptor, binding);
    auto error = maplesu_request_owner_channel(metadata, descriptor, binding);
    if (is_failed(error)) return error;
    if ((metadata.common.capabilities & MAPLESU_MANAGEMENT_CAPABILITIES) != MAPLESU_MANAGEMENT_CAPABILITIES)
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    maplesu_management_v3 operation{};
    operation.host = binding.host;
    owner_management.binding = binding;
    error = management_exchange(MAPLESU_REQUEST_SESSION_OPEN, operation, binding);
    if (is_failed(error)) return error;
    if (!management_reply.result) {
        owner_management.uncertain = true;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    owner_management.session = management_reply.result;
    owner_management.binding = binding;
    owner_management.uncertain = false;
    return KModErr::OK;
}
KModErr owner_manage(uint32_t command, uint64_t handle, uint64_t address,
                    const void* data, uint32_t length, uint32_t flags = 0) {
    management_reply = {};
    if (command == MAPLESU_REQUEST_VENDOR_STATE) {
        errno = EPERM;
        return KModErr::ERR_MODULE_PARAM;
    }
    if (maplesu_request_helper_mode() && command != MAPLESU_REQUEST_CRED_ROOT &&
        command != MAPLESU_REQUEST_TASK_STATE && command != MAPLESU_REQUEST_CRED_PROCATTR &&
        command != MAPLESU_REQUEST_DEPLOYMENT_READ && command != MAPLESU_REQUEST_SU_RUNTIME_READ) {
        errno = EPERM;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    auto error = management_session();
    if (is_failed(error)) return error;
    maplesu_management_v3 operation{};
    operation.host = owner_management.binding.host;
    operation.session = owner_management.session;
    operation.handle = handle;
    operation.address = address;
    operation.data_user = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(data));
    operation.length = length;
    operation.flags = flags;
    error = management_exchange(command, operation, owner_management.binding);
    // CRED_ROOT/CAPS may commit the replacement before a post-commit
    // continuity check reports an error. Preserve the complete receipt for
    // diagnostics, but quarantine this session so no later request relies on
    // an unverified credential binding; explicit CLOSE remains available.
    if (management_reply.completed && management_reply.status < 0 &&
        (command == MAPLESU_REQUEST_CRED_ROOT || command == MAPLESU_REQUEST_CRED_CAPS) &&
        (management_reply.effects & MAPLESU_EFFECT_COMMITTED)) {
        owner_management.uncertain = true;
    }
    if (management_reply.completed && (management_reply.effects &
            (MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED)) &&
        command >= MAPLESU_REQUEST_PUBLICATION_PUBLISH && command <= MAPLESU_REQUEST_PUBLICATION_RETIRE) {
        const auto publication = std::find_if(owner_management.publications.begin(), owner_management.publications.end(),
            [handle](const OwnerPublication& value) { return value.id == handle; });
        if (publication != owner_management.publications.end()) {
            auto& allocations = owner_management.allocations;
            allocations.erase(std::remove_if(allocations.begin(), allocations.end(),
                [&](const OwnerAllocation& value) {
                    return std::find(publication->handles.begin(), publication->handles.begin() + publication->count,
                        value.handle) != publication->handles.begin() + publication->count;
                }), allocations.end());
            owner_management.publications.erase(publication);
        }
    }
    if (management_reply.completed && (management_reply.status == MAPLESU_REQUEST_STATUS_DENIED ||
            management_reply.status == MAPLESU_REQUEST_STATUS_STALE) &&
        !(command == MAPLESU_REQUEST_SU_RUNTIME_READ &&
          management_reply.result == sizeof(maplesu_su_runtime_status_v3) && !management_reply.effects))
        owner_management.uncertain = true;
    return error;
}
auto owner_allocation(uint64_t address) {
    management_reset_after_fork();
    return std::find_if(owner_management.allocations.begin(), owner_management.allocations.end(),
        [address](const OwnerAllocation& value) {
            return address >= value.address && address - value.address < value.length;
        });
}
KModErr owner_alloc(uint32_t size, uint64_t& output, uint64_t near_anchor = 0, uint32_t flags = 0) {
    management_reply = {};
    if (!size || size > MAPLESU_MANAGEMENT_MAX_BYTES) return KModErr::ERR_MODULE_PARAM;
    auto error = owner_manage(MAPLESU_REQUEST_ALLOC, 0, near_anchor, nullptr, size, flags);
    if (is_failed(error)) return error;
    const auto address = management_reply.result, handle = management_reply.handle;
    if (!address || !handle || address > UINT64_MAX - (size - 1) ||
        !(management_reply.effects & MAPLESU_EFFECT_ALLOCATED)) {
        owner_management.uncertain = true;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    try {
        if (!remember_managed_address(address, size)) throw std::bad_alloc();
        owner_management.allocations.push_back({address, handle, size});
    }
    catch (const std::bad_alloc&) {
        CleanupReceiptScope preserve_failure;
        if (is_failed(owner_manage(MAPLESU_REQUEST_RELEASE, handle, 0, nullptr, 0)))
            owner_management.uncertain = true;
        return KModErr::ERR_NO_MEM;
    }
    // Native allocation is the newest provenance if its allocator reuses an
    // address formerly released by an old module's direct module_memfree call.
    legacy_address_ranges.erase(std::remove_if(legacy_address_ranges.begin(), legacy_address_ranges.end(),
        [address, size](const ManagedAddressRange& range) {
            return range.first <= address + size - 1 && address <= range.last;
        }), legacy_address_ranges.end());
    output = address;
    return KModErr::OK;
}
KModErr owner_read(uint64_t address, void* output, uint32_t size) {
    maplesu_metadata_owner_v3 metadata{};
    RequestOwnerBinding binding{};
    uint64_t descriptor = 0;
    const auto error = maplesu_request_owner_channel(metadata, descriptor, binding);
    return is_failed(error) ? error : maplesu_request_owner_read(address, output, size, binding);
}
KModErr owner_write(uint64_t address, const void* data, uint32_t size) {
    management_reply = {};
    if (!valid_memory_range(address, data, size) || size > MAPLESU_MANAGEMENT_MAX_BYTES)
        return KModErr::ERR_MODULE_PARAM;
    const auto entry = owner_allocation(address);
    const auto handle = entry == owner_management.allocations.end() ? 0 : entry->handle;
    if (!handle && known_managed_address(address)) return KModErr::ERR_MODULE_PARAM;
    const auto offset = handle ? address - entry->address : address;
    if (handle && size > entry->length - offset) return KModErr::ERR_MODULE_PARAM;
    return owner_manage(MAPLESU_REQUEST_WRITE, handle, offset, data, size);
}
KModErr owner_release(uint64_t address) {
    management_reply = {};
    const auto entry = owner_allocation(address);
    if (entry == owner_management.allocations.end() || entry->address != address)
        return KModErr::ERR_MODULE_PARAM;
    const auto error = owner_manage(MAPLESU_REQUEST_RELEASE, entry->handle, 0, nullptr, 0);
    if (management_reply.completed && (management_reply.effects &
            (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED))) owner_management.allocations.erase(entry);
    return error;
}
KModErr owner_execute(uint64_t address, uint32_t size, uint64_t& result) {
    management_reply = {};
    const auto entry = owner_allocation(address);
    if (entry == owner_management.allocations.end() || entry->address != address || entry->length != size)
        return KModErr::ERR_MODULE_PARAM;
    const auto error = owner_manage(MAPLESU_REQUEST_EXEC, entry->handle, 0, nullptr, size);
    if (management_reply.completed && (management_reply.effects &
            (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED))) owner_management.allocations.erase(entry);
    if (is_ok(error)) {
        if (!(management_reply.effects & MAPLESU_EFFECT_EXECUTED)) return KModErr::ERR_MODULE_TEST_CHANNEL;
        result = management_reply.result;
    }
    return error;
}
}

RequestManagementReply maplesu_request_management_reply() {
    management_reset_after_fork();
    return management_reply;
}
RequestUidReadbackDiagnostic maplesu_request_uid_readback_diagnostic() {
    management_reset_after_fork();
    return uid_readback_diagnostic;
}
KModErr maplesu_request_helper_open() {
    management_reset_after_fork();
    management_reply = {};
    if (!maplesu_request_helper_mode()) {
        errno = EPERM;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    maplesu_metadata_owner_v3 metadata{};
    uint64_t descriptor = 0;
    RequestOwnerBinding binding{};
    return helper_management_channel(metadata, descriptor, binding);
}
CleanupReceiptScope::CleanupReceiptScope() noexcept
    : saved_errno_(errno), saved_process_(static_cast<uint64_t>(getpid())) {
    management_reset_after_fork();
    saved_reply_ = management_reply;
}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {
    if (saved_process_ != static_cast<uint64_t>(getpid())) {
        management_reset_after_fork();
        return;
    }
    management_reply = saved_reply_;
    errno = saved_errno_;
}
KModErr maplesu_request_owner_close() {
    management_reset_after_fork();
    management_reply = {};
    if (!owner_management.session && !owner_management.uncertain) return KModErr::OK;
    // Cleanup remains available after a local failure or credential transition.
    auto binding = owner_management.binding;
    if (binding.process != static_cast<uint64_t>(getpid())) return KModErr::ERR_MODULE_ROOT_KEY;
    binding.auth_state = maplesu_request_auth_state();
    binding.actual_uid = getuid();
    maplesu_management_v3 operation{};
    operation.host = binding.host;
    operation.session = 0; // Explicit cleanup of this task, including async revoke/exit retirement.
    const auto error = management_exchange(MAPLESU_REQUEST_SESSION_CLOSE, operation, binding);
    if (management_reply.completed && (management_reply.effects & MAPLESU_EFFECT_SESSION_CLOSED)) {
        owner_management = {};
        owner_channel = {};
        return error; // Resource cleanup may have failed after the session closed.
    }
    return is_failed(error) ? error : KModErr::ERR_MODULE_TEST_CHANNEL;
}
KModErr maplesu_request_owner_deployment(RequestDeploymentNamespace& output) {
    RequestDeploymentNamespace candidate{};
    const auto error = owner_manage(MAPLESU_REQUEST_DEPLOYMENT_READ, 0, 0,
        &candidate.record, sizeof(candidate.record));
    if (is_failed(error)) {
        if (management_reply.completed && management_reply.status < 0)
            errno = -management_reply.status;
        return error;
    }
    const auto& record = candidate.record;
    bool valid = record.magic == MAPLESU_DEPLOYMENT_NAMESPACE_MAGIC &&
        record.schema == MAPLESU_DEPLOYMENT_NAMESPACE_SCHEMA &&
        record.bytes == sizeof(record);
    for (const auto value : record.name)
        valid = valid && ((value >= 'A' && value <= 'Z') ||
            (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9'));
    if (!valid) {
        management_reply = {};
        owner_management.uncertain = true;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    candidate.binding = owner_management.binding;
    if (!maplesu_request_owner_binding_matches(candidate.binding))
        return owner_failed(KModErr::ERR_MODULE_ROOT_KEY, candidate.binding.auth_state);
    output = candidate;
    return KModErr::OK;
}
KModErr maplesu_request_owner_su_runtime(RequestSuRuntimeStatus& output) {
    management_reset_after_fork();
    management_reply = {};
    if (!maplesu_request_auth_authenticated(maplesu_request_auth_state())) {
        errno = EPERM;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    RequestSuRuntimeStatus candidate{};
    const auto error = owner_manage(MAPLESU_REQUEST_SU_RUNTIME_READ, 0, 0,
        &candidate.record, sizeof(candidate.record));
    const auto reply = management_reply;
    if (reply.completed && reply.status < 0) errno = -reply.status;
    if (!reply.completed || reply.result != sizeof(candidate.record)) return error;
    candidate.binding = owner_management.binding;
    // A copied snapshot before a later authority failure is not publishable.
    if (reply.effects || (is_failed(error) && !reply.status) ||
        !maplesu_request_owner_binding_matches(candidate.binding)) {
        if (reply.status >= 0) errno = ESTALE;
        return owner_failed(is_failed(error) ? error : KModErr::ERR_MODULE_ROOT_KEY,
            candidate.binding.auth_state);
    }
    const auto& record = candidate.record;
    const auto native_error = [](int32_t value) { return value <= 0 && value >= -4095; };
    const bool empty_host = !(record.host.low | record.host.high);
    const bool matching_host = record.host.low == candidate.binding.host.low &&
        record.host.high == candidate.binding.host.high;
    bool absent = !record.flags && !record.users && !record.producers && !record.hook_count &&
        !record.installation_fence && !record.target_error && !record.cleanup_error &&
        !record.start_error && !record.target_qualified && !record.installation_flags;
    for (const auto byte : record.installation_generation) absent = absent && byte == 0;
    for (const auto byte : record.runtime_generation) absent = absent && byte == 0;
    const uint32_t known_flags = MAPLESU_SU_RUNTIME_INITIALIZED | MAPLESU_SU_RUNTIME_BOUND |
        MAPLESU_SU_RUNTIME_STARTED | MAPLESU_SU_RUNTIME_PUBLISHED | MAPLESU_SU_RUNTIME_CLOSED |
        MAPLESU_SU_RUNTIME_INSTALLATION_CLOSED;
    if (record.schema != MAPLESU_SU_RUNTIME_STATUS_SCHEMA || record.bytes != sizeof(record) ||
        (record.flags & ~known_flags) || record.hook_count > MAPLESU_SU_RUNTIME_MAX_HOOKS ||
        record.target_qualified > 1 || (record.installation_flags & ~MAPLESU_INSTALLATION_PENDING) ||
        !native_error(record.status) || !native_error(record.target_error) ||
        !native_error(record.cleanup_error) || !native_error(record.start_error) ||
        record.status != reply.status || (!matching_host && !(empty_host && absent && record.status < 0))) {
        owner_management.uncertain = true;
        errno = EPROTO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (!maplesu_request_owner_binding_matches(candidate.binding)) {
        errno = reply.status < 0 ? -reply.status : ESTALE;
        return owner_failed(is_failed(error) ? error : KModErr::ERR_MODULE_ROOT_KEY,
            candidate.binding.auth_state);
    }
    output = candidate;
    return error;
}
namespace {
bool valid_installation_state(const maplesu_installation_state_v3& value) {
    const auto& record = value.record;
    bool generation = false;
    for (const auto byte : record.generation) generation = generation || byte != 0;
    if (value.magic != MAPLESU_INSTALLATION_STATE_MAGIC ||
        value.schema != MAPLESU_INSTALLATION_STATE_SCHEMA || value.bytes != sizeof(value) ||
        value.reserved || (value.flags & ~MAPLESU_INSTALLATION_PENDING) ||
        !(value.host.low | value.host.high) || !value.revision ||
        record.magic != 0x5349534dU || record.schema != 1 ||
        record.bytes != sizeof(record) || record.active > 1 || record.reserved ||
        record.publication_reserved || record.publication_source > 2 ||
        record.publication_phase > 16 || record.version_published > 1 ||
        (record.active && (!generation || record.publication_source ||
            record.publication_phase != 16 || !record.version_published || record.publication_code))) return false;
    for (const auto c : value.name)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
    for (const auto& stage : value.record.stages)
        if (stage.reserved || (stage.flags & ~15u) || ((stage.flags & 2) && !(stage.flags & 1))) return false;
    return true;
}
}
KModErr maplesu_request_owner_installation(uint64_t action, maplesu_installation_state_v3& value) {
    management_reset_after_fork();
    management_reply = {};
    if (action < MAPLESU_INSTALLATION_READ || action > MAPLESU_INSTALLATION_REVOKE) {
        errno = EINVAL;
        return KModErr::ERR_MODULE_PARAM;
    }
    auto candidate = value;
    const auto error = owner_manage(MAPLESU_REQUEST_INSTALLATION_STATE, 0, action,
        &candidate, sizeof(candidate));
    if (is_failed(error)) {
        if (management_reply.completed && management_reply.status < 0) errno = -management_reply.status;
        return error;
    }
    if (action == MAPLESU_INSTALLATION_READ) {
        if (!valid_installation_state(candidate) || candidate.host.low != owner_management.binding.host.low ||
            candidate.host.high != owner_management.binding.host.high) {
            management_reply = {};
            owner_management.uncertain = true;
            errno = EPROTO;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        const auto binding = owner_management.binding;
        if (!maplesu_request_owner_binding_matches(binding)) {
            errno = ESTALE;
            return owner_failed(KModErr::ERR_MODULE_ROOT_KEY, binding.auth_state);
        }
        value = candidate;
    }
    return KModErr::OK;
}
bool maplesu_request_helper_vendor_matches(const maplesu_installation_state_v3& value) {
    management_reset_after_fork();
    return !helper_channel.uncertain && helper_channel.matches() &&
        helper_channel.host.low == value.host.low && helper_channel.host.high == value.host.high &&
        helper_channel.revision == value.revision;
}
KModErr maplesu_request_helper_vendor(uint64_t action, unsigned index,
    maplesu_installation_state_v3& value) {
    management_reset_after_fork();
    management_reply = {};
    if ((action != MAPLESU_INSTALLATION_READ && action != MAPLESU_VENDOR_BEGIN &&
         action != MAPLESU_VENDOR_BEFORE && action != MAPLESU_VENDOR_COMPLETE) ||
        (action <= MAPLESU_VENDOR_BEGIN ? index != 0 : index >= 3)) {
        errno = EINVAL;
        return KModErr::ERR_MODULE_PARAM;
    }
    const HelperChannel identity{maplesu_request_auth_state(), getpid(), getuid(), geteuid(), false};
    if (!identity.matches() || (action != MAPLESU_INSTALLATION_READ &&
        !helper_channel.uncertain && !helper_channel.matches())) {
        helper_channel.uncertain = true;
        errno = ESTALE;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    if (action != MAPLESU_INSTALLATION_READ && helper_channel.uncertain) {
        errno = EIO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    maplesu_installation_state_v3 candidate = value;
    maplesu_management_v3 operation{};
    operation.host = value.host;
    operation.address = action;
    operation.handle = index;
    operation.data_user = reinterpret_cast<uintptr_t>(&candidate);
    operation.length = sizeof(candidate);
    maplesu_response_owner_v3 response{};
    maplesu_request_owner_v3 request{};
    request.magic = MAPLESU_REQUEST_MAGIC;
    request.version = MAPLESU_OWNER_PROTOCOL_VERSION;
    request.length = sizeof(request);
    request.command = MAPLESU_REQUEST_VENDOR_STATE;
    request.request_id = request_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    request.response_user = reinterpret_cast<uintptr_t>(&response);
    request.arg1 = reinterpret_cast<uintptr_t>(&operation);
    const auto pointer = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&request));
    if (!identity.matches()) {
        helper_channel.uncertain = true;
        errno = ESTALE;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    std::atomic_thread_fence(std::memory_order_release);
    const auto sent = dispatch_kernel_request(KernelCmdFlag::SET_SUID_SGID, MAPLESU_REQUEST_SELECTOR_SUB,
        0, static_cast<uint32_t>(pointer), static_cast<uint32_t>(pointer >> 32), MAPLESU_OWNER_ENVELOPE_PREFIX);
    std::atomic_thread_fence(std::memory_order_acquire);
    if (sent) {
        helper_channel.uncertain = true;
        return static_cast<KModErr>(sent);
    }
    if (response.completion_magic != MAPLESU_RESPONSE_MAGIC ||
        response.version != MAPLESU_OWNER_PROTOCOL_VERSION || response.length != sizeof(response) ||
        response.command != request.command || response.request_id != request.request_id ||
        response.metadata_address || response.metadata_version || response.status > 0 || response.status < -4095 ||
        (response.metadata_length & ~MAPLESU_INSTALLATION_LIFECYCLE_EFFECTS) ||
        (response.metadata_length && !(response.metadata_length & MAPLESU_EFFECT_COMMITTED)) ||
        ((response.metadata_length & MAPLESU_EFFECT_PENDING) &&
            !(response.metadata_length & MAPLESU_EFFECT_COMMITTED)) ||
        (response.status < 0 ? response.result != 0 :
            (action == MAPLESU_INSTALLATION_READ ?
                response.result != sizeof(candidate) ||
                    (response.metadata_length & ~MAPLESU_EFFECT_COMMITTED) ||
                    !valid_installation_state(candidate) :
                response.metadata_length != MAPLESU_EFFECT_COMMITTED ||
                    value.revision == std::numeric_limits<uint64_t>::max() ||
                    response.result != value.revision + 1))) {
        helper_channel.uncertain = true;
        errno = EPROTO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    management_reply = {response.status, response.metadata_length, response.result, 0, request.command, true};
    const bool same_identity = identity.matches();
    if (!same_identity || (response.status < 0 &&
        (response.metadata_length || response.status == MAPLESU_REQUEST_STATUS_DENIED ||
            response.status == MAPLESU_REQUEST_STATUS_STALE))) helper_channel.uncertain = true;
    if (response.status < 0) {
        errno = -response.status;
        return management_status(response.status);
    }
    if (!same_identity) {
        errno = ESTALE;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    if (action == MAPLESU_INSTALLATION_READ) {
        helper_channel = identity;
        helper_channel.host = candidate.host;
        helper_channel.revision = candidate.revision;
        value = candidate;
    } else {
        helper_channel.revision = response.result;
        value.revision = response.result;
    }
    return KModErr::OK;
}
KModErr maplesu_request_credential_channel(bool& managed, uint64_t& capabilities) {
    managed = maplesu_request_owner_mode();
    capabilities = 0;
    if (managed) {
        maplesu_metadata_owner_v3 metadata{};
        RequestOwnerBinding binding{};
        uint64_t descriptor = 0;
        const auto error = maplesu_request_owner_channel(metadata, descriptor, binding);
        if (is_ok(error)) capabilities = metadata.common.capabilities;
        return error;
    }
    management_reset_after_fork();
    if (owner_management.uncertain) return KModErr::ERR_MODULE_TEST_CHANNEL;
    maplesu_response_v2 ordinary{}, response{};
    bool supported = false;
    auto error = maplesu_request_v2_channel(ordinary, supported);
    if (is_failed(error) || !supported) return error;
    error = exchange_v2(MAPLESU_REQUEST_QUERY, MAPLESU_KEY_CREDENTIAL_QUERY, 0,
        false, response, supported);
    if (is_failed(error)) return error;
    if (response.status) {
        errno = response.status < 0 ? -response.status : EPROTO;
        return response.status < 0 ? management_status(response.status) : KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (response.metadata_address != ordinary.metadata_address ||
        response.metadata_length != ordinary.metadata_length ||
        response.metadata_version != ordinary.metadata_version ||
        (response.result & ~MAPLESU_KEY_CREDENTIAL_QUERY) != ordinary.result ||
        ((response.result & MAPLESU_KEY_CREDENTIAL_QUERY) && !(response.result & MAPLESU_CAP_CREDENTIAL))) {
        owner_management.uncertain = true;
        errno = EPROTO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    // An old producer ignores the optional query and returns the exact ordinary
    // descriptor. It alone selects the centralized credential compatibility path.
    if (!(response.result & MAPLESU_CAP_CREDENTIAL)) return KModErr::OK;
    managed = true;
    capabilities = response.result;
    error = key_management_session(supported);
    if (is_failed(error)) return error;
    if (!supported) {
        owner_management.uncertain = true;
        errno = EPROTO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    return KModErr::OK;
}
KModErr maplesu_request_owner_root() {
    if (!maplesu_request_owner_mode()) {
        bool managed = false;
        uint64_t capabilities = 0;
        const auto error = maplesu_request_credential_channel(managed, capabilities);
        if (is_failed(error)) return error;
        if (!managed) { errno = EOPNOTSUPP; return KModErr::ERR_MODULE_TEST_CHANNEL; }
    }
    return owner_manage(MAPLESU_REQUEST_CRED_ROOT, 0, 0, nullptr, 0);
}
KModErr maplesu_request_owner_caps(const maplesu_caps_v3& caps) {
    if (!maplesu_request_owner_mode()) {
        bool managed = false;
        uint64_t capabilities = 0;
        const auto error = maplesu_request_credential_channel(managed, capabilities);
        if (is_failed(error)) return error;
        if (!managed) { errno = EOPNOTSUPP; return KModErr::ERR_MODULE_TEST_CHANNEL; }
    }
    return owner_manage(MAPLESU_REQUEST_CRED_CAPS, 0, 0, &caps, sizeof(caps));
}
KModErr maplesu_request_owner_write_text(uint64_t address, const void* data, uint32_t size) {
    management_reply = {};
    if (!valid_memory_range(address, data, size) ||
        address < UINT64_C(0xffff000000000000) || (address & 3) ||
        size > MAPLESU_MANAGEMENT_MAX_BYTES) return KModErr::ERR_MODULE_PARAM;
    const uint64_t rounded = (static_cast<uint64_t>(size) + 3) & ~UINT64_C(3);
    if (rounded > MAPLESU_MANAGEMENT_MAX_BYTES ||
        rounded - 1 > std::numeric_limits<uint64_t>::max() - address) return KModErr::ERR_MODULE_PARAM;
    maplesu_metadata_owner_v3 metadata{};
    RequestOwnerBinding binding{};
    uint64_t descriptor = 0;
    const auto error = maplesu_request_owner_channel(metadata, descriptor, binding);
    if (is_failed(error)) return error;
    if (!(metadata.common.capabilities & MAPLESU_CAP_TEXT_WRITE)) return KModErr::ERR_MODULE_TEST_CHANNEL;
    return owner_manage(MAPLESU_REQUEST_WRITE, 0, address, data, size, MAPLESU_MANAGEMENT_WRITE_TEXT);
}
namespace {
KModErr owner_require_capability(uint64_t capability) {
    if (!maplesu_request_owner_mode() &&
        (capability == MAPLESU_CAP_PROCATTR || capability == MAPLESU_CAP_TASK_STATE)) {
        bool managed = false;
        uint64_t capabilities = 0;
        const auto error = maplesu_request_credential_channel(managed, capabilities);
        if (is_failed(error)) return error;
        if (!managed || !(capabilities & capability)) {
            errno = EOPNOTSUPP;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        return KModErr::OK;
    }
    maplesu_metadata_owner_v3 metadata{};
    RequestOwnerBinding binding{};
    uint64_t descriptor = 0;
    const auto error = maplesu_request_owner_channel(metadata, descriptor, binding);
    if (is_failed(error)) return error;
    return (metadata.common.capabilities & capability) == capability
        ? KModErr::OK : KModErr::ERR_MODULE_TEST_CHANNEL;
}
bool owner_shared_bool_matches(const RequestSharedBool& object) {
    return object.id && object.address >= UINT64_C(0xffff000000000000) && object.epoch &&
        object.host.low == owner_channel.binding.host.low &&
        object.host.high == owner_channel.binding.host.high;
}
KModErr owner_shared_bool_operation(uint32_t command, const RequestSharedBool& object, const uint8_t* value) {
    management_reply = {};
    auto error = owner_require_capability(MAPLESU_CAP_SHARED_BOOL);
    if (is_failed(error)) return error;
    if (!owner_shared_bool_matches(object)) return KModErr::ERR_MODULE_ROOT_KEY;
    return owner_manage(command, object.id, object.address, value, value ? 1 : 0);
}
KModErr owner_publication_operation(uint32_t command, const RequestPublication& publication) {
    management_reply = {};
    if (!publication.id || !(publication.host.low || publication.host.high)) return KModErr::ERR_MODULE_PARAM;
    auto error = owner_require_capability(MAPLESU_CAP_PUBLICATION);
    if (is_failed(error)) return error;
    if (publication.host.low != owner_channel.binding.host.low ||
        publication.host.high != owner_channel.binding.host.high) return KModErr::ERR_MODULE_ROOT_KEY;
    return owner_manage(command, publication.id, 0, nullptr, 0);
}
}
KModErr maplesu_request_owner_task_state() {
    management_reply = {};
    const auto error = owner_require_capability(MAPLESU_CAP_TASK_STATE);
    if (is_failed(error)) {
        if (error == KModErr::ERR_MODULE_TEST_CHANNEL && owner_channel.ready && !owner_management.uncertain) {
            errno = EOPNOTSUPP;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        return error;
    }
    const auto result = owner_manage(MAPLESU_REQUEST_TASK_STATE, 0, 0, nullptr, 0);
    if (management_reply.completed && management_reply.status < 0) {
        errno = -management_reply.status;
    }
    return result;
}
KModErr maplesu_request_owner_procattr(uint32_t attribute, const char* context, uint32_t length) {
    management_reply = {};
    if ((attribute != MAPLESU_PROCATTR_CURRENT && attribute != MAPLESU_PROCATTR_EXEC) ||
        !context || !length || length > MAPLESU_PROCATTR_MAX_BYTES ||
        reinterpret_cast<uintptr_t>(context) > UINTPTR_MAX - (length - 1)) {
        errno = EINVAL;
        return KModErr::ERR_MODULE_PARAM;
    }
    std::array<char, MAPLESU_PROCATTR_MAX_BYTES> stable{};
    std::memcpy(stable.data(), context, length);
    if (stable[length - 1] || std::memchr(stable.data(), 0, length - 1)) {
        errno = EINVAL;
        return KModErr::ERR_MODULE_PARAM;
    }
    auto error = owner_require_capability(MAPLESU_CAP_PROCATTR);
    if (is_failed(error)) {
        if (error == KModErr::ERR_MODULE_TEST_CHANNEL && owner_channel.ready && !owner_management.uncertain)
            errno = EOPNOTSUPP;
        return error;
    }
    const int previous_errno = errno;
    errno = 0;
    error = owner_manage(MAPLESU_REQUEST_CRED_PROCATTR, 0, attribute, stable.data(), length);
    if (is_failed(error)) {
        if (management_reply.completed && management_reply.status < 0) errno = -management_reply.status;
        else if (!errno) errno = EIO;
    } else errno = previous_errno;
    return error;
}
KModErr maplesu_request_owner_reserve_code(uint32_t size, uint64_t near_anchor, uint64_t& address) {
    management_reply = {};
    if (!size || size > MAPLESU_MANAGEMENT_MAX_BYTES || (near_anchor &&
        (near_anchor < UINT64_C(0xffff000000000000) || (near_anchor & 3)))) return KModErr::ERR_MODULE_PARAM;
    const auto error = owner_require_capability(MAPLESU_CAP_CODE_RESERVE);
    if (is_failed(error)) return error;
    uint64_t candidate = 0;
    const auto allocation_error = owner_alloc(size, candidate, near_anchor, MAPLESU_MANAGEMENT_ALLOC_CODE);
    if (is_ok(allocation_error)) address = candidate;
    return allocation_error;
}
KModErr maplesu_request_owner_shared_bool_create(bool initial, RequestSharedBool& object) {
    management_reply = {};
    auto error = owner_require_capability(MAPLESU_CAP_SHARED_BOOL);
    if (is_failed(error)) return error;
    const uint8_t value = initial ? 1 : 0;
    error = owner_manage(MAPLESU_REQUEST_SHARED_BOOL_CREATE, 0, 0, &value, sizeof(value));
    if (is_failed(error)) return error;
    object = {management_reply.handle, management_reply.result, owner_management.binding.host,
        owner_management.binding.epoch};
    return KModErr::OK;
}
KModErr maplesu_request_owner_shared_bool_store(const RequestSharedBool& object, bool value) {
    const uint8_t candidate = value ? 1 : 0;
    return owner_shared_bool_operation(MAPLESU_REQUEST_SHARED_BOOL_STORE, object, &candidate);
}
KModErr maplesu_request_owner_shared_bool_release(const RequestSharedBool& object) {
    return owner_shared_bool_operation(MAPLESU_REQUEST_SHARED_BOOL_RELEASE, object, nullptr);
}
KModErr maplesu_request_owner_publication_prepare(const RequestPublicationMember* members,
    uint32_t count, uint32_t gate_index, uint64_t entry, uint64_t gate_offset,
    uint32_t expected_instruction, uint64_t payload_entry, RequestPublication& publication) {
    management_reply = {};
    if (!members || !count || count > 64 || gate_index >= count ||
        reinterpret_cast<uintptr_t>(members) > std::numeric_limits<uintptr_t>::max() - (count * sizeof(*members) - 1) ||
        entry < UINT64_C(0xffff000000000000) || entry > UINT64_MAX - 4 || (entry & 3) || (gate_offset & 3) ||
        payload_entry < UINT64_C(0xffff000000000000) || (payload_entry & 3)) return KModErr::ERR_MODULE_PARAM;
    auto error = owner_require_capability(MAPLESU_CAP_PUBLICATION);
    if (is_failed(error)) return error;
    error = management_session();
    if (is_failed(error)) return error;
    std::array<maplesu_publication_member_v3, 64> wire_members{};
    OwnerPublication local{};
    local.count = count;
    for (uint32_t i = 0; i < count; ++i) {
        if (members[i].role < MAPLESU_PUBLICATION_GATE_CODE || members[i].role > MAPLESU_PUBLICATION_SHARED_BOOL)
            return KModErr::ERR_MODULE_PARAM;
        if (members[i].role == MAPLESU_PUBLICATION_SHARED_BOOL) {
            if (!(owner_channel.metadata.common.capabilities & MAPLESU_CAP_SHARED_BOOL))
                return KModErr::ERR_MODULE_TEST_CHANNEL;
            if (members[i].address != members[i].shared_bool.address ||
                !owner_shared_bool_matches(members[i].shared_bool)) return KModErr::ERR_MODULE_ROOT_KEY;
            for (uint32_t j = 0; j < i; ++j)
                if (wire_members[j].role == MAPLESU_PUBLICATION_SHARED_BOOL &&
                    wire_members[j].handle == members[i].shared_bool.id) return KModErr::ERR_MODULE_PARAM;
            wire_members[i] = {members[i].shared_bool.id, members[i].role, 0, members[i].shared_bool.address};
            continue;
        }
        const auto allocation = owner_allocation(members[i].address);
        if (allocation == owner_management.allocations.end() || allocation->address != members[i].address)
            return KModErr::ERR_MODULE_PARAM;
        if (std::find(local.handles.begin(), local.handles.begin() + i, allocation->handle) != local.handles.begin() + i)
            return KModErr::ERR_MODULE_PARAM;
        wire_members[i] = {allocation->handle, members[i].role, 0, 0};
        local.handles[i] = allocation->handle;
    }
    if (members[gate_index].role != MAPLESU_PUBLICATION_GATE_CODE || owner_management.publications.size() >= 64)
        return KModErr::ERR_MODULE_PARAM;
    try { owner_management.publications.reserve(owner_management.publications.size() + 1); }
    catch (const std::bad_alloc&) { return KModErr::ERR_NO_MEM; }
    const maplesu_publication_prepare_v3 prepare{
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(wire_members.data())), count, gate_index,
        entry, gate_offset, expected_instruction, 0, payload_entry, {0, 0}};
    error = owner_manage(MAPLESU_REQUEST_PUBLICATION_PREPARE, 0, 0, &prepare, sizeof(prepare));
    if (is_failed(error)) {
        if (management_reply.completed && (management_reply.effects &
                (MAPLESU_EFFECT_RELEASED | MAPLESU_EFFECT_QUARANTINED))) {
            auto& allocations = owner_management.allocations;
            allocations.erase(std::remove_if(allocations.begin(), allocations.end(),
                [&](const OwnerAllocation& value) {
                    return std::find(local.handles.begin(), local.handles.begin() + count, value.handle) !=
                        local.handles.begin() + count;
                }), allocations.end());
        }
        return error;
    }
    local.id = management_reply.result;
    owner_management.publications.push_back(local);
    publication = {local.id, management_reply.handle, owner_management.binding.host};
    return KModErr::OK;
}
KModErr maplesu_request_owner_publication_publish(const RequestPublication& publication) {
    return owner_publication_operation(MAPLESU_REQUEST_PUBLICATION_PUBLISH, publication);
}
KModErr maplesu_request_owner_publication_disable(const RequestPublication& publication) {
    return owner_publication_operation(MAPLESU_REQUEST_PUBLICATION_DISABLE, publication);
}
KModErr maplesu_request_owner_publication_retire(const RequestPublication& publication) {
    return owner_publication_operation(MAPLESU_REQUEST_PUBLICATION_RETIRE, publication);
}
KModErr maplesu_request_owner_publication_control(const RequestPublication& publication,
    maplesu_publication_control_v3& control) {
    if (!publication.id || !publication.control_address) return KModErr::ERR_MODULE_PARAM;
    const auto error = owner_require_capability(MAPLESU_CAP_PUBLICATION);
    if (is_failed(error)) return error;
    if (publication.host.low != owner_channel.binding.host.low || publication.host.high != owner_channel.binding.host.high)
        return KModErr::ERR_MODULE_ROOT_KEY;
    maplesu_publication_control_v3 candidate{};
    const auto read_error = maplesu_request_owner_read(publication.control_address, &candidate,
        sizeof(candidate), owner_channel.binding);
    if (is_failed(read_error)) return read_error;
    if (candidate.schema != 1 || candidate.length != sizeof(candidate) || candidate.reserved ||
        candidate.publication_id != publication.id || !candidate.epoch ||
        candidate.enter_function < UINT64_C(0xffff000000000000) || (candidate.enter_function & 3) ||
        candidate.leave_function < UINT64_C(0xffff000000000000) || (candidate.leave_function & 3) ||
        candidate.payload_entry < UINT64_C(0xffff000000000000) || (candidate.payload_entry & 3) ||
        candidate.entry_address < UINT64_C(0xffff000000000000) || (candidate.entry_address & 3) ||
        candidate.entry_address > UINT64_MAX - 4 || candidate.resume_address != candidate.entry_address + 4)
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    control = candidate;
    return KModErr::OK;
}
namespace {
bool uid_records_valid(const maplesu_uid_record_v3* records, uint32_t count) {
    if (count > MAPLESU_UID_SNAPSHOT_MAX_RECORDS || (count && (!records ||
        reinterpret_cast<uintptr_t>(records) > UINTPTR_MAX - (count * sizeof(*records) - 1)))) return false;
    for (uint32_t i = 0; i < count; ++i) {
        if (records[i].full_uid == UINT32_MAX || records[i].decision > 1 ||
            !records[i].installation_generation || !records[i].profile_revision ||
            (i && records[i - 1].full_uid >= records[i].full_uid) ||
            !std::memchr(records[i].package, 0, sizeof(records[i].package))) return false;
    }
    return true;
}
KModErr uid_controller_ready(const RequestUidController& controller) {
    if (!controller.id || !(controller.host.low || controller.host.high)) return KModErr::ERR_MODULE_PARAM;
    const auto error = owner_require_capability(MAPLESU_CAP_UID_SNAPSHOT);
    if (is_failed(error)) return error;
    return controller.host.low == owner_channel.binding.host.low && controller.host.high == owner_channel.binding.host.high
        ? KModErr::OK : KModErr::ERR_MODULE_ROOT_KEY;
}
KModErr uid_candidate_operation(uint32_t command, RequestUidCandidate& candidate) {
    management_reply = {};
    if (!candidate.id) return KModErr::ERR_MODULE_PARAM;
    const auto error = uid_controller_ready(candidate.controller);
    if (is_failed(error)) return error;
    const auto result = owner_manage(command, candidate.id, candidate.controller.id, nullptr, 0);
    if (management_reply.completed && management_reply.status < 0) errno = -management_reply.status;
    if (management_reply.completed && (management_reply.effects & MAPLESU_EFFECT_REFERENCE_DROPPED)) candidate = {};
    return result;
}
}
KModErr maplesu_request_owner_uid_create(RequestUidController& controller, uint64_t& revision) {
    management_reply = {};
    auto error = owner_require_capability(MAPLESU_CAP_UID_SNAPSHOT);
    if (is_failed(error)) return error;
    error = owner_manage(MAPLESU_REQUEST_UID_CREATE, 0, 0, nullptr, 0);
    if (is_failed(error)) return error;
    controller = {management_reply.handle, owner_management.binding.host};
    revision = management_reply.result;
    return KModErr::OK;
}
KModErr maplesu_request_owner_uid_prepare(const RequestUidController& controller,
    const maplesu_uid_record_v3* records, uint32_t count, uint64_t expected_revision,
    RequestUidCandidate& candidate) {
    management_reply = {};
    if (!uid_records_valid(records, count) || !expected_revision) return KModErr::ERR_MODULE_PARAM;
    auto error = uid_controller_ready(controller);
    if (is_failed(error)) return error;
    const maplesu_uid_prepare_v3 prepare{static_cast<uint64_t>(reinterpret_cast<uintptr_t>(records)),
        expected_revision, count, sizeof(*records), MAPLESU_UID_SNAPSHOT_SCHEMA, 0};
    error = owner_manage(MAPLESU_REQUEST_UID_PREPARE, controller.id, 0, &prepare, sizeof(prepare));
    if (is_ok(error)) candidate = {management_reply.result, controller};
    return error;
}
KModErr maplesu_request_owner_uid_commit(RequestUidCandidate& candidate, uint64_t& revision) {
    const auto error = uid_candidate_operation(MAPLESU_REQUEST_UID_COMMIT, candidate);
    if (is_ok(error)) revision = management_reply.result;
    return error;
}
KModErr maplesu_request_owner_uid_cancel(RequestUidCandidate& candidate) {
    return uid_candidate_operation(MAPLESU_REQUEST_UID_CANCEL, candidate);
}
namespace {
bool uid_readback_output_valid(const maplesu_uid_record_v3* records, uint32_t capacity) {
    return capacity <= MAPLESU_UID_SNAPSHOT_MAX_RECORDS && (!capacity || (records &&
        reinterpret_cast<uintptr_t>(records) <= UINTPTR_MAX - (capacity * sizeof(*records) - 1)));
}
KModErr uid_readback_finish(KModErr error, RequestUidReadbackPhase phase) {
    uid_readback_diagnostic.phase = phase;
    uid_readback_diagnostic.errorCode = to_num(error);
    uid_readback_diagnostic.systemErrno = is_failed(error) ? errno : 0;
    uid_readback_diagnostic.reply = management_reply;
    return error;
}
KModErr uid_readback_capability() {
    maplesu_metadata_owner_v3 metadata{};
    RequestOwnerBinding binding{};
    uint64_t descriptor = 0;
    const auto error = maplesu_request_owner_channel(metadata, descriptor, binding);
    if (is_failed(error)) return uid_readback_finish(error, RequestUidReadbackPhase::CapabilityQuery);
    uid_readback_diagnostic.capabilities = metadata.common.capabilities;
    if (!(metadata.common.capabilities & MAPLESU_CAP_UID_SNAPSHOT)) {
        errno = EOPNOTSUPP;
        return uid_readback_finish(KModErr::ERR_MODULE_TEST_CHANNEL, RequestUidReadbackPhase::CapabilityMissing);
    }
    return KModErr::OK;
}
KModErr uid_readback_current(uint64_t controller_id, const maplesu_host_instance& host,
    uint64_t expected_revision, maplesu_uid_metadata_v3& metadata,
    maplesu_uid_record_v3* records, uint32_t capacity) {
    management_reply = {};
    KModErr error;
    try {
        const size_t bytes = sizeof(maplesu_uid_metadata_v3) + capacity * sizeof(*records);
        std::vector<uint64_t> storage(bytes / sizeof(uint64_t));
        const maplesu_uid_readback_v3 readback{static_cast<uint64_t>(reinterpret_cast<uintptr_t>(storage.data())),
            capacity, 0, expected_revision};
        error = owner_manage(MAPLESU_REQUEST_UID_READBACK, controller_id, 0, &readback, sizeof(readback));
        if (is_failed(error)) {
            if (management_reply.completed && management_reply.status < 0) errno = -management_reply.status;
            return uid_readback_finish(error, RequestUidReadbackPhase::Exchange);
        }
        const auto binding = owner_management.binding;
        maplesu_uid_metadata_v3 actual{};
        std::memcpy(&actual, storage.data(), sizeof(actual));
        uid_readback_diagnostic.revision = actual.content_revision;
        uid_readback_diagnostic.count = actual.count;
        uid_readback_diagnostic.schema = actual.schema;
        if (actual.schema != MAPLESU_UID_SNAPSHOT_SCHEMA || actual.reserved || actual.count > capacity ||
            actual.record_bytes != sizeof(*records) || !actual.content_revision ||
            actual.content_revision != management_reply.result ||
            (expected_revision && actual.content_revision != expected_revision) ||
            actual.host.low != host.low || actual.host.high != host.high) {
            errno = EPROTO;
            uid_readback_finish(KModErr::ERR_MODULE_TEST_CHANNEL, RequestUidReadbackPhase::Metadata);
            management_reply = {};
            owner_management.uncertain = true;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        // Keep caller outputs intact until the entire immutable readback validates.
        std::vector<maplesu_uid_record_v3> rows(actual.count);
        if (actual.count) std::memcpy(rows.data(), reinterpret_cast<const uint8_t*>(storage.data()) +
            sizeof(actual), actual.count * sizeof(*records));
        if (!uid_records_valid(rows.data(), actual.count)) {
            errno = EBADMSG;
            uid_readback_finish(KModErr::ERR_MODULE_TEST_CHANNEL, RequestUidReadbackPhase::Records);
            management_reply = {};
            owner_management.uncertain = true;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        if (!maplesu_request_owner_binding_matches(binding)) {
            errno = ESTALE;
            uid_readback_finish(KModErr::ERR_MODULE_ROOT_KEY, RequestUidReadbackPhase::Binding);
            return owner_failed(KModErr::ERR_MODULE_ROOT_KEY, binding.auth_state);
        }
        if (actual.count) std::memcpy(records, rows.data(), actual.count * sizeof(*records));
        metadata = actual;
        return uid_readback_finish(KModErr::OK, RequestUidReadbackPhase::Complete);
    } catch (const std::bad_alloc&) {
        errno = ENOMEM;
        return uid_readback_finish(KModErr::ERR_NO_MEM, RequestUidReadbackPhase::Allocation);
    }
}
}
KModErr maplesu_request_owner_uid_readback(const RequestUidController& controller,
    uint64_t expected_revision, maplesu_uid_metadata_v3& metadata,
    maplesu_uid_record_v3* records, uint32_t capacity) {
    management_reset_after_fork();
    uid_readback_diagnostic = {};
    management_reply = {};
    if (!uid_readback_output_valid(records, capacity) || !controller.id ||
        !(controller.host.low || controller.host.high)) {
        errno = EINVAL;
        return uid_readback_finish(KModErr::ERR_MODULE_PARAM, RequestUidReadbackPhase::Output);
    }
    const auto error = uid_readback_capability();
    if (is_failed(error)) return error;
    if (controller.host.low != owner_channel.binding.host.low || controller.host.high != owner_channel.binding.host.high) {
        errno = ESTALE;
        return uid_readback_finish(KModErr::ERR_MODULE_ROOT_KEY, RequestUidReadbackPhase::Binding);
    }
    return uid_readback_current(controller.id, controller.host, expected_revision, metadata, records, capacity);
}
KModErr maplesu_request_owner_runtime_uid_sync(uint32_t full_uid) {
    management_reply = {};
    if (full_uid == UINT32_MAX) return KModErr::ERR_MODULE_PARAM;
    if (!maplesu_request_manager_mode()) {
        errno = EPERM;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const auto error = owner_require_capability(MAPLESU_CAP_UID_SNAPSHOT);
    if (is_failed(error)) return error;
    const auto result = owner_manage(MAPLESU_REQUEST_UID_COMMIT, 0, full_uid, nullptr, 0);
    if (management_reply.completed && management_reply.status < 0) errno = -management_reply.status;
    return result;
}
KModErr maplesu_request_owner_runtime_uid_readback(uint64_t expected_revision,
    maplesu_uid_metadata_v3& metadata, maplesu_uid_record_v3* records, uint32_t capacity) {
    management_reset_after_fork();
    uid_readback_diagnostic = {};
    management_reply = {};
    if (!uid_readback_output_valid(records, capacity)) {
        errno = EINVAL;
        return uid_readback_finish(KModErr::ERR_MODULE_PARAM, RequestUidReadbackPhase::Output);
    }
    if (!maplesu_request_manager_mode()) {
        errno = EPERM;
        return uid_readback_finish(KModErr::ERR_MODULE_ROOT_KEY, RequestUidReadbackPhase::Identity);
    }
    const auto error = uid_readback_capability();
    if (is_failed(error)) return error;
    const auto host = owner_channel.binding.host;
    return uid_readback_current(0, host, expected_revision, metadata, records, capacity);
}
KModErr maplesu_request_owner_uid_shutdown(const RequestUidController& controller) {
    management_reply = {};
    const auto error = uid_controller_ready(controller);
    if (is_failed(error)) return error;
    const auto result = owner_manage(MAPLESU_REQUEST_UID_SHUTDOWN, controller.id, 0, nullptr, 0);
    if (management_reply.completed && management_reply.status < 0) errno = -management_reply.status;
    return result;
}
KModErr maplesu_request_owner_execute(const uint8_t* bytes, uint32_t size, uint64_t& result) {
    management_reply = {};
    if (!bytes || !size || size > MAPLESU_MANAGEMENT_MAX_BYTES ||
        reinterpret_cast<uintptr_t>(bytes) > std::numeric_limits<uintptr_t>::max() - (size - 1))
        return KModErr::ERR_MODULE_PARAM;
    uint64_t address = 0;
    auto error = owner_alloc(size, address);
    if (is_failed(error)) return error;
    error = owner_write(address, bytes, size);
    if (is_ok(error)) error = owner_execute(address, size, result);
    if (is_failed(error)) {
        CleanupReceiptScope preserve_failure;
        if (management_reply.completed && !owner_management.uncertain &&
            owner_allocation(address) != owner_management.allocations.end()) (void)owner_release(address);
    }
    return error;
}
bool maplesu_request_managed_allocation(uint64_t address) {
    management_reset_after_fork();
    // A later, explicitly legacy ALLOC can legitimately reuse a retired managed
    // address. Only that task's still-live legacy allocation selects the adapter.
    if (std::any_of(legacy_address_ranges.begin(), legacy_address_ranges.end(),
            [address](const ManagedAddressRange& range) { return address >= range.first && address <= range.last; }))
        return false;
    return known_managed_address(address);
}
KModErr maplesu_request_key_credential_begin() {
    management_reset_after_fork();
    if (!maplesu_request_auth_legacy(maplesu_request_auth_state())) return KModErr::ERR_MODULE_ROOT_KEY;
    if (owner_management.uncertain) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (owner_management.session && !owner_identity_matches(owner_management.binding))
        return KModErr::ERR_MODULE_ROOT_KEY;
    if (!key_management_identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    return KModErr::OK;
}
KModErr maplesu_request_key_credential_end(KModErr execution_error) {
    const int execution_errno = errno;
    management_reset_after_fork();
    const bool same_identity = maplesu_request_auth_legacy(maplesu_request_auth_state()) &&
        key_management_identity.matches() && (!owner_management.session ||
            (owner_management.binding.auth_state == maplesu_request_auth_state() &&
             owner_management.binding.process == static_cast<uint64_t>(getpid())));
    if (is_failed(execution_error) || !same_identity) {
        if (owner_management.session) owner_management.uncertain = true;
        if (is_failed(execution_error)) errno = execution_errno;
        return is_failed(execution_error) ? execution_error : KModErr::ERR_MODULE_ROOT_KEY;
    }
    if (owner_management.session) owner_management.binding.actual_uid = getuid();
    return KModErr::OK;
}
KModErr maplesu_request_key_alloc(uint32_t size, uint64_t& address, bool& supported) {
    supported = true;
    if (!size || size > MAPLESU_MANAGEMENT_MAX_BYTES) return KModErr::ERR_MODULE_PARAM;
    const auto error = key_management_session(supported);
    return is_failed(error) || !supported ? error : owner_alloc(size, address);
}
KModErr maplesu_request_key_execute(const uint8_t* bytes, uint32_t size,
    uint64_t& result, bool& supported) {
    supported = true;
    if (!bytes || !size || size > MAPLESU_MANAGEMENT_MAX_BYTES ||
        reinterpret_cast<uintptr_t>(bytes) > std::numeric_limits<uintptr_t>::max() - (size - 1))
        return KModErr::ERR_MODULE_PARAM;
    const auto error = key_management_session(supported);
    return is_failed(error) || !supported ? error : maplesu_request_owner_execute(bytes, size, result);
}

KModErr maplesu_request_v2_probe(maplesu_response_v2& response, bool& supported) {
    return exchange_v2(MAPLESU_REQUEST_QUERY, 0, 0, true, response, supported);
}

KModErr maplesu_request_v2_exchange(uint32_t command, uint64_t arg0, uint64_t arg1,
                                 maplesu_response_v2& response) {
    bool supported = false;
    return exchange_v2(command, arg0, arg1, false, response, supported);
}

KModErr maplesu_request_v2_channel(maplesu_response_v2& response, bool& supported) {
    if (maplesu_request_owner_mode()) {
        response = {};
        supported = false;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    struct Channel {
        std::array<char, 48> key{};
        pid_t process = 0;
        uint64_t auth_state = 0;
        bool ready = false;
        bool supported = false;
        maplesu_response_v2 response{};
    };
    thread_local Channel channel;
    response = {};
    supported = false;
    RequestIdentity operation;
    if (!operation.capture() || !maplesu_request_auth_legacy(operation.auth_state)) return KModErr::ERR_MODULE_ROOT_KEY;
    const char* key = current_module_root_key();
    if (!key || strnlen(key, kRootKeyMaxLen) != channel.key.size()) {
        channel.ready = false;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    const auto process = getpid();
    const auto auth_state = maplesu_request_auth_state();
    if (!channel.ready || channel.process != process || channel.auth_state != auth_state ||
        std::memcmp(channel.key.data(), key, channel.key.size())) {
        channel.ready = false;
        std::array<char, 48> identity{};
        std::memcpy(identity.data(), key, identity.size());
        const auto error = maplesu_request_v2_probe(response, supported);
        if (is_failed(error)) return error;
        if (supported && response.status != MAPLESU_REQUEST_STATUS_OK)
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        const char* after = current_module_root_key();
        if (!after || strnlen(after, kRootKeyMaxLen) != identity.size() ||
            std::memcmp(identity.data(), after, identity.size()) || process != getpid() || !operation.matches()) {
            response = {};
            supported = false;
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
        // A failed request copy is indistinguishable from an old gateway's untouched
        // response. Do not turn that transient observation into a cached legacy choice.
        if (!supported) return response.completion_magic ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK;
        channel.key = identity;
        channel.process = process;
        channel.auth_state = auth_state;
        channel.supported = supported;
        channel.response = response;
        channel.ready = true;
    }
    if (!operation.matches()) {
        channel.ready = false;
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    response = channel.response;
    supported = channel.supported;
    return KModErr::OK;
}

KModErr maplesu_request_v2_read(uint64_t source, void* destination, uint32_t size) {
    if (maplesu_request_owner_mode()) return KModErr::ERR_MODULE_TEST_CHANNEL;
    const auto user = reinterpret_cast<uintptr_t>(destination);
    if (!destination || !size || source < UINT64_C(0xffff000000000000) ||
        source > std::numeric_limits<uint64_t>::max() - (size - 1) ||
        user > std::numeric_limits<uintptr_t>::max() - (size - 1))
        return KModErr::ERR_MODULE_PARAM;
    RequestIdentity identity;
    if (!identity.capture() || identity.length != 48) return KModErr::ERR_MODULE_ROOT_KEY;
    maplesu_response_v2 channel{};
    bool supported = false;
    const auto error = maplesu_request_v2_channel(channel, supported);
    if (is_failed(error)) return error;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (!supported || !(channel.result & MAPLESU_CAP_READ)) return KModErr::ERR_MODULE_TEST_CHANNEL;
    for (uint32_t done = 0; done < size;) {
        // The producer uses copy_to_user_nofault. A caller's large heap buffer
        // can still need a COW/page fault after fork; use this written task-local
        // batch instead, then publish only its complete, identity-bound reply.
        std::array<uint8_t, MAPLESU_READ_MAX_BYTES> staging{};
        maplesu_read_v2 read{};
        read.destination_user = reinterpret_cast<uintptr_t>(staging.data());
        const auto count = std::min(MAPLESU_READ_MAX_BYTES, size - done);
        read.length = count;
        maplesu_response_v2 response{};
        if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
        const auto result = maplesu_request_v2_exchange(MAPLESU_REQUEST_READ, source + done,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&read)), response);
        if (is_failed(result)) return result;
        if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
        if (response.status == MAPLESU_REQUEST_STATUS_INVALID) return KModErr::ERR_MODULE_PARAM;
        if (response.status == MAPLESU_REQUEST_STATUS_FAULT) return KModErr::ERR_MODULE_NOT_KADDR;
        if (response.status != MAPLESU_REQUEST_STATUS_OK || response.result != count)
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        std::memcpy(static_cast<uint8_t*>(destination) + done, staging.data(), count);
        done += count;
    }
    return KModErr::OK;
}

static KModErr legacy_alloc(uint32_t size, uint64_t& out_kaddr, const char* key_snapshot = nullptr) {
    management_reset_after_fork();
    const uint32_t page_size = get_page_size();
    const uint32_t aligned_size = align_to_page(size, page_size);
    if (aligned_size == 0) return KModErr::ERR_MODULE_PARAM;
    const uint32_t page_count = aligned_size / page_size;
    uint32_t saved_suid = 0, saved_sgid = 0;
    const KModErr snapshot_error = SuidSgidGuard::snapshot(saved_suid, saved_sgid);
    if (is_failed(snapshot_error)) return snapshot_error;

    uint64_t candidate = 0;
    const int64_t error = send_kernel_request(KernelCmdFlag::ALLOC_MEM, 0, 0,
                                              aligned_size, page_count, &candidate, key_snapshot);
    if (error != 0) {
        return static_cast<KModErr>(error);
    }
    // 分配地址通过 saved ids 回传；两者均未改变表示请求未被通道接收。
    if (saved_suid == static_cast<uint32_t>(candidate) && saved_sgid == static_cast<uint32_t>(candidate >> 32)) {
        return KModErr::ERR_MODULE_NO_BOOT;
    }
    if (candidate == 0) {
        return KModErr::ERR_MODULE_ALLOC_MEM;
    }
    if (candidate < UINT64_C(0xffff000000000000) || (candidate & (page_size - 1)) ||
        candidate > std::numeric_limits<uint64_t>::max() - (aligned_size - 1))
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    try { legacy_address_ranges.push_back({candidate, candidate + aligned_size - 1}); }
    catch (const std::bad_alloc&) {
        (void)send_kernel_request(KernelCmdFlag::RELEASE_STAGING, 0, candidate, 0, 0, nullptr, key_snapshot);
        return KModErr::ERR_NO_MEM;
    }
    out_kaddr = candidate;
    return KModErr::OK;
}

// 内核请求通道公开入口（成员导出符号）
KModErr unsafe_request_kernel_alloc_mem(uint32_t size, uint64_t& out_kaddr) {
    return maplesu_request_owner_mode() ? owner_alloc(size, out_kaddr) : legacy_alloc(size, out_kaddr);
}

KModErr unsafe_request_kernel_write_mem(uint64_t kaddr, const void* buf, uint32_t size) {
    if (maplesu_request_owner_mode() || maplesu_request_managed_allocation(kaddr)) return owner_write(kaddr, buf, size);
    if (!valid_memory_range(kaddr, buf, size)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    const auto* bytes = static_cast<const uint8_t*>(buf);
    for (uint32_t i = 0; i < size; ++i) {
        // 一次请求只搬 1 字节：sub 即数据，addr 为目标地址。
        const int64_t error = send_kernel_request(KernelCmdFlag::WRITE_MEM, bytes[i],
                                                  kaddr + i, 0, 0, nullptr);
        if (error != 0) {
            return static_cast<KModErr>(error);
        }
    }
    return KModErr::OK;
}

KModErr unsafe_request_kernel_read_mem(uint64_t kaddr, void* buf, uint32_t size) {
    if (maplesu_request_managed_allocation(kaddr)) {
        const auto entry = owner_allocation(kaddr);
        if (entry == owner_management.allocations.end() || !size ||
            size > entry->length - (kaddr - entry->address)) return KModErr::ERR_MODULE_PARAM;
        return maplesu_request_owner_mode() ? owner_read(kaddr, buf, size) :
            maplesu_request_v2_read(kaddr, buf, size);
    }
    if (maplesu_request_owner_mode()) return owner_read(kaddr, buf, size);
    if (!valid_memory_range(kaddr, buf, size)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    auto* bytes = static_cast<uint8_t*>(buf);
    for (uint32_t i = 0; i < size; ++i) {
        uint64_t reply = 0;
        const int64_t error = send_kernel_request(KernelCmdFlag::READ_MEM, 0,
                                                  kaddr + i, 0, 0, &reply);
        if (error != 0) {
            return static_cast<KModErr>(error);
        }
        if (reply > std::numeric_limits<uint8_t>::max()) return KModErr::ERR_MODULE_TEST_CHANNEL;
        bytes[i] = static_cast<uint8_t>(reply);
    }
    return KModErr::OK;
}

KModErr unsafe_request_kernel_exec_mem(uint64_t kaddr, uint32_t size, uint64_t& out_reply) {
    if (maplesu_request_owner_mode() || maplesu_request_managed_allocation(kaddr)) return owner_execute(kaddr, size, out_reply);
    const uint32_t page_size = get_page_size();
    const uint32_t aligned_size = align_to_page(size, page_size);
    const uint32_t page_count = page_size == 0 ? 0 : aligned_size / page_size;

    // r13 修订：地址 / 长度 / 页数任一为 0 直接判失败，不再发给内核。
    if (kaddr == 0 || aligned_size == 0 || page_count == 0) {
        return static_cast<KModErr>(kExecFailedDecoded);
    }
    const auto error = static_cast<KModErr>(send_kernel_request(
        KernelCmdFlag::EXEC_MEM, 0, kaddr, aligned_size, page_count, &out_reply));
    legacy_address_ranges.erase(std::remove_if(legacy_address_ranges.begin(), legacy_address_ranges.end(),
        [kaddr](const ManagedAddressRange& range) { return range.first == kaddr; }), legacy_address_ranges.end());
    return error;
}

KModErr request_kernel_set_suid_sgid(uint32_t suid, uint32_t sgid) {
    if (maplesu_request_owner_mode()) return KModErr::ERR_MODULE_TEST_CHANNEL;
    const uint64_t packed = (static_cast<uint64_t>(sgid) << 32) | static_cast<uint64_t>(suid);
    return static_cast<KModErr>(
        send_kernel_request(KernelCmdFlag::SET_SUID_SGID, 0, packed, 0, 0, nullptr));
}

KModErr request_kernel_alloc_mem(uint32_t size, uint64_t& out_kaddr) {
    if (maplesu_request_owner_mode()) return owner_alloc(size, out_kaddr);
    if (align_to_page(size, get_page_size()) == 0) return KModErr::ERR_MODULE_PARAM;
    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    uint32_t saved_suid = 0, saved_sgid = 0;
    const KModErr snapshot_error = SuidSgidGuard::snapshot(saved_suid, saved_sgid);
    if (is_failed(snapshot_error)) return snapshot_error;
    uint64_t candidate = 0;
    const KModErr error = legacy_alloc(size, candidate, identity.key.data());
    const int allocation_errno = errno;
    const bool allocation_identity = identity.matches();
    // Restore the original action's receipt once, even if its Key publication
    // changed. A different process or mode must never receive this restore.
    const bool restore_context = identity.process == getpid() &&
        identity.auth_state == maplesu_request_auth_state() && maplesu_request_auth_legacy(identity.auth_state);
    const uint64_t saved = (static_cast<uint64_t>(saved_sgid) << 32) | saved_suid;
    const KModErr restore_error = restore_context ? static_cast<KModErr>(send_kernel_request(
        KernelCmdFlag::SET_SUID_SGID, 0, saved, 0, 0, nullptr, identity.key.data())) :
        KModErr::ERR_MODULE_ROOT_KEY;
    const int restore_errno = errno;
    const bool restored_identity = identity.matches();
    if (is_failed(error)) { errno = allocation_errno; return error; }
    if (is_failed(restore_error) || !allocation_identity || !restored_identity) {
        const KModErr failure = is_failed(restore_error) ? restore_error : KModErr::ERR_MODULE_ROOT_KEY;
        const int failure_errno = is_failed(restore_error) && restore_context ? restore_errno : 0;
        // RELEASE has no independent legacy acknowledgement. Dispatch once
        // only for the same observed identity, retaining the restore failure.
        if (identity.matches()) (void)send_kernel_request(KernelCmdFlag::RELEASE_STAGING,
            0, candidate, 0, 0, nullptr, identity.key.data());
        errno = failure_errno;
        return failure;
    }
    out_kaddr = candidate;
    return KModErr::OK;
}

KModErr request_kernel_write_mem(uint64_t kaddr, const void* buf, uint32_t size) {
    return unsafe_request_kernel_write_mem(kaddr, buf, size);
}

// request_kernel_read_mem 不在本 TU 定义。
// （copy_from_kernel_nofault + copy_to_user_nofault，带 asmjit 生成的可失败读
// 与 kallsyms 冷解析）。该 TU 以 -DMAPLESU_KERNEL_READ_CANONICAL 编进本成员，
// 直接复用 runtime/ultra/authorization/kernel_read.cpp 原文件，不复制实现。
// 本 TU 只保留历史 staging 读（unsafe_ / legacy 两个符号），二者同名不同义：
//   request_kernel_read_mem       -> kernel_read.cpp（安全读，失败返回 NOT_KADDR）
//   unsafe_request_kernel_read_mem-> 本文件（逐字节通道读，会真的走 syscall 通道）

// MapleSU 分支对该成员追加的导出（extern "C"，无名字修饰）

// 每个请求前把 current->cred 私有化（capget + capset）的 maplesu_prepare_kernel_request
// 不在本 TU 定义：该符号由 request_context.cpp 提供（本成员的第 2 个 TU，
// 直接引用 runtime/ultra/authorization/request_context.cpp 原文件）。
// 声明见 sdk/include/module_base_kernel_request.h 末尾的 extern "C" 声明。

// 释放通道 staging 暂存页。
extern "C" __attribute__((visibility("hidden")))
int64_t maplesu_release_staging(uint64_t address) {
    if (maplesu_request_owner_mode() || maplesu_request_managed_allocation(address)) return to_num(owner_release(address));
    const auto error = send_kernel_request(KernelCmdFlag::RELEASE_STAGING, 0, address, 0, 0, nullptr);
    legacy_address_ranges.erase(std::remove_if(legacy_address_ranges.begin(), legacy_address_ranges.end(),
        [address](const ManagedAddressRange& range) { return range.first == address; }), legacy_address_ranges.end());
    return error;
}

// 保留，同名的新实现由 kernel_read.cpp 提供。
extern "C" __attribute__((visibility("hidden")))
KModErr maplesu_legacy_request_kernel_read_mem(uint64_t kaddr, void* buf, uint32_t size) {
    if (maplesu_request_owner_mode()) return owner_read(kaddr, buf, size);
    if (!valid_memory_range(kaddr, buf, size)) return KModErr::ERR_MODULE_PARAM;
    SuidSgidGuard guard;
    if (is_failed(guard.status())) return guard.status();
    const KModErr error = unsafe_request_kernel_read_mem(kaddr, buf, size);
    const KModErr restore_error = guard.restore();
    return is_failed(error) ? error : restore_error;
}

KModErr maplesu_request_helper_fixed(uint32_t operation, uint32_t mode,
    uint32_t exploit, uint64_t value, RequestEarlyFixedResult& output) {
    management_reset_after_fork();
    output = {};
    management_reply = {};
    if (!maplesu_request_helper_mode()) { errno = EPERM; return KModErr::ERR_MODULE_ROOT_KEY; }
    if (operation < MAPLESU_EARLY_FIXED_OEM_MTK || operation > MAPLESU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE ||
        mode > MAPLESU_EARLY_FIXED_MODE_MAX || exploit > MAPLESU_EARLY_FIXED_EXPLOIT_MAX) {
        errno = EINVAL; return KModErr::ERR_MODULE_PARAM;
    }
    if (!owner_management.session) {
        const auto opened = maplesu_request_helper_open();
        if (is_failed(opened)) return opened;
    }
    if (owner_management.uncertain || !owner_channel.ready ||
        !maplesu_request_owner_binding_matches(owner_management.binding)) {
        errno = ESTALE; return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    RequestEarlyFixedResult candidate{};
    maplesu_management_v3 request{};
    request.host = owner_management.binding.host;
    request.session = owner_management.session;
    request.handle = mode;
    request.address = operation;
    request.data_user = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&candidate));
    request.length = sizeof(candidate);
    request.flags = exploit;
    request.reserved = value;
    const auto error = management_exchange(MAPLESU_REQUEST_EARLY_FIXED, request,
        owner_management.binding);
    const auto receipt = management_reply;
    if (!receipt.completed || (receipt.result && receipt.result != sizeof(candidate))) {
        owner_management.uncertain = true;
        errno = EPROTO;
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    if (receipt.result == sizeof(candidate)) {
        const uint32_t allowed_effects = early_fixed_effect_mask(operation);
        if (!allowed_effects || candidate.code > 0 || candidate.native_errno < 0 ||
            candidate.native_errno > 4095 || (candidate.effects & ~allowed_effects) ||
            (!receipt.status && !(candidate.effects & MAPLESU_EARLY_FIXED_EFFECT_ATTEMPTED))) {
            owner_management.uncertain = true;
            errno = EPROTO;
            return KModErr::ERR_MODULE_TEST_CHANNEL;
        }
        output = candidate;
    }
    if (receipt.status < 0) errno = -receipt.status;
    if (is_failed(error)) return error;
    return receipt.status ? management_status(receipt.status) : KModErr::OK;
}

}  // namespace kernel_module
