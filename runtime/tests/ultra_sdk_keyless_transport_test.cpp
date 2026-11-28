// Actual selected m023 with a captured syscall seam; no kernel/device claims.
#include "../maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <thread>

namespace {
constexpr uint64_t descriptor = UINT64_C(0xffff000020000000);
constexpr uint64_t allocation = UINT64_C(0xffff000030000000);
constexpr uint64_t answer = UINT64_C(0xfedcba9876543210);
constexpr maplesu_host_instance host{0x1122334455667788, 0x8877665544332211};
struct Fixture {
    uint32_t uid = 0, epoch = 1, fail_command = 0;
    int32_t status = 0;
    uint32_t extra_effects = 0;
    bool missing = false, malformed = false, helper = false;
    bool no_uid_capability = false, bad_uid_metadata = false, bad_uid_record = false;
    std::array<unsigned, 40> calls{};
    std::vector<uint8_t> bytes;
    uint64_t last_id = 0, revision = 7;
};
thread_local Fixture state;
std::atomic<unsigned> checks{0};
void check(bool value, const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno); std::abort(); }
}
unsigned calls() {
    unsigned result = 0;
    for (auto n : state.calls) result += n;
    return result;
}
maplesu_metadata_owner_v3 metadata() {
    maplesu_metadata_owner_v3 m{};
    m.common.magic = MAPLESU_METADATA_MAGIC;
    m.common.version = MAPLESU_OWNER_METADATA_VERSION;
    m.common.length = sizeof(m);
    m.common.capabilities = (state.helper ? MAPLESU_HELPER_BASE_CAPABILITIES | MAPLESU_HELPER_OPTIONAL_CAPABILITIES
        : MAPLESU_OWNER_CAPABILITIES) | MAPLESU_CAP_APPEND64;
    if (state.no_uid_capability) m.common.capabilities &= ~MAPLESU_CAP_UID_SNAPSHOT;
    m.common.kernel_base_displacement = -0x10000000;
    m.common.legacy_metadata_displacement = -0x1000;
    m.owner_schema = MAPLESU_OWNER_SCHEMA;
    m.owner_state = state.helper ? MAPLESU_OWNER_STATE_HELPER : MAPLESU_OWNER_STATE_BOUND;
    m.owner_epoch = state.epoch;
    m.owner_full_uid = state.uid;
    m.host = host;
    return m;
}
void reset(uint32_t uid = 0, uint32_t epoch = 1) {
    state = {};
    state.uid = uid;
    state.epoch = epoch;
    kernel_module::owner_management = {};
    kernel_module::owner_channel = {};
    kernel_module::helper_channel = {};
    kernel_module::management_reply = {};
    kernel_module::management_process = getpid();
    kernel_module::request_auth_state.store(0);
}
void close() {
    state.fail_command = 0;
    state.missing = state.malformed = false;
    check(kernel_module::maplesu_request_owner_close() == KModErr::OK, "explicit current-task CLOSE");
}
}

namespace kernel_module {
uint32_t get_page_size() { return 4096; }
KModErr maplesu_kernel_legacy_read(uint64_t, void*, uint32_t) {
    check(false, "owner READ never dispatches to the legacy seam");
    return KModErr::ERR_MODULE_TEST_CHANNEL;
}
KModErr maplesu_kernel_metadata_v2(maplesu_metadata_v2&, uint64_t&, bool&) {
    check(false, "owner metadata never dispatches to the legacy seam");
    return KModErr::ERR_MODULE_TEST_CHANNEL;
}
}
extern "C" uid_t __wrap_getuid() { return state.uid; }
extern "C" uid_t __wrap_geteuid() { return state.uid; }
extern "C" long __wrap_syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    const auto* packet = va_arg(args, const uint8_t*);
    va_end(args);
    constexpr size_t prefix = sizeof(MAPLESU_OWNER_ENVELOPE_PREFIX) - 1;
    check(number == 221 && prefix == 48 && std::memcmp(packet, MAPLESU_OWNER_ENVELOPE_PREFIX, prefix) == 0,
        "one fixed non-secret v3 envelope");
    std::array<uint8_t, 18> frame{};
    for (size_t i = 0; i < frame.size(); ++i) {
        check(packet[prefix + i] && packet[prefix + 18 + i], "encoded packet contains no NUL");
        frame[i] = packet[prefix + i] + packet[prefix + 18 + i];
    }
    uint64_t pointer = 0, reserved = 1;
    std::memcpy(&reserved, frame.data() + 2, 8);
    std::memcpy(&pointer, frame.data() + 10, 8);
    check(frame[0] == MAPLESU_REQUEST_SELECTOR_FLAG && frame[1] == MAPLESU_REQUEST_SELECTOR_SUB &&
        !reserved && packet[prefix + 36] == 0, "unchanged 18+18 selector and zero transport address");
    const auto& r = *reinterpret_cast<const maplesu_request_owner_v3*>(pointer);
    check(r.magic == MAPLESU_REQUEST_MAGIC && r.version == MAPLESU_OWNER_PROTOCOL_VERSION &&
        r.length == sizeof(r) && r.request_id > state.last_id && r.response_user > UINT32_MAX,
        "v3 request shape and full-width userspace pointers");
    check(r.command < state.calls.size(), "bounded typed command");
    state.last_id = r.request_id;
    ++state.calls[r.command];
    if (state.missing && r.command == state.fail_command) return -1;
    maplesu_response_owner_v3 response{};
    response.completion_magic = MAPLESU_RESPONSE_MAGIC;
    response.version = MAPLESU_OWNER_PROTOCOL_VERSION;
    response.length = sizeof(response);
    response.command = r.command;
    response.request_id = r.request_id;
    if (r.command == state.fail_command) response.status = state.status;
    if (!response.status) {
        if (r.command == MAPLESU_REQUEST_QUERY) {
            check(!state.helper && !r.expected_epoch && r.arg0 == MAPLESU_OWNER_TASK_QUERY,
                "cold current-task QUERY with no assumed Manager identity");
            response.result = metadata().common.capabilities;
            response.metadata_address = descriptor;
            response.metadata_length = sizeof(maplesu_metadata_owner_v3);
            response.metadata_version = MAPLESU_OWNER_METADATA_VERSION;
        } else if (r.command == MAPLESU_REQUEST_READ) {
            const auto& read = *reinterpret_cast<const maplesu_read_owner_v3*>(r.arg1);
            check(read.length && read.length <= MAPLESU_READ_MAX_BYTES && !read.reserved,
                "bounded typed READ");
            if (r.arg0 == descriptor) {
                check(read.length == sizeof(maplesu_metadata_owner_v3), "complete descriptor READ");
                const auto m = metadata();
                std::memcpy(reinterpret_cast<void*>(read.destination_user), &m, sizeof(m));
            } else {
                check(r.expected_epoch == state.epoch && read.host.low == host.low && read.host.high == host.high,
                    "READ binds full current epoch and host");
                for (uint32_t n = 0; n < read.length; ++n)
                    reinterpret_cast<uint8_t*>(read.destination_user)[n] = static_cast<uint8_t>(r.arg0 + n);
            }
            response.result = read.length;
        } else if (r.command == MAPLESU_REQUEST_ECHO64) response.result = r.arg0;
        else {
            const auto& op = *reinterpret_cast<const maplesu_management_v3*>(r.arg1);
            if (r.command == MAPLESU_REQUEST_SESSION_OPEN) {
                response.result = 0x91;
                if (state.helper) {
                    check(!r.expected_epoch && op.length == sizeof(maplesu_metadata_owner_v3), "Helper opens its restricted descriptor directly");
                    const auto m = metadata();
                    std::memcpy(reinterpret_cast<void*>(op.data_user), &m, sizeof(m));
                    response.metadata_address = descriptor;
                }
            } else if (r.command == MAPLESU_REQUEST_SESSION_CLOSE) {
                check(!op.session, "CLOSE cleans only this task including uncertain OPEN");
                response.metadata_length = MAPLESU_EFFECT_SESSION_CLOSED;
            } else {
                check(op.session == 0x91 && op.host.low == host.low && op.host.high == host.high &&
                    r.expected_epoch == state.epoch, "management binds the opened task/session");
                switch (r.command) {
                case MAPLESU_REQUEST_ALLOC:
                    state.bytes.resize(op.length);
                    response.result = allocation;
                    response.metadata_address = 0xa1;
                    response.metadata_length = MAPLESU_EFFECT_ALLOCATED;
                    break;
                case MAPLESU_REQUEST_WRITE:
                    check(op.handle == 0xa1 && op.address + op.length <= state.bytes.size(), "WRITE uses its own allocation handle");
                    std::memcpy(state.bytes.data() + op.address, reinterpret_cast<const void*>(op.data_user), op.length);
                    response.result = op.length;
                    response.metadata_length = MAPLESU_EFFECT_WRITTEN;
                    break;
                case MAPLESU_REQUEST_EXEC:
                    check(op.handle == 0xa1 && op.length == state.bytes.size(), "EXEC consumes only its own complete allocation");
                    response.result = answer;
                    response.metadata_length = MAPLESU_EFFECT_EXECUTED | MAPLESU_EFFECT_RELEASED;
                    break;
                case MAPLESU_REQUEST_UID_COMMIT:
                    check(!op.handle && op.address == UINT32_MAX - 1, "Root durable mirror uses handle 0 and preserves fullUID");
                    response.result = state.revision;
                    response.metadata_length = MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_REFERENCE_DROPPED;
                    break;
                case MAPLESU_REQUEST_UID_READBACK: {
                    check(!op.handle, "Root reads the durable mirror using handle 0");
                    const auto& read = *reinterpret_cast<const maplesu_uid_readback_v3*>(op.data_user);
                    maplesu_uid_metadata_v3 m{};
                    m.schema = MAPLESU_UID_SNAPSHOT_SCHEMA;
                    m.record_bytes = sizeof(maplesu_uid_record_v3);
                    m.content_revision = state.revision;
                    m.host = host;
                    if (state.bad_uid_metadata) m.schema = 99;
                    if (state.bad_uid_record) m.count = 1;
                    std::memcpy(reinterpret_cast<void*>(read.destination_user), &m, sizeof(m));
                    if (state.bad_uid_record) {
                        maplesu_uid_record_v3 row{};
                        row.full_uid = 12345;
                        std::memcpy(reinterpret_cast<uint8_t*>(read.destination_user) + sizeof(m), &row, sizeof(row));
                    }
                    response.result = state.revision;
                    break;
                }
                default: check(false, "expected fixture command");
                }
            }
        }
    }
    if (state.malformed && r.command == state.fail_command) ++response.request_id;
    if (r.command == state.fail_command) response.metadata_length |= state.extra_effects;
    std::memcpy(reinterpret_cast<void*>(r.response_user), &response, sizeof(response));
    return -1; // The receipt, never the unrelated syscall return, decides success.
}

int main() {
    using namespace kernel_module;
    reset();
    maplesu_request_clear_legacy();
    check(!maplesu_request_auth_usable(0) && !maplesu_request_auth_legacy(0) &&
        !maplesu_request_auth_usable(UINT64_MAX) && !maplesu_request_auth_legacy(UINT64_MAX) &&
        !maplesu_request_auth_usable(6), "uninitialized, exhausted and invalid tags never select legacy");
    const auto default_state = maplesu_request_auth_state();
    const auto no_calls = calls();
    const std::string oversized(1024, 'X');
    for (const char* invalid : {static_cast<const char*>(nullptr), "short", oversized.c_str()}) {
        check(maplesu_request_select_legacy(invalid) == KModErr::ERR_MODULE_ROOT_KEY &&
            maplesu_request_auth_state() == default_state && calls() == no_calls &&
            !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(),
            "invalid explicit credentials preserve the default protocol and context");
    }
    constexpr char first_key[] = "HistoricalFixtureCredentialParent1234567890";
    constexpr char second_key[] = "HistoricalFixtureCredentialWorker1234567890";
    check(maplesu_request_select_legacy(first_key) == KModErr::OK &&
        maplesu_request_auth_legacy(maplesu_request_auth_state()) && calls() == no_calls,
        "only explicit valid credentials select legacy without sending a request");
    RequestIdentity legacy_identity;
    check(legacy_identity.capture() && legacy_identity.matches() &&
        maplesu_request_worker_admission() == KModErr::OK && calls() == no_calls,
        "legacy admission captures the real credential without an added Root probe");
    const auto parent_auth = maplesu_request_auth_state();
    std::thread isolated([&] {
        check(maplesu_request_auth_manager(maplesu_request_auth_state()) &&
            !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(),
            "a new thread keeps owner default and inherits no legacy credential");
        check(maplesu_request_select_legacy(second_key) == KModErr::OK &&
            !std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), second_key),
            "a worker explicitly selects its own independent legacy credential");
        maplesu_request_clear_legacy();
    });
    isolated.join();
    check(maplesu_request_auth_state() == parent_auth && legacy_identity.matches() &&
        !std::strcmp(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(), first_key),
        "worker credential changes leave the parent context intact");
    maplesu_request_clear_legacy();
    check(maplesu_request_auth_state() == parent_auth && !legacy_identity.matches() &&
        maplesu_request_worker_admission() == KModErr::ERR_MODULE_ROOT_KEY && calls() == no_calls,
        "clearing credentials retains explicit mode and reports failure without automatic downgrade");
    reset();
    const auto initial = maplesu_request_auth_state();
    check(maplesu_request_auth_manager(initial), "new thread defaults to existing mode 1");
    RequestMetadataFacts facts{};
    bool supported = false;
    check(maplesu_kernel_metadata_facts(facts, supported) == KModErr::OK && supported &&
        facts.owner.full_uid == 0 && facts.owner.epoch == 1 && facts.kernel_base == descriptor - 0x10000000 &&
        facts.append == descriptor - 0x1000 && facts.append_bytes == MAPLESU_APPEND64_BYTES &&
        (facts.capabilities & MAPLESU_CAP_UID_SNAPSHOT), "Root uid0/epoch1 with signed APPEND64 facts and UID mirror capability");
    for (auto value : {UINT64_C(0), UINT64_C(0x00000001ffffffff), UINT64_MAX, answer}) {
        uint64_t actual = 5;
        check(maplesu_request_owner_echo(value, actual) == KModErr::OK && actual == value, "full 64-bit ECHO result");
    }
    std::vector<uint8_t> read(600, 0);
    check(request_kernel_read_mem(descriptor + 0x100, read.data(), read.size()) == KModErr::OK, "canonical keyless READ batches");
    for (size_t n = 0; n < read.size(); ++n) check(read[n] == static_cast<uint8_t>(descriptor + 0x100 + n), "READ preserves each byte");
    const uint8_t bytes[] = {1, 0, 2, 0, 0xff, 0x80, 3, 4};
    uint64_t address = 7, result = 8;
    check(request_kernel_alloc_mem(sizeof(bytes), address) == KModErr::OK && address == allocation, "typed ALLOC");
    RequestOwnerLifetimeToken token;
    check(maplesu_request_owner_lifetime_capture(token) && maplesu_request_owner_lifetime_matches(token), "in-flight token witnesses this session");
    check(maplesu_request_set_auth_mode(RequestAuthMode::EarlyHelper) != KModErr::OK, "mode change cannot abandon a live session");
    const auto live_auth = maplesu_request_auth_state();
    check(maplesu_request_select_legacy(first_key) != KModErr::OK &&
        maplesu_request_auth_state() == live_auth &&
        !*__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(),
        "failed legacy selection cannot replace a live owner session or credential");
    check(request_kernel_write_mem(address, bytes, sizeof(bytes)) == KModErr::OK, "typed WRITE");
    check(unsafe_request_kernel_exec_mem(address, sizeof(bytes), result) == KModErr::OK && result == answer,
        "one EXEC publishes the full u64 result");
    const auto before = calls();
    check(unsafe_request_kernel_exec_mem(address, sizeof(bytes), result) != KModErr::OK && calls() == before,
        "consumed EXEC is never replayed");
    check(maplesu_request_owner_runtime_uid_sync(UINT32_MAX - 1) == KModErr::OK, "Root handle0 UID mirror sync");
    maplesu_uid_metadata_v3 mirror{};
    check(maplesu_request_owner_runtime_uid_readback(7, mirror, nullptr, 0) == KModErr::OK && mirror.content_revision == 7,
        "Root handle0 UID mirror readback");
    const auto readback = maplesu_request_uid_readback_diagnostic();
    check(readback.phase == RequestUidReadbackPhase::Complete && !readback.errorCode && !readback.systemErrno &&
        (readback.capabilities & MAPLESU_CAP_UID_SNAPSHOT) && readback.revision == 7 &&
        readback.reply.completed && readback.reply.command == MAPLESU_REQUEST_UID_READBACK && readback.reply.result == 7,
        "UID diagnostics retain this successful READ's original facts");
    close();
    check(maplesu_request_uid_readback_diagnostic().reply.command == MAPLESU_REQUEST_UID_READBACK,
        "CLOSE does not replace UID READ diagnostics");
    check(!maplesu_request_owner_lifetime_matches(token), "CLOSE invalidates in-flight witness");
    check(maplesu_request_set_auth_mode(RequestAuthMode::EarlyHelper) == KModErr::OK &&
        initial != maplesu_request_auth_state(), "closed phase may select a new mode/generation");
    state.helper = true;
    check(maplesu_request_helper_open() == KModErr::OK, "explicit existing Helper authentication opens without Manager QUERY");
    close();

    for (unsigned fault = 0; fault < 5; ++fault) {
        reset();
        state.no_uid_capability = fault == 0;
        state.bad_uid_metadata = fault == 1;
        state.bad_uid_record = fault == 2;
        if (fault >= 3) {
            state.fail_command = MAPLESU_REQUEST_UID_READBACK;
            state.missing = fault == 3;
            state.status = fault == 4 ? -EIO : 0;
        }
        maplesu_uid_metadata_v3 saved{};
        saved.content_revision = 900;
        maplesu_uid_record_v3 saved_row{};
        saved_row.full_uid = 54321;
        errno = EBUSY;
        const auto error = maplesu_request_owner_runtime_uid_readback(0, saved, &saved_row, 1);
        const auto detail = maplesu_request_uid_readback_diagnostic();
        const auto phase = fault == 0 ? RequestUidReadbackPhase::CapabilityMissing :
            fault == 1 ? RequestUidReadbackPhase::Metadata : fault == 2 ? RequestUidReadbackPhase::Records :
            RequestUidReadbackPhase::Exchange;
        const int expected_errno = fault == 0 ? EOPNOTSUPP : fault == 2 ? EBADMSG : fault == 4 ? EIO : EPROTO;
        check(error == KModErr::ERR_MODULE_TEST_CHANNEL && errno == expected_errno &&
            detail.errorCode == to_num(error) && detail.systemErrno == expected_errno && detail.phase == phase,
            "UID failure has one exact phase/code/errno, independent of stale errno");
        check(saved.content_revision == 900 && saved_row.full_uid == 54321,
            "failed UID READ preserves all caller outputs");
        check(state.calls[MAPLESU_REQUEST_UID_READBACK] == (fault == 0 ? 0u : 1u),
            "UID diagnosis performs no additional exchange or retry");
        if (fault == 1 || fault == 2 || fault == 4)
            check(detail.reply.completed && detail.reply.command == MAPLESU_REQUEST_UID_READBACK &&
                detail.reply.result == (fault == 4 ? 0 : 7), "local validation retains original UID management receipt");
        close();
        check(maplesu_request_uid_readback_diagnostic().phase == phase,
            "session cleanup preserves the UID first failure");
    }

    for (auto status : {-EPERM, -ESTALE, -EINVAL, -EFAULT, -ENOMEM, -EIO}) {
        reset();
        state.fail_command = MAPLESU_REQUEST_READ;
        state.status = status;
        uint8_t untouched = 0x9a;
        errno = 0;
        const auto error = request_kernel_read_mem(descriptor + 0x100, &untouched, 1);
        const auto expected = status == -EPERM || status == -ESTALE ? KModErr::ERR_MODULE_ROOT_KEY :
            status == -EINVAL ? KModErr::ERR_MODULE_PARAM : status == -EFAULT ? KModErr::ERR_MODULE_NOT_KADDR :
            status == -ENOMEM ? KModErr::ERR_NO_MEM : KModErr::ERR_MODULE_TEST_CHANNEL;
        check(error == expected && errno == -status && untouched == 0x9a && state.calls[MAPLESU_REQUEST_QUERY] == 1 &&
            state.calls[MAPLESU_REQUEST_READ] == 1, "failed READ keeps exact errno/output and issues no fallback or retry");
    }
    for (bool missing : {false, true}) {
        reset();
        state.fail_command = MAPLESU_REQUEST_SESSION_OPEN;
        state.missing = missing;
        state.malformed = !missing;
        uint64_t untouched = 0x1234;
        errno = 0;
        check(request_kernel_alloc_mem(8, untouched) == KModErr::ERR_MODULE_TEST_CHANNEL && errno == EPROTO && untouched == 0x1234,
            "lost or malformed OPEN is uncertain and preserves outputs");
        const auto used = calls();
        check(request_kernel_alloc_mem(8, untouched) != KModErr::OK && calls() == used && state.calls[MAPLESU_REQUEST_SESSION_OPEN] == 1,
            "uncertain OPEN is never replayed");
        close();
    }
    reset();
    state.fail_command = MAPLESU_REQUEST_SESSION_OPEN;
    state.extra_effects = UINT32_C(0x80000000);
    uint64_t malformed_output = 0x1234;
    errno = 0;
    check(request_kernel_alloc_mem(8, malformed_output) == KModErr::ERR_MODULE_TEST_CHANNEL &&
        errno == EPROTO && malformed_output == 0x1234,
        "malformed management effects preserve EPROTO and the original output");
    close();
    reset();
    check(request_kernel_alloc_mem(8, address) == KModErr::OK, "open before revoke");
    state.fail_command = MAPLESU_REQUEST_WRITE;
    state.status = -ESTALE;
    check(request_kernel_write_mem(address, bytes, sizeof(bytes)) == KModErr::ERR_MODULE_ROOT_KEY && errno == ESTALE,
        "revoked WRITE preserves the kernel rejection");
    const auto rejected = calls();
    check(request_kernel_write_mem(address, bytes, sizeof(bytes)) != KModErr::OK && calls() == rejected,
        "revocation invalidates the in-flight session without retry");
    close();

    std::array<uint64_t, 6> generations{};
    std::vector<std::thread> workers;
    for (size_t i = 0; i < generations.size(); ++i) workers.emplace_back([&, i] {
        reset(1010123 + i, 9 + i);
        generations[i] = maplesu_request_auth_state();
        uint64_t output = 0;
        for (unsigned repeat = 0; repeat < 5; ++repeat)
            check(maplesu_request_owner_echo(answer + i, output) == KModErr::OK && output == answer + i,
                "interleaved tasks retain independent fullUID/epoch/response");
    });
    for (auto& worker : workers) worker.join();
    check(std::set<uint64_t>(generations.begin(), generations.end()).size() == generations.size(),
        "thread generations never alias");
    std::printf("PASS keyless transport: %u checks; Root uid0/epoch1, signed metadata, UID mirror, u64, batching, errors, no replay, revoke, Helper, threads\n", checks.load());
}
