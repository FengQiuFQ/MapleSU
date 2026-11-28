// Private result of one UID read worker. It grants no authorization or identity.
#pragma once
#include "su_auth_result_private.h"

namespace maplesu::su_auth {
enum class ReadPhase : uint32_t {
    None, Validate, Admission, Fork, Root, Read, Close, Records, Transfer, Wait
};
struct ReadStepV1 {
    int64_t code = 0;
    int32_t systemErrno = 0;
    uint32_t completed = 0;
};
struct UidReadbackV1 {
    int64_t code = 0;
    int32_t systemErrno = 0;
    uint32_t phase = 0;
    uint64_t capabilities = 0, revision = 0;
    uint32_t count = 0, schema = 0;
    int32_t managementStatus = 0;
    uint32_t managementEffects = 0;
    uint64_t managementResult = 0;
    uint32_t managementCommand = 0, managementCompleted = 0, managementHasHandle = 0, reserved = 0;
};
constexpr size_t kReadResultBytes = 176;
constexpr uint32_t kReadResultAvailable = 1;
struct ReadResultV1 {
    uint32_t magic = 0x31525553;
    uint16_t version = 1, headerBytes = kReadResultBytes;
    uint32_t byteLength = kReadResultBytes, flags = 0;
    int64_t resultCode = 0;
    uint32_t primaryPhase = 0, authMode = 0;
    ReadStepV1 root{}, read{}, close{};
    UidReadbackV1 readback{};
    uint32_t recordCount = 0;
    int32_t primaryErrno = 0;
    uint32_t transportStatus = 0;
    int32_t transportErrno = 0, childWaitStatus = 0;
    uint32_t childWaitStatusValid = 0;
};
static_assert(sizeof(ReadStepV1) == 16 && sizeof(UidReadbackV1) == 72);
static_assert(sizeof(ReadResultV1) == kReadResultBytes);

namespace read_wire {
inline void put_step(uint8_t* p, size_t offset, const ReadStepV1& step) {
    wire::put(p, offset, static_cast<uint64_t>(step.code), 8);
    wire::put(p, offset + 8, static_cast<uint32_t>(step.systemErrno), 4);
    wire::put(p, offset + 12, step.completed, 4);
}
inline ReadStepV1 get_step(const uint8_t* p, size_t offset) {
    return {wire::signed64(wire::get(p, offset, 8)),
        static_cast<int32_t>(wire::get(p, offset + 8, 4)),
        static_cast<uint32_t>(wire::get(p, offset + 12, 4))};
}
inline std::vector<uint8_t> encode(const ReadResultV1& r) {
    std::vector<uint8_t> bytes(kReadResultBytes, 0);
    auto* p = bytes.data();
    wire::put(p, 0, r.magic, 4); wire::put(p, 4, r.version, 2); wire::put(p, 6, r.headerBytes, 2);
    wire::put(p, 8, r.byteLength, 4); wire::put(p, 12, r.flags, 4);
    wire::put(p, 16, static_cast<uint64_t>(r.resultCode), 8);
    wire::put(p, 24, r.primaryPhase, 4); wire::put(p, 28, r.authMode, 4);
    put_step(p, 32, r.root); put_step(p, 48, r.read); put_step(p, 64, r.close);
    const auto& d = r.readback;
    wire::put(p, 80, static_cast<uint64_t>(d.code), 8);
    wire::put(p, 88, static_cast<uint32_t>(d.systemErrno), 4); wire::put(p, 92, d.phase, 4);
    wire::put(p, 96, d.capabilities, 8); wire::put(p, 104, d.revision, 8);
    wire::put(p, 112, d.count, 4); wire::put(p, 116, d.schema, 4);
    wire::put(p, 120, static_cast<uint32_t>(d.managementStatus), 4);
    wire::put(p, 124, d.managementEffects, 4); wire::put(p, 128, d.managementResult, 8);
    wire::put(p, 136, d.managementCommand, 4); wire::put(p, 140, d.managementCompleted, 4);
    wire::put(p, 144, d.managementHasHandle, 4); wire::put(p, 148, d.reserved, 4);
    wire::put(p, 152, r.recordCount, 4); wire::put(p, 156, static_cast<uint32_t>(r.primaryErrno), 4);
    // Transport and child wait facts belong to the parent and stay zero here.
    return bytes;
}
inline bool code_valid(int64_t code) {
    return code >= std::numeric_limits<ssize_t>::min() && code <= std::numeric_limits<ssize_t>::max();
}
inline bool step_valid(const ReadStepV1& step) {
    return code_valid(step.code) && step.completed <= 1 &&
        (step.completed || (!step.code && !step.systemErrno));
}
inline bool decode(const uint8_t* p, size_t size, ReadResultV1& output) {
    if (!p || size != kReadResultBytes) return false;
    ReadResultV1 r;
    if (wire::get(p, 0, 4) != r.magic || wire::get(p, 4, 2) != r.version ||
        wire::get(p, 6, 2) != r.headerBytes || wire::get(p, 8, 4) != r.byteLength ||
        wire::get(p, 12, 4) != kReadResultAvailable) return false;
    r.flags = kReadResultAvailable;
    r.resultCode = wire::signed64(wire::get(p, 16, 8));
    r.primaryPhase = wire::get(p, 24, 4); r.authMode = wire::get(p, 28, 4);
    r.root = get_step(p, 32); r.read = get_step(p, 48); r.close = get_step(p, 64);
    auto& d = r.readback;
    d.code = wire::signed64(wire::get(p, 80, 8));
    d.systemErrno = static_cast<int32_t>(wire::get(p, 88, 4)); d.phase = wire::get(p, 92, 4);
    d.capabilities = wire::get(p, 96, 8); d.revision = wire::get(p, 104, 8);
    d.count = wire::get(p, 112, 4); d.schema = wire::get(p, 116, 4);
    d.managementStatus = static_cast<int32_t>(wire::get(p, 120, 4));
    d.managementEffects = wire::get(p, 124, 4); d.managementResult = wire::get(p, 128, 8);
    d.managementCommand = wire::get(p, 136, 4); d.managementCompleted = wire::get(p, 140, 4);
    d.managementHasHandle = wire::get(p, 144, 4); d.reserved = wire::get(p, 148, 4);
    r.recordCount = wire::get(p, 152, 4); r.primaryErrno = static_cast<int32_t>(wire::get(p, 156, 4));
    if (!code_valid(r.resultCode) || !code_valid(d.code) || !step_valid(r.root) ||
        !step_valid(r.read) || !step_valid(r.close) || !r.root.completed || !r.close.completed ||
        r.read.completed != (r.root.code == 0) || (r.authMode != 0 && r.authMode != 1 && r.authMode != 3) ||
        d.phase > 10 || d.managementCompleted > 1 || d.managementHasHandle > 1 || d.reserved)
        return false;
    if ((!d.phase && (d.code || d.systemErrno || d.capabilities || d.revision || d.count || d.schema)) ||
        (d.phase == 10 && (d.code || d.systemErrno)) || (!r.resultCode && d.code) ||
        ((r.root.code || r.read.code) && r.recordCount)) return false;
    const auto code = r.root.code ? r.root.code : r.read.code ? r.read.code : r.close.code;
    const auto phase = r.root.code ? ReadPhase::Root : r.read.code ? ReadPhase::Read :
        r.close.code ? ReadPhase::Close : ReadPhase::None;
    const auto error_number = r.root.code ? r.root.systemErrno : r.read.code ? r.read.systemErrno :
        r.close.code ? r.close.systemErrno : 0;
    if (r.resultCode != code || r.primaryPhase != static_cast<uint32_t>(phase) || r.primaryErrno != error_number)
        return false;
    for (size_t offset = 160; offset < kReadResultBytes; ++offset) if (p[offset]) return false;
    output = r;
    return true;
}
} // namespace read_wire
} // namespace maplesu::su_auth
