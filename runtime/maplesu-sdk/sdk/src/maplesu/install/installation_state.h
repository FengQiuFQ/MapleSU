#pragma once

#include "maplesu_storage_private.h"
#include "executable_publish_result.h"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/random.h>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#pragma GCC visibility push(hidden)
namespace maplesu::install::state {
// Private disk metadata, not an authenticated gateway response or a Ready bit.
// trusted.* adds no visible state file and leaves existing path/permission formats intact.
struct ErrnoGuard {
    int saved = errno;
    ~ErrnoGuard() { errno = saved; }
};
constexpr const char* kAttribute = "trusted.maplesu.install.v1";
enum class Phase : uint32_t { None, Storage, Open, Stat, Owner, Lock, Read, Validate, Random, Write, Sync, Identity, Gateway };
struct Result { int64_t code = 0; Phase phase = Phase::None; bool applied = false; };
struct VendorStage { uint32_t flags = 0, reserved = 0; int64_t code = 0; };
constexpr uint32_t kAttempted = 1, kCompleted = 2, kDiscarded = 4, kControlsNext = 8;
struct Record {
    uint32_t magic = 0x5349534d;
    uint16_t schema = 1, bytes = 160;
    uint32_t active = 0, reserved = 0;
    uint8_t generation[16]{};
    uint8_t attempt[16]{};
    char boot[40]{};
    VendorStage stages[3]{};
    uint32_t publication_source = 0, publication_phase = 0;
    int64_t publication_code = 0;
    uint32_t version_published = 0, publication_reserved = 0;
};
// This conservative deletion fence grants no authority. Legacy callers leave
// a possibly live host-owned generation intact until authenticated retirement.
struct HostGuard {
    uint32_t magic;
    uint16_t schema, bytes;
    maplesu_host_instance host;
    uint8_t generation[16];
    uint32_t active, reserved;
    char boot[40];
};
static_assert(sizeof(HostGuard) == 88);
static_assert(sizeof(Record) == 160 && offsetof(Record, generation) == 16 &&
              offsetof(Record, stages) == 88 && offsetof(Record, publication_code) == 144);

inline bool mutation_open_failed(Result result) {
    // A missing legacy directory or unsupported tracking leaves the old path intact.
    return result.code && !(result.phase == Phase::Open && result.code == ENOENT) &&
        !(result.phase == Phase::Read && result.code == EOPNOTSUPP);
}
inline bool nonzero(const uint8_t* bytes) {
    uint8_t value = 0;
    for (unsigned i = 0; i < 16; ++i) value |= bytes[i];
    return value != 0;
}
inline bool valid_record(const Record& value) {
    if (value.magic != 0x5349534d || value.schema != 1 || value.bytes != sizeof(Record) ||
        value.active > 1 || value.reserved || value.publication_reserved ||
        value.publication_source > static_cast<uint32_t>(PublishErrorSource::Condition) ||
        value.publication_phase > static_cast<uint32_t>(PublishPhase::Complete) ||
        value.version_published > 1 || (value.active && (!nonzero(value.generation) ||
        value.publication_source != 0 || !value.version_published ||
        value.publication_phase != static_cast<uint32_t>(PublishPhase::Complete) || value.publication_code))) return false;
    for (const auto& stage : value.stages)
        if (stage.reserved || (stage.flags & ~15u) ||
            ((stage.flags & kCompleted) && !(stage.flags & kAttempted))) return false;
    return true;
}
inline bool valid_boot(const char* boot) {
    if (!boot || strnlen(boot, 37) != 36) return false;
    for (unsigned i = 0; i < 36; ++i) {
        const char c = boot[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != '-') return false; }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}
inline Result random_id(uint8_t (&out)[16]) {
    size_t done = 0;
    while (done < sizeof(out)) {
        const long count = syscall(SYS_getrandom, out + done, sizeof(out) - done, GRND_NONBLOCK);
        if (count < 0) { if (errno == EINTR) continue; return {errno, Phase::Random, false}; }
        if (!count) return {EIO, Phase::Random, false};
        done += static_cast<size_t>(count);
    }
    return nonzero(out) ? Result{} : Result{EIO, Phase::Random, false};
}
inline void diagnose(const char* operation, Result result) {
    ErrnoGuard restore;
    if (result.code) std::fprintf(stderr, "MapleSU installation-state %s phase=%u code=%lld applied=%u\n",
        operation, static_cast<unsigned>(result.phase), static_cast<long long>(result.code), result.applied ? 1u : 0u);
}

class Mutation final {
public:
    Mutation() = default;
    ~Mutation() { close(); }
    Mutation(const Mutation&) = delete;
    Mutation& operator=(const Mutation&) = delete;
    Result open() { return open_directory(nullptr); }
    Result open_vendor(const maplesu_installation_state_v3& value) {
        if (value.magic != MAPLESU_INSTALLATION_STATE_MAGIC ||
            value.schema != MAPLESU_INSTALLATION_STATE_SCHEMA || value.bytes != sizeof(value))
            return {EINVAL, Phase::Validate, false};
        // Check the helper's last accepted snapshot before any disk mutation.
        if (!kernel_module::maplesu_request_helper_vendor_matches(value))
            return {ESTALE, Phase::Identity, false};
        const std::string path = std::string("/data/") +
            std::string(reinterpret_cast<const char*>(value.name), sizeof(value.name));
        return open_directory(path.c_str(), true);
    }
    Result open_retired(const std::string& path) {
        // Only the existing /data retirement enumeration supplies this path.
        if (path.compare(0, 6, "/data/") || path.find('/', 6) != std::string::npos || path.size() <= 6)
            return {EINVAL, Phase::Validate, false};
        return open_directory(path.c_str());
    }
private:
    Result open_directory(const char* retired_path, bool vendor_path = false) {
        ErrnoGuard restore;
        close();
        auth_ = kernel_module::maplesu_request_auth_state();
        process_ = getpid();
        std::string path;
        if (vendor_path) { path = retired_path; vendor_scope_ = true; }
        else {
            const auto error = storage::current_kernel_directory(path);
            if (error != KModErr::OK) return {static_cast<int64_t>(error), Phase::Storage, false};
        }
        if (path.empty()) return {EINVAL, Phase::Storage, false};
        if (auth_ != kernel_module::maplesu_request_auth_state()) return {ESTALE, Phase::Identity, false};
        if (!vendor_scope_ && (auth_ & 1) && !kernel_module::maplesu_request_owner_lifetime_capture(lifetime_))
            return {ESTALE, Phase::Identity, false};
        // Strip the final slash so O_NOFOLLOW also protects the directory itself.
        while (path.size() > 1 && path.back() == '/') path.pop_back();
        scope_path_ = path;
        path_ = retired_path ? retired_path : path;
        directory_ = ::open(path_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory_ < 0) return {errno, Phase::Open, false};
        struct stat st{};
        if (fstat(directory_, &st) != 0) return fail(errno, Phase::Stat);
        if (!S_ISDIR(st.st_mode) || st.st_uid != 0) return fail(EPERM, Phase::Owner);
        while (flock(directory_, LOCK_EX | LOCK_NB) != 0) {
            if (errno != EINTR) return fail(errno, Phase::Lock);
        }
        device_ = st.st_dev; inode_ = st.st_ino;
        if (!vendor_scope_ && !(auth_ & 1)) {
            HostGuard guard{};
            const ssize_t count = fgetxattr(directory_, "trusted.maplesu.install.host.v1", &guard, sizeof(guard));
            if (count >= 0) {
                if (count != sizeof(guard) || guard.magic != 0x4749534d || guard.schema != 2 ||
                    guard.bytes != sizeof(guard) || guard.reserved || guard.active > 1 ||
                    !valid_boot(guard.boot) || guard.boot[36] || guard.boot[37] || guard.boot[38] || guard.boot[39])
                    return fail(EBADMSG, Phase::Validate);
                if (guard.active) {
                    char current_boot[40]{};
                    FILE* boot_file = fopen("/proc/sys/kernel/random/boot_id", "r");
                    if (!boot_file) return fail(errno, Phase::Read);
                    const bool read = fgets(current_boot, sizeof(current_boot), boot_file) &&
                        std::strlen(current_boot) == 37 && current_boot[36] == '\n';
                    const int read_error = errno;
                    const int closed = fclose(boot_file);
                    if (!read || closed) return fail(closed ? errno : read_error ? read_error : EIO, Phase::Read);
                    current_boot[36] = 0;
                    if (!valid_boot(current_boot)) return fail(EBADMSG, Phase::Validate);
                    // Boot-owned references ended before a different boot. This is not identity.
                    if (!std::memcmp(current_boot, guard.boot, sizeof(current_boot)))
                        return fail(EBUSY, Phase::Gateway);
                }
            } else if (errno != ENODATA && errno != EOPNOTSUPP) return fail(errno, Phase::Read);
        }
        const ssize_t size = fgetxattr(directory_, kAttribute, &record_, sizeof(record_));
        if (size < 0) {
            if (errno == ENODATA) { record_ = {}; ready_ = true; return capture_gateway(); }
            return fail(errno, Phase::Read);
        }
        if (size != sizeof(record_) || !valid_record(record_)) return fail(EBADMSG, Phase::Validate);
        present_ = true; ready_ = true;
        return capture_gateway();
    }
    Result capture_gateway() {
        if (vendor_scope_ || !(auth_ & 1) || path_ != scope_path_) return {};
        const auto result = kernel_module::maplesu_request_owner_installation(
            MAPLESU_INSTALLATION_READ, gateway_);
        if (result != KModErr::OK) {
            const auto receipt = kernel_module::maplesu_request_management_reply();
            return fail(receipt.completed && receipt.status < 0 ? -receipt.status :
                static_cast<int64_t>(result), Phase::Gateway);
        }
        const std::string expected = std::string("/data/") +
            std::string(reinterpret_cast<const char*>(gateway_.name), sizeof(gateway_.name));
        if (scope_path_ != expected) return fail(ESTALE, Phase::Identity);
        authenticated_ = true;
        return {};
    }
public:
    void close() {
        ErrnoGuard restore;
        if (directory_ >= 0) { (void)flock(directory_, LOCK_UN); (void)::close(directory_); }
        directory_ = -1; present_ = ready_ = false; record_ = {};
        lifetime_ = {}; path_.clear(); scope_path_.clear();
        authenticated_ = vendor_scope_ = false; gateway_ = {};
    }
    bool ready() const { return ready_; }
    bool active() const { return ready_ && present_ && record_.active; }
    bool revocation_required() const { return active() ||
        (authenticated_ && (gateway_.record.active || gateway_.flags)); }
    const Record& record() const { return record_; }
    dev_t device() const { return device_; }
    ino_t inode() const { return inode_; }
    Result revoke() {
        ErrnoGuard restore;
        if (!ready_) return {EBADF, Phase::Open, false};
        if (!active() && !authenticated_) return {};
        if (authenticated_ && (gateway_.record.active || gateway_.flags)) {
            const auto result = kernel_module::maplesu_request_owner_installation(
                MAPLESU_INSTALLATION_REVOKE, gateway_);
            const auto receipt = kernel_module::maplesu_request_management_reply();
            if (result != KModErr::OK) return {receipt.completed && receipt.status < 0 ?
                -receipt.status : static_cast<int64_t>(result), Phase::Gateway,
                receipt.completed && (receipt.effects & MAPLESU_EFFECT_COMMITTED)};
            const auto read = kernel_module::maplesu_request_owner_installation(MAPLESU_INSTALLATION_READ, gateway_);
            if (read != KModErr::OK) return {static_cast<int64_t>(read), Phase::Gateway, true};
        }
        if (!active()) return {};
        auto next = record_; next.active = 0;
        return replace(next);
    }
    Result observe_version(const PublishResult& publication) {
        ErrnoGuard restore;
        if (!ready_) return {EBADF, Phase::Open, false};
        auto next = record_;
        next.active = 0;
        next.publication_source = static_cast<uint32_t>(publication.source);
        next.publication_phase = static_cast<uint32_t>(publication.phase);
        next.publication_code = publication.code;
        next.version_published = publication.published ? 1u : 0u;
        if (publication.source == PublishErrorSource::None && publication.published) {
            const auto random = random_id(next.generation);
            if (random.code) return random;
            if (std::memcmp(next.generation, record_.generation, 16) == 0)
                return {EEXIST, Phase::Random, false};
            next.active = 1;
            std::memset(next.attempt, 0, sizeof(next.attempt));
            std::memset(next.boot, 0, sizeof(next.boot));
            for (auto& stage : next.stages) stage = {};
        }
        const auto observed = replace(next);
        if (!observed.code || !authenticated_ || !observed.applied || !next.active) return observed;
        if (observed.phase == Phase::Gateway) {
            const auto reply = kernel_module::maplesu_request_management_reply();
            // An unknown or applied COMMIT is reconciled through its original
            // task. Retiring its disk generation could invalidate a live helper.
            if (!reply.completed || (reply.effects & MAPLESU_EFFECT_COMMITTED)) return observed;
        }
        // Retire only this known failed publication, retaining its original
        // command receipt, published-version fact and error.
        kernel_module::CleanupReceiptScope receipt;
        diagnose("commit-compensate", retire_publication(next));
        return observed;
    }
    Result replace(const Record& next) {
        ErrnoGuard restore;
        if (!ready_) return {EBADF, Phase::Open, false};
        if (!valid_record(next)) return {EBADMSG, Phase::Validate, false};
        std::string current;
        if (vendor_scope_) current = scope_path_;
        else {
            const auto context_error = storage::current_kernel_directory(current);
            if (context_error != KModErr::OK) return {static_cast<int64_t>(context_error), Phase::Storage, false};
        }
        while (current.size() > 1 && current.back() == '/') current.pop_back();
        if (getpid() != process_ || auth_ != kernel_module::maplesu_request_auth_state() || current != scope_path_ ||
            (!vendor_scope_ && (auth_ & 1) && !kernel_module::maplesu_request_owner_lifetime_matches(lifetime_)))
            return {ESTALE, Phase::Identity, false};
        struct stat current_stat{};
        if (lstat(path_.c_str(), &current_stat) != 0) return {errno, Phase::Stat, false};
        if (!S_ISDIR(current_stat.st_mode) || current_stat.st_dev != device_ || current_stat.st_ino != inode_)
            return {ESTALE, Phase::Identity, false};
        if (fsetxattr(directory_, kAttribute, &next, sizeof(next), present_ ? XATTR_REPLACE : XATTR_CREATE) != 0)
            return {errno, Phase::Write, false};
        record_ = next; present_ = true;
        if (fsync(directory_) != 0) return {errno, Phase::Sync, true};
        if (authenticated_ && next.active &&
            std::memcmp(next.generation, gateway_.record.generation, 16)) {
            gateway_.device = static_cast<uint64_t>(device_);
            gateway_.inode = static_cast<uint64_t>(inode_);
            std::memcpy(&gateway_.record, &next, sizeof(next));
            const auto sent = kernel_module::maplesu_request_owner_installation(MAPLESU_INSTALLATION_COMMIT, gateway_);
            if (sent != KModErr::OK) {
                const auto receipt = kernel_module::maplesu_request_management_reply();
                return {receipt.completed && receipt.status < 0 ? -receipt.status :
                    static_cast<int64_t>(sent), Phase::Gateway, true};
            }
        }
        return {0, Phase::None, true};
    }
private:
    Result retire_publication(const Record& expected) {
        ErrnoGuard restore;
        // A failed gateway may invalidate the session. Cleanup owns only this
        // still-locked inode and the exact record this Mutation just published.
        if (!ready_ || directory_ < 0) return {EBADF, Phase::Open, false};
        if (getpid() != process_ || !present_ || !expected.active ||
            std::memcmp(&record_, &expected, sizeof(expected)))
            return {ESTALE, Phase::Identity, false};
        struct stat held{}, current{};
        if (fstat(directory_, &held) != 0 || lstat(path_.c_str(), &current) != 0)
            return {errno, Phase::Stat, false};
        if (!S_ISDIR(held.st_mode) || held.st_uid != 0 ||
            held.st_dev != device_ || held.st_ino != inode_ ||
            !S_ISDIR(current.st_mode) || current.st_dev != device_ || current.st_ino != inode_)
            return {ESTALE, Phase::Identity, false};
        Record disk{};
        const ssize_t size = fgetxattr(directory_, kAttribute, &disk, sizeof(disk));
        if (size < 0) return {errno, Phase::Read, false};
        if (size != sizeof(disk) || std::memcmp(&disk, &expected, sizeof(disk)))
            return {ESTALE, Phase::Identity, false};
        auto inactive = expected;
        inactive.active = 0;
        if (fsetxattr(directory_, kAttribute, &inactive, sizeof(inactive), XATTR_REPLACE) != 0)
            return {errno, Phase::Write, false};
        record_ = inactive;
        if (fsync(directory_) != 0) return {errno, Phase::Sync, true};
        return {0, Phase::None, true};
    }
    Result fail(int error, Phase phase) { close(); return {error, phase, false}; }
    int directory_ = -1;
    bool present_ = false, ready_ = false;
    dev_t device_ = 0;
    ino_t inode_ = 0;
    Record record_{};
    std::string path_, scope_path_;
    pid_t process_ = 0;
    uint64_t auth_ = 0;
    kernel_module::RequestOwnerLifetimeToken lifetime_{};
    bool authenticated_ = false, vendor_scope_ = false;
    maplesu_installation_state_v3 gateway_{};
};

class VendorAttempt final {
public:
    Result begin(const char* boot) {
        ErrnoGuard restore;
        selected_ = false;
        if (!valid_boot(boot)) return {EINVAL, Phase::Identity, false};
        const auto enrolled = kernel_module::maplesu_request_helper_vendor(MAPLESU_INSTALLATION_READ, 0, gateway_);
        if (enrolled != KModErr::OK) {
            const auto receipt = kernel_module::maplesu_request_management_reply();
            return {receipt.completed && receipt.status < 0 ? -receipt.status :
                static_cast<int64_t>(enrolled), Phase::Gateway,
                receipt.completed && (receipt.effects & MAPLESU_EFFECT_COMMITTED)};
        }
        Mutation mutation;
        auto result = mutation.open_vendor(gateway_);
        if (result.code) return result;
        if (!gateway_.record.active || gateway_.device != static_cast<uint64_t>(mutation.device()) ||
            gateway_.inode != static_cast<uint64_t>(mutation.inode()) ||
            std::memcmp(gateway_.record.generation, mutation.record().generation, 16))
            return {ESTALE, Phase::Identity, false};
        auto next = mutation.record();
        result = random_id(next.attempt);
        if (result.code) return result;
        std::memset(next.boot, 0, sizeof(next.boot));
        std::memcpy(next.boot, boot, 36);
        for (auto& stage : next.stages) stage = {};
        result = mutation.replace(next);
        if (result.code) return result;
        std::memcpy(&gateway_.record, &next, sizeof(next));
        const auto sent = kernel_module::maplesu_request_helper_vendor(MAPLESU_VENDOR_BEGIN, 0, gateway_);
        if (sent != KModErr::OK) {
            const auto receipt = kernel_module::maplesu_request_management_reply();
            return {receipt.completed && receipt.status < 0 ? -receipt.status :
                static_cast<int64_t>(sent), Phase::Gateway, true};
        }
        snapshot_ = next; device_ = mutation.device(); inode_ = mutation.inode(); selected_ = true;
        return result;
    }
    Result before(unsigned index) { return mark(index, false, 0); }
    Result complete(unsigned index, int64_t code) { return mark(index, true, code); }
private:
    Result mark(unsigned index, bool completed, int64_t code) {
        ErrnoGuard restore;
        if (!selected_) return {};
        if (index >= 3) return {EINVAL, Phase::Validate, false};
        Mutation mutation;
        auto result = mutation.open_vendor(gateway_);
        if (result.code) return result;
        const auto& current = mutation.record();
        if (!mutation.active() || mutation.device() != device_ || mutation.inode() != inode_ ||
            std::memcmp(current.generation, snapshot_.generation, 16) ||
            std::memcmp(current.attempt, snapshot_.attempt, 16) ||
            std::memcmp(current.boot, snapshot_.boot, sizeof(current.boot))) {
            selected_ = false;
            return {ESTALE, Phase::Identity, false};
        }
        auto next = current;
        auto& stage = next.stages[index];
        stage.flags = kAttempted | (completed ? kCompleted : 0u) |
            (index < 2 ? kControlsNext : kDiscarded);
        stage.code = completed ? code : 0;
        result = mutation.replace(next);
        if (result.code) { selected_ = false; return result; }
        std::memcpy(&gateway_.record, &next, sizeof(next));
        const auto sent = kernel_module::maplesu_request_helper_vendor(
            completed ? MAPLESU_VENDOR_COMPLETE : MAPLESU_VENDOR_BEFORE, index, gateway_);
        if (sent != KModErr::OK) {
            selected_ = false;
            const auto receipt = kernel_module::maplesu_request_management_reply();
            return {receipt.completed && receipt.status < 0 ? -receipt.status :
                static_cast<int64_t>(sent), Phase::Gateway, true};
        }
        return result;
    }
    bool selected_ = false;
    dev_t device_ = 0;
    ino_t inode_ = 0;
    Record snapshot_{};
    maplesu_installation_state_v3 gateway_{};
};
} // namespace maplesu::install::state
#pragma GCC visibility pop
