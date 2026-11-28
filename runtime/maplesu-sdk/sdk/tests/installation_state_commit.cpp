// Real Mutation and POSIX directory I/O; gateway/lifetime/publication are fixtures.
#include "../src/maplesu/install/installation_state.h"
#include <cassert>
#include <cstdlib>
#include <filesystem>

namespace fs = std::filesystem;
namespace state = maplesu::install::state;
namespace {
constexpr char directory[] = "/data/ABCDEFGHIJKLMNOP";
constexpr char attribute[] = "user.maplesu.install.v1";
std::string scenario;
bool alive = true, failed = false, gateway_committed = false;
unsigned storage_after_failure = 0, commits = 0, gateway_reads = 0, writes = 0, syncs = 0;
kernel_module::RequestManagementReply reply;
state::Record changed;
state::Record committed_record;
void require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s: %s\n", scenario.c_str(), message); std::exit(1); }
}
}

extern "C" int __real_fsetxattr(int, const char*, const void*, size_t, int);
extern "C" ssize_t __real_fgetxattr(int, const char*, void*, size_t);
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
    require(!std::strcmp(name, state::kAttribute), "unexpected attribute write");
    ++writes;
    if ((scenario == "prewrite-failure" && writes == 1) ||
        (scenario == "compensate-write-failure" && writes == 2)) { errno = EIO; return -1; }
    return __real_fsetxattr(fd, attribute, value, size, flags);
}
extern "C" ssize_t __wrap_fgetxattr(int fd, const char* name, void* value, size_t size) {
    require(!std::strcmp(name, state::kAttribute), "unexpected attribute read");
    return __real_fgetxattr(fd, attribute, value, size);
}
extern "C" int __wrap_fsync(int fd) {
    ++syncs;
    if ((scenario == "sync-failure" && syncs == 1) ||
        (scenario == "compensate-sync-failure" && syncs == 2)) { errno = EIO; return -1; }
    return __real_fsync(fd);
}

namespace maplesu::storage {
KModErr current_kernel_directory(std::string& path) {
    if (failed) ++storage_after_failure;
    if (!alive) return KModErr::ERR_MODULE_ROOT_KEY;
    path = std::string(directory) + '/'; return KModErr::OK;
}
}
namespace kernel_module {
uint64_t maplesu_request_auth_state() { return 1; }
bool maplesu_request_owner_lifetime_capture(RequestOwnerLifetimeToken&) { return alive; }
bool maplesu_request_owner_lifetime_matches(const RequestOwnerLifetimeToken&) { return alive; }
RequestManagementReply maplesu_request_management_reply() { return reply; }
CleanupReceiptScope::CleanupReceiptScope() noexcept
    : saved_errno_(errno), saved_process_(getpid()), saved_reply_(reply) {}
CleanupReceiptScope::~CleanupReceiptScope() noexcept {
    if (saved_process_ == static_cast<uint64_t>(getpid())) { reply = saved_reply_; errno = saved_errno_; }
}
KModErr maplesu_request_owner_installation(uint64_t action, maplesu_installation_state_v3& value) {
    if (action == MAPLESU_INSTALLATION_READ) {
        ++gateway_reads;
        value = {};
        value.magic = MAPLESU_INSTALLATION_STATE_MAGIC;
        value.schema = MAPLESU_INSTALLATION_STATE_SCHEMA; value.bytes = sizeof(value);
        std::memcpy(value.name, "ABCDEFGHIJKLMNOP", 16);
        value.revision = 1;
        return KModErr::OK;
    }
    require(action == MAPLESU_INSTALLATION_COMMIT, "unexpected gateway mutation");
    ++commits;
    if (scenario == "success" || scenario == "gateway-unknown-committed" || scenario == "gateway-committed-error") {
        gateway_committed = true;
        std::memcpy(&committed_record, &value.record, sizeof(committed_record));
    }
    if (scenario == "success") {
        reply = {}; reply.completed = true; reply.effects = MAPLESU_EFFECT_COMMITTED;
        return KModErr::OK;
    }
    std::memcpy(&changed, &value.record, sizeof(changed));
    if (scenario == "changed-generation") changed.generation[0] ^= 0x7f;
    if (scenario == "changed-record") changed.attempt[0] = 1;
    if (scenario == "changed-generation" || scenario == "changed-record") {
        require(setxattr(directory, attribute, &changed, sizeof(changed), XATTR_REPLACE) == 0,
            "fixture replacing disk record");
    }
    if (scenario == "replaced-directory") {
        fs::rename(directory, std::string(directory) + "-previous");
        fs::create_directory(directory); chmod(directory, 0700);
        changed.generation[0] ^= 0x7f;
        require(setxattr(directory, attribute, &changed, sizeof(changed), XATTR_CREATE) == 0,
            "fixture replacing directory");
    }
    failed = true;
    alive = scenario == "gateway-kept-session";
    reply = {}; reply.completed = scenario != "gateway-unknown" && scenario != "gateway-unknown-committed";
    reply.status = reply.completed ? (scenario == "gateway-committed-error" ? -EIO : -EPERM) : 0;
    reply.effects = scenario == "gateway-committed-error" ? MAPLESU_EFFECT_COMMITTED : 0;
    errno = reply.completed ? -reply.status : EIO;
    return KModErr::ERR_MODULE_TEST_CHANNEL;
}
}

int main(int argc, char** argv) {
    assert(argc == 2 && geteuid() == 0);
    scenario = argv[1];
    fs::create_directories(directory); chmod(directory, 0700);
    state::Record initial;
    require(setxattr(directory, attribute, &initial, sizeof(initial), XATTR_CREATE) == 0,
        "fixture initial record");
    state::Mutation mutation;
    require(mutation.open().code == 0, "open production Mutation");
    errno = ENOTTY;
    const auto result = mutation.observe_version({maplesu::install::PublishErrorSource::None, 0,
        maplesu::install::PublishPhase::Complete, true});
    const int observed_errno = errno;
    state::Record disk;
    require(getxattr(directory, attribute, &disk, sizeof(disk)) == sizeof(disk), "read disk record");
    require(state::valid_record(disk), "disk record remains valid");
    require(observed_errno == ENOTTY, "caller errno preserved");
    if (scenario == "success") {
        require(!result.code && result.applied && disk.active && commits == 1, "successful commit preserved");
    } else if (scenario == "prewrite-failure") {
        require(result.code == EIO && result.phase == state::Phase::Write && !result.applied &&
            !commits && std::memcmp(&initial, &disk, sizeof(disk)) == 0, "prewrite failure leaves disk untouched");
    } else {
        const bool sync_failure = scenario == "sync-failure";
        const bool unknown_commit = scenario == "gateway-unknown" || scenario == "gateway-unknown-committed";
        const bool committed_error = scenario == "gateway-committed-error";
        const int64_t expected = sync_failure || committed_error ? EIO : unknown_commit ?
            static_cast<int64_t>(KModErr::ERR_MODULE_TEST_CHANNEL) : EPERM;
        require(result.code == expected && result.applied && result.phase ==
            (sync_failure ? state::Phase::Sync : state::Phase::Gateway), "original failure preserved");
        require(commits == (sync_failure ? 0u : 1u), "no repeated gateway commit");
        if (scenario == "changed-generation" || scenario == "changed-record" || scenario == "replaced-directory") {
            require(std::memcmp(&changed, &disk, sizeof(disk)) == 0, "different publication remains untouched");
            if (scenario == "replaced-directory") {
                state::Record previous;
                require(getxattr((std::string(directory) + "-previous").c_str(), attribute,
                    &previous, sizeof(previous)) == sizeof(previous) && previous.active,
                    "replaced directory's old inode remains untouched");
            }
        } else if (unknown_commit || committed_error) {
            require(disk.active && writes == 1, "uncertain or committed generation stays intact pending reconciliation");
            if (gateway_committed) require(std::memcmp(&committed_record, &disk, sizeof(disk)) == 0,
                "lost response does not invalidate committed helper generation");
        } else if (scenario == "compensate-write-failure") {
            require(disk.active && writes == 2, "failed retirement remains a reported failure");
        } else {
            require(!disk.active && disk.version_published && state::nonzero(disk.generation),
                "own failed generation retired while preserving published version fact");
        }
        require(!storage_after_failure, "cleanup does not reacquire failed storage session");
        require(alive == (sync_failure || scenario == "gateway-kept-session"), "cleanup grants no session");
        if (!sync_failure) require(reply.completed == !unknown_commit &&
            reply.status == (reply.completed ? (committed_error ? -EIO : -EPERM) : 0) &&
            reply.effects == (committed_error ? MAPLESU_EFFECT_COMMITTED : 0), "original gateway receipt preserved");
    }
    require(gateway_reads == 1, "cleanup neither queries nor replays the original command");
    std::printf("INSTALLATION_STATE_RESULT %s code=%lld phase=%u applied=%u initialActive=%u diskActive=%u "
        "receiptCompleted=%u receiptStatus=%lld receiptEffects=%u gatewayCommitted=%u commits=%u reads=%u writes=%u syncs=%u\n",
        scenario.c_str(), static_cast<long long>(result.code), static_cast<unsigned>(result.phase),
        result.applied ? 1u : 0u, initial.active, disk.active, reply.completed ? 1u : 0u,
        static_cast<long long>(reply.status), reply.effects, gateway_committed ? 1u : 0u,
        commits, gateway_reads, writes, syncs);
    std::printf("INSTALLATION_STATE_PASS %s gateway=fixture publication=fixture posix=real\n", scenario.c_str());
}
