#include "maplesu_deadline_private.h"
#include "maplesu/compat/fork_legacy_abi.h"
#include <sys/wait.h>
static uint32_t expire_on_command;
// EXACT_TRANSPORT_FIXTURE_PREFIX

int main() {
    using namespace kernel_module;
    reset();
    maplesu_request_set_operation_deadline_nanos(1);
    maplesu_metadata_owner_v3 m{};
    uint64_t address = 0;
    RequestOwnerBinding binding{};
    errno = 0;
    const auto expired = maplesu_request_owner_channel(m, address, binding);
    check(is_failed(expired) && errno == ETIMEDOUT && calls() == 0 && !owner_channel.ready,
        "expired current identity emits no QUERY/syscall and no current positive");
    maplesu_request_set_operation_deadline_nanos(0);

    reset();
    uint64_t allocated = 0;
    check(request_kernel_alloc_mem(8, allocated) == KModErr::OK,
        "open known session before expiring cleanup");
    const auto session = owner_management.session;
    const auto used = calls();
    management_reply = {0, MAPLESU_EFFECT_COMMITTED, 0, 0, MAPLESU_REQUEST_CRED_ROOT, true};
    maplesu_request_set_operation_deadline_nanos(1);
    errno = 0;
    {
        CleanupReceiptScope original;
        check(is_failed(maplesu_request_owner_close()) && errno == ETIMEDOUT &&
            calls() == used && state.calls[MAPLESU_REQUEST_SESSION_CLOSE] == 0 &&
            !management_reply.completed && owner_management.session == session && owner_management.uncertain,
            "expired CLOSE stays pending without submitting or inventing cleanup");
    }
    check(management_reply.completed && management_reply.command == MAPLESU_REQUEST_CRED_ROOT &&
        management_reply.effects == MAPLESU_EFFECT_COMMITTED,
        "cleanup scope keeps original committed Root receipt after expired CLOSE");
    maplesu_request_set_operation_deadline_nanos(0);
    close();

    reset();
    check(request_kernel_alloc_mem(8, allocated) == KModErr::OK, "open session before Root receipt");
    expire_on_command = MAPLESU_REQUEST_CRED_ROOT;
    errno = 0;
    const auto committed = maplesu_request_owner_root();
    const auto receipt = maplesu_request_management_reply();
    check(committed == KModErr::OK && receipt.completed && receipt.command == MAPLESU_REQUEST_CRED_ROOT &&
        receipt.effects == MAPLESU_EFFECT_COMMITTED && state.calls[MAPLESU_REQUEST_CRED_ROOT] == 1 &&
        maplesu_request_operation_deadline_nanos() == 1,
        "valid in-kernel Root completion survives deadline reached during syscall");
    expire_on_command = 0;
    maplesu_request_set_operation_deadline_nanos(0);
    close();

    reset();
    check(maplesu_request_set_auth_mode(RequestAuthMode::EarlyHelper) == KModErr::OK,
        "select actual Helper source before vendor frame ABI check");
    state.helper = true;
    state.fail_command = MAPLESU_REQUEST_VENDOR_STATE;
    state.status = -EACCES;
    maplesu_installation_state_v3 vendor{};
    errno = 0;
    check(is_failed(maplesu_request_helper_vendor(MAPLESU_INSTALLATION_READ, 0, vendor)) &&
        errno == EACCES && state.calls[MAPLESU_REQUEST_VENDOR_STATE] == 1 &&
        management_reply.completed && management_reply.command == MAPLESU_REQUEST_VENDOR_STATE &&
        management_reply.status == -EACCES,
        "real Helper vendor pointer frame returns original denial without replay");
    reset();
#ifndef MAPLESU_DEADLINE_BASELINE
    check(remember_managed_address(allocation, 8), "register real managed-address atfork hook");
    std::atomic<bool> locked{false}, release{false};
    std::thread holder([&] {
        pthread_mutex_lock(&managed_address_mutex);
        locked.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) std::this_thread::yield();
        pthread_mutex_unlock(&managed_address_mutex);
    });
    while (!locked.load(std::memory_order_acquire)) std::this_thread::yield();
    timespec current{};
    clock_gettime(CLOCK_MONOTONIC, &current);
    maplesu_request_set_operation_deadline_nanos(int64_t(current.tv_sec) * 1000000000 +
        current.tv_nsec + 500000000);
    maplesu::sdk::fork_pipe_info blocked;
    errno = 0;
    const bool blocked_child = maplesu::sdk::fork_pipe_child_process(blocked);
    if (blocked_child) _exit(91);
    check(blocked.child_pid <= 0 && errno == EAGAIN && managed_address_fork_depth == 0,
        "live managed-address contention rejects once before raw fork");
    release.store(true, std::memory_order_release);
    holder.join();
    check(maplesu_request_try_fork_prepare() && maplesu_request_try_fork_prepare() &&
        managed_address_fork_depth == 2, "explicit nested fork admissions share one held mutex");
    maplesu::sdk::fork_pipe_info nested;
    if (maplesu::sdk::fork_pipe_child_process(nested)) {
        const bool inherited = managed_address_fork_depth == 2;
        maplesu_request_fork_complete(); maplesu_request_fork_complete();
        const bool unlocked = managed_address_fork_depth == 0 && !pthread_mutex_trylock(&managed_address_mutex);
        if (unlocked) pthread_mutex_unlock(&managed_address_mutex);
        _exit(inherited && unlocked ? 0 : 92);
    }
    check(nested.child_pid > 0 && managed_address_fork_depth == 2,
        "real libc atfork and SDK guards keep parent admission depths paired");
    maplesu_request_fork_complete(); maplesu_request_fork_complete();
    int status = 0;
    check(waitpid(nested.child_pid, &status, 0) == nested.child_pid &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0 && managed_address_fork_depth == 0,
        "fork child and parent each release all real managed gates");
    check(!pthread_mutex_trylock(&managed_address_mutex), "parent managed mutex is unlocked after nested fork");
    pthread_mutex_unlock(&managed_address_mutex);
    maplesu_request_set_operation_deadline_nanos(0);
#endif
    std::printf("PASS operation deadline dispatch: %u seam assertions; no device/kernel timing claim\n", checks.load());
}
