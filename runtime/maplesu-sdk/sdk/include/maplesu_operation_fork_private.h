#pragma once

#include "maplesu_operation_wait_private.h"

extern "C" __attribute__((weak, visibility("hidden"))) bool maplesu_hook_try_fork_prepare() noexcept;
extern "C" __attribute__((weak, visibility("hidden"))) void maplesu_hook_fork_complete() noexcept;
extern "C" __attribute__((weak, visibility("hidden"))) bool maplesu_request_try_fork_prepare() noexcept;
extern "C" __attribute__((weak, visibility("hidden"))) void maplesu_request_fork_complete() noexcept;

namespace maplesu::deadline {

// The same ordering is used by the Manager wrapper and the libc atfork hooks.
// Weak references retain standalone transport fixtures and older private links;
// current m023/m029 supply the real gates in the composed SDK.
class ForkAdmission final {
public:
    bool prepare() noexcept {
        if (!available()) return false;
        if (!maplesu_request_operation_deadline_nanos()) return true;
        if (maplesu_hook_try_fork_prepare && maplesu_hook_fork_complete) {
            if (!maplesu_hook_try_fork_prepare()) return false;
            publication_ = true;
        }
        if (maplesu_request_try_fork_prepare && maplesu_request_fork_complete) {
            if (!maplesu_request_try_fork_prepare()) return false;
            managed_ = true;
        }
        return available();
    }
    void complete() noexcept {
        const int error = errno;
        if (managed_) { managed_ = false; maplesu_request_fork_complete(); }
        if (publication_) { publication_ = false; maplesu_hook_fork_complete(); }
        errno = error;
    }
    ~ForkAdmission() { complete(); }
private:
    bool publication_ = false;
    bool managed_ = false;
};

} // namespace maplesu::deadline
