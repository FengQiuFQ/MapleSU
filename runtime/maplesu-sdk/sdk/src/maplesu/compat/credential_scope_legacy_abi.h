#pragma once

#include "maplesu_request_private.h"
#include <array>
#include <cstring>
#include <unistd.h>

extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);

namespace maplesu::compat {
class __attribute__((visibility("hidden"))) LegacyCredentialScope final {
public:
    explicit LegacyCredentialScope(const char* key) : process_(getpid()) {
        using namespace kernel_module;
        const auto state = maplesu_request_auth_state();
        if (!maplesu_request_auth_usable(state)) {
            error_ = KModErr::ERR_MODULE_TEST_CHANNEL;
            return;
        }
        previous_ = maplesu_request_auth_mode(state);
        if (previous_ == RequestAuthMode::LegacyKey) {
            const auto* old = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
            if (old) std::strncpy(previous_key_.data(), old, previous_key_.size() - 1);
        }
        error_ = maplesu_request_select_legacy(key);
        active_ = is_ok(error_);
    }
    ~LegacyCredentialScope() { (void)restore(); erase(); }
    LegacyCredentialScope(const LegacyCredentialScope&) = delete;
    LegacyCredentialScope& operator=(const LegacyCredentialScope&) = delete;
    KModErr error() const { return error_; }
    KModErr restore() {
        if (!active_) return KModErr::OK;
        active_ = false;
        if (process_ != getpid()) return KModErr::ERR_MODULE_ROOT_KEY;
        using namespace kernel_module;
        CleanupReceiptScope diagnostic;
        const auto closed = maplesu_request_owner_close();
        maplesu_request_clear_legacy();
        const auto restored = maplesu_request_set_auth_mode(previous_);
        if (is_ok(restored) && previous_ == RequestAuthMode::LegacyKey)
            __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(previous_key_.data());
        erase();
        return is_failed(closed) ? closed : restored;
    }
    KModErr finish(KModErr result) {
        const auto restored = restore();
        return is_failed(result) ? result : restored;
    }
private:
    void erase() {
        volatile char* bytes = previous_key_.data();
        for (size_t i = 0; i < previous_key_.size(); ++i) bytes[i] = 0;
    }
    std::array<char, 1024> previous_key_{};
    kernel_module::RequestAuthMode previous_ = kernel_module::RequestAuthMode::ManagerOwner;
    KModErr error_ = KModErr::OK;
    pid_t process_;
    bool active_ = false;
};

template <class Operation> KModErr legacy_call(const char* key, Operation&& operation) {
    LegacyCredentialScope scope(key);
    if (is_failed(scope.error())) return scope.error();
    return scope.finish(operation());
}
}
