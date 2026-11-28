#pragma once

#include <cstdint>

namespace maplesu {
int64_t sdk_call_deadline_nanos() noexcept;

class SdkDeadlineScope final {
public:
    explicit SdkDeadlineScope(int64_t deadline_nanos) noexcept;
    ~SdkDeadlineScope();
    SdkDeadlineScope(const SdkDeadlineScope&) = delete;
    SdkDeadlineScope& operator=(const SdkDeadlineScope&) = delete;
private:
    int64_t previous_;
};

enum class SdkCallAccess { Local, Read, Exclusive, Isolated };
SdkCallAccess sdk_call_access(const char* operation);

struct SdkTransportOwner;
struct SdkCallContext {
    bool retry_interrupted_wait = true;
    bool owns_transport = true;
    int process_error = 0;
    int owner_pid = 0;
    SdkTransportOwner* transport_owner = nullptr;
};

struct SdkCallCompletion {
    int process_error = 0;
    int cleanup_error = 0;
    uint64_t owner_generation = 0;
    uint32_t pending_fds = 0;
    bool cleanup_pending = false;
    bool cleanup_scheduled = false;
    bool admission_release_pending = false;
};

// Known calls own their transport and conflict only on the resources they
// actually share. Unknown entries retain conservative exclusive admission.
// Isolated calls retain their own bounded worker/slot and real deadline.
class SdkCallScope final {
public:
    explicit SdkCallScope(const char* operation);
    ~SdkCallScope();
    bool acquired() const { return acquired_; }
    bool deadline_exceeded() const { return deadline_exceeded_; }
    int process_error() const { return context_.process_error; }
    SdkCallCompletion finalize() noexcept;
    SdkCallScope(const SdkCallScope&) = delete;
    SdkCallScope& operator=(const SdkCallScope&) = delete;
private:
    SdkCallAccess access_;
    unsigned read_mask_ = 0;
    unsigned write_mask_ = 0;
    bool owned_transport_ = false;
    bool acquired_ = false;
    bool deadline_exceeded_ = false;
    bool finalized_ = false;
    SdkCallContext context_;
    SdkCallContext* previous_call_ = nullptr;
};
}
