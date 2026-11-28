// Keep the real deadline scope while each worker fixture owns its OS fault
// wrappers. Unused bridge transport sections are removed at link time.
#define __wrap_fork unused_bridge_wrap_fork
#define __wrap_pipe2 unused_bridge_wrap_pipe2
#define __wrap_waitpid unused_bridge_wrap_waitpid
#define __wrap_close unused_bridge_wrap_close
#include "../ultra/bridge/sdk_call_scope.cpp"

#if !defined(FIXTURE_REAL_REQUEST_TLS)
namespace { thread_local int64_t fixture_operation_deadline = 0; }
extern "C" int64_t maplesu_request_operation_deadline_nanos() noexcept {
    return fixture_operation_deadline;
}
extern "C" int64_t maplesu_request_set_operation_deadline_nanos(int64_t value) noexcept {
    const auto previous = fixture_operation_deadline;
    fixture_operation_deadline = value;
    return previous;
}
#endif
