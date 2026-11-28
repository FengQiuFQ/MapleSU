#pragma once

#include <stdint.h>

// Private observation scope. Zero retains the caller's existing unbounded API
// contract; positive values are absolute CLOCK_MONOTONIC nanoseconds. The setter
// returns the exact previous thread-local value so nested scopes can restore it.
#ifdef __cplusplus
extern "C" {
#define MAPLESU_DEADLINE_NOEXCEPT noexcept
#else
#define MAPLESU_DEADLINE_NOEXCEPT
#endif

__attribute__((visibility("hidden"))) int64_t
maplesu_request_operation_deadline_nanos(void) MAPLESU_DEADLINE_NOEXCEPT;
__attribute__((visibility("hidden"))) int64_t
maplesu_request_set_operation_deadline_nanos(int64_t deadline_nanos) MAPLESU_DEADLINE_NOEXCEPT;

#ifdef __cplusplus
}
#endif
#undef MAPLESU_DEADLINE_NOEXCEPT
