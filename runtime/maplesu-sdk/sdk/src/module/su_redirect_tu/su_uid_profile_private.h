// Private full-UID authorization; the public MapleSU package ABI stays unchanged.
#pragma once
#include "su_auth_result_private.h"
#include "su_uid_read_result_private.h"

namespace maplesu::su_auth {
struct UidProfileV1 {
    uint32_t uid = 0;
    uint32_t allow = 0;
    char package[256]{};
};
static_assert(sizeof(UidProfileV1) == 264);

KModErr set_uid_profile(uint32_t uid, const char* package,
                       bool allow, ResultV1& result);
KModErr get_uid_profiles_with_cb(void (*callback)(const UidProfileV1*));
KModErr get_uid_profiles_with_cb(void (*callback)(const UidProfileV1*), ReadResultV1& result);
namespace detail {
// Raw records share the existing atomic su_allowlist file. No second authority.
KModErr replace_uid_profile(std::vector<std::string>& raw, uint32_t uid,
                           const char* package, bool allow);
KModErr replace_legacy_uid_profile(std::vector<std::string>& raw, const char* package, bool allow);
KModErr collect_uid_profiles(const std::vector<std::string>& raw, std::vector<UidProfileV1>& profiles);
KModErr sdk_set_uid_profile(uint32_t uid, const char* package, bool allow, ResultV1& result);
KModErr sdk_get_uid_profiles(void (*callback)(const UidProfileV1*));
KModErr sdk_refresh_uid_profiles(ResultV1& result);
KModErr transact_set_uid_profile(uint32_t uid, const char* package, bool allow, ResultV1& result);
KModErr transact_get_uid_profiles(void (*callback)(const UidProfileV1*));
}
}
