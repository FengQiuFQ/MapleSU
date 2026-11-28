#pragma once

#include "maplesu_sdk/maplesu_su_auth.h"
#include "maplesu/compat/legacy_sdk_abi.h"
#include <vector>

namespace skroot_env {
static_assert(sizeof(su_auth_item) == 256 && alignof(su_auth_item) == 1);

KModErr get_su_auth_list_with_cb(void (*callback)(const su_auth_item*));
KModErr add_su_auth_list(const char* app_package_name);
KModErr remove_su_auth_list(const char* app_package_name);
KModErr clear_su_auth_list();
}  // namespace skroot_env
