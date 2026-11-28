#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""从 `.research/{KernelSU,7kimisu}` 生成 7K 功能补丁序列（可 `git apply -p1`）。

生成方式（可复现，无网络）：
  1) 用 export_snapshot 同一套逻辑把两个仓库导出成 LF 字节树（临时目录）；
  2) 建临时 git 仓库，第 0 个提交 = upstream 快照；
  3) 逐个补丁把「目标文件内容」写到工作树 —— 新增文件直接取 7K 源（带路径改写），
     改动文件用唯一锚点插入/替换（锚点不唯一或缺失 → 立即失败，绝不写「差不多」的补丁）；
  4) `git diff HEAD --binary` 落成 `<patch>.patch`，然后 commit 进入下一阶段；
  5) 在干净目录里按 series 顺序 `git apply --check -p1 --whitespace=error-all` + 实际应用，
     复算树哈希必须等于第 3 步最终阶段。

设计立场（与 03 分册一致）：
  * 0001–0005、0009 落地为真实补丁；
  * 0006（webadmin）/0007（boot-patch 安全增强）/0008（restore-user-data）**不生成**
    假补丁，原因写进 manifest.todos（任务书允许 TODO 而非伪造）。
  * 0003 的 stealth 安全阀采用「root | 已认主」保守形态（7K 的「签名即放行」属
    产品决策 R2，需要 0005 的 signed-manager 链路，未落地）。

用法：
  python third_party/kernelsu/scripts/gen_patches.py [--research-root <dir>] [--keep]
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import ksu_common as C
from patch_defs_w18b import PATCHES_W18B
from patch_defs_w18b_boot import PATCHES_BOOT_COPY, PATCHES_EMPTY_RAMDISK_RESTORE, PATCHES_TARGET_KERNEL_KMI
from patch_defs_backup_optional import PATCHES_BACKUP_OPTIONAL
from patch_defs_normal_recovery import PATCHES_NORMAL_RECOVERY
from patch_defs_ksud_identity import PATCHES_KSUD_IDENTITY
from patch_defs_selinux_upstream import PATCHES_SELINUX_UPSTREAM, SUPERSEDED_PATCHES
from patch_defs_vivo import PATCHES_VIVO
from patch_defs_maplesu93260 import PATCHES_MAPLESU93260
from patch_defs_jailbreak_session import PATCHES_JAILBREAK_SESSION
from patch_defs_module_install_transaction import PATCHES_MODULE_INSTALL_TRANSACTION
from patch_defs_module_removal_transaction import PATCHES_MODULE_REMOVAL_TRANSACTION
from patch_defs_native_current_info import PATCHES_NATIVE_CURRENT_INFO

UPSTREAM = "upstream"
S7K = "source7k"
# 由 main() 在导出快照后赋值；patch_* 函数通过它读取 7K 源文件。
S7K_ROOT: Path = Path()


# ---------------------------------------------------------------- 工作树
class Tree:
    def __init__(self, root: Path):
        self.root = Path(root)

    def read(self, rel: str) -> str:
        return C.read_text(self.root / rel)

    def write(self, rel: str, text: str) -> None:
        C.write_text(self.root / rel, text)

    def read_from(self, other: "Tree", src_rel: str) -> str:
        return other.read(src_rel)

    def add_from(self, other: "Tree", src_rel: str, dst_rel: str | None = None,
                 replacements: list[tuple[str, str]] | None = None,
                 required: bool = True) -> None:
        text = other.read(src_rel)
        for old, new in replacements or []:
            if old not in text:
                if required:
                    raise C.KsuError(f"{src_rel}: 期望出现的片段不存在: {old!r}")
                continue
            text = text.replace(old, new)
        self.write(dst_rel or src_rel, text)

    def replace_once(self, rel: str, old: str, new: str) -> None:
        text = self.read(rel)
        n = text.count(old)
        if n != 1:
            raise C.KsuError(f"{rel}: 锚点出现 {n} 次（要求恰好 1 次）: {old[:80]!r}")
        self.write(rel, text.replace(old, new, 1))

    def replace_all(self, rel: str, old: str, new: str, count: int) -> None:
        text = self.read(rel)
        n = text.count(old)
        if n != count:
            raise C.KsuError(f"{rel}: 锚点出现 {n} 次（要求 {count} 次）: {old[:80]!r}")
        self.write(rel, text.replace(old, new))

    def insert_before(self, rel: str, anchor: str, text: str) -> None:
        self.replace_once(rel, anchor, text + anchor)

    def insert_after(self, rel: str, anchor: str, text: str) -> None:
        self.replace_once(rel, anchor, anchor + text)

    def append(self, rel: str, text: str) -> None:
        self.write(rel, self.read(rel) + text)


# ---------------------------------------------------------------- 0001
KSU_VERSION_PIN_SNIPPET = """\
#
# ── MapleSU：发布构建必须钉死内核版本号（03-ksu-contract §0.1 版本号陷阱）──────
# DDK 容器只挂 kernel/，没有 .git → KSU_GIT_VERSION_VALID 不会被定义 →
# 直接落到最后的 else，KSU_VERSION 变成 16（比线上倒退三万）。
# 发布流水线显式传：-e KSU_VERSION_PIN=32650
ifdef KSU_VERSION_PIN
$(eval KSU_VERSION=$(KSU_VERSION_PIN))
$(info -- KernelSU version (pinned by KSU_VERSION_PIN): $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
else ifdef KSU_GIT_VERSION_VALID
"""

MANAGER_GEN_SNIPPET = """\
#
# ── 管理器世代闸门（03 分册 §2.2.4）─────────────────────────────────────────
# 认主除签名外还要求 APK 自带 `assets/ksu_manager_gen<N>`，且 N >= 本值。
# 「再断一代」= 这里 +1，并同批发一版带 assets/ksu_manager_gen<N+1> 的管理器。
ifndef KSU_MANAGER_MIN_GEN
KSU_MANAGER_MIN_GEN := 2
endif
$(info -- KernelSU manager generation gate: KSU_MANAGER_MIN_GEN=$(KSU_MANAGER_MIN_GEN))
ccflags-y += -DKSU_MANAGER_MIN_GEN=$(KSU_MANAGER_MIN_GEN)

# 可选的双重校验（包名 + 证书 + gen），发布流水线传 -e KSU_MANAGER_PACKAGE=...
# 注：0005 只落地「证书 + gen」两重；包名校验需要额外路径解析，见 manifest.todos。
ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\\"$(KSU_MANAGER_PACKAGE)\\"
endif
"""


def patch_0001(tree: Tree, s7k: Tree) -> list[str]:
    """构建身份：KSU_VERSION_PIN / KSU_GIT_VERSION / PACKAGE_NAME / MANAGER_MIN_GEN。"""
    kbuild = "kernel/Kbuild"
    tree.replace_once(kbuild,
        "KSU_GIT_VERSION := $(shell cd $(GIT_ROOT) && $(GIT) rev-list --count HEAD 2>/dev/null)\n",
        "# MapleSU: 允外部钉死 KSU_GIT_VERSION（浅克隆时 rev-list 数偏小，版本号会倒退）\n"
        "ifndef KSU_GIT_VERSION\n"
        "KSU_GIT_VERSION := $(shell cd $(GIT_ROOT) && $(GIT) rev-list --count HEAD 2>/dev/null)\n"
        "endif\n")
    tree.replace_once(kbuild,
        "ifdef KSU_GIT_VERSION_VALID\n"
        "# ksu_version: major * 10000 + git version + 200 for historical reasons\n",
        KSU_VERSION_PIN_SNIPPET +
        "# ksu_version: major * 10000 + git version + 200 for historical reasons\n")
    tree.replace_once(kbuild,
        "ifeq ($(KSU_IS_PR_BUILD),0)\n"
        "KSU_PACKAGE_NAME ?= me.weishu.kernelsu\n"
        "else\n"
        "KSU_PACKAGE_NAME ?= me.weishu.kernelsu.pr\n"
        "endif\n"
        "KSU_EXPECTED_SIZE ?= 0x033b\n",
        "ifeq ($(KSU_IS_PR_BUILD),0)\n"
        "KSU_PACKAGE_NAME ?= dev.maplesu.manager\n"
        "else\n"
        "KSU_PACKAGE_NAME ?= dev.maplesu.manager.pr\n"
        "endif\n"
        "# TODO(release): 下面两个默认值仍是上游占位（绝不冒充我方指纹）。\n"
        "# 发布流水线必须显式 -e KSU_EXPECTED_SIZE=<DER 长度> -e KSU_EXPECTED_HASH=<cert sha256>。\n"
        "KSU_EXPECTED_SIZE ?= 0x033b\n")
    tree.insert_before(kbuild,
        "$(info -- KernelSU Manager package name: $(KSU_PACKAGE_NAME))",
        MANAGER_GEN_SNIPPET + "\n")
    tree.replace_once("userspace/ksud/build.rs",
        'println!("cargo:rustc-env=KSU_PACKAGE_NAME=me.weishu.kernelsu");',
        'println!("cargo:rustc-env=KSU_PACKAGE_NAME=dev.maplesu.manager");')
    return [kbuild, "userspace/ksud/build.rs"]


# ---------------------------------------------------------------- 0002
UAPI_BLOCK = """\

/*
 * ── MapleSU 分支扩展（UAPI 7）────────────────────────────────────────────
 * 上游 22 = LOOKUP_SYMBOLS；7K 的 22/23/24 = APP_LOCK_*、25/26 = STEALTH_*、
 * 27/28 = STEALTH_*_G，语义冲突。MapleSU 把它们整体重编号到 30–36
 * （docs/dual-mode/impl/03-ksu-contract.md §1.5 冻结表），22 保留给上游。
 * 37–39 预留给「再断一代」的安全阀扩展，不得用于普通功能。
 */

/* App lock（7K 侧为弃用桩，v1 supportsAppLock=false；编号保留，见 §2.2.2） */
struct ksu_app_lock_state_cmd {
    __u8 configured; /* Output: whether a lock is configured */
    __u8 authed; /* Output: whether already authenticated this boot */
};

struct ksu_app_lock_auth_cmd {
    __u8 hash[32]; /* Input: SHA-256(password) */
};

struct ksu_app_lock_set_cmd {
    __u8 hash[32]; /* Input: new SHA-256(password) */
    __u8 disable; /* Input: 1 to disable the lock */
    __u8 state; /* Output: 1 if a lock is configured after the operation */
};

static const __u32 KSU_IOCTL_APP_LOCK_STATE = _IOR('K', 30, struct ksu_app_lock_state_cmd);
static const __u32 KSU_IOCTL_APP_LOCK_AUTH = _IOW('K', 31, struct ksu_app_lock_auth_cmd);
static const __u32 KSU_IOCTL_APP_LOCK_SET = _IOWR('K', 32, struct ksu_app_lock_set_cmd);

/*
 * 隐身模式：开启后 GET_INFO 不再上报 MANAGER 标志，管理器界面伪装成「未安装」。
 * 内核真实权限不变，因此只有真正的管理器能读写该开关（见 dispatch/perm）。
 */
struct ksu_stealth_cmd {
    __u8 enabled; /* Input for SET, Output for GET */
};

static const __u32 KSU_IOCTL_STEALTH_GET = _IOR('K', 33, struct ksu_stealth_cmd);
static const __u32 KSU_IOCTL_STEALTH_SET = _IOW('K', 34, struct ksu_stealth_cmd);

/* 安全阀：调用方声明管理器世代号，内核回告 KSU_MANAGER_MIN_GEN（诊断用） */
struct ksu_stealth_gen_cmd {
    __u32 manager_gen; /* Input: 管理器世代号; Output(GET): 内核要求的世代号下限 */
    __u8 enabled; /* Input for SET, Output for GET */
    __u8 _pad[3];
};

static const __u32 KSU_IOCTL_STEALTH_GET_G = _IOR('K', 35, struct ksu_stealth_gen_cmd);
static const __u32 KSU_IOCTL_STEALTH_SET_G = _IOW('K', 36, struct ksu_stealth_gen_cmd);
"""


def patch_0002(tree: Tree, s7k: Tree) -> list[str]:
    """UAPI=7：冻结 30–36，保留上游 22；结构体与 7K 字节一致。"""
    uapi = "uapi/supercall.h"
    tree.replace_once(uapi,
        "// 6: add KSU_IOCTL_LOOKUP_SYMBOLS and KSU_GET_INFO_FLAG_PREINIT; "
        "modules.rc and preinit may live under /metadata/vold/ksu\n"
        "static const __u32 KERNEL_SU_UAPI_VERSION = 6;\n",
        "// 6: add KSU_IOCTL_LOOKUP_SYMBOLS and KSU_GET_INFO_FLAG_PREINIT; "
        "modules.rc and preinit may live under /metadata/vold/ksu\n"
        "// 7: MapleSU branch (UAPI6 + 7K extensions, ioctls 30-36)\n"
        "static const __u32 KERNEL_SU_UAPI_VERSION = 7;\n")
    tree.insert_after(uapi,
        "static const __u32 KSU_IOCTL_LOOKUP_SYMBOLS = _IOW('K', 22, "
        "struct ksu_lookup_symbols_cmd);\n",
        UAPI_BLOCK)
    return [uapi]


# ---------------------------------------------------------------- 0003
STEALTH_HANDLERS = """\
/*
 * 隐身模式（MapleSU 分支，移植自 7K v2.30 manager/stealth.c）。
 *
 * 注意：这里只抑制「上报给 App 的 MANAGER flag」，内核真实权限判定不变，
 * 所以已认主的管理器仍然能读/写这个开关（UI 的「点 5 下内核版本恢复」依赖它）。
 * STEALTH_*_G 是安全阀变体，供「管理器没被认主也要能关隐身」的救砖路径使用。
 */
static int do_stealth_get(void __user *arg)
{
    struct ksu_stealth_cmd cmd = { 0 };

    cmd.enabled = ksu_stealth_is_enabled() ? 1 : 0;

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

static int do_stealth_set(void __user *arg)
{
    struct ksu_stealth_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    return ksu_stealth_set(cmd.enabled != 0);
}

static int do_stealth_get_g(void __user *arg)
{
    struct ksu_stealth_gen_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.manager_gen < 1) {
        pr_warn("stealth: bad manager generation %u\\n", cmd.manager_gen);
        return -EINVAL;
    }

    /* 回告内核要求的世代下限（诊断用：网页管理器 / 日志能看到） */
    cmd.manager_gen = KSU_MANAGER_MIN_GEN;
    cmd.enabled = ksu_stealth_is_enabled() ? 1 : 0;

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

static int do_stealth_set_g(void __user *arg)
{
    struct ksu_stealth_gen_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.manager_gen < 1) {
        pr_warn("stealth: bad manager generation %u\\n", cmd.manager_gen);
        return -EINVAL;
    }

    pr_info("stealth: set %d via valve (gen %u)\\n", cmd.enabled ? 1 : 0, cmd.manager_gen);
    return ksu_stealth_set(cmd.enabled != 0);
}

"""

STEALTH_TABLE = """\
    {
        .cmd = KSU_IOCTL_STEALTH_GET,
        .name = "STEALTH_GET",
        .handler = do_stealth_get,
        .perm_check = only_manager
    },
    {
        .cmd = KSU_IOCTL_STEALTH_SET,
        .name = "STEALTH_SET",
        .handler = do_stealth_set,
        .perm_check = only_manager
    },
    {
        /* 安全阀：调用方需声明世代号（老 APK 代码里没有这两条命令） */
        .cmd = KSU_IOCTL_STEALTH_GET_G,
        .name = "STEALTH_GET_G",
        .handler = do_stealth_get_g,
        .perm_check = stealth_valve_allowed
    },
    {
        .cmd = KSU_IOCTL_STEALTH_SET_G,
        .name = "STEALTH_SET_G",
        .handler = do_stealth_set_g,
        .perm_check = stealth_valve_allowed
    },
"""

STEALTH_PERM = """\

/*
 * MapleSU 分支：断代闸门的安全阀权限（03 分册 §2.3 / §9-R2）。
 *
 * ⚠️ 7K v2.30 的实现还放行「任意用我方证书签名、但没被认主的 APK」
 *    （ksu_is_signed_manager_uid）。那条链路需要 manager 侧 signed-appid 记录
 *    （7K 的 note_signed_manager / ksu_set_signed_manager_appid），且属产品决策 R2；
 *    0005 只落地「证书 + 世代」闸门，不落地 signed-manager 记录。
 *    v1 因此采用保守形态：root 或**已认主**的管理器。
 * TODO(R2): 若产品决定「签名即可关隐身」，在 0005 补齐 note_signed_manager 后放宽。
 */
bool stealth_valve_allowed(void)
{
    return current_uid().val == 0 || is_manager();
}
"""


def patch_0003(tree: Tree, s7k: Tree) -> list[str]:
    """stealth 隐身：内核新文件 + GET_INFO 抑制 + 4 条 ioctl。"""
    tree.add_from(s7k, "kernel/manager/stealth.h")
    tree.add_from(s7k, "kernel/manager/stealth.c",
                  replacements=[("/data/adb/sevenk", "/data/adb/ksu")])
    tree.replace_once("kernel/Kbuild",
        "kernelsu-objs += manager/apk_sign.o\n",
        "kernelsu-objs += manager/stealth.o\nkernelsu-objs += manager/apk_sign.o\n")
    tree.insert_after("kernel/supercall/internal.h",
        "bool allowed_for_su(void);\n",
        "/* MapleSU: 断代闸门安全阀的权限检查（见 perm.c） */\n"
        "bool stealth_valve_allowed(void);\n")
    tree.append("kernel/supercall/perm.c", STEALTH_PERM)
    tree.insert_after("kernel/supercall/dispatch.c",
        '#include "manager/manager_identity.h"\n', '#include "manager/stealth.h"\n')
    tree.replace_all("kernel/supercall/dispatch.c",
        "    if (is_manager()) {\n        cmd.flags |= KSU_GET_INFO_FLAG_MANAGER;\n    }\n",
        "    if (is_manager() && !ksu_stealth_is_enabled()) {\n"
        "        cmd.flags |= KSU_GET_INFO_FLAG_MANAGER;\n    }\n", count=2)
    tree.insert_after("kernel/supercall/dispatch.c",
        "            post_fs_data_lock = true;\n",
        "            ksu_stealth_load();\n")
    tree.insert_before("kernel/supercall/dispatch.c",
        "\n// IOCTL handlers mapping table", STEALTH_HANDLERS)
    tree.insert_before("kernel/supercall/dispatch.c",
        "    {\n        .cmd = 0,\n        .name = NULL,\n        .handler = NULL,\n"
        "        .perm_check = NULL\n    } // Sentinel\n",
        STEALTH_TABLE)
    return [
        "kernel/Kbuild", "kernel/supercall/internal.h", "kernel/supercall/perm.c",
        "kernel/supercall/dispatch.c", "kernel/manager/stealth.c", "kernel/manager/stealth.h",
    ]


# ---------------------------------------------------------------- 0004
APP_LOCK_HANDLERS = """\
/*
 * App lock（应用锁）—— 7K v2.30 起内核侧是**弃用桩**：
 * 锁永远「未配置 + 已解锁」，所以下面 3 条 ioctl 只做形态兼容，
 * 不产生任何拦截能力（见 kernel/manager/app_lock.c 文件头）。
 * MapleSU v1 因此 supportsAppLock=false，设置页不显示入口（03 分册 §2.2.2）。
 */
static int do_app_lock_state(void __user *arg)
{
    struct ksu_app_lock_state_cmd cmd = { 0 };

    cmd.configured = ksu_app_lock_is_configured() ? 1 : 0;
    cmd.authed = ksu_app_lock_is_authed() ? 1 : 0;

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

static int do_app_lock_auth(void __user *arg)
{
    struct ksu_app_lock_auth_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    return ksu_app_lock_auth(cmd.hash);
}

static int do_app_lock_set(void __user *arg)
{
    struct ksu_app_lock_set_cmd cmd;
    int ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    ret = ksu_app_lock_set(cmd.hash, cmd.disable ? true : false);
    cmd.state = ksu_app_lock_is_configured() ? 1 : 0;

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return ret;
}

"""

APP_LOCK_TABLE = """\
    {
        .cmd = KSU_IOCTL_APP_LOCK_STATE,
        .name = "APP_LOCK_STATE",
        .handler = do_app_lock_state,
        .perm_check = manager_or_root
    },
    {
        .cmd = KSU_IOCTL_APP_LOCK_AUTH,
        .name = "APP_LOCK_AUTH",
        .handler = do_app_lock_auth,
        .perm_check = only_manager
    },
    {
        .cmd = KSU_IOCTL_APP_LOCK_SET,
        .name = "APP_LOCK_SET",
        .handler = do_app_lock_set,
        .perm_check = only_manager_authed
    },
"""

APP_LOCK_PERM = """\

/*
 * ── App lock 权限形态（03 分册 §2.3）────────────────────────────────────
 * 因为 ksu_app_lock_ok() 恒为 true，*_authed 变体**当前等价**于原函数：
 *   only_manager_authed  == only_manager
 *   manager_or_root_authed == manager_or_root
 *   allowed_for_su_authed  == allowed_for_su
 * 这条等价关系必须钉死：未来若真实现 app lock，授权语义变化必须显式 review，
 * 不允许「顺手」改变 GRANT_ROOT / SET_APP_PROFILE / SET_FEATURE 的权限面。
 */
bool only_manager_authed(void)
{
    return is_manager() && ksu_app_lock_ok();
}

bool manager_or_root_authed(void)
{
    return current_uid().val == 0 || only_manager_authed();
}

bool allowed_for_su_authed(void)
{
    if (current_uid().val == 0) {
        return true;
    }

    if (ksu_is_allow_uid_for_current(current_uid().val)) {
        return true;
    }

    return only_manager_authed();
}
"""


def patch_0004(tree: Tree, s7k: Tree) -> list[str]:
    """app lock：保留 7K 的弃用桩语义 + 权限形态，不产生拦截能力。"""
    tree.add_from(s7k, "kernel/manager/app_lock.h")
    tree.add_from(s7k, "kernel/manager/app_lock.c",
                  replacements=[("/data/adb/sevenk", "/data/adb/ksu")])
    tree.replace_once("kernel/Kbuild",
        "kernelsu-objs += manager/stealth.o\n",
        "kernelsu-objs += manager/app_lock.o\nkernelsu-objs += manager/stealth.o\n")
    tree.insert_after("kernel/supercall/internal.h",
        "bool stealth_valve_allowed(void);\n",
        "bool only_manager_authed(void);\n"
        "bool manager_or_root_authed(void);\n"
        "bool allowed_for_su_authed(void);\n")
    tree.replace_once("kernel/supercall/perm.c",
        '#include "manager/manager_identity.h"\n',
        '#include "manager/manager_identity.h"\n#include "manager/app_lock.h"\n')
    tree.append("kernel/supercall/perm.c", APP_LOCK_PERM)
    tree.insert_after("kernel/supercall/dispatch.c",
        '#include "manager/manager_identity.h"\n', '#include "manager/app_lock.h"\n')
    tree.insert_after("kernel/supercall/dispatch.c",
        "            post_fs_data_lock = true;\n", "            ksu_app_lock_load();\n")
    tree.insert_before("kernel/supercall/dispatch.c",
        "\n// IOCTL handlers mapping table", APP_LOCK_HANDLERS)
    tree.insert_before("kernel/supercall/dispatch.c",
        "    {\n        .cmd = 0,\n        .name = NULL,\n        .handler = NULL,\n"
        "        .perm_check = NULL\n    } // Sentinel\n",
        APP_LOCK_TABLE)
    # 权限表三处改为 *_authed 变体（当前等价，见 APP_LOCK_PERM 注释）
    tree.replace_once("kernel/supercall/dispatch.c",
        "        .handler = do_grant_root,\n        .perm_check = allowed_for_su \n",
        "        .handler = do_grant_root,\n        .perm_check = allowed_for_su_authed\n")
    tree.replace_once("kernel/supercall/dispatch.c",
        "        .handler = do_set_app_profile,\n        .perm_check = only_manager\n",
        "        .handler = do_set_app_profile,\n        .perm_check = only_manager_authed\n")
    tree.replace_once("kernel/supercall/dispatch.c",
        "        .handler = do_set_feature,\n        .perm_check = manager_or_root\n",
        "        .handler = do_set_feature,\n        .perm_check = manager_or_root_authed\n")
    return [
        "kernel/Kbuild", "kernel/supercall/internal.h", "kernel/supercall/perm.c",
        "kernel/supercall/dispatch.c", "kernel/manager/app_lock.c", "kernel/manager/app_lock.h",
    ]


# ---------------------------------------------------------------- 0005
GEN_SCAN_CODE = """\
/*
 * ── MapleSU 分支：管理器世代闸门（移植自 7K v2.30 kernel/manager/apk_sign.c）──
 *
 * 认主是内核扫包自动完成的（throne_tracker.c）。闸门加在那一步：除签名匹配外，
 * base.apk 还必须声明世代号 —— 包内的 ZIP 条目 `assets/ksu_manager_gen<N>`（N>=1）。
 *   · 老版本 APK 没有这条条目 → 世代号 0 → 不认主；
 *   · 条目名在 ZIP 中央目录里，只读中央目录即可，不解压、不碰 v2 签名块；
 *   · 条目名是包的静态属性 → 「先装新版再换老版」骗不过去。
 *
 * 与 7K 的差异（写进 manifest.todos，不假装一致）：
 *   · 7K 还在 ksu_manager_apk_gen() 里做 KSU_MANAGER_PACKAGE 包名双重校验，
 *     那需要 get_pkg_from_apk_path()（7K 新增）；本补丁只做「证书 + 世代」两重。
 *   · 7K 的 signed-manager 安全阀记录（note_signed_manager）不在本补丁内（R2 未决）。
 */
#define KSU_GEN_ENTRY_PREFIX "assets/ksu_manager_gen"
#define KSU_CD_HEADER_SIZE 46 // sizeof(central directory file header)
#define KSU_CD_MAX_NAME 512

/* ZIP 多字节字段一律小端；不引 asm/unaligned.h，手工拼 */
static u32 ksu_le32(const unsigned char *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static u16 ksu_le16(const unsigned char *p)
{
    return (u16)((u16)p[0] | ((u16)p[1] << 8));
}

/*
 * 找 EOCD 位置。逻辑与 check_v2_signature() 里那段一致，但**单独写一份**：
 * 签名校验是 root 的命门，不去重构它、免得闸门出错连累签名。
 */
static bool ksu_find_eocd(struct file *fp, loff_t file_size, loff_t *eocd_offset)
{
    int i;
    loff_t pos;

    for (i = 0; i <= 0xffff; ++i) {
        unsigned short comment_size;
        u32 magic;

        pos = file_size - i - 2;
        if (!read_exact(fp, &comment_size, sizeof(comment_size), &pos, file_size))
            return false;
        if (comment_size != i)
            continue;

        pos -= 22; // 回到 EOCD 记录开头
        if (!read_exact(fp, &magic, sizeof(magic), &pos, file_size))
            return false;
        if (magic == 0x06054b50) {
            *eocd_offset = pos - sizeof(magic);
            return true;
        }
    }

    return false;
}

/* 条目名形如 assets/ksu_manager_gen2 → 返回 2；不是这个形状 → 返回 0 */
static int ksu_parse_gen_name(const char *name, u16 len)
{
    static const char prefix[] = KSU_GEN_ENTRY_PREFIX;
    const u16 plen = (u16)(sizeof(prefix) - 1);
    u16 i;
    int gen = 0;

    if (len <= plen || len > KSU_CD_MAX_NAME)
        return 0;
    if (memcmp(name, prefix, plen))
        return 0;

    /* 前缀后面必须全是数字（.bak/.txt 后缀一律不算，防误判） */
    for (i = plen; i < len; i++) {
        if (name[i] < '0' || name[i] > '9')
            return 0;
        gen = gen * 10 + (name[i] - '0');
        if (gen > 1000000)
            return 0;
    }

    return gen;
}

/*
 * 扫一遍中央目录，返回 APK 声明的世代号；0 = 没有这条条目（老 APK）。
 * 只在签名校验通过后调用；任何异常都退回 0（宁可不认主，也不误认）。
 */
static int ksu_scan_manager_gen(struct file *fp, u32 cd_offset, u32 cd_size, loff_t file_size)
{
    loff_t pos = (loff_t)cd_offset;
    const loff_t end = (loff_t)cd_offset + (loff_t)cd_size;

    if (end > file_size || end <= pos)
        return 0;

    while (pos + KSU_CD_HEADER_SIZE <= end) {
        unsigned char hdr[KSU_CD_HEADER_SIZE];
        char name[KSU_CD_MAX_NAME + 1];
        u16 name_len, extra_len, comment_len;
        loff_t skip;

        if (!read_exact(fp, hdr, sizeof(hdr), &pos, end))
            return 0;
        if (ksu_le32(hdr) != 0x02014b50) // central directory file header 签名
            return 0;

        name_len = ksu_le16(hdr + 28);
        extra_len = ksu_le16(hdr + 30);
        comment_len = ksu_le16(hdr + 32);
        if (name_len == 0 || name_len > KSU_CD_MAX_NAME)
            return 0;

        if (!read_exact(fp, name, name_len, &pos, end))
            return 0;
        name[name_len] = '\\0';

        {
            int gen = ksu_parse_gen_name(name, name_len);
            if (gen > 0)
                return gen;
        }

        skip = (loff_t)extra_len + (loff_t)comment_len;
        if (skip < 0 || pos + skip > end)
            return 0;
        pos += skip;
    }

    return 0;
}

/* 读 APK 里声明的世代号（不校验签名；调用方先过签名） */
static int ksu_read_manager_gen(char *path)
{
    struct file *fp;
    loff_t file_size, eocd_offset, pos;
    u32 cd_size, cd_offset;
    int gen;

    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("gen: open %s error.\\n", path);
        return 0;
    }

    file_size = generic_file_llseek(fp, 0, SEEK_END);
    if (file_size <= 0)
        goto out;

    if (!ksu_find_eocd(fp, file_size, &eocd_offset))
        goto out;

    pos = eocd_offset + 12;
    if (!read_exact(fp, &cd_size, sizeof(cd_size), &pos, file_size))
        goto out;
    if (!read_exact(fp, &cd_offset, sizeof(cd_offset), &pos, file_size))
        goto out;

    gen = ksu_scan_manager_gen(fp, cd_offset, cd_size, file_size);
    filp_close(fp, 0);
    return gen;

out:
    filp_close(fp, 0);
    return 0;
}

/*
 * 返回值（认主与安全阀的唯一判据）：
 *   -1 : 不是我们签名的 APK
 *    0 : 签名对，但包里没有世代标记（= 老版本管理器）→ 不认主
 *   >0 : 签名对 + 声明的世代号（>= KSU_MANAGER_MIN_GEN 才认主）
 */
int ksu_manager_apk_gen(char *path)
{
    if (!check_v2_signature(path, EXPECTED_SIZE, EXPECTED_HASH)) {
#ifdef EXPECTED_SIZE2
        if (!check_v2_signature(path, EXPECTED_SIZE2, EXPECTED_HASH2))
            return -1;
#else
        return -1;
#endif
    }

    return ksu_read_manager_gen(path);
}

"""

GEN_GATE_THRONE = """\
            int manager_gen = ksu_manager_apk_gen(candidate_path);
            pr_info("Found manager base.apk at path: %s, manager gen: %d\\n",
                    candidate_path, manager_gen);

            // 不是我们签名的包 → 和以前一样跳过
            if (unlikely(manager_gen < 0))
                goto skip_iterate;

            // 签名对但没过世代闸门（老 APK / 世代号太低）→ 明确拒绝认主
            if (unlikely(manager_gen < KSU_MANAGER_MIN_GEN)) {
                pr_warn("manager apk rejected by generation gate (gen %d < %d): %s\\n",
                        manager_gen, KSU_MANAGER_MIN_GEN, candidate_path);
                goto skip_iterate;
            }

            crown_manager(candidate_path, uid_data);
"""


def patch_0005(tree: Tree, s7k: Tree) -> list[str]:
    """管理器世代闸门：证书 + gen 双判据；旧 APK 永久不被认主（D2）。"""
    tree.insert_after("kernel/manager/manager_identity.h",
        "#define KSU_PER_USER_RANGE 100000\n",
        "\n"
        "/*\n"
        " * 管理器世代闸门（03 分册 §2.2.4）：APK 必须带 assets/ksu_manager_gen<N>，\n"
        " * 且 N >= KSU_MANAGER_MIN_GEN 才被认主。Kbuild 会 -D 注入；这里留兜底值，\n"
        " * 供非 Kbuild 的静态检查/单文件包含时不至于未定义。\n"
        " * 「再断一代」= 这个值 +1，并同批发一版带新标记的管理器。\n"
        " */\n"
        "#ifndef KSU_MANAGER_MIN_GEN\n"
        "#define KSU_MANAGER_MIN_GEN 2\n"
        "#endif\n",
    )
    tree.insert_after("kernel/manager/apk_sign.h",
        "bool is_manager_apk(char *path);\n",
        "/* MapleSU: 返回 -1=非我方签名 / 0=签名对但无世代标记 / >0=世代号 */\n"
        "int ksu_manager_apk_gen(char *path);\n")
    tree.replace_once("kernel/manager/apk_sign.c",
        "    return v2_signing_valid;\n}\n\n#ifdef CONFIG_KSU_DEBUG\n",
        "    return v2_signing_valid;\n}\n\n" + GEN_SCAN_CODE + "#ifdef CONFIG_KSU_DEBUG\n")
    tree.replace_once("kernel/manager/throne_tracker.c",
        "            bool is_manager = is_manager_apk(candidate_path);\n"
        '            pr_info("Found manager base.apk at path: %s, is_manager: %d\\n", '
        "candidate_path, is_manager);\n"
        "\n"
        "            // Only crown if signature verification pass\n"
        "            if (unlikely(!is_manager))\n"
        "                goto skip_iterate;\n"
        "\n"
        "            crown_manager(candidate_path, uid_data);\n",
        GEN_GATE_THRONE)
    return [
        "kernel/manager/manager_identity.h", "kernel/manager/apk_sign.h",
        "kernel/manager/apk_sign.c", "kernel/manager/throne_tracker.c",
    ]


# ---------------------------------------------------------------- 0009（本分支独有）
def patch_0009(tree: Tree, s7k: Tree) -> list[str]:
    """W12b：ksud install 的 staging 标签分支（A→B 首次切换，源策略无 ksu_file）。"""
    utils = "userspace/ksud/src/utils.rs"
    tree.replace_once(utils,
        "pub fn install(libadbroot: Option<PathBuf>, data_path: Option<PathBuf>) -> Result<()> {\n",
        "pub fn install(\n"
        "    libadbroot: Option<PathBuf>,\n"
        "    data_path: Option<PathBuf>,\n"
        "    // MapleSU W12b: 切换事务内调用时为 true —— 源（Lite）策略里没有 ksu_file\n"
        "    // 类型，标签失败不能当作安装失败，否则重启后内核在、ksud 缺失。\n"
        "    stage_for_switch: bool,\n"
        ") -> Result<()> {\n")
    tree.replace_once(utils,
        "    restorecon::lsetfilecon(defs::DAEMON_PATH, restorecon::KSU_CON)?;\n",
        "    match restorecon::lsetfilecon(defs::DAEMON_PATH, restorecon::KSU_CON) {\n"
        "        std::result::Result::Ok(()) => {}\n"
        "        Err(e) if stage_for_switch => {\n"
        "            // 保留当前标签，写待办标记；B 内核开机第一次 post-fs-data 的\n"
        "            // restorecon() 会把标签补上并删除该标记（见 restorecon.rs）。\n"
        "            std::fs::write(\n"
        "                std::path::Path::new(defs::WORKING_DIR).join(\".pending_label\"),\n"
        "                restorecon::KSU_CON,\n"
        "            )?;\n"
        "            log::warn!(\"stage_for_switch: deferring daemon label ({e:#})\");\n"
        "        }\n"
        "        Err(e) => return Err(e).context(\"failed to label ksud\"),\n"
        "    }\n")
    # restorecon(): 标签补上后清掉待办标记
    tree.replace_once("userspace/ksud/src/restorecon.rs",
        "pub fn restorecon() -> Result<()> {\n"
        "    lsetfilecon(defs::DAEMON_PATH, KSU_CON)?;\n",
        "pub fn restorecon() -> Result<()> {\n"
        "    lsetfilecon(defs::DAEMON_PATH, KSU_CON)?;\n"
        "    // MapleSU W12b: 若上次 install 是 stage_for_switch 且标签被推迟，这里补完后清标记\n"
        "    let pending = Path::new(defs::WORKING_DIR).join(\".pending_label\");\n"
        "    if pending.exists() {\n"
        "        let _ = std::fs::remove_file(&pending);\n"
        "        log::info!(\"restorecon: cleared pending ksud label\");\n"
        "    }\n")
    # CLI: --stage-for-switch
    tree.replace_once("userspace/ksud/src/cli.rs",
        "    Install {\n"
        "        #[arg(long, default_value = None)]\n"
        "        libadbroot: Option<PathBuf>,\n"
        "\n"
        "        #[arg(long, default_value = None)]\n"
        "        data_path: Option<PathBuf>,\n"
        "    },\n",
        "    Install {\n"
        "        #[arg(long, default_value = None)]\n"
        "        libadbroot: Option<PathBuf>,\n"
        "\n"
        "        #[arg(long, default_value = None)]\n"
        "        data_path: Option<PathBuf>,\n"
        "\n"
        "        /// MapleSU W12b: 切换事务内使用；标签失败时写 .pending_label 而不是失败\n"
        "        #[arg(long, default_value_t = false)]\n"
        "        stage_for_switch: bool,\n"
        "    },\n")
    tree.replace_once("userspace/ksud/src/cli.rs",
        "        Commands::Install {\n"
        "            libadbroot,\n"
        "            data_path,\n"
        "        } => utils::install(libadbroot, data_path),\n",
        "        Commands::Install {\n"
        "            libadbroot,\n"
        "            data_path,\n"
        "            stage_for_switch,\n"
        "        } => utils::install(libadbroot, data_path, stage_for_switch),\n")
    tree.replace_once("userspace/ksud/src/late_load.rs",
        "    utils::install(None, None).context(\"Failed to install ksud\")?;\n",
        "    utils::install(None, None, false).context(\"Failed to install ksud\")?;\n")
    return [
        "userspace/ksud/src/utils.rs", "userspace/ksud/src/restorecon.rs",
        "userspace/ksud/src/cli.rs", "userspace/ksud/src/late_load.rs",
    ]


# ---------------------------------------------------------------- 0006/0007/0008
# 说明：这三个补丁把 7K 的**全部用户态功能源码**纳入 applied/（不丢文件），
# 但 wiring（mod/CLI/API-surface）分两步：
#   * 已在 patch 内接线的：webadmin.rs（纯 std+log+serde_json，7K 自己注明「开发机也能编」）、
#     atomic.rs / script_path.rs（7K 注明故意不加 cfg，宿主可编）；
#   * 需要 7K 独有 ksud API 才能接线的（webadmin_ksud.rs 依赖 7K ksucalls/module；
#     restore_user_data.rs 依赖 migrate/webadmin）→ 文件已入库（真实 7K 源码），
#     `mod` 行留给 API-surface 补丁，否则 applied 树不可编译。
# 7K 的 boot_patch.rs（0007 主体）是结构性重写（diff 2252 行），与上游 cli.rs
# 的 BootPatchArgs 调用约定绑定，不能作为「整文件替换」安全合入；剩余工作见
# patches.json.todos。
PATH_REWRITES = [("/data/adb/sevenk", "/data/adb/ksu")]


def patch_0006(tree: Tree, s7k: Tree) -> list[str]:
    """webadmin：7K 两个用户态源文件 + Cargo 依赖 + 只接线纯 HTTP 层。"""
    tree.add_from(s7k, "userspace/ksud/src/webadmin.rs", replacements=PATH_REWRITES)
    tree.add_from(s7k, "userspace/ksud/src/webadmin_ksud.rs", replacements=PATH_REWRITES)
    # rust-embed 8.x：`WebAsset::get` 来自 `Embed` trait，必须显式 use（7K 的旧版不需）。
    tree.replace_once(
        "userspace/ksud/src/webadmin.rs",
        "use log::{debug, info, warn};\n",
        "use log::{debug, info, warn};\n"
        "// MapleSU W12d：rust-embed 8.x 的 `WebAsset::get` 由 `Embed` trait 提供\n"
        "use rust_embed::Embed;\n",
    )
    # webadmin 前端静态资源（#[derive(RustEmbed)] folder = "assets/webadmin"；7K 同目录逐字节）
    for asset in ("app.css", "app.js", "icons.svg", "index.html", "modbridge.js",
                  "themes.css"):
        rel = f"userspace/ksud/assets/webadmin/{asset}"
        tree.add_from(s7k, rel, rel)
    tree.replace_once("userspace/ksud/Cargo.toml",
        'memmap2 = "0.9"\n',
        'memmap2 = "0.9"\n'
        '# MapleSU（7K 0006）：webadmin 的纯 HTTP 层与 rs 后端都需要 serde_json\n'
        'serde_json = "1"\n'
        '# 读 APK 资源（应用名）必须能宿主编译：只用 rust_backend，不引 zip crate\n'
        'flate2 = { version = "1", default-features = false, features = ["rust_backend"] }\n')
    package_header = '[[package]]\nname = "ksud"\n'
    package = tree.read("Cargo.lock").split(package_header, 1)[1].split('\n[[package]]', 1)[0]
    if package.count(' "extattr",\n') != 1 or ' "flate2",\n' in package:
        raise C.KsuError("Cargo.lock: unexpected ksud direct dependency list")
    tree.replace_once("Cargo.lock", package_header + package,
        package_header + package.replace(' "extattr",\n', ' "extattr",\n "flate2",\n', 1))
    tree.replace_once("userspace/ksud/src/main.rs",
        '#[cfg(target_os = "android")]\nmod utils;\n',
        '#[cfg(target_os = "android")]\nmod utils;\n'
        '// MapleSU 0006：webadmin 纯 HTTP 层（7K 注释：故意不加 cfg，宿主也能编/测）\n'
        'mod webadmin;\n'
        '// MapleSU 0006：rs 后端 webadmin_ksud.rs 依赖 7K ksucalls/module API-surface，\n'
        '// 待 0006b 接线；文件已在 applied 树内，未 mod 因此不参与本次编译。\n')
    return ["userspace/ksud/src/webadmin.rs", "userspace/ksud/src/webadmin_ksud.rs",
            "userspace/ksud/Cargo.toml", "Cargo.lock", "userspace/ksud/src/main.rs",
            "userspace/ksud/assets/webadmin/app.css",
            "userspace/ksud/assets/webadmin/app.js",
            "userspace/ksud/assets/webadmin/icons.svg",
            "userspace/ksud/assets/webadmin/index.html",
            "userspace/ksud/assets/webadmin/modbridge.js",
            "userspace/ksud/assets/webadmin/themes.css"]


def patch_0007(tree: Tree, s7k: Tree) -> list[str]:
    """boot-patch 安全增强的**可独立合入部分**：7K 的三个用户态小模块。

    主体 boot_patch.rs 重写未合入（见 patches.json.todos 0007b）；本补丁纳入 7K 为
    那条链抽出、与上游无冲突的模块，保证 applied 不丢 7K 源码。
    """
    for rel, required in (("userspace/ksud/src/atomic.rs", True),
                          ("userspace/ksud/src/script_path.rs", False),
                          ("userspace/ksud/src/res_label.rs", False)):
        tree.add_from(s7k, rel, replacements=PATH_REWRITES, required=required)
    tree.replace_once("userspace/ksud/src/main.rs",
        '// MapleSU 0006：rs 后端 webadmin_ksud.rs 依赖 7K ksucalls/module API-surface，\n'
        '// 待 0006b 接线；文件已在 applied 树内，未 mod 因此不参与本次编译。\n',
        '// MapleSU 0006：rs 后端 webadmin_ksud.rs 依赖 7K ksucalls/module API-surface，\n'
        '// 待 0006b 接线；文件已在 applied 树内，未 mod 因此不参与本次编译。\n'
        '// MapleSU 0007：7K 抽出的跨平台小工具（7K 注明故意不加 cfg，宿主可编/测）\n'
        'mod atomic;\n'
        'mod script_path;\n'
        '// MapleSU 0007：res_label.rs（APK 资源读应用名）依赖 7K 的 apk 资源解析\n'
        '// API-surface，待 0007b 接线；文件已入库，未 mod。\n')
    return ["userspace/ksud/src/atomic.rs", "userspace/ksud/src/script_path.rs",
            "userspace/ksud/src/res_label.rs", "userspace/ksud/src/main.rs"]


def patch_0008(tree: Tree, s7k: Tree) -> list[str]:
    """restore-user-data：7K 源文件入库（依赖 migrate/webadmin，mod 待 0008b）。"""
    tree.add_from(s7k, "userspace/ksud/src/restore_user_data.rs",
                  replacements=PATH_REWRITES, required=False)
    return ["userspace/ksud/src/restore_user_data.rs"]
# ---------------------------------------------------------------- 0010
JNI_SYMBOL_OLD = "Java_com_sevenk_core_Natives_"
JNI_SYMBOL_NEW = "Java_dev_maplesu_manager_ksu_KsuNatives_"

JNI_CMAKE = """\
# MapleSU KSU JNI（03 分册 §4.2）。
# 注意：uapi 不再依赖仓库里的 symlink（Windows 上会落成 19 字节文本文件），
# 而是直接 -I applied 根目录；applied/manager/app/src/main/cpp/uapi 是真实副本。
cmake_minimum_required(VERSION 3.22.1)

project("maplesu_ksu")

# libcxx 由 prefab 提供（gradle/libs.versions.toml 的 lsposed-cxx）；
# 独立命令行构建（无 prefab）时退化为 NDK 自带的 c++_static（build_jni.sh 走这条）。
find_package(cxx QUIET CONFIG)
if(cxx_FOUND)
    link_libraries(cxx::cxx)
endif()

set(KSU_APPLIED "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../applied")
if(NOT EXISTS "${KSU_APPLIED}/uapi/supercall.h")
    message(FATAL_ERROR "applied/uapi missing: run third_party/kernelsu/scripts/apply_patches.py --clean")
endif()

add_library(maplesu_ksu SHARED jni.cc ksu.cc)
target_include_directories(maplesu_ksu PRIVATE . "${KSU_APPLIED}")
target_compile_definitions(maplesu_ksu PRIVATE KSU_MANAGER_GEN=2)

find_library(log-lib log)
target_link_libraries(maplesu_ksu ${log-lib})

add_library(adbroot SHARED adbroot.cc)
target_link_libraries(adbroot ${log-lib})
"""


def patch_0010(tree: Tree, s7k: Tree) -> list[str]:
    """manager 侧 JNI 全量移植：7K jni.cc/ksu.cc/adbroot.cc + 机械符号改名。

    - 25 个导出符号 `Java_com_sevenk_core_Natives_*` → `Java_dev_maplesu_manager_ksu_KsuNatives_*`
      （与 `KsuNatives.kt` 的方法名逐字对应；改的是符号前缀，方法名不变）；
    - `FindClass("com/sevenk/core/Natives$Profile")` **保持不变**（MapleSU 的 Profile 同 FQN，
      03 分册 §8-C5：7K 源码已是目标形态）；
    - magica 导出 `Java_com_sevenk_core_magica_*` 保留原名（v1 不接线，supportsMagica=false）；
    - ksu.cc 的 `KSU_MANAGER_GEN` 改成 `#ifndef` 守卫，允许 CMake `-D` 注入同值；
    - CMakeLists 重写：不再依赖 cpp/uapi symlink，直接 -I applied 根。
    """
    cpp = "manager/app/src/main/cpp/"
    jni = tree.read_from(s7k, cpp + "jni.cc").replace(JNI_SYMBOL_OLD, JNI_SYMBOL_NEW)
    if jni.count(JNI_SYMBOL_NEW) != 25:
        raise C.KsuError(f"jni.cc: 期望 25 个改名符号，实际 {jni.count(JNI_SYMBOL_NEW)}")
    tree.write(cpp + "jni.cc", jni)

    ksu_cc = tree.read_from(s7k, cpp + "ksu.cc").replace(
        "#define KSU_MANAGER_GEN 2",
        "#ifndef KSU_MANAGER_GEN\n"
        "// 由 CMake -DKSU_MANAGER_GEN=2 注入（与 kernel KSU_MANAGER_MIN_GEN、ksud 同值）\n"
        "#define KSU_MANAGER_GEN 2\n"
        "#endif")
    tree.write(cpp + "ksu.cc", ksu_cc)
    for name in ("ksu.h", "logging.h", "adbroot.cc"):
        tree.add_from(s7k, cpp + name)
    tree.write(cpp + "CMakeLists.txt", JNI_CMAKE)
    return [cpp + name for name in
            ("jni.cc", "ksu.cc", "ksu.h", "logging.h", "adbroot.cc", "CMakeLists.txt")]


PATCHES = [
    {
        "name": "0001-manager-identity.patch",
        "summary": "构建身份：KSU_VERSION_PIN / KSU_GIT_VERSION 覆盖 / "
                   "KSU_PACKAGE_NAME=dev.maplesu.manager / KSU_MANAGER_MIN_GEN=2",
        "apply": patch_0001,
        "status": "implemented",
    },
    {
        "name": "0002-uapi-v7.patch",
        "summary": "UAPI=7：保留上游 22；新增 app lock 30-32、stealth 33-36 共 7 条 ioctl",
        "apply": patch_0002,
        "status": "implemented",
    },
    {
        "name": "0003-stealth.patch",
        "summary": "stealth 隐身：内核 stealth.c/h + GET_INFO 抑制 + 4 条 ioctl + 保守安全阀",
        "apply": patch_0003,
        "status": "implemented",
    },
    {
        "name": "0004-app-lock.patch",
        "summary": "app lock：保留 7K 弃用桩语义 + *_authed 权限形态（当前等价 only_manager）",
        "apply": patch_0004,
        "status": "implemented",
    },
    {
        "name": "0005-manager-generation-gate.patch",
        "summary": "管理器世代闸门：证书 + assets/ksu_manager_gen<N> 双判据；旧 APK 不被认主",
        "apply": patch_0005,
        "status": "implemented",
    },
    {
        "name": "0006-webadmin.patch",
        "summary": "webadmin 网页管理器：7K webadmin.rs/webadmin_ksud.rs 全量入库 + Cargo 依赖；"
                   "纯 HTTP 层由本补丁接线；rs 后端与 API surface 由 0011（0006b）接线",
        "apply": patch_0006,
        "status": "implemented",
    },
    {
        "name": "0007-boot-patch-safety.patch",
        "summary": "boot-patch 安全增强：7K atomic/script_path/res_label 模块入库并接线；"
                   "boot_patch.rs 重写由 0012（0007b）完成接线",
        "apply": patch_0007,
        "status": "implemented",
    },
    {
        "name": "0008-restore-user-data.patch",
        "summary": "restore-user-data：7K restore_user_data.rs 全量入库；"
                   "`mod`/CLI 接线由 0013（0008b）完成（migrate 常量就地定义，不采用迁移链）",
        "apply": patch_0008,
        "status": "implemented",
    },
    {
        "name": "0009-install-staging-label.patch",
        "summary": "W12b：ksud install --stage-for-switch，标签失败写 .pending_label 交给 B 内核 restorecon",
        "apply": patch_0009,
        "status": "implemented",
    },
    {
        "name": "0010-manager-jni-facade.patch",
        "summary": "manager JNI 全量移植：7K jni.cc/ksu.cc/adbroot.cc + 25 个符号机械改名 "
                   "Java_dev_maplesu_manager_ksu_KsuNatives_* + 同树 CMake（-I applied）",
        "apply": patch_0010,
        "status": "implemented",
    },
]

# W18b（task-21）补齐的 7K 剩余移植补丁（定义在 patch_defs_w18b.py）
def patch_maplesu_namespace(tree: Tree, _source: Tree) -> list[str]:
    path = "manager/app/src/main/cpp/jni.cc"
    tree.replace_all(path, "com/sevenk/core/Natives$Profile",
                     "com/maplesu/core/Natives$Profile", count=2)
    tree.replace_once(path, "Java_com_sevenk_core_magica_AppZygotePreload_",
                      "Java_com_maplesu_core_magica_AppZygotePreload_")
    return [path]


PATCHES = PATCHES + PATCHES_W18B + PATCHES_NORMAL_RECOVERY + PATCHES_KSUD_IDENTITY + PATCHES_SELINUX_UPSTREAM + PATCHES_VIVO + PATCHES_MAPLESU93260 + PATCHES_JAILBREAK_SESSION + [{
    "name": "0021-maplesu-manager-namespace.patch",
    "summary": "Align JNI profile lookup and Magica entry with the MapleSU manager namespace",
    "apply": patch_maplesu_namespace,
    "status": "implemented",
}] + PATCHES_BOOT_COPY + PATCHES_BACKUP_OPTIONAL + PATCHES_EMPTY_RAMDISK_RESTORE + PATCHES_TARGET_KERNEL_KMI + PATCHES_MODULE_INSTALL_TRANSACTION + PATCHES_MODULE_REMOVAL_TRANSACTION + PATCHES_NATIVE_CURRENT_INFO
_W18B_RESOLVED_TODOS = {
    "0006b-webadmin-ksud-api-surface",
    "0007b-boot-patch-rewrite",
    "0008b-restore-user-data-wiring",
    "KSU_MANAGER_PACKAGE 包名双重校验",
}

TODOS = [
    {
        "name": "W18b blocker: 7K 内核归属探测闸",
        "status": "todo",
        "blockedBy": ["0012-boot-patch-safety-wiring.patch"],
        "reason": "7K boot_patch.rs:779-930 在写分区前用 ksucalls::stealth_probe_get() 探测"
                  "「内核是否本分支内核」（KernelOwner），并据此打印/拒绝。本分支改用"
                  "「按目标镜像 RamdiskState 拒绝 Foreign」这道不依赖内核的闸（0012 已实现），"
                  "因此探测闸未移植；它还需要内核侧安全阀命令先真机验证。",
        "next": "设备轮次在应用层/ksud 侧复测 KernelOwner 探测（只读信息用途），"
                "不改写分区准入判据。",
        "evidence": ["7K boot_patch.rs:900-930 detect_kernel_owner/report_kernel_owner",
                     "7K boot_patch.rs:779-830 KernelOwner 定义"],
    },
    {
        "name": "W18b blocker: --force-foreign 逃生口",
        "status": "todo",
        "blockedBy": ["0012-boot-patch-safety-wiring.patch"],
        "reason": "7K 给 boot-patch/boot-restore 都加了 --force-foreign（advanced users only），"
                  "用于明确拆除别的 root 方案。v1 有意收紧为 fail-closed（不提供逃生口），"
                  "避免误操作把第三方 root 拆掉；CLI/参数接线未移植。",
        "next": "产品决策后加 cli 参数 + 两处判据放行（7K boot_patch.rs:858-880、"
                "must_refuse_unsafe_flash），并补反例测试。",
        "evidence": ["7K boot_patch.rs:835-880 is_restorable/must_refuse_foreign_restore/"
                     "restore_admission", "7K cli.rs BootRestoreArgs force_foreign"],
    },
    {
        "name": "W18b blocker: uninstall 失败语义硬化",
        "status": "todo",
        "blockedBy": ["0013-restore-user-data-wiring.patch"],
        "reason": "7K utils.rs:626-700 把 uninstall 的 4 处 remove_dir_all(...).ok() 改成"
                  "remove_dir_all_checked / remove_file_checked / remove_dir_if_empty，"
                  "删失败即中止且不 reboot。0013 只改了顺序（先还原镜像+备份，再删），"
                  "删除失败的「静默吞错」语义仍是上游形态。",
        "next": "把 7K 的 remove_dir_all_checked/remove_file_checked/remove_dir_if_empty/"
                "remove_legacy_compat_symlink 一并移植（依赖 defs 兼容软链，需单独补丁）。",
        "evidence": ["7K utils.rs:626-700 uninstall 重写", "7K utils.rs:540-620 删除 helpers"],
    },
    {
        "name": "0006b-webadmin-ksud-api-surface",
        "status": "todo",
        "blockedBy": ["0006-webadmin.patch"],
        "reason": "webadmin_ksud.rs 的编译面依赖 7K 独有的 "
                  "ksud API：ksucalls::{stealth_get_authed,stealth_set_authed,allow_list_uids,"
                  "deny_list_uids,manager_appid,get_app_profile,set_app_profile,read_cstr,write_cstr}、"
                  "module::{list_package_names,packages_info,parse_exec_options,run_in_module,"
                  "run_action_capture,get_common_script_envs,validate_module_id}、"
                  "atomic::write_atomic/script_path 两个 7K 模块；上游 528bafc 均不存在。"
                  "只挂文件+mod 会产出不可编译的 applied 树（本机又无法 cargo 构建 ksud 验证），"
                  "故按任务书『无法生成则 TODO，不伪造』处理。",
        "next": "先在 applied/userspace/ksud 落地 API-surface 补丁（ksucalls/module/atomic/script_path），"
                "再用 W18 轮次整体移植并跑 aarch64-linux-android cargo check。",
        "evidence": [
            "7K userspace/ksud/src/main.rs:67,74（mod webadmin / webadmin_ksud）",
            "7K userspace/ksud/src/webadmin_ksud.rs:18-22（crate::module/ksucalls/ksu_uapi 依赖）",
            "7K userspace/ksud/Cargo.toml:26-30（serde_json / flate2=rust_backend）",
            "diff -u [UP]/userspace/ksud/src/ksucalls.rs [7K]/... = 841 行差异",
        ],
    },
    {
        "name": "0007b-boot-patch-rewrite",
        "status": "todo",
        "blockedBy": ["0007-boot-patch-safety.patch"],
        "reason": "7K boot_patch.rs 相对上游 528bafc 是**结构性重写**（diff 2252 行；新增 "
                  "RamdiskState 四态/init_disposition/should_record_stock/write_and_verify/"
                  "rollback_partition/restore_admission，并重写 do_backup/flash_partition/restore），"
                  "不是可机械切分的 hunk 集；且本机无 rust NDK 构建验证（任务书禁止构建 ksud），"
                  "无法证明补丁后的树可编译。按『无法生成则 TODO』处理。",
        "next": "W12 轮次按函数级对照重写 boot_patch.rs，并落地 §2.2.5 的 maplesu_id 标记"
                "（Ours 判据从 7K 的 sevenk.ko 改回 kernelsu.ko + maplesu_id）。",
        "evidence": [
            "diff -u [UP]/userspace/ksud/src/boot_patch.rs [7K]/... = 2252 行",
            "7K boot_patch.rs:601-621（OURS_KSU_ENTRY=sevenk.ko，与主文档 467 冲突）",
            "03 分册 §1.4 补丁 7 行（内容清单）",
        ],
    },
    {
        "name": "0008b-restore-user-data-wiring",
        "status": "todo",
        "blockedBy": ["0006-webadmin.patch"],
        "reason": "7K restore_user_data.rs:25-29 直接 use crate::migrate::{ALLOWLIST_FILE,"
                  "STEALTH_CODE_FILE,STEALTH_FILE}，:410 依赖 crate::webadmin::random_hex；"
                  "而 migrate.rs 是 5985 行的 /data/adb/sevenk 迁移链（03 分册 §2.2.7 明确不采用）。"
                  "把文件搬进来 = 引入不采用的数据目录迁移链；故 TODO。",
        "next": "重写为不依赖 migrate/webadmin 的最小实现（备份 .allowlist/stealth/module_configs/"
                "profile/feature_config → /data/adb/ksu_uninstall_backup_<ts>），再挂 CLI。",
        "evidence": [
            "7K userspace/ksud/src/restore_user_data.rs:25-29,410",
            "7K userspace/ksud/src/migrate.rs 5985 行（不采用，03 §2.2.7）",
        ],
    },
    {
        "name": "KSU_MANAGER_PACKAGE 包名双重校验",
        "status": "todo",
        "blockedBy": ["0005-manager-generation-gate.patch"],
        "reason": "7K 在 ksu_manager_apk_gen() 里用 get_pkg_from_apk_path()（7K 新增的 base.apk "
                  "路径解析）做包名校验；上游只有 get_pkg_from_apk_dir_path()（目录形态）。"
                  "0005 只落地「证书 + 世代」两重；Kbuild 已透传 -DKSU_MANAGER_PACKAGE，"
                  "接上包名判据即可启用第三重。",
        "next": "在 0005 基础上增加 get_pkg_from_apk_path()（从 `/data/app/<hash>/<pkg>-<suffix>/base.apk` "
                "取 pkg 段）并在 ksu_manager_apk_gen() 里 #ifdef KSU_MANAGER_PACKAGE 比较。",
        "evidence": ["7K kernel/manager/apk_sign.c:465-475（包名校验）",
                     "上游 kernel/manager/apk_sign.c:301（只有 dir 形态）"],
    },
    {
        "name": "7K signed-manager 安全阀（ksu_is_signed_manager_uid）",
        "status": "todo",
        "blockedBy": ["0005-manager-generation-gate.patch"],
        "reason": "产品决策 R2 未定（03 分册 §2.3/§9-R2）：7K 放行「任意我方签名 APK」关隐身。"
                  "0003 的 stealth_valve_allowed 采用保守形态（root | 已认主管理器）。"
                  "若决定保留 7K 语义，需要 manager_identity.h 的 signed-appid 记录 + "
                  "throne_tracker 的 note_signed_manager 链路。",
        "next": "产品决策后补齐 0005b：manager_identity.h signed_appid + throne_tracker note + "
                "perm.c stealth_valve_allowed 放宽；并加「非管理器签名 → -EPERM」负向测试（D4）。",
        "evidence": ["7K kernel/manager/manager_identity.h:40-120",
                     "7K kernel/manager/throne_tracker.c:69-78",
                     "7K kernel/supercall/perm.c:61-80"],
    },
]



def _assert_patch_checks(spec: dict, repo: Path) -> None:
    """补丁应用后的静态断言（metadata.checks）：缺一个 needle 立即失败。"""
    for rel, needles in spec.get("checks", []):
        target = repo / rel
        if not target.is_file():
            raise C.KsuError(f"{spec['name']}: checks 目标不存在: {rel}")
        text = target.read_bytes().decode("utf-8", "replace")
        for needle in needles:
            if needle not in text:
                raise C.KsuError(f"{spec['name']}: {rel} 缺少 {needle!r}")


def _filter_todos(todos: list[dict], resolved: set[str]) -> list[dict]:
    out = []
    for todo in todos:
        name = todo.get("name", "")
        if name in resolved:
            continue
        if name.startswith("KSU_MANAGER_PACKAGE"):
            # 0014 已实现（三重校验），保留一条「发布期填证书指纹」的提醒由 manifest.identity 承担
            continue
        out.append(todo)
    return out

# ---------------------------------------------------------------- 生成
def git_stage(repo: Path, message: str) -> str:
    add = C.git(["add", "-A"], cwd=repo)
    if add.returncode != 0:
        raise C.KsuError(f"git add 失败: {add.stderr.decode('utf-8', 'replace')}")
    commit = C.git(["-c", "user.name=MapleSU", "-c", "user.email=ci@maplesu.invalid",
                    "commit", "-q", "-m", message], cwd=repo)
    if commit.returncode != 0:
        raise C.KsuError(f"git commit 失败: {commit.stderr.decode('utf-8', 'replace')}")
    head = C.git(["rev-parse", "HEAD"], cwd=repo)
    return head.stdout.decode().strip()


def diff_bytes(repo: Path) -> bytes:
    """index vs HEAD 的完整 diff（含新增文件）。

    注意：`git diff HEAD` **不包含 untracked 文件**，新增的 stealth.c/app_lock.c 会
    静默从补丁里消失（实测让 applied 树少 4 个文件）。所以先 `git add -A`
    再 `git diff --cached HEAD`。
    """
    add = C.git(["-c", "core.autocrlf=false", "add", "-A"], cwd=repo)
    if add.returncode != 0:
        raise C.KsuError(f"git add 失败: {add.stderr.decode('utf-8', 'replace')}")
    d = C.git(["-c", "core.autocrlf=false", "diff", "--cached", "HEAD", "--binary", "--no-color"],
              cwd=repo)
    if d.returncode != 0:
        raise C.KsuError(f"git diff 失败: {d.stderr.decode('utf-8', 'replace')}")
    return d.stdout


def write_patches(out_dir: Path, repo: Path) -> tuple[list[str], list[dict]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.patch"):
        stale.unlink()
    names: list[str] = []
    entries: list[dict] = []
    # 阶段 0：快照基线提交
    git_stage(repo, "base: upstream snapshot")
    for spec in PATCHES:
        tree = Tree(repo)
        touched = spec["apply"](tree, Tree(S7K_ROOT))
        patch = diff_bytes(repo)
        if not patch:
            raise C.KsuError(f"{spec['name']}: 没有产生任何差异")
        _assert_patch_hygiene(spec["name"], patch)
        path = out_dir / spec["name"]
        C.write_bytes(path, patch)
        git_stage(repo, spec["name"])
        names.append(spec["name"])
        entry = {
            "name": spec["name"],
            "sha256": C.sha256_file(path),
            "size": path.stat().st_size,
            "status": spec["status"],
            "summary": spec["summary"],
            "touches": sorted(set(touched)),
        }
        for optional in ("checks", "compile_verified", "compile_note"):
            if optional in spec:
                entry[optional] = spec[optional]
        entries.append(entry)
        _assert_patch_checks(spec, repo)
        print(f"  + {spec['name']}: {len(patch)} bytes, {len(set(touched))} files")
    series = ("# MapleSU 7K 功能补丁序列（顺序即依赖顺序；由 gen_patches.py 生成）\n"
              "# UAPI 重编号（0002）必须先于 stealth/app-lock（0003/0004）。\n"
              "# 0017 is superseded by the pinned upstream; see patches.json.\n"
              + "".join(f"{n}\n" for n in names))
    C.write_text(out_dir / "series", series)
    C.write_json(out_dir / "patches.json", {
        "schema": 1,
        "generator": "third_party/kernelsu/scripts/gen_patches.py@1",
        "entries": entries,
        "superseded": SUPERSEDED_PATCHES,
        "todos": _filter_todos(TODOS, _W18B_RESOLVED_TODOS),
    })
    return names, entries


def _assert_patch_hygiene(name: str, patch: bytes) -> None:
    if b"\r" in patch:
        raise C.KsuError(f"{name}: 补丁含 CR（必须 LF）")
    for lineno, line in enumerate(patch.split(b"\n"), 1):
        if line.startswith(b"+") and not line.startswith(b"+++") and line.endswith(b" "):
            raise C.KsuError(f"{name}: 第 {lineno} 行新增内容带行尾空格（git apply -whitespace=error-all 会拒绝）")


def verify_series(upstream_dir: Path, patches: list[str], expected_tree_sha: str,
                  _workdir: Path) -> None:
    # A parent Git worktree can make git apply silently skip every patch.
    # Match apply_patches/verify_payload: isolated directory + checked shared helper.
    workdir = C.isolated_apply_root("maplesu-patches-verify-")
    try:
        C.copy_tree(upstream_dir, workdir)
        for name in patches:
            p = (C.PATCH_DIR / name).resolve()
            C.git_apply(workdir, p, check=True)
            C.git_apply(workdir, p, check=False)
        got = C.tree_sha256(workdir)
        if got != expected_tree_sha:
            raise C.KsuError(f"应用后的树哈希与阶段树不一致: {got} != {expected_tree_sha}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="生成 7K 功能补丁序列")
    ap.add_argument("--research-root", default=str(C.RESEARCH_ROOT))
    ap.add_argument("--keep", action="store_true", help="保留临时目录（调试用）")
    args = ap.parse_args(argv)
    research = Path(args.research_root)
    if not (research / "KernelSU" / ".git").exists() or not (research / "7kimisu" / ".git").exists():
        raise C.KsuError(f"{research} 下缺少 KernelSU/7kimisu 的 git 仓库（来源快照不可得）")
    C.require_git()

    # C: 盘只剩 ~1GB（本机实测 100% 占用）；临时树必须放 D: 的仓库侧目录，
    # 否则两棵树（upstream 798 文件 + 7K 1896 文件）的连续副本会 ENOSPC。
    tmp_root = C.KSU_ROOT / ".tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="ksu-patches-", dir=str(tmp_root)))
    global S7K_ROOT
    S7K_ROOT = tmp / "s7k"
    stage = tmp / "stage"
    print(f"[1/4] exporting LF snapshots into {tmp}")
    C.export_git_tree(research / "KernelSU", C.UPSTREAM_COMMIT, tmp / UPSTREAM, clean=True)
    C.export_git_tree(research / "7kimisu", C.SOURCE7K_COMMIT, S7K_ROOT, clean=True)

    print("[2/4] building staged git repo and per-patch diffs")
    stage.mkdir(parents=True)
    C.copy_tree(tmp / UPSTREAM, stage)
    init = C.git(["-c", "init.defaultBranch=main", "init", "-q"], cwd=stage)
    if init.returncode != 0:
        raise C.KsuError(init.stderr.decode("utf-8", "replace"))

    names, entries = write_patches(C.PATCH_DIR, stage)
    final_sha = C.tree_sha256(stage, exclude_prefixes=(".git/",))

    print("[3/4] verifying series in a clean dir (--check + apply + tree hash)")
    verify_series(tmp / UPSTREAM, names, final_sha, tmp / "verify")

    print("[4/4] CR gate")
    bad = C.crlf_offenders(stage)
    if bad:
        raise C.KsuError(f"应用补丁后的构建相关树含 CR: {bad[:5]}")
    uapi = C.read_text(stage / "uapi/supercall.h")
    if "KERNEL_SU_UAPI_VERSION = 7;" not in uapi:
        raise C.KsuError("补丁后的 uapi/supercall.h 不是 UAPI 7")
    print(f"OK: {len(names)} 个补丁, treeSha256={final_sha}")
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print(f"kept temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except C.KsuError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
