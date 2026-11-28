"""Compile the selected production GET_INFO functions against controlled ioctl replies.

The Android syscall boundary is substituted; function bodies and GET_INFO fields
are copied unchanged from the selected production sources. This is a host native
regression, not a device, SELinux, complete JNI or product identity acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CPP = ROOT / "third_party/kernelsu/applied/manager/app/src/main/cpp"


def function(text, name):
    signature = r"^(?:(?:struct ksu_get_info_cmd|uint32_t|bool|int) |JNIEXPORT jintArray JNICALL\s+)"
    match = re.search(signature + name + r"\([^)]*\) \{", text, re.M)
    if not match:
        raise ValueError("Missing production function: " + name)
    depth = 1
    index = match.end()
    while depth:
        depth += (text[index] == "{") - (text[index] == "}")
        index += 1
    return text[match.start():index] + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--cxx", default=os.environ.get("CXX") or shutil.which("g++") or shutil.which("clang++"))
    args = parser.parse_args()
    if not args.cxx:
        parser.error("Set CXX or pass --cxx for the host C++ compiler")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = (CPP / "ksu.cc").read_text(encoding="utf-8")
    uapi = (CPP / "uapi/supercall.h").read_text(encoding="utf-8")
    declaration = re.search(r"struct ksu_get_info_cmd \{.*?\n\};", uapi, re.S).group().replace("__u32", "uint32_t")
    constants = "\n".join(re.findall(r"^static const __u32 KSU_GET_INFO_FLAG_.*;$", uapi, re.M)).replace("__u32", "uint32_t")
    names = ["get_current_info", "get_info", "get_kernel_uapi_version", "get_version", "is_lkm_mode", "is_lkm_bundled", "is_late_load_mode", "is_manager", "is_pr_build"]
    cache = "static struct ksu_get_info_cmd g_version {};\n" if "static struct ksu_get_info_cmd g_version" in source else ""
    harness = r'''
#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <utility>
DECLARATION
CONSTANTS
static constexpr unsigned long KSU_IOCTL_GET_INFO = 2, KSU_IOCTL_GET_INFO_LEGACY = 3;
struct Reply { int error; ksu_get_info_cmd info; };
static Reply modern, legacy;
static int modern_calls, legacy_calls, prctl_calls, failures;
static std::pair<int, int> prctl_info {-1, 0};
static int ksuctl(unsigned long op, ksu_get_info_cmd *info) {
    const Reply &reply = op == KSU_IOCTL_GET_INFO ? modern : legacy;
    if (op == KSU_IOCTL_GET_INFO) ++modern_calls; else ++legacy_calls;
    *info = reply.info;  // Failed copy-out can have touched the caller buffer.
    if (reply.error) { errno = reply.error; return -1; }
    return 0;
}
static std::pair<int, int> legacy_get_info() { ++prctl_calls; return prctl_info; }
CACHE
FUNCTIONS
using jint = int32_t;
struct Array { jint values[4]; };
using jintArray = Array *;
using jobject = void *;
#define JNIEXPORT
#define JNICALL
struct JNIEnv {
    Array result {};
    bool allocation = true, exception = false;
    jintArray NewIntArray(int size) { return allocation && size == 4 ? &result : nullptr; }
    void SetIntArrayRegion(jintArray array, int start, int count, const jint *values) {
        if (!exception) std::memcpy(array->values + start, values, count * sizeof(jint));
    }
    bool ExceptionCheck() { return exception; }
};
JNI_FUNCTION
static void expect(bool condition, const char *name) {
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++failures;
}
static void current(uint32_t flags) {
    modern = {0, {32650, flags, 9, 7}};
    legacy = {ENOTTY, {}};
}
int main() {
    const uint32_t all = KSU_GET_INFO_FLAG_MANAGER | KSU_GET_INFO_FLAG_LKM |
        KSU_GET_INFO_FLAG_BUNDLED | KSU_GET_INFO_FLAG_LATE_LOAD | KSU_GET_INFO_FLAG_PR_BUILD;
    current(all);
    expect(get_version() == 32650 && is_manager(), "initial current Normal manager");
    const int before = modern_calls;
    expect(get_version() == 32650 && modern_calls == before + 1, "positive version is read again");
    current(0);
    expect(!is_manager(), "current manager revocation replaces positive");
    expect(!is_lkm_mode() && !is_lkm_bundled() && !is_late_load_mode() && !is_pr_build(), "current mode flags replace positive");
    current(all);
    expect(is_manager(), "current manager recovery is immediate");
    modern = {EACCES, {32650, all, 9, 7}};
    legacy = {EACCES, {32650, all, 9, 7}};
    const int denied_legacy = legacy_calls;
    const auto denied = get_info();
    expect(denied.version == 0 && denied.flags == 0 && denied.features == 0 && denied.uapi_version == 0,
        "denied current read discards old and partial positives");
    expect(errno == EACCES && legacy_calls == denied_legacy, "access denial preserves errno without ABI fallback");
    expect(get_version() == 0 && !is_manager() && !is_lkm_bundled(), "current consumers lose stale capabilities");
    modern = {ENOTTY, {32650, all, 9, 7}};
    legacy = {0, {32000, KSU_GET_INFO_FLAG_MANAGER, 3, 99}};
    const auto compat = get_info();
    expect(compat.version == 32000 && compat.flags == KSU_GET_INFO_FLAG_MANAGER && compat.uapi_version == 0,
        "legacy ioctl remains available and reports no new UAPI");
    legacy = {EPIPE, {32650, all, 9, 7}};
    const auto gone = get_info();
    expect(gone.version == 0 && gone.flags == 0 && gone.features == 0 && gone.uapi_version == 0 && errno == EPIPE,
        "failed legacy reply discards partial bytes and preserves errno");
    current(0);
    modern.info.version = 0;
    expect(get_version() == 0 && !is_manager(), "current absent response never reuses prior boot identity");
    current(all);
    expect(get_kernel_uapi_version() == 7 && is_lkm_mode() && is_lkm_bundled() && is_late_load_mode() && is_pr_build(),
        "all info consumers recover from current evidence");
    JNIEnv env;
    const int snapshot_calls = modern_calls;
    const auto snapshot = Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr);
    expect(snapshot && snapshot->values[0] == 0 && snapshot->values[1] == 32650 &&
        snapshot->values[2] == static_cast<jint>(all) && snapshot->values[3] == 7 && modern_calls == snapshot_calls + 1,
        "JNI snapshot carries fields from one current reply");
    current(0);
    const auto revoked = Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr);
    expect(revoked && revoked->values[0] == 0 && revoked->values[1] == 32650 && revoked->values[2] == 0,
        "JNI snapshot records current manager revocation");
    modern = {EACCES, {32650, all, 9, 7}};
    const int denied_prctl = prctl_calls;
    const auto denied_snapshot = Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr);
    expect(denied_snapshot && denied_snapshot->values[0] == -EACCES && denied_snapshot->values[1] == 0 &&
        denied_snapshot->values[2] == 0 && denied_snapshot->values[3] == 0 && prctl_calls == denied_prctl && errno == EACCES,
        "JNI denial preserves error and grants no partial fields or fallback");
    modern = {ENOTTY, {32650, all, 9, 7}};
    legacy = {0, {32000, KSU_GET_INFO_FLAG_MANAGER, 3, 99}};
    const auto legacy_snapshot = Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr);
    expect(legacy_snapshot && legacy_snapshot->values[0] == 0 && legacy_snapshot->values[1] == 32000 &&
        legacy_snapshot->values[2] == static_cast<jint>(KSU_GET_INFO_FLAG_MANAGER) && legacy_snapshot->values[3] == 0,
        "JNI current snapshot retains the legacy ioctl ABI");
    modern = {EBADF, {32650, all, 9, 7}};
    prctl_info = {12345, KSU_GET_INFO_FLAG_LKM};
    const int old_getter_prctl = prctl_calls;
    expect(is_manager() && prctl_calls == old_getter_prctl + 1,
        "existing manager getter keeps one legacy fallback");
    const int snapshot_prctl = prctl_calls;
    const auto predriver = Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr);
    expect(predriver && predriver->values[0] == 0 && predriver->values[1] == 12345 &&
        predriver->values[2] == static_cast<jint>(KSU_GET_INFO_FLAG_MANAGER | KSU_GET_INFO_FLAG_LKM) && predriver->values[3] == 0 &&
        prctl_calls == snapshot_prctl + 1,
        "JNI current snapshot retains pre-driver prctl manager compatibility");
    prctl_info = {-1, 0};
    const auto no_response = Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr);
    expect(no_response && no_response->values[0] == -EBADF && no_response->values[1] == 0 &&
        no_response->values[2] == 0 && no_response->values[3] == 0,
        "missing current legacy reply never reuses a positive snapshot");
    current(all);
    env.allocation = false;
    expect(Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr) == nullptr,
        "JNI allocation failure does not publish an array");
    env.allocation = true; env.exception = true;
    expect(Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(&env, nullptr) == nullptr,
        "JNI copy exception does not publish a partial array");
    return failures ? 1 : 0;
}
'''
    for key, value in {"DECLARATION": declaration, "CONSTANTS": constants, "CACHE": cache,
                       "FUNCTIONS": "\n".join(function(source, name) for name in names),
                       "JNI_FUNCTION": function((CPP / "jni.cc").read_text(encoding="utf-8"),
                           "Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo")}.items():
        harness = harness.replace(key, value)
    test_source = out / "normal-current-info.cpp"
    test_source.write_text(harness, encoding="utf-8", newline="\n")
    exe = out / ("normal-current-info.exe" if os.name == "nt" else "normal-current-info")
    env = os.environ.copy()
    env["PATH"] = str(Path(args.cxx).resolve().parent) + os.pathsep + env.get("PATH", "")
    result = subprocess.run([args.cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", str(test_source), "-o", str(exe)], capture_output=True, text=True, env=env, timeout=60)
    (out / "compile.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout + result.stderr, end="")
    if result.returncode == 0:
        result = subprocess.run([str(exe)], capture_output=True, text=True, env=env, timeout=10)
        (out / "tests.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        print(result.stdout + result.stderr, end="")
    inputs = [CPP / "ksu.cc", CPP / "ksu.h", CPP / "jni.cc", CPP / "uapi/supercall.h", Path(__file__)]
    (out / "RESULT.json").write_text(json.dumps({"passed": result.returncode == 0,
        "returncode": result.returncode, "functions": names,
        "sourceSha256": {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
        "boundary": "Host compiled exact production functions, controlled ioctl/prctl boundary",
        "fullNativeTranslationUnit": False, "deviceTested": False}, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
