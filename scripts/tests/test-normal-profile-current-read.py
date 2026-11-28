"""Run the complete selected profile JNI getter with controlled ioctl/JNI boundaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "third_party/kernelsu/applied/manager/app/src/main/cpp/jni.cc"


def getter(text):
    start = text.index('extern "C"\nJNIEXPORT jobject JNICALL\nJava_dev_maplesu_manager_ksu_KsuNatives_getAppProfile(')
    end = text.index('\nextern "C"', start + 1)
    return text[start:end]


def binding(path):
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--cxx", default="C:/msys64/ucrt64/bin/g++.exe")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = binding(args.source)
    production = getter(args.source.read_text(encoding="utf-8-sig").replace("\r\n", "\n"))
    harness = r'''
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
using jint = int;
using jlong = long long;
using jboolean = bool;
using jobject = void *;
using jclass = const char *;
using jfieldID = const char *;
using jstring = const char *;
#define JNIEXPORT
#define JNICALL
#define LOGD(...) ((void)0)
static constexpr int KSU_APP_PROFILE_VER = 1, KSU_MAX_GROUPS = 32, CAP_LAST_CAP = 40;
struct RootProfile {
    int uid = 0, gid = 0, groups_count = 0, groups[32] = {}, namespaces = 0;
    struct { uint64_t effective = 0; } capabilities;
    char selinux_domain[64] = {};
    uint64_t flags = 0;
};
struct app_profile {
    int version = 0, curr_uid = 0;
    char key[256] = {};
    bool allow_su = false;
    struct { bool use_default = true; char template_name[256] = {}; RootProfile profile; } rp_config;
    struct { bool use_default = true; struct { bool umount_modules = true; } profile; } nrp_config;
};
struct JNIEnv {
    std::map<std::string, long long> fields;
    JNIEnv() : fields{{"currentReadCode", INT_MIN}, {"currentReadErrno", 0}} {}
    jclass FindClass(const char *name) { return name; }
    const char *GetMethodID(jclass, const char *name, const char *) { return name; }
    jobject NewObject(jclass, const char *) { return this; }
    jfieldID GetFieldID(jclass, const char *name, const char *) { errno = EBUSY; return name; }
    const char *NewStringUTF(const char *value) { return value; }
    void SetObjectField(jobject, jfieldID, const char *) {}
    void SetIntField(jobject, jfieldID name, jint value) { fields[name] = value; }
    void SetBooleanField(jobject, jfieldID name, jboolean value) { fields[name] = value; }
    void SetLongField(jobject, jfieldID name, jlong value) { fields[name] = value; }
    jobject GetObjectField(jobject, jfieldID) { return this; }
};
template<class T> static bool jni_null(JNIEnv *, T value) { return value == nullptr; }
static bool copy_string_into(JNIEnv *, jstring value, char *output, size_t size) {
    if (!value || std::strlen(value) >= size) return false;
    std::strcpy(output, value);
    return true;
}
static void fillIntArray(JNIEnv *, jobject, int *, int) {}
static void addIntToList(JNIEnv *, jobject, int) {}
static int query_error = 0, query_calls = 0;
static bool query_allow = true;
static int get_app_profile(app_profile *profile) {
    ++query_calls;
    profile->allow_su = query_allow;
    errno = query_error;
    return query_error ? -1 : 0;
}
PRODUCTION_GETTER
static int failures = 0;
static void expect(bool pass, const char *name) {
    std::printf("%s %s\n", pass ? "PASS" : "FAIL", name);
    failures += !pass;
}
int main() {
    JNIEnv granted;
    auto allow = Java_dev_maplesu_manager_ksu_KsuNatives_getAppProfile(&granted, nullptr, "fixture.su", 110123);
    expect(allow && granted.fields["currentUid"] == 110123 && granted.fields["allowSu"] == 1,
        "successful getter preserves the full UID and grant");
    expect(granted.fields["currentReadCode"] == 0 && granted.fields["currentReadErrno"] == 0,
        "successful current ioctl has an explicit result");
    query_error = EACCES;
    JNIEnv denied;
    auto failed = Java_dev_maplesu_manager_ksu_KsuNatives_getAppProfile(&denied, nullptr, "fixture.su", 110123);
    expect(failed && denied.fields["allowSu"] == 0 && denied.fields["nonRootUseDefault"] == 1,
        "failed getter retains the legacy default non-authorized profile");
    expect(denied.fields["currentReadCode"] == -1 && denied.fields["currentReadErrno"] == EACCES,
        "failed ioctl preserves its raw status and errno before JNI lookup");
    query_error = 0; query_allow = false;
    JNIEnv revoked;
    Java_dev_maplesu_manager_ksu_KsuNatives_getAppProfile(&revoked, nullptr, "fixture.su", 110123);
    expect(revoked.fields["allowSu"] == 0 && revoked.fields["currentReadCode"] == 0,
        "a current deny is distinct from failed-read defaults");
    const int before = query_calls;
    JNIEnv invalid;
    auto invalid_key = Java_dev_maplesu_manager_ksu_KsuNatives_getAppProfile(&invalid, nullptr, nullptr, 110123);
    expect(invalid_key && query_calls == before && invalid.fields["allowSu"] == 0,
        "null keys preserve default behavior without an ioctl");
    expect(invalid.fields["currentReadCode"] == -1 && invalid.fields["currentReadErrno"] == EINVAL,
        "invalid input has a current local error rather than success");
    return failures ? 1 : 0;
}
'''.replace("PRODUCTION_GETTER", production)
    generated = out / "profile-current-read.cpp"
    generated.write_text(harness, encoding="utf-8")
    binary = out / "profile-current-read.exe"
    env = os.environ.copy()
    env["PATH"] = str(Path(args.cxx).parent) + os.pathsep + env.get("PATH", "")
    command = [args.cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", str(generated), "-o", str(binary)]
    compiled = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=60)
    (out / "compile.log").write_bytes(compiled.stdout + compiled.stderr)
    executed = None
    if compiled.returncode == 0:
        executed = subprocess.run([str(binary)], cwd=ROOT, env=env, capture_output=True, timeout=10)
        (out / "tests.log").write_bytes(executed.stdout + executed.stderr)
        print(executed.stdout.decode("utf-8", errors="replace"))
    result = {"passed": compiled.returncode == 0 and executed is not None and executed.returncode == 0,
              "compileExit": compiled.returncode, "testExit": None if executed is None else executed.returncode,
              "command": command, "source": before, "sourceDrift": binding(args.source) != before,
              "test": binding(Path(__file__)), "generated": binding(generated),
              "boundary": "Complete unmodified selected JNI getter; controlled ioctl and JNI object boundaries",
              "fullNativeTranslationUnit": False, "packaged": False, "deviceTested": False}
    (out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
