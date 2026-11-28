# SPDX-License-Identifier: GPL-3.0-or-later
"""Read Normal JNI identity from the current ioctl response on every call."""

CURRENT_INFO = """int get_current_info(struct ksu_get_info_cmd &info) {
    info = {};
    if (ksuctl(KSU_IOCTL_GET_INFO, &info) == 0) {
        return 0;
    }
    // Only an unsupported ioctl selects the older ABI. Permission/transport
    // failures are current failures, and partial copy-out bytes grant nothing.
    int error = errno ? errno : EIO;
    if (error == ENOTTY) {
        info = {};
        if (ksuctl(KSU_IOCTL_GET_INFO_LEGACY, &info) == 0) {
            info.uapi_version = 0;
            return 0;
        }
        error = errno ? errno : EIO;
    }
    info = {};
    errno = error;
    return -error;
}

struct ksu_get_info_cmd get_info() {
    struct ksu_get_info_cmd info {};
    get_current_info(info);
    return info;
}

"""

CURRENT_INFO_JNI = """extern "C"
JNIEXPORT jintArray JNICALL
Java_dev_maplesu_manager_ksu_KsuNatives_getCurrentInfo(JNIEnv *env, jobject) {
    struct ksu_get_info_cmd info {};
    jint status = get_current_info(info);
    // Match the existing pre-driver getVersion()/is_manager() contract using
    // one current legacy reply, without adding a fallback to the old getters.
    if (status == -EBADF || status == -ENOTTY) {
        const auto legacy = legacy_get_info();
        if (legacy.first > 0) {
            info.version = static_cast<uint32_t>(legacy.first);
            info.flags = static_cast<uint32_t>(legacy.second) | KSU_GET_INFO_FLAG_MANAGER;
            status = 0;
        }
    }
    if (status < 0) errno = -status;
    const jint values[] = {status, static_cast<jint>(info.version),
                           static_cast<jint>(info.flags), static_cast<jint>(info.uapi_version)};
    jintArray result = env->NewIntArray(4);
    if (result == nullptr) return nullptr;
    env->SetIntArrayRegion(result, 0, 4, values);
    return env->ExceptionCheck() ? nullptr : result;
}

"""


def patch_native_current_info(tree, _source):
    path = "manager/app/src/main/cpp/ksu.cc"
    text = tree.read(path)
    start = text.index("struct ksu_get_info_cmd get_info() {")
    end = text.index("uint32_t get_kernel_uapi_version()", start)
    tree.replace_once(path, text[start:end], CURRENT_INFO)
    tree.replace_once(path, "static struct ksu_get_info_cmd g_version {};\n\n", "")
    tree.replace_once(path,
        '        // 拿到 fd 说明现在能通了，把之前可能缓存的"不是管理器"结论作废\n'
        '        g_version = {};\n', "")
    tree.replace_once(path,
        "    /* get_info() 的结果被缓存在 g_version 里,切换隐身状态后必须让它\n"
        "     * 重新从内核读取 flags,否则 Natives.isManager 不会立刻变化。 */\n"
        "    g_version = {};\n", "")
    header = "manager/app/src/main/cpp/ksu.h"
    tree.replace_once(header, "uint32_t get_version();\n",
        "uint32_t get_version();\n\n"
        "// One current response: 0 on success, -errno on failure with zeroed fields.\n"
        "int get_current_info(struct ksu_get_info_cmd &info);\n")
    jni = "manager/app/src/main/cpp/jni.cc"
    tree.replace_once(jni, "#include <cstring>\n", "#include <cstring>\n#include <cerrno>\n")
    tree.replace_once(jni, '#include "logging.h"\n\n', '#include "logging.h"\n\n' + CURRENT_INFO_JNI)
    text = tree.read(jni)
    start = text.index('extern "C"\nJNIEXPORT jobject JNICALL\nJava_dev_maplesu_manager_ksu_KsuNatives_getAppProfile(')
    end = text.index('\nextern "C"', start + 1)
    original = text[start:end]
    profile = original
    replacements = {
        "    bool useDefaultProfile = !keyOk || get_app_profile(&profile) != 0;\n":
            "    const int currentReadCode = keyOk ? get_app_profile(&profile) : -1;\n"
            "    const int currentReadErrno = !keyOk ? EINVAL : currentReadCode == 0 ? 0 : errno;\n"
            "    const bool useDefaultProfile = currentReadCode != 0;\n",
        '    auto currentUidField = env->GetFieldID(cls, "currentUid", "I");\n':
            '    auto currentUidField = env->GetFieldID(cls, "currentUid", "I");\n'
            '    auto currentReadCodeField = env->GetFieldID(cls, "currentReadCode", "I");\n'
            '    auto currentReadErrnoField = env->GetFieldID(cls, "currentReadErrno", "I");\n',
        "    if (jni_null(env, keyField) || jni_null(env, currentUidField) || jni_null(env, allowSuField) ||\n":
            "    if (jni_null(env, keyField) || jni_null(env, currentUidField) ||\n"
            "        jni_null(env, currentReadCodeField) || jni_null(env, currentReadErrnoField) || jni_null(env, allowSuField) ||\n",
        "    env->SetIntField(obj, currentUidField, profile.curr_uid);\n":
            "    env->SetIntField(obj, currentUidField, profile.curr_uid);\n"
            "    env->SetIntField(obj, currentReadCodeField, currentReadCode);\n"
            "    env->SetIntField(obj, currentReadErrnoField, currentReadErrno);\n",
    }
    for before, after in replacements.items():
        assert profile.count(before) == 1, before
        profile = profile.replace(before, after, 1)
    tree.replace_once(jni, original, profile)
    return [path, header, jni]


PATCHES_NATIVE_CURRENT_INFO = [{
    "name": "0028-native-current-info.patch",
    "summary": "Read current Normal identity and profile ioctl results without cached or default-profile success",
    "apply": patch_native_current_info,
    "status": "implemented",
}]
