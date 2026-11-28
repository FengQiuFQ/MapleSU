#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# MapleSU · KSU JNI（libmaplesu_ksu.so + libadbroot.so）构建入口。
#
# 源码在 applied/manager/app/src/main/cpp/（0010 补丁把 7K 的 jni.cc/ksu.cc 搬进来并
# 机械改名为 Java_dev_maplesu_manager_ksu_KsuNatives_*，CMake 直接 -I applied/ 根拿 uapi）。
#
# 两种接法：
#   A) Gradle：manager/build.gradle.kts 的 externalNativeBuild 随 APK 构建当前源码；
#      不会消费 jniLibs 中留存的 libmaplesu_ksu.so / libadbroot.so；
#   B) 本脚本：维护/CI 的 CMake + NDK 导入入口，产物写入留存 jniLibs。
#
# 用法：
#   bash third_party/kernelsu/scripts/build_jni.sh --dry-run
#   ANDROID_NDK_HOME=<ndk> bash third_party/kernelsu/scripts/build_jni.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSU_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$KSU_ROOT/../.." && pwd)"
CPP_DIR="$KSU_ROOT/applied/manager/app/src/main/cpp"
JNI_DIR="$REPO_ROOT/manager/src/main/jniLibs/arm64-v8a"
BUILD_DIR="$KSU_ROOT/.tmp/jni-build"

DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
[ -f "$CPP_DIR/CMakeLists.txt" ] || die "缺 $CPP_DIR/CMakeLists.txt（先跑 rebuild.sh）"
[ -f "$CPP_DIR/jni.cc" ] || die "缺 $CPP_DIR/jni.cc"
[ -f "$KSU_ROOT/applied/uapi/supercall.h" ] || die "缺 applied/uapi/supercall.h"
grep -q 'Java_dev_maplesu_manager_ksu_KsuNatives_' "$CPP_DIR/jni.cc" || \
  die "jni.cc 未改名（0010 补丁未应用）"
COUNT_SYMBOLS="$(grep -c 'Java_dev_maplesu_manager_ksu_KsuNatives_' "$CPP_DIR/jni.cc" || true)"
[ "$COUNT_SYMBOLS" -ge 25 ] || die "导出符号不足 25 个（实际 $COUNT_SYMBOLS）"

: "${ANDROID_NDK_HOME:=${ANDROID_NDK_HOME:-}}"
if [ -z "$ANDROID_NDK_HOME" ]; then
  for cand in "${ANDROID_HOME:-}/ndk/26.1.10909125" "${ANDROID_SDK_ROOT:-}/ndk/26.1.10909125" \
              "$HOME/Android/Sdk/ndk/26.1.10909125" "/opt/android-ndk-r29"; do
    if [ -d "$cand" ]; then ANDROID_NDK_HOME="$cand"; break; fi
  done
fi

CMAKE_BIN="${CMAKE_BIN:-cmake}"
TOOLCHAIN="${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake"
# Android 15+ 的 16KB page 设备要求 ELF LOAD 段 align >= 0x4000（NDK 26 默认仍是 4KB；
# NDK r28+ 才默认 16KB）。本仓用 NDK 26.1 构建，必须显式传 max-page-size=16384，
# 否则 verify 的 readelf -l 断言会失败（W12d 实测）。
PAGE16_LDFLAGS="-Wl,-z,max-page-size=16384"
CMAKE_ARGS=(-S "$CPP_DIR" -B "$BUILD_DIR" -G Ninja
  "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN"
  "-DCMAKE_SHARED_LINKER_FLAGS=$PAGE16_LDFLAGS"
  "-DCMAKE_EXE_LINKER_FLAGS=$PAGE16_LDFLAGS"
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-31
  -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release)

echo "== KSU JNI build"
echo "   source:   $CPP_DIR"
echo "   ndk:      ${ANDROID_NDK_HOME:-MISSING}"
echo "   symbols:  $COUNT_SYMBOLS (expect 25)"
echo "   cmd:      $CMAKE_BIN ${CMAKE_ARGS[*]} && $CMAKE_BIN --build $BUILD_DIR"

if [ "$DRY_RUN" = "1" ]; then
  echo "== dry-run: verifying source surface"
  for f in jni.cc ksu.cc ksu.h logging.h adbroot.cc CMakeLists.txt; do
    [ -f "$CPP_DIR/$f" ] || die "缺 $CPP_DIR/$f"
  done
  grep -q 'KSU_MANAGER_GEN' "$CPP_DIR/ksu.cc" || die "ksu.cc 缺 KSU_MANAGER_GEN"
  grep -q 'com/maplesu/core/Natives$Profile' "$CPP_DIR/jni.cc" || \
    die "jni.cc 的 Profile FindClass 必须是 com/maplesu/core/Natives\$Profile（MapleSU 同 FQN）"
  echo "OK dry-run: JNI source surface complete"
  exit 0
fi

[ -n "$ANDROID_NDK_HOME" ] && [ -d "$ANDROID_NDK_HOME" ] || die "ANDROID_NDK_HOME 不存在"
command -v "$CMAKE_BIN" >/dev/null 2>&1 || die "cmake 不可用"
mkdir -p "$JNI_DIR" "$KSU_ROOT/.tmp"
"$CMAKE_BIN" "${CMAKE_ARGS[@]}"
"$CMAKE_BIN" --build "$BUILD_DIR" --parallel 2

cp -f "$BUILD_DIR/libmaplesu_ksu.so" "$JNI_DIR/libmaplesu_ksu.so"
cp -f "$BUILD_DIR/libadbroot.so" "$JNI_DIR/libadbroot.so"
echo "OK: $JNI_DIR/libmaplesu_ksu.so"
echo "OK: $JNI_DIR/libadbroot.so"
echo "设备断言（03 §7.3）：KsuNatives.version>0 && isManager && kernelUAPIVersion==7"
echo "下一步：python3 $SCRIPT_DIR/gen_payload.py"
