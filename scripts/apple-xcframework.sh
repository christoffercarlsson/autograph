#!/bin/sh

set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_DIR="${ROOT_DIR}/c"
SOURCE_INCLUDE_DIR="${SOURCE_DIR}/include"
PREFIX="${ROOT_DIR}/build/apple"
TARGET_INCLUDE_DIR="${PREFIX}/include"
XCFRAMEWORK_ARGS=""
RIMRAF_ARGS=""

swift_module_map() {
  echo 'module Clibautograph {'
  echo '  header "autograph.h"'
  echo '  export *'
  echo '}'
}

build_headers() {
  mkdir "${1}"
  cp "${SOURCE_INCLUDE_DIR}/autograph.h" "${1}"
  swift_module_map > "${1}/module.modulemap"
}

build_cmake() {
  local build_path="${PREFIX}/${1}/${2}"
  cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="${ROOT_DIR}/cmake/toolchains/apple/${1}.toolchain.cmake" \
        -DCMAKE_OSX_ARCHITECTURES="${2}" \
        -B "${build_path}" "${SOURCE_DIR}"
  (cd "${build_path}" && make)
}

build_target() {
  local platform="${1}"
  local headers_path="${PREFIX}/${platform}/include"
  local library_path="${PREFIX}/${platform}/libautograph.a"
  local lipo_args=""
  shift
  for arch in "$@"
  do
    build_cmake ${platform} ${arch} > /dev/null
    lipo_args="${lipo_args} ${PREFIX}/${platform}/${arch}/libautograph.a"
  done
  lipo -create ${lipo_args} -output ${library_path} > /dev/null
  build_headers "${headers_path}"
  XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -library ${library_path} -headers ${headers_path}"
  RIMRAF_ARGS="${RIMRAF_ARGS} ${PREFIX}/${platform}"
}

build_framework() {
  xcodebuild -create-xcframework ${XCFRAMEWORK_ARGS} -output "${PREFIX}/Clibautograph.xcframework" > /dev/null
}

rm -rf "${PREFIX}"

echo "(1/7) Building for iOS..."
build_target ios arm64

echo "(2/7) Building for iOS Simulator..."
build_target ios-simulator arm64 x86_64

echo "(3/7) Building for watchOS..."
build_target watchos arm64

echo "(4/7) Building for watchOS Simulator..."
build_target watchos-simulator arm64 x86_64

echo "(5/7) Building for macOS..."
build_target macos arm64

echo "(6/7) Building for tvOS..."
build_target tvos arm64

echo "(7/7) Building for tvOS Simulator..."
build_target tvos-simulator arm64 x86_64

echo "Building XCFramework..."
build_framework

echo "Cleaning up..."
rm -rf ${RIMRAF_ARGS}

echo "Done!"
