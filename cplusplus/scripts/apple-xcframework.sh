#!/bin/sh

set -e

SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_INCLUDE_DIR="${SOURCE_DIR}/include"
PREFIX="${SOURCE_DIR}/build/apple"
XCFRAMEWORK_ARGS=""
RIMRAF_ARGS=""

if [ -d "$1" ]
then
    OUTPUT_DIR="$(cd "$1" && pwd)"
else
    OUTPUT_DIR="${PREFIX}"
fi

OUTPUT_PATH="${OUTPUT_DIR}/Clibautograph.xcframework"

if [ -d "${OUTPUT_PATH}" ]
then
    rm -rf "${OUTPUT_PATH}"
fi

swift_module_map() {
    echo 'module Clibautograph {'
    echo '  header "autograph.h"'
    echo '  export *'
    echo '}'
}

build_headers() {
    mkdir "${1}"
    cp "${SOURCE_INCLUDE_DIR}/autograph.h" "${1}/autograph.h"
    swift_module_map > "${1}/module.modulemap"
}

build_cmake() {
    local build_path="${PREFIX}/${1}/${2}"
    cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="${SOURCE_DIR}/cmake/toolchains/apple/${1}.toolchain.cmake" \
        -DCMAKE_OSX_ARCHITECTURES="${2}" \
        -DAUTOGRAPH_INSTALL=0 \
        -DAUTOGRAPH_TESTS=0 \
        -B "${build_path}" "${SOURCE_DIR}/.."
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
    xcodebuild -create-xcframework ${XCFRAMEWORK_ARGS} -output "${OUTPUT_PATH}" > /dev/null
}

rm -rf "${PREFIX}"
mkdir "${PREFIX}"

echo "[  1%] Building for iOS..."
build_target ios arm64

echo "[ 14%] Building for iOS Simulator..."
build_target ios-simulator arm64 x86_64

echo "[ 29%] Building for watchOS..."
build_target watchos arm64

echo "[ 43%] Building for watchOS Simulator..."
build_target watchos-simulator arm64 x86_64

echo "[ 57%] Building for macOS..."
build_target macos arm64 x86_64

echo "[ 71%] Building for tvOS..."
build_target tvos arm64

echo "[ 86%] Building for tvOS Simulator..."
build_target tvos-simulator arm64 x86_64

echo "[ 97%] Building XCFramework..."
build_framework

echo "[100%] Cleaning up..."
rm -rf ${RIMRAF_ARGS}

echo "Done!"
