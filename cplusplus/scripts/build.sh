#!/bin/sh

set -e

SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_INCLUDE_DIR="${SOURCE_DIR}/include"
TOOLCHAIN="${1}"
TOOLCHAIN_FILE="${SOURCE_DIR}/toolchains/${TOOLCHAIN}.toolchain.cmake"
PREFIX="${SOURCE_DIR}/build/${TOOLCHAIN}"
TARGET_ARCH="${2}"

if [[ -n "${TARGET_ARCH}" ]]
then
  TARGET_DIR="${PREFIX}/${TARGET_ARCH}"
else
  TARGET_DIR="${PREFIX}"
fi

if [[ -n "${TOOLCHAIN}" && -z "${TARGET_ARCH}" ]]
then
  echo "Target architecture not specified" >&2
  exit 1
fi

if [[ -n "${TOOLCHAIN}" && ! -f "${TOOLCHAIN_FILE}" ]]
then
  echo "Toolchain file not found: ${TOOLCHAIN_FILE}" >&2
  exit 1
fi

AUTOGRAPH_CORE=$(tr '[:upper:]' '[:lower:]' <<< "${AUTOGRAPH_CORE}")
if [[ "${AUTOGRAPH_CORE}" == "1" || "${AUTOGRAPH_CORE}" == "true" ]]
then
  AUTOGRAPH_CORE=1
else
  AUTOGRAPH_CORE=0
fi

AUTOGRAPH_TESTS=$(tr '[:upper:]' '[:lower:]' <<< "${AUTOGRAPH_TESTS}")
if [[ "${AUTOGRAPH_TESTS}" == "1" || "${AUTOGRAPH_TESTS}" == "true" ]]
then
  AUTOGRAPH_TESTS=1
else
  AUTOGRAPH_TESTS=0
fi

AUTOGRAPH_BUILD_TYPE=$(tr '[:upper:]' '[:lower:]' <<< "${AUTOGRAPH_BUILD_TYPE}")
if [[ "${AUTOGRAPH_BUILD_TYPE}" == "d" || "${AUTOGRAPH_BUILD_TYPE}" == "debug" ]]
then
  AUTOGRAPH_BUILD_TYPE="Debug"
else
  AUTOGRAPH_BUILD_TYPE="Release"
fi

generate_cmake() {
  rm -rf "${TARGET_DIR}"
  cmake --no-warn-unused-cli \
        -DAUTOGRAPH_CORE=${AUTOGRAPH_CORE} \
        -DAUTOGRAPH_TESTS=${AUTOGRAPH_TESTS} \
        -DAUTOGRAPH_TOOLCHAIN=${TOOLCHAIN} \
        -DAUTOGRAPH_ARCH=${TARGET_ARCH} \
        -DCMAKE_BUILD_TYPE=${AUTOGRAPH_BUILD_TYPE} \
        -B "${TARGET_DIR}" "${SOURCE_DIR}"
}

build_target() {
  (cd "${TARGET_DIR}" && make)
}

generate_cmake > /dev/null
build_target > /dev/null

echo "${TARGET_DIR}"
