#!/bin/sh

set -e

SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${SOURCE_DIR}/build"

AUTOGRAPH_BENCHMARKS=0
AUTOGRAPH_DEBUG=0
AUTOGRAPH_INSTALL=0
AUTOGRAPH_TESTS=0
AUTOGRAPH_WASM=0

while [ $# -gt 0 ]; do
  case $1 in
    -b | --benchmarks | --with-benchmarks)
      AUTOGRAPH_BENCHMARKS=1
      AUTOGRAPH_INSTALL=1
      shift
      ;;
    -d | --debug)
      AUTOGRAPH_DEBUG=1
      shift
      ;;
    -i | --install)
      AUTOGRAPH_INSTALL=1
      shift
      ;;
    -t | --tests | --with-tests)
      AUTOGRAPH_BENCHMARKS=1
      AUTOGRAPH_INSTALL=1
      AUTOGRAPH_TESTS=1
      shift
      ;;
    -w | --wasm | --web-assembly)
      AUTOGRAPH_WASM=1
      shift
      ;;
    *)
      echo "Invalid option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "${AUTOGRAPH_WASM}" == "1" ]]
then
  AUTOGRAPH_BENCHMARKS=0
  AUTOGRAPH_DEBUG=0
  AUTOGRAPH_INSTALL=0
  AUTOGRAPH_TESTS=0
  AUTOGRAPH_CMAKE_CMD="emcmake cmake"
else
  AUTOGRAPH_CMAKE_CMD="cmake"
fi

if [[ "${AUTOGRAPH_INSTALL}" == "1" ]]
then
  sudo -v
fi

if [[ "${AUTOGRAPH_DEBUG}" == "1" ]]
then
  AUTOGRAPH_BUILD_TYPE="Debug"
else
  AUTOGRAPH_BUILD_TYPE="Release"
fi

generate_cmake() {
  rm -rf "${BUILD_DIR}"
  ${AUTOGRAPH_CMAKE_CMD} --no-warn-unused-cli \
    -DCMAKE_BUILD_TYPE=${AUTOGRAPH_BUILD_TYPE} \
    -DAUTOGRAPH_BENCHMARKS=${AUTOGRAPH_BENCHMARKS} \
    -DAUTOGRAPH_INSTALL=${AUTOGRAPH_INSTALL} \
    -DAUTOGRAPH_TESTS=${AUTOGRAPH_TESTS} \
    -B "${BUILD_DIR}" "${SOURCE_DIR}/.."
}

build_target() {
  if [[ "${AUTOGRAPH_INSTALL}" == "1" ]]
  then
    (cd "${BUILD_DIR}" && sudo make install)
  else
    (cd "${BUILD_DIR}" && make)
  fi
}

generate_cmake > /dev/null
build_target
