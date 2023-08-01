#!/bin/sh

set -e

SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${SOURCE_DIR}/build"

AUTOGRAPH_DEBUG=0
AUTOGRAPH_INSTALL=0
AUTOGRAPH_TESTS=0

while [ $# -gt 0 ]; do
  case $1 in
    -d | --debug)
      AUTOGRAPH_DEBUG=1
      shift
      ;;
    -i | --install)
      AUTOGRAPH_INSTALL=1
      shift
      ;;
    -t | --tests | --with-tests)
      AUTOGRAPH_INSTALL=1
      AUTOGRAPH_TESTS=1
      shift
      ;;
    *)
      echo "Invalid option: $1" >&2
      exit 1
      ;;
  esac
done

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
  cmake --no-warn-unused-cli \
        -DCMAKE_BUILD_TYPE=${AUTOGRAPH_BUILD_TYPE} \
        -DAUTOGRAPH_INSTALL=${AUTOGRAPH_INSTALL} \
        -DAUTOGRAPH_TESTS=${AUTOGRAPH_TESTS} \
        -B "${BUILD_DIR}" "${SOURCE_DIR}"
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
