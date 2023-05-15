#!/bin/sh

set -e

while [ $# -gt 0 ]; do
  case $1 in
    -t | --tests | --with-tests)
      export AUTOGRAPH_TESTS=1
      shift
      ;;
    *)
      echo "Invalid option: $1" >&2
      exit 1
      ;;
  esac
done

sudo -v

if [[ "${AUTOGRAPH_TESTS}" == "1" ]]
then
  echo "Installing with tests..."
else
  echo "Installing without any tests..."
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="$(realpath "$(${SCRIPT_DIR}/build.sh)")"

(cd "${TARGET_DIR}" && sudo make install)
rm -rf "${TARGET_DIR}"
