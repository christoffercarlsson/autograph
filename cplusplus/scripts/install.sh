#!/bin/sh

set -e

sudo -v

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="$(realpath "$(${SCRIPT_DIR}/build.sh)")"

(cd "${TARGET_DIR}" && sudo make install)
rm -rf "${TARGET_DIR}"
