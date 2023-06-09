#!/bin/sh

SOURCE_DIR="$(cd "$(dirname "$0")/../c" && pwd)"
SODIUM_SOURCES_PATH="${SOURCE_DIR}/libsodium/src/libsodium"

find "${SODIUM_SOURCES_PATH}" \( -name "*.c" -o -name "*.h" \) -not -path "${SODIUM_SOURCES_PATH}/include/*" -type f -print0 | while read -d '' file; do
  realpath "$file" 
done | sort
