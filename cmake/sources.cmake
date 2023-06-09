execute_process(COMMAND "/bin/bash"
                        ${CMAKE_CURRENT_LIST_DIR}/../scripts/sodium-version.sh)
execute_process(
  COMMAND "/bin/bash" ${CMAKE_CURRENT_LIST_DIR}/../scripts/sodium-sources.sh
  OUTPUT_VARIABLE SODIUM_SOURCES)
string(REPLACE "\n" ";" SODIUM_SOURCES ${SODIUM_SOURCES})

file(GLOB_RECURSE AUTOGRAPH_C_SOURCES ${CMAKE_CURRENT_LIST_DIR}/../c/src/*.c)

set(AUTOGRAPH_SOURCES ${SODIUM_SOURCES} ${AUTOGRAPH_C_SOURCES})
