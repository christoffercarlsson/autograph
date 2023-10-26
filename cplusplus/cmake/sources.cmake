execute_process(
  COMMAND "/bin/bash"
          ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/scripts/sodium-version.sh)
execute_process(
  COMMAND "/bin/bash"
          ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/scripts/sodium-sources.sh
  OUTPUT_VARIABLE SODIUM_SOURCES)
string(REPLACE "\n" ";" SODIUM_SOURCES ${SODIUM_SOURCES})

file(GLOB_RECURSE AUTOGRAPH_C_SOURCES
     ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/src/*.c)
file(GLOB_RECURSE AUTOGRAPH_CPP_SOURCES
     ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/src/*.cpp)

set(AUTOGRAPH_SOURCES ${SODIUM_SOURCES} ${AUTOGRAPH_C_SOURCES}
                      ${AUTOGRAPH_CPP_SOURCES})
