cmake_minimum_required(VERSION 3.5)

if(DEFINED AUTOGRAPH_TOOLCHAIN AND NOT AUTOGRAPH_TOOLCHAIN STREQUAL "")
  set(CMAKE_TOOLCHAIN_FILE
      ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/cmake/toolchains/${AUTOGRAPH_TOOLCHAIN}.toolchain.cmake
  )
endif()

include(cplusplus/cmake/project.cmake)

if(NOT DEFINED PROJECT_NAME)
  project(
    ${AUTOGRAPH_PROJECT_NAME}
    VERSION ${AUTOGRAPH_PROJECT_VERSION}
    LANGUAGES C CXX)
endif()

include(cplusplus/cmake/sources.cmake)

if(DEFINED EMSCRIPTEN)
  include(cplusplus/cmake/emscripten.cmake)
else()
  add_library(${AUTOGRAPH_TARGET} STATIC ${AUTOGRAPH_SOURCES})
endif()

include(cplusplus/cmake/targets.cmake)
include(cplusplus/cmake/benchmarks.cmake)
include(cplusplus/cmake/tests.cmake)
include(cplusplus/cmake/install.cmake)
