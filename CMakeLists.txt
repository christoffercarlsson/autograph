cmake_minimum_required(VERSION 3.5)

include(cplusplus/cmake/project.cmake)

if(NOT DEFINED PROJECT_NAME)
  project(
    ${AUTOGRAPH_PROJECT_NAME}
    VERSION ${AUTOGRAPH_PROJECT_VERSION}
    LANGUAGES C CXX)
endif()

include(cplusplus/cmake/sources.cmake)
include(cplusplus/cmake/targets.cmake)
include(cplusplus/cmake/benchmarks.cmake)
include(cplusplus/cmake/tests.cmake)
include(cplusplus/cmake/install.cmake)
