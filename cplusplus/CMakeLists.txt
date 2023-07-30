cmake_minimum_required(VERSION 3.5)

include(cmake/project.cmake)

if(NOT DEFINED PROJECT_NAME)
  project(
    ${AUTOGRAPH_PROJECT_NAME}
    VERSION ${AUTOGRAPH_PROJECT_VERSION}
    LANGUAGES C CXX)
endif()

include(cmake/sources.cmake)
include(cmake/targets.cmake)
include(cmake/tests.cmake)
include(cmake/install.cmake)
