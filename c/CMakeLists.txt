cmake_minimum_required(VERSION 3.5)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/project.cmake)

if(NOT DEFINED PROJECT_NAME)
  project(
    ${AUTOGRAPH_PROJECT_NAME}
    VERSION ${AUTOGRAPH_PROJECT_VERSION}
    LANGUAGES C)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/targets.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/install.cmake)
