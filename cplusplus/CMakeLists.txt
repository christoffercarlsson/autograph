cmake_minimum_required(VERSION 3.5)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/project.cmake)

if(NOT DEFINED PROJECT_NAME)
  project(
    ${AUTOGRAPH_PROJECT_NAME}
    VERSION ${AUTOGRAPH_PROJECT_VERSION}
    LANGUAGES C CXX)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/sources.cmake)

file(GLOB_RECURSE AUTOGRAPH_CPP_SOURCES src/*.cpp)
list(APPEND AUTOGRAPH_SOURCES ${AUTOGRAPH_CPP_SOURCES})

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/targets.cmake)

if(AUTOGRAPH_TESTS)
  add_subdirectory(catch2)

  file(GLOB_RECURSE AUTOGRAPH_TEST_SOURCES tests/*.cpp)
  add_executable(autograph-tests ${AUTOGRAPH_TEST_SOURCES})

  target_link_libraries(autograph-tests PRIVATE autograph
                                                Catch2::Catch2WithMain)

  target_include_directories(autograph-tests PRIVATE include)

  list(APPEND AUTOGRAPH_INSTALL_TARGETS autograph-tests)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/install.cmake)
