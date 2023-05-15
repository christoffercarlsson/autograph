cmake_minimum_required(VERSION 3.5)

if(DEFINED AUTOGRAPH_TOOLCHAIN
   AND DEFINED AUTOGRAPH_ARCH
   AND NOT "${AUTOGRAPH_TOOLCHAIN}" STREQUAL ""
   AND NOT "${AUTOGRAPH_ARCH}" STREQUAL "")
  include(toolchains/${AUTOGRAPH_TOOLCHAIN}.toolchain.cmake)
endif()

if(APPLE)
  set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_C_ARCHIVE_FINISH
      "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
  set(CMAKE_CXX_ARCHIVE_FINISH
      "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

project(
  autograph
  VERSION 0.2.0
  LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MESSAGE_LOG_LEVEL ERROR)

execute_process(COMMAND "/bin/bash"
                        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/sodium-version.sh)
execute_process(
  COMMAND "/bin/bash" ${CMAKE_CURRENT_SOURCE_DIR}/scripts/sodium-sources.sh
  OUTPUT_VARIABLE SODIUM_SOURCES)
string(REPLACE "\n" ";" SODIUM_SOURCES ${SODIUM_SOURCES})

if(DEFINED AUTOGRAPH_CORE AND AUTOGRAPH_CORE EQUAL 1)
  file(GLOB_RECURSE AUTOGRAPH_SOURCES src/core/*.cpp src/crypto/*.cpp)
else()
  file(GLOB_RECURSE AUTOGRAPH_SOURCES src/*.cpp)
endif()

add_library(autograph STATIC ${SODIUM_SOURCES} ${AUTOGRAPH_SOURCES})

target_include_directories(
  autograph
  PUBLIC $<INSTALL_INTERFACE:include>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE include/autograph libsodium/src/libsodium/include
          libsodium/src/libsodium/include/sodium)

target_compile_definitions(autograph PRIVATE CONFIGURED)

if(DEFINED AUTOGRAPH_TESTS AND AUTOGRAPH_TESTS EQUAL 1)
  file(GLOB_RECURSE AUTOGRAPH_TEST_SOURCES tests/*.cpp)
  add_subdirectory(catch2)
  add_executable(autograph-tests ${AUTOGRAPH_TEST_SOURCES})
  target_link_libraries(autograph-tests PRIVATE autograph
                                                Catch2::Catch2WithMain)
  target_include_directories(autograph-tests PRIVATE include)
  set(AUTOGRAPH_INSTALL_TARGETS autograph autograph-tests)
else()
  set(AUTOGRAPH_INSTALL_TARGETS autograph)
endif()

install(
  TARGETS ${AUTOGRAPH_INSTALL_TARGETS}
  EXPORT autographTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES
  DESTINATION include)

if(DEFINED AUTOGRAPH_CORE AND AUTOGRAPH_CORE EQUAL 1)
  install(FILES include/autograph.h DESTINATION include)
else()
  install(FILES include/autograph.hpp DESTINATION include)
  install(FILES include/autograph/types.hpp DESTINATION include/autograph)
endif()

install(
  EXPORT autographTargets
  FILE autographTargets.cmake
  DESTINATION lib/cmake/autograph)
