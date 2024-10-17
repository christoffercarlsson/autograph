cmake_minimum_required(VERSION 3.5)

project(
  autograph
  VERSION 0.5.0
  LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(AUTOGRAPH_TARGET autograph)
set(AUTOGRAPH_CMAKE_LIST_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../cplusplus/cmake")

include(${AUTOGRAPH_CMAKE_LIST_DIR}/sources.cmake)

add_library(
  ${AUTOGRAPH_TARGET} SHARED
  ${AUTOGRAPH_SOURCES}
  auth.c
  cert.c
  channel.c
  support.c
  key_exchange.c
  key_pair.c
  message.c)

include(${AUTOGRAPH_CMAKE_LIST_DIR}/targets.cmake)
