set(AUTOGRAPH_PROJECT_NAME autograph)
set(AUTOGRAPH_PROJECT_VERSION 1.0.0)

set(AUTOGRAPH_TARGET autograph)

set(AUTOGRAPH_INSTALL ON)

if(NOT DEFINED PROJECT_NAME)
  set(CMAKE_C_STANDARD 11)
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_C_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_MESSAGE_LOG_LEVEL ERROR)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
else()
  set(AUTOGRAPH_BENCHMARKS OFF)
  set(AUTOGRAPH_INSTALL OFF)
  set(AUTOGRAPH_TESTS OFF)
endif()
