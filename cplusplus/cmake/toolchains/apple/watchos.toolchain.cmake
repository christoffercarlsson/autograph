set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_OSX_SYSROOT "watchos")

if(AUTOGRAPH_ARCH STREQUAL "armv7k")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mthumb")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mthumb")
endif()

set(CMAKE_OSX_DEPLOYMENT_TARGET
    "9.0"
    CACHE STRING "Minimum watchOS deployment target")
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -arch ${CMAKE_OSX_ARCHITECTURES} -mwatchos-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}"
)
set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -arch ${CMAKE_OSX_ARCHITECTURES} -mwatchos-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}"
)
set(CMAKE_XCODE_ATTRIBUTE_WATCHOS_DEPLOYMENT_TARGET
    "${CMAKE_OSX_DEPLOYMENT_TARGET}")

set(CMAKE_XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "4")

set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_C_ARCHIVE_FINISH
    "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
set(CMAKE_CXX_ARCHIVE_FINISH
    "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
