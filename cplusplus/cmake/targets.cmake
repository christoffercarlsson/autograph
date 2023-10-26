if(DEFINED EMSCRIPTEN)
  include(${CMAKE_CURRENT_LIST_DIR}/emscripten.cmake)
else()
  add_library(${AUTOGRAPH_TARGET} STATIC ${AUTOGRAPH_SOURCES})
endif()

target_include_directories(
  ${AUTOGRAPH_TARGET}
  PUBLIC $<INSTALL_INTERFACE:include>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/include/autograph
    ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/libsodium/src/libsodium/include
    ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/libsodium/src/libsodium/include/sodium
)

target_compile_definitions(${AUTOGRAPH_TARGET} PRIVATE CONFIGURED DEV_MODE=0)

set(AUTOGRAPH_INSTALL_TARGETS ${AUTOGRAPH_TARGET})
