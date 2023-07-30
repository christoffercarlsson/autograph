add_library(${AUTOGRAPH_LIBRARY_TARGET} STATIC ${AUTOGRAPH_SOURCES})

target_include_directories(
  ${AUTOGRAPH_LIBRARY_TARGET}
  PUBLIC $<INSTALL_INTERFACE:include>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/autograph
          ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include
          ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include/sodium)

target_compile_definitions(${AUTOGRAPH_LIBRARY_TARGET} PRIVATE CONFIGURED
                                                               DEV_MODE=0)

set(AUTOGRAPH_INSTALL_TARGETS ${AUTOGRAPH_LIBRARY_TARGET})
