target_include_directories(
  ${AUTOGRAPH_TARGET}
  PUBLIC $<INSTALL_INTERFACE:include>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../include>
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include/autograph
          ${CMAKE_CURRENT_LIST_DIR}/../libsodium/src/libsodium/include
          ${CMAKE_CURRENT_LIST_DIR}/../libsodium/src/libsodium/include/sodium)

target_compile_definitions(${AUTOGRAPH_TARGET} PRIVATE CONFIGURED DEV_MODE=0)

set(AUTOGRAPH_INSTALL_TARGETS ${AUTOGRAPH_TARGET})
