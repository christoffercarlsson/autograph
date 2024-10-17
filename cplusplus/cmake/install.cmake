if(AUTOGRAPH_INSTALL)
  install(
    TARGETS ${AUTOGRAPH_INSTALL_TARGETS}
    EXPORT autograph-targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES
    DESTINATION include)

  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/include/autograph.h
          DESTINATION include)

  install(
    EXPORT autograph-targets
    FILE autograph-targets.cmake
    DESTINATION lib/cmake/autograph)
endif()
