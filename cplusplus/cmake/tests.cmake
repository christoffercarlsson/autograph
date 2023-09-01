if(AUTOGRAPH_TESTS)
  add_subdirectory(catch2)

  file(GLOB_RECURSE AUTOGRAPH_TEST_SOURCES
       ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)
  add_executable(autograph-tests ${AUTOGRAPH_TEST_SOURCES})

  target_link_libraries(autograph-tests PRIVATE ${AUTOGRAPH_TARGET}
                                                Catch2::Catch2WithMain)

  target_include_directories(autograph-tests
                             PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

  list(APPEND AUTOGRAPH_INSTALL_TARGETS autograph-tests)
endif()
