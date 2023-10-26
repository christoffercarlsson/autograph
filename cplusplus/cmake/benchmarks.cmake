if(AUTOGRAPH_BENCHMARKS)
  set(BENCHMARK_ENABLE_TESTING OFF)

  add_subdirectory(cplusplus/benchmark)

  file(GLOB_RECURSE AUTOGRAPH_BENCHMARK_SOURCES
       ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/benchmarks/*.cpp)
  add_executable(autograph-benchmarks ${AUTOGRAPH_BENCHMARK_SOURCES})

  target_link_libraries(autograph-benchmarks PRIVATE ${AUTOGRAPH_TARGET}
                                                     benchmark::benchmark)

  target_include_directories(
    autograph-benchmarks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/cplusplus/include)

  list(APPEND AUTOGRAPH_INSTALL_TARGETS autograph-benchmarks)
endif()
