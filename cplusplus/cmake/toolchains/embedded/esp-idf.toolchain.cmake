include($ENV{IDF_PATH}/tools/cmake/project.cmake)

add_definitions(
  -DRANDOMBYTES_DEFAULT_IMPLEMENTATION
  -D__STDC_CONSTANT_MACROS
  -D__STDC_LIMIT_MACROS
  -fexceptions
  -Wno-deprecated-declarations
  -Wno-implicit-fallthrough
  -Wno-type-limits
  -Wno-unknown-pragmas
  -Wno-unused-function
  -Wno-unused-variable)
