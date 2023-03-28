cmake_minimum_required(VERSION 3.5)

project(autograph VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the libsodium package
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# Add source files
set(SOURCES
    src/aes.cpp
    src/autograph_init.cpp
    src/autograph.cpp
    src/calculate_safety_number.cpp
    src/certify_ownership.cpp
    src/create_calculate_safety_number.cpp
    src/create_handshake.cpp
    src/create_session.cpp
    src/decrypt_message.cpp
    src/derive_secret_keys.cpp
    src/encrypt_message.cpp
    src/generate_key_pair.cpp
    src/handshake.cpp
    src/sign_message.cpp
    src/verify_ownership.cpp
    src/verify_session.cpp
    src/verify_signature.cpp
)

# Add header files
set(HEADERS
    include/autograph/aes.h
    include/autograph/autograph_init.h
    include/autograph/calculate_safety_number.h
    include/autograph/certify_ownership.h
    include/autograph/constants.h
    include/autograph/core.h
    include/autograph/create_calculate_safety_number.h
    include/autograph/create_handshake.h
    include/autograph/create_session.h
    include/autograph/decrypt_message.h
    include/autograph/derive_secret_keys.h
    include/autograph/encrypt_message.h
    include/autograph/generate_key_pair.h
    include/autograph/handshake.h
    include/autograph/sign_message.h
    include/autograph/types.h
    include/autograph/verify_ownership.h
    include/autograph/verify_session.h
    include/autograph/verify_signature.h
    include/autograph.h
)

# Add library target
add_library(autograph ${SOURCES} ${HEADERS})

# Link against libsodium
target_link_libraries(autograph PRIVATE ${LIBSODIUM_LIBRARIES})

# Set output name of the library
set_target_properties(autograph PROPERTIES OUTPUT_NAME autograph)

# Set include directories
target_include_directories(autograph
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${LIBSODIUM_INCLUDE_DIRS}
)

# Install headers and library
install(TARGETS autograph EXPORT autographTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(DIRECTORY include/ DESTINATION include)
install(EXPORT autographTargets
    FILE autographTargets.cmake
    NAMESPACE autograph::
    DESTINATION lib/cmake/autograph
)
