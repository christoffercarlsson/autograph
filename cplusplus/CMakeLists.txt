cmake_minimum_required(VERSION 3.5)

project(autograph VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the libsodium package
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# Add source files
set(SOURCES
    src/autograph.cpp
    src/create_calculate_safety_number.cpp
    src/create_certify.cpp
    src/create_decrypt.cpp
    src/create_encrypt.cpp
    src/create_handshake.cpp
    src/create_key_pair.cpp
    src/create_party.cpp
    src/create_session.cpp
    src/create_verify.cpp
    src/decrypt.cpp
    src/derive_secret_keys.cpp
    src/diffie_hellman.cpp
    src/encrypt.cpp
    src/generate_ephemeral_key_pair.cpp
    src/get_transcript.cpp
    src/hash.cpp
    src/index_to_nonce.cpp
    src/kdf.cpp
    src/sign_message.cpp
    src/verify_signature.cpp
    src/verify_transcript.cpp
)

# Add header files
set(HEADERS
    include/autograph/create_calculate_safety_number.h
    include/autograph/create_certify.h
    include/autograph/create_decrypt.h
    include/autograph/create_encrypt.h
    include/autograph/create_handshake.h
    include/autograph/create_key_pair.h
    include/autograph/create_party.h
    include/autograph/create_session.h
    include/autograph/create_verify.h
    include/autograph/decrypt.h
    include/autograph/derive_secret_keys.h
    include/autograph/diffie_hellman.h
    include/autograph/encrypt.h
    include/autograph/generate_ephemeral_key_pair.h
    include/autograph/get_transcript.h
    include/autograph/hash.h
    include/autograph/index_to_nonce.h
    include/autograph/kdf.h
    include/autograph/sign_message.h
    include/autograph/types.h
    include/autograph/verify_signature.h
    include/autograph/verify_transcript.h
    include/autograph.h
)

# Add library target
add_library(autograph ${SOURCES} ${HEADERS})

# Link against libsodium
target_link_libraries(autograph PRIVATE ${LIBSODIUM_LIBRARIES})

# Set include directories
target_include_directories(autograph
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
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
