cmake_minimum_required(VERSION 3.5)

project(autograph VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})
link_directories(${LIBSODIUM_LIBRARY_DIRS})

# Add source files
set(SOURCES
    src/crypto/decrypt.cpp
    src/crypto/diffie_hellman.cpp
    src/crypto/encrypt.cpp
    src/crypto/hash.cpp
    src/crypto/index_to_nonce.cpp
    src/crypto/kdf.cpp
    src/crypto/sign_message.cpp
    src/crypto/verify_signature.cpp
    src/autograph.cpp
    src/create_calculate_safety_number.cpp
    src/create_certify.cpp
    src/create_decrypt.cpp
    src/create_encrypt.cpp
    src/create_handshake.cpp
    src/create_party.cpp
    src/create_session.cpp
    src/create_verify.cpp
    src/derive_secret_keys.cpp
    src/generate_ephemeral_key_pair.cpp
    src/get_transcript.cpp
    src/verify_transcript.cpp
)

# Add header files
set(HEADERS
    include/autograph/create_calculate_safety_number.h
    include/autograph/create_certify.h
    include/autograph/create_decrypt.h
    include/autograph/create_encrypt.h
    include/autograph/create_handshake.h
    include/autograph/create_party.h
    include/autograph/create_session.h
    include/autograph/create_verify.h
    include/autograph/crypto.h
    include/autograph/derive_secret_keys.h
    include/autograph/generate_ephemeral_key_pair.h
    include/autograph/get_transcript.h
    include/autograph/types.h
    include/autograph/verify_transcript.h
    include/autograph.h
)

# Add library target
add_library(autograph ${SOURCES} ${HEADERS})
target_include_directories(autograph PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(autograph PUBLIC sodium)

# Add unit tests
add_executable(autograph_tests
    test/generate_key_pair_test.cpp
)
target_include_directories(autograph_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(autograph_tests autograph)

# Install targets
install(TARGETS autograph
    EXPORT autographTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/autograph
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
install(EXPORT autographTargets
    FILE autographTargets.cmake
    NAMESPACE autograph::
    DESTINATION lib/cmake/autograph
)
