cmake_minimum_required(VERSION 3.5)

project(autograph VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the libsodium package
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# Add source files
set(SOURCES
    src/core/handshake.cpp
    src/core/init.cpp
    src/core/key_pair.cpp
    src/core/message.cpp
    src/core/ownership.cpp
    src/core/safety_number.cpp
    src/core/session.cpp
    src/crypto/aes.cpp
    src/crypto/diffie_hellman.cpp
    src/crypto/hash.cpp
    src/crypto/kdf.cpp
    src/crypto/sign.cpp
    src/autograph.cpp
    src/handshake.cpp
    src/key_pair.cpp
    src/party.cpp
    src/safety_number.cpp
    src/session.cpp
)

# Add header files
set(HEADERS
    include/autograph/core/handshake.h
    include/autograph/core/init.h
    include/autograph/core/key_pair.h
    include/autograph/core/message.h
    include/autograph/core/ownership.h
    include/autograph/core/safety_number.h
    include/autograph/core/session.h
    include/autograph/crypto/aes.h
    include/autograph/crypto/diffie_hellman.h
    include/autograph/crypto/hash.h
    include/autograph/crypto/kdf.h
    include/autograph/crypto/sign.h
    include/autograph/core.h
    include/autograph/handshake.h
    include/autograph/key_pair.h
    include/autograph/party.h
    include/autograph/safety_number.h
    include/autograph/session.h
    include/autograph/types.h
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
    DESTINATION lib/cmake/autograph
)
