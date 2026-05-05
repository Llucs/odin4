cmake_minimum_required(VERSION 3.10)
project(odin4 LANGUAGES C CXX)

# =========================
# C / C++ Standards
# =========================
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# =========================
# Build flags
# =========================
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# =========================
# Dependencies
# =========================
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

# Prefer Crypto++ static to avoid runtime dependency on libcrypto++.so
find_path(CRYPTOPP_INCLUDE_DIR cryptlib.h
    PATHS
        /usr/local/include
        /usr/include
    PATH_SUFFIXES
        cryptopp
        crypto++
)

# Force static lookup for Crypto++ only
set(_OLD_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(CMAKE_FIND_LIBRARY_SUFFIXES .a)

find_library(CRYPTOPP_STATIC_LIB
    NAMES cryptopp libcryptopp
    PATHS
        /usr/local/lib
        /usr/local/lib64
        /usr/lib
        /usr/lib64
        /usr/lib/x86_64-linux-gnu
        /usr/lib/aarch64-linux-gnu
)

set(CMAKE_FIND_LIBRARY_SUFFIXES ${_OLD_CMAKE_FIND_LIBRARY_SUFFIXES})

if (CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_STATIC_LIB AND CRYPTOPP_STATIC_LIB MATCHES "\\.a$")
    set(CRYPTOPP_USE_STATIC ON)
else()
    set(CRYPTOPP_USE_STATIC OFF)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)
endif()

# =========================
# LZ4 static library (C)
# =========================
add_library(lz4_lib STATIC
    lib/lz4/lz4.c
    lib/lz4/lz4hc.c
    lib/lz4/lz4frame.c
    lib/lz4/xxhash.c
)
target_include_directories(lz4_lib PUBLIC lib/lz4)

# =========================
# Shared Library (C++)
# =========================
add_library(odin4_lib SHARED
    src/odin4.cpp
    src/core/logger.cpp
    src/usb/usb_device.cpp
    src/firmware/firmware_package.cpp
)
set_target_properties(odin4_lib PROPERTIES 
    OUTPUT_NAME "odin4"
    VERSION "5.1.0"
    SOVERSION "5"
)

target_include_directories(odin4_lib PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(odin4_lib PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LIBUSB_INCLUDE_DIRS}
)

if (CRYPTOPP_USE_STATIC)
    target_include_directories(odin4_lib PRIVATE ${CRYPTOPP_INCLUDE_DIR})
else()
    target_include_directories(odin4_lib PRIVATE ${CRYPTOPP_INCLUDE_DIRS})
endif()

target_link_libraries(odin4_lib PRIVATE
    ${LIBUSB_LIBRARIES}
    lz4_lib
)

if (CRYPTOPP_USE_STATIC)
    target_link_libraries(odin4_lib PRIVATE ${CRYPTOPP_STATIC_LIB})
else()
    target_link_libraries(odin4_lib PRIVATE ${CRYPTOPP_LIBRARIES})
endif()

# =========================
# Main executable (C++)
# =========================
add_executable(odin4 src/main.cpp)
set_target_properties(odin4 PROPERTIES OUTPUT_NAME "odin4")

# =========================
# Compile options
# =========================
target_compile_options(odin4_lib PRIVATE -Wall -Wextra -Wno-cast-function-type)
target_compile_options(odin4 PRIVATE -Wall -Wextra)

# =========================
# Includes
# =========================
target_include_directories(odin4 PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# =========================
# Linking
# =========================
target_link_libraries(odin4 PRIVATE
    odin4_lib
    -static-libgcc
    -static-libstdc++
)
