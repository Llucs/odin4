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
pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)

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
# Main executable (C++)
# =========================
add_executable(odin4 
    src/main.cpp
    src/usb_device.cpp
    src/firmware_package.cpp
)
set_target_properties(odin4 PROPERTIES OUTPUT_NAME "odin4")

# =========================
# Compile options
# =========================
target_compile_options(odin4 PRIVATE
    -Wall
    -Wextra
    -fpermissive
    -Wno-cast-function-type
)

# =========================
# Includes
# =========================
target_include_directories(odin4 PRIVATE
    ${LIBUSB_INCLUDE_DIRS}
    ${CRYPTOPP_INCLUDE_DIRS}
)

# =========================
# Linking
# =========================
target_link_libraries(odin4 PRIVATE
    ${LIBUSB_LIBRARIES}
    lz4_lib
    ${CRYPTOPP_LIBRARIES}
    -static-libgcc
    -static-libstdc++
)
