cmake_minimum_required(VERSION 3.10)
project(odin4 LANGUAGES C CXX)

# Extract version from src/odin4.cpp
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/odin4.cpp" ODIN4_SRC_CONTENT)
string(REGEX MATCH "#define ODIN4_VERSION \"([0-9]+\\.[0-9]+\\.[0-9]+)\"" _ ${ODIN4_SRC_CONTENT})
set(ODIN4_VERSION ${CMAKE_MATCH_1})
if(NOT ODIN4_VERSION)
    set(ODIN4_VERSION "0.0.0")
    message(WARNING "Could not extract version from src/odin4.cpp, defaulting to 0.0.0")
endif()
message(STATUS "Odin4 Version: ${ODIN4_VERSION}")

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
if(MSVC)
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DNOMINMAX)
else()
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
endif()

# =========================
# Dependencies
# =========================

# LibUSB
if(WIN32)
    find_path(LIBUSB_INCLUDE_DIR libusb.h PATH_SUFFIXES libusb-1.0)
    find_library(LIBUSB_LIBRARY NAMES usb-1.0 libusb-1.0)
    if(LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARY)
        set(LIBUSB_FOUND TRUE)
        set(LIBUSB_INCLUDE_DIRS ${LIBUSB_INCLUDE_DIR})
        set(LIBUSB_LIBRARIES ${LIBUSB_LIBRARY})
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
endif()

if(NOT LIBUSB_FOUND)
    message(FATAL_ERROR "libusb-1.0 not found")
endif()

# Crypto++
if(WIN32)
    # On Windows via vcpkg, cryptopp provides a config file
    find_package(cryptopp CONFIG)
    if(cryptopp_FOUND)
        set(CRYPTOPP_LIBRARIES cryptopp::cryptopp)
    else()
        find_path(CRYPTOPP_INCLUDE_DIR cryptlib.h PATH_SUFFIXES cryptopp crypto++)
        find_library(CRYPTOPP_LIBRARY NAMES cryptopp libcryptopp)
        if(CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_LIBRARY)
            set(CRYPTOPP_FOUND TRUE)
            set(CRYPTOPP_INCLUDE_DIRS ${CRYPTOPP_INCLUDE_DIR})
            set(CRYPTOPP_LIBRARIES ${CRYPTOPP_LIBRARY})
        endif()
    endif()
else()
    # On Linux/macOS, try pkg-config first, then manual search
    find_package(PkgConfig)
    pkg_check_modules(CRYPTOPP libcrypto++)
    
    if(NOT CRYPTOPP_FOUND)
        find_path(CRYPTOPP_INCLUDE_DIR cryptlib.h
            PATHS /usr/local/include /usr/include /opt/homebrew/include
            PATH_SUFFIXES cryptopp crypto++
        )
        set(CRYPTOPP_INCLUDE_DIRS ${CRYPTOPP_INCLUDE_DIR})

        # Find static for the static target
        set(_OLD_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
        set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
        find_library(CRYPTOPP_STATIC_LIB
            NAMES cryptopp libcryptopp
            PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /opt/homebrew/lib
        )
        set(CMAKE_FIND_LIBRARY_SUFFIXES ${_OLD_CMAKE_FIND_LIBRARY_SUFFIXES})

        # Find shared for the shared target
        if(APPLE)
            set(CMAKE_FIND_LIBRARY_SUFFIXES .dylib)
        else()
            set(CMAKE_FIND_LIBRARY_SUFFIXES .so)
        endif()
        find_library(CRYPTOPP_SHARED_LIB
            NAMES cryptopp libcryptopp
            PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /opt/homebrew/lib
        )
        set(CMAKE_FIND_LIBRARY_SUFFIXES ${_OLD_CMAKE_FIND_LIBRARY_SUFFIXES})
    endif()
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
if(NOT MSVC)
    set_target_properties(lz4_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# =========================
# Core Library Sources
# =========================
set(ODIN4_CORE_SOURCES
    src/odin4.cpp
    src/core/logger.cpp
    src/usb/usb_device.cpp
    src/firmware/firmware_package.cpp
)

# =========================
# Static Library (Internal for CLI)
# =========================
add_library(odin4_static STATIC ${ODIN4_CORE_SOURCES})
target_include_directories(odin4_static PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
)
target_include_directories(odin4_static PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LIBUSB_INCLUDE_DIRS}
    ${CRYPTOPP_INCLUDE_DIRS}
)
if(WIN32)
    target_link_libraries(odin4_static PRIVATE ${CRYPTOPP_LIBRARIES} ${LIBUSB_LIBRARIES} lz4_lib)
else()
    if(CRYPTOPP_STATIC_LIB)
        target_link_libraries(odin4_static PRIVATE ${CRYPTOPP_STATIC_LIB} ${LIBUSB_LIBRARIES} lz4_lib)
    else()
        target_link_libraries(odin4_static PRIVATE ${CRYPTOPP_LIBRARIES} ${LIBUSB_LIBRARIES} lz4_lib)
    endif()
endif()

# =========================
# Shared Library (External use)
# =========================
add_library(odin4_shared SHARED ${ODIN4_CORE_SOURCES})
set_target_properties(odin4_shared PROPERTIES 
    OUTPUT_NAME "odin4"
    VERSION "${ODIN4_VERSION}"
    SOVERSION "5"
)
target_include_directories(odin4_shared PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(odin4_shared PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LIBUSB_INCLUDE_DIRS}
    ${CRYPTOPP_INCLUDE_DIRS}
)
if(WIN32)
    target_link_libraries(odin4_shared PRIVATE ${CRYPTOPP_LIBRARIES} ${LIBUSB_LIBRARIES} lz4_lib)
else()
    if(CRYPTOPP_SHARED_LIB)
        target_link_libraries(odin4_shared PRIVATE ${CRYPTOPP_SHARED_LIB} ${LIBUSB_LIBRARIES} lz4_lib)
    else()
        target_link_libraries(odin4_shared PRIVATE ${CRYPTOPP_LIBRARIES} ${LIBUSB_LIBRARIES} lz4_lib)
    endif()
endif()

# =========================
# Common Configuration for Libraries
# =========================
foreach(target odin4_static odin4_shared)
    if(NOT MSVC)
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-cast-function-type)
    endif()
endforeach()

# =========================
# Main executable (C++)
# =========================
add_executable(odin4 src/main.cpp)
set_target_properties(odin4 PROPERTIES OUTPUT_NAME "odin4")

target_include_directories(odin4 PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Link CLI against STATIC library to keep it self-contained
target_link_libraries(odin4 PRIVATE odin4_static)

if(NOT MSVC)
    target_compile_options(odin4 PRIVATE -Wall -Wextra)
    if(NOT APPLE)
        # Static link stdlibs on Linux for better portability
        target_link_libraries(odin4 PRIVATE -static-libgcc -static-libstdc++)
    endif()
endif()
