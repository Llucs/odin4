cmake_minimum_required(VERSION 3.22)
project(odin4 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

find_path(CRYPTOPP_INCLUDE_DIR cryptlib.h
    PATHS /usr/local/include /usr/include
    PATH_SUFFIXES cryptopp crypto++
)

set(_OLD_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(CMAKE_FIND_LIBRARY_SUFFIXES .a)

find_library(CRYPTOPP_STATIC_LIB
    NAMES cryptopp libcryptopp
    PATHS /usr/local/lib /usr/local/lib64 /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu
)

set(CMAKE_FIND_LIBRARY_SUFFIXES ${_OLD_CMAKE_FIND_LIBRARY_SUFFIXES})

if (CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_STATIC_LIB AND CRYPTOPP_STATIC_LIB MATCHES "\\.a$")
    set(CRYPTOPP_USE_STATIC ON)
else()
    set(CRYPTOPP_USE_STATIC OFF)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)
endif()

file(STRINGS "${CMAKE_SOURCE_DIR}/src/odin4.cpp" ODIN_VERSION_LINE REGEX "#define ODIN4_VERSION")
string(REGEX MATCH "\"[^\"]*\"" ODIN_VERSION_RAW "${ODIN_VERSION_LINE}")
string(REPLACE "\"" "" ODIN_VERSION_CLEAN "${ODIN_VERSION_RAW}")
string(REGEX MATCH "^[0-9]+" ODIN_SOVERSION "${ODIN_VERSION_CLEAN}")

add_library(lz4_lib STATIC
    lib/lz4/lz4.c
    lib/lz4/lz4hc.c
    lib/lz4/lz4frame.c
    lib/lz4/xxhash.c
)
target_include_directories(lz4_lib PUBLIC lib/lz4)

set(ODIN4_CORE_SOURCES
    src/odin4.cpp
    src/core/logger.cpp
    src/usb/usb_device.cpp
    src/firmware/firmware_package.cpp
)

add_library(odin4_static STATIC ${ODIN4_CORE_SOURCES})
target_include_directories(odin4_static PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
target_include_directories(odin4_static PRIVATE ${CMAKE_SOURCE_DIR}/src ${LIBUSB_INCLUDE_DIRS})

add_library(odin4_shared SHARED ${ODIN4_CORE_SOURCES})
set_target_properties(odin4_shared PROPERTIES 
    OUTPUT_NAME "odin4" 
    VERSION "${ODIN_VERSION_CLEAN}" 
    SOVERSION "${ODIN_SOVERSION}"
)
target_include_directories(odin4_shared PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_include_directories(odin4_shared PRIVATE ${CMAKE_SOURCE_DIR}/src ${LIBUSB_INCLUDE_DIRS})

foreach(target odin4_static odin4_shared)
    if (CRYPTOPP_USE_STATIC)
        target_include_directories(${target} PRIVATE ${CRYPTOPP_INCLUDE_DIR})
        target_link_libraries(${target} PRIVATE ${CRYPTOPP_STATIC_LIB})
    else()
        target_include_directories(${target} PRIVATE ${CRYPTOPP_INCLUDE_DIRS})
        target_link_libraries(${target} PRIVATE ${CRYPTOPP_LIBRARIES})
    endif()
    target_link_libraries(${target} PRIVATE ${LIBUSB_LIBRARIES} lz4_lib)
endforeach()

add_executable(odin4 src/main.cpp)
set_target_properties(odin4 PROPERTIES OUTPUT_NAME "odin4")
target_include_directories(odin4 PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(odin4 PRIVATE odin4_static -static-libgcc -static-libstdc++)

foreach(target odin4_static odin4_shared odin4)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-cast-function-type)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target} PRIVATE -fstack-protector-strong -D_FORTIFY_SOURCE=2)
        target_link_options(${target} PRIVATE "SHELL:-z relro" "SHELL:-z now")
        if(target STREQUAL "odin4")
            target_compile_options(${target} PRIVATE -fPIE)
            target_link_options(${target} PRIVATE "-pie")
        endif()
    endif()
endforeach()

# ============================================================================
# Tests
# ============================================================================
include(CTest)
enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    URL_HASH SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# LZ4 block API tests (tests for lz4.c and lz4.h changes)
add_executable(test_lz4_api tests/test_lz4_api.cpp)
target_include_directories(test_lz4_api PRIVATE ${CMAKE_SOURCE_DIR}/lib/lz4)
target_link_libraries(test_lz4_api PRIVATE lz4_lib GTest::gtest_main)
target_compile_options(test_lz4_api PRIVATE -Wall -Wextra)
add_test(NAME test_lz4_api COMMAND test_lz4_api)

# LZ4 frame API tests (tests for lz4frame.c and lz4frame.h changes)
add_executable(test_lz4frame_api tests/test_lz4frame_api.cpp)
target_include_directories(test_lz4frame_api PRIVATE ${CMAKE_SOURCE_DIR}/lib/lz4)
target_link_libraries(test_lz4frame_api PRIVATE lz4_lib GTest::gtest_main)
target_compile_options(test_lz4frame_api PRIVATE -Wall -Wextra)
add_test(NAME test_lz4frame_api COMMAND test_lz4frame_api)

# Thor protocol tests (tests for thor_protocol.h changes — endianness helpers and structs)
add_executable(test_thor_protocol tests/test_thor_protocol.cpp)
target_include_directories(test_thor_protocol PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_thor_protocol PRIVATE GTest::gtest_main)
target_compile_options(test_thor_protocol PRIVATE -Wall -Wextra)
add_test(NAME test_thor_protocol COMMAND test_thor_protocol)

# Logger tests (tests for logger.h API)
add_executable(test_logger tests/test_logger.cpp)
target_include_directories(test_logger PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_logger PRIVATE odin4_static GTest::gtest_main)
target_compile_options(test_logger PRIVATE -Wall -Wextra)
add_test(NAME test_logger COMMAND test_logger)

# Firmware package utility tests (tests for sanitize_filename in firmware_package.h/cpp)
add_executable(test_sanitize_filename tests/test_sanitize_filename.cpp)
target_include_directories(test_sanitize_filename PRIVATE ${CMAKE_SOURCE_DIR}/src ${LIBUSB_INCLUDE_DIRS})
target_link_libraries(test_sanitize_filename PRIVATE odin4_static GTest::gtest_main)
target_compile_options(test_sanitize_filename PRIVATE -Wall -Wextra)
add_test(NAME test_sanitize_filename COMMAND test_sanitize_filename)
