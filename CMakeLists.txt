cmake_minimum_required(VERSION 3.22)
project(odin4 LANGUAGES C CXX)

# Platform definitions
if(APPLE)
    add_definitions(-DPLATFORM_MACOS)
elseif(WIN32)
    add_definitions(-DPLATFORM_WINDOWS -DNOMINMAX)
else()
    add_definitions(-DPLATFORM_LINUX)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# =========================
# Dependencies (vcpkg ONLY)
# =========================
find_package(libusb CONFIG REQUIRED)
find_package(cryptopp CONFIG REQUIRED)

# Qt optional (GUI)
find_package(Qt6 COMPONENTS Widgets QUIET)

# =========================
# Version
# =========================
file(STRINGS "${CMAKE_SOURCE_DIR}/src/odin4.cpp" ODIN_VERSION_LINE REGEX "#define ODIN4_VERSION")
string(REGEX MATCH "\"[^\"]*\"" ODIN_VERSION_RAW "${ODIN_VERSION_LINE}")
string(REPLACE "\"" "" ODIN_VERSION_CLEAN "${ODIN_VERSION_RAW}")
string(REGEX MATCH "^[0-9]+" ODIN_SOVERSION "${ODIN_VERSION_CLEAN}")

# =========================
# LZ4 (internal)
# =========================
add_library(lz4_lib STATIC
    lib/lz4/lz4.c
    lib/lz4/lz4hc.c
    lib/lz4/lz4frame.c
    lib/lz4/xxhash.c
)
target_include_directories(lz4_lib PUBLIC lib/lz4)

# =========================
# Core sources
# =========================
set(ODIN4_CORE_SOURCES
    src/odin4.cpp
    src/core/logger.cpp
    src/usb/usb_device.cpp
    src/firmware/firmware_package.cpp
)

add_library(odin4_static STATIC ${ODIN4_CORE_SOURCES})
target_include_directories(odin4_static PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_include_directories(odin4_static PRIVATE ${CMAKE_SOURCE_DIR}/src)

add_library(odin4_shared SHARED ${ODIN4_CORE_SOURCES})

set_target_properties(odin4_shared PROPERTIES
    OUTPUT_NAME "odin4"
    VERSION "${ODIN_VERSION_CLEAN}"
    SOVERSION "${ODIN_SOVERSION}"
)

target_include_directories(odin4_shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(odin4_shared PRIVATE ${CMAKE_SOURCE_DIR}/src)

# =========================
# Link deps (clean vcpkg style)
# =========================
foreach(target odin4_static odin4_shared)
    target_link_libraries(${target}
        PRIVATE
        libusb::libusb
        cryptopp::cryptopp
        lz4_lib
    )
endforeach()

# =========================
# CLI executable
# =========================
add_executable(odin4 src/main.cpp)
set_target_properties(odin4 PROPERTIES OUTPUT_NAME "odin4")

target_include_directories(odin4 PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(odin4 PRIVATE odin4_static)

if(NOT MSVC)
    target_link_options(odin4 PRIVATE -static-libgcc -static-libstdc++)
endif()

# =========================
# GUI (optional)
# =========================
option(ODIN4_BUILD_GUI "Build Qt6 GUI target" ON)

set(ODIN4_ALL_TARGETS odin4_static odin4_shared odin4)

if(ODIN4_BUILD_GUI AND Qt6_FOUND)
    add_executable(odin4-gui src-gui/main.cpp)

    set_target_properties(odin4-gui PROPERTIES
        OUTPUT_NAME "odin4-gui"
        AUTOMOC ON
    )

    target_include_directories(odin4-gui PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(odin4-gui PRIVATE odin4_static Qt6::Widgets)

    if(NOT MSVC)
        target_link_options(odin4-gui PRIVATE -static-libgcc -static-libstdc++)
    endif()

    list(APPEND ODIN4_ALL_TARGETS odin4-gui)
endif()

# =========================
# Tests
# =========================
option(ODIN4_BUILD_TESTS "Build test suite" ON)

if(ODIN4_BUILD_TESTS)
    enable_testing()

    set(ODIN4_TEST_SOURCES
        tests/main.cpp
        tests/test_framework.h
        tests/test_thor_protocol.cpp
        tests/test_odin_types.cpp
        tests/test_logger.cpp
    )

    add_executable(odin4_tests ${ODIN4_TEST_SOURCES})

    target_include_directories(odin4_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(odin4_tests PRIVATE odin4_static)

    add_test(NAME odin4_tests COMMAND odin4_tests)

    list(APPEND ODIN4_ALL_TARGETS odin4_tests)
endif()

# =========================
# Common compile options
# =========================
foreach(target ${ODIN4_ALL_TARGETS})
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-cast-function-type)

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -fstack-protector-strong -D_FORTIFY_SOURCE=2)

        if(NOT APPLE AND NOT WIN32)
            target_link_options(${target} PRIVATE -Wl,-z,relro -Wl,-z,now)
        endif()

        if(${target} STREQUAL "odin4")
            target_compile_options(${target} PRIVATE -fPIE)

            if(NOT APPLE AND NOT WIN32)
                target_link_options(${target} PRIVATE -pie)
            endif()
        endif()
    endif()
endforeach()