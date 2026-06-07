cmake_minimum_required(VERSION 3.22)
project(odin4 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

find_package(PkgConfig QUIET)

if(WIN32)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a .dll.a)
    find_package(libusb CONFIG QUIET)
    if(NOT libusb_FOUND)
        find_path(LIBUSB_INCLUDE_DIRS libusb.h
            PATHS "$ENV{VCPKG_ROOT}/installed/$ENV{VCPKG_TARGET_TRIPLET}/include"
                  "$ENV{CONAN_PREFIX}/include"
                  "C:/mingw64/include"
                  "C:/msys64/mingw64/include"
                  "C:/msys64/usr/include"
            PATH_SUFFIXES libusb-1.0
        )
        find_library(LIBUSB_LIBRARIES
            NAMES libusb-1.0 usb-1.0
            PATHS "$ENV{VCPKG_ROOT}/installed/$ENV{VCPKG_TARGET_TRIPLET}/lib"
                  "$ENV{CONAN_PREFIX}/lib"
                  "C:/mingw64/lib"
                  "C:/msys64/mingw64/lib"
                  "C:/msys64/usr/lib"
        )
        if(NOT LIBUSB_INCLUDE_DIRS OR NOT LIBUSB_LIBRARIES)
            message(FATAL_ERROR "libusb not found. Install it via MSYS2 (pacman -S mingw-w64-x86_64-libusb) or vcpkg.")
        endif()
    else()
        get_target_property(LIBUSB_INCLUDE_DIRS libusb::usb INTERFACE_INCLUDE_DIRECTORIES)
    endif()
elseif(APPLE)
    find_package(libusb CONFIG QUIET)
    if(NOT libusb_FOUND)
        find_path(LIBUSB_INCLUDE_DIRS libusb.h
            PATHS /usr/local/include /opt/homebrew/include
            PATH_SUFFIXES libusb-1.0
        )
        find_library(LIBUSB_LIBRARIES
            NAMES libusb-1.0 usb-1.0
            PATHS /usr/local/lib /opt/homebrew/lib
        )
        if(NOT LIBUSB_INCLUDE_DIRS OR NOT LIBUSB_LIBRARIES)
            if(PkgConfig_FOUND)
                pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
            else()
                message(FATAL_ERROR "libusb not found. Install it via Homebrew.")
            endif()
        endif()
    else()
        get_target_property(LIBUSB_INCLUDE_DIRS libusb::usb INTERFACE_INCLUDE_DIRECTORIES)
    endif()
else()
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
    else()
        find_path(LIBUSB_INCLUDE_DIRS libusb.h
            PATHS /usr/local/include /usr/include
            PATH_SUFFIXES libusb-1.0
        )
        find_library(LIBUSB_LIBRARIES
            NAMES libusb-1.0 usb-1.0
            PATHS /usr/local/lib /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu
        )
        if(NOT LIBUSB_INCLUDE_DIRS OR NOT LIBUSB_LIBRARIES)
            message(FATAL_ERROR "libusb not found.")
        endif()
    endif()
endif()

macro(find_cryptopp_include OUT_VAR)
    find_path(_CRYPTOPP_RAW_DIR cryptlib.h
        ${ARGN}
    )
    if(_CRYPTOPP_RAW_DIR)
        get_filename_component(${OUT_VAR} "${_CRYPTOPP_RAW_DIR}" DIRECTORY)
    endif()
endmacro()

if(WIN32)
    find_cryptopp_include(CRYPTOPP_INCLUDE_DIR
        PATHS "$ENV{VCPKG_ROOT}/installed/$ENV{VCPKG_TARGET_TRIPLET}/include"
              "$ENV{CONAN_PREFIX}/include"
              "C:/mingw64/include"
              "C:/msys64/mingw64/include"
        PATH_SUFFIXES cryptopp crypto++
    )
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
    find_library(CRYPTOPP_STATIC_LIB
        NAMES cryptopp libcryptopp cryptopp-static
        PATHS "$ENV{VCPKG_ROOT}/installed/$ENV{VCPKG_TARGET_TRIPLET}/lib"
              "$ENV{CONAN_PREFIX}/lib"
              "C:/mingw64/lib"
              "C:/msys64/mingw64/lib"
    )
elseif(APPLE)
    find_cryptopp_include(CRYPTOPP_INCLUDE_DIR
        PATHS /usr/local/include /opt/homebrew/include
        PATH_SUFFIXES cryptopp crypto++
    )
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a .dylib)
    find_library(CRYPTOPP_STATIC_LIB
        NAMES cryptopp libcryptopp
        PATHS /usr/local/lib /opt/homebrew/lib
    )
else()
    find_cryptopp_include(CRYPTOPP_INCLUDE_DIR
        PATHS /usr/local/include /usr/include
        PATH_SUFFIXES cryptopp crypto++
    )
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    find_library(CRYPTOPP_STATIC_LIB
        NAMES cryptopp libcryptopp
        PATHS /usr/local/lib /usr/local/lib64 /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu
    )
endif()

if (CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_STATIC_LIB)
    set(CRYPTOPP_USE_STATIC ON)
elseif(PkgConfig_FOUND)
    set(CRYPTOPP_USE_STATIC OFF)
    pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)
else()
    message(FATAL_ERROR "Crypto++ not found. Install it via vcpkg, Homebrew, or your package manager.")
endif()

if(WIN32)
    add_definitions(-DNOMINMAX)
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

add_subdirectory(src)

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
    target_link_libraries(${target} PRIVATE ${LIBUSB_LDFLAGS} ${LIBUSB_LIBRARIES} lz4_lib)
endforeach()

add_executable(odin4 src/cli/main.cpp)
set_target_properties(odin4 PROPERTIES OUTPUT_NAME "odin4")
target_include_directories(odin4 PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(odin4 PRIVATE odin4_static)
if(NOT MSVC AND NOT APPLE)
    target_link_options(odin4 PRIVATE "-static-libgcc" "-static-libstdc++")
endif()

# Optional GUI build
option(ODIN4_BUILD_GUI "Build Qt6 GUI target" ON)
set(ODIN4_ALL_TARGETS odin4_static odin4_shared odin4)

# GUI Target
if(ODIN4_BUILD_GUI)
    find_package(Qt6 COMPONENTS Widgets QUIET)
    if(NOT Qt6_FOUND)
        message(WARNING "Qt6 not found (missing OpenGL or other dependencies). GUI target will not be built.")
        set(ODIN4_BUILD_GUI OFF)
    endif()
endif()

if(ODIN4_BUILD_GUI)
    add_executable(odin4-gui src/gui/main.cpp)
    set_target_properties(odin4-gui PROPERTIES
        OUTPUT_NAME "odin4-gui"
        AUTOMOC ON
    )
    target_include_directories(odin4-gui PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(odin4-gui PRIVATE odin4_static Qt6::Widgets)
    if(NOT MSVC AND NOT APPLE)
        target_link_options(odin4-gui PRIVATE "-static-libgcc" "-static-libstdc++")
    endif()
    list(APPEND ODIN4_ALL_TARGETS odin4-gui)
endif()

# Tests
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
    set_target_properties(odin4_tests PROPERTIES OUTPUT_NAME "odin4_tests")
    target_include_directories(odin4_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_include_directories(odin4_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_options(odin4_tests PRIVATE -Wall -Wextra -Wno-cast-function-type)
    
    add_test(NAME odin4_tests COMMAND $<TARGET_FILE:odin4_tests>)
    list(APPEND ODIN4_ALL_TARGETS odin4_tests)
endif()

# Fuzz targets are built in .clusterfuzzlite/build.sh
# The odin4_fuzz library provides PIT parsing for fuzzing

set(ODIN4_FUZZ_SOURCES
    src/fuzz_utils.cpp
    lib/lz4/lz4.c
    lib/lz4/lz4hc.c
    lib/lz4/lz4frame.c
    lib/lz4/xxhash.c
)

add_library(odin4_fuzz STATIC ${ODIN4_FUZZ_SOURCES})
target_include_directories(odin4_fuzz PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_include_directories(odin4_fuzz PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(odin4_fuzz PUBLIC ${CMAKE_SOURCE_DIR}/lib)

foreach(target ${ODIN4_ALL_TARGETS})
    if(MSVC)
        target_compile_options(${target} PRIVATE /W3)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-cast-function-type)
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target} PRIVATE -fstack-protector-strong -D_FORTIFY_SOURCE=2)
        if(NOT APPLE)
            target_link_options(${target} PRIVATE "SHELL:-z relro" "SHELL:-z now")
        endif()
        if(target STREQUAL "odin4")
            target_compile_options(${target} PRIVATE -fPIE)
            target_link_options(${target} PRIVATE "-pie")
        endif()
    endif()
endforeach()

# macOS universal build
if(APPLE)
    set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "Universal build for macOS")
endif()

# Install rules
install(TARGETS odin4_static odin4_shared odin4
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
if(ODIN4_BUILD_GUI)
    install(TARGETS odin4-gui RUNTIME DESTINATION bin)
endif()
install(FILES include/odin4/odin4.h DESTINATION include/odin4)
install(FILES udev/60-odin4.rules DESTINATION share/odin4)