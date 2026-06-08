cmake_minimum_required(VERSION 3.22)
project(odin4 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_STRIP_EXCLUDE_PATTERNS "")

if(MSVC)
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "/O2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/O2 /DNDEBUG")
else()
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
endif()

find_package(PkgConfig QUIET)

if(WIN32)
    file(TO_CMAKE_PATH "$ENV{VCPKG_ROOT}" _VCPKG_ROOT_NORM)

    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a .dll.a)
    find_package(libusb CONFIG QUIET)
    if(NOT libusb_FOUND)
        find_path(LIBUSB_INCLUDE_DIRS libusb.h
            PATHS "${_VCPKG_ROOT_NORM}/installed/$ENV{VCPKG_TARGET_TRIPLET}/include"
                  "$ENV{CONAN_PREFIX}/include"
                  "C:/mingw64/include"
                  "C:/msys64/mingw64/include"
                  "C:/msys64/usr/include"
            PATH_SUFFIXES libusb-1.0
        )
        find_library(LIBUSB_LIBRARIES
            NAMES libusb-1.0 usb-1.0
            PATHS "${_VCPKG_ROOT_NORM}/installed/$ENV{VCPKG_TARGET_TRIPLET}/lib"
                  "$ENV{CONAN_PREFIX}/lib"
                  "C:/mingw64/lib"
                  "C:/msys64/mingw64/lib"
                  "C:/msys64/usr/lib"
        )
        if(NOT LIBUSB_INCLUDE_DIRS OR NOT LIBUSB_LIBRARIES)
            message(FATAL_ERROR "libusb not found.")
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
                message(FATAL_ERROR "libusb not found.")
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
    set(_CLEANED_ARGS "")
    foreach(_arg ${ARGN})
        string(REPLACE "\\" "/" _arg "${_arg}")
        list(APPEND _CLEANED_ARGS "${_arg}")
    endforeach()
    find_path(_CRYPTOPP_RAW_DIR cryptlib.h
        ${_CLEANED_ARGS}
    )
    if(_CRYPTOPP_RAW_DIR)
        get_filename_component(${OUT_VAR} "${_CRYPTOPP_RAW_DIR}" DIRECTORY)
    endif()
endmacro()

if(WIN32)
    find_cryptopp_include(CRYPTOPP_INCLUDE_DIR
        PATHS "${_VCPKG_ROOT_NORM}/installed/$ENV{VCPKG_TARGET_TRIPLET}/include"
              "$ENV{CONAN_PREFIX}/include"
              "C:/mingw64/include"
              "C:/msys64/mingw64/include"
        PATH_SUFFIXES cryptopp crypto++
    )
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
    find_library(CRYPTOPP_STATIC_LIB
        NAMES cryptopp libcryptopp cryptopp-static
        PATHS "${_VCPKG_ROOT_NORM}/installed/$ENV{VCPKG_TARGET_TRIPLET}/lib"
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
    message(FATAL_ERROR "Crypto++ not found.")
endif()

if(WIN32)
    add_definitions(-DNOMINMAX)
    add_definitions(-DLIBUSB_STATIC)
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
if(WIN32)
    set_target_properties(odin4_static PROPERTIES PREFIX "")
endif()

add_library(odin4_shared SHARED ${ODIN4_CORE_SOURCES})
set_target_properties(odin4_shared PROPERTIES
    OUTPUT_NAME "odin4"
    VERSION "${ODIN_VERSION_CLEAN}"
    SOVERSION "${ODIN_SOVERSION}"
)
if(WIN32)
    set_target_properties(odin4_shared PROPERTIES PREFIX "")
endif()
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

option(ODIN4_BUILD_GUI "Build Qt6 GUI target" ON)
set(ODIN4_ALL_TARGETS odin4_static odin4_shared odin4)

# Qt6 GUI target
if(ODIN4_BUILD_GUI)
    find_package(Qt6 REQUIRED COMPONENTS Widgets)
    add_executable(odin4-gui
        src/gui/main.cpp
        src/gui/resources.qrc
    )
    set_target_properties(odin4-gui PROPERTIES
        OUTPUT_NAME "odin4-gui"
        AUTOMOC ON
        AUTORCC ON
    )
    if(WIN32)
        set_target_properties(odin4-gui PROPERTIES WIN32_EXECUTABLE TRUE)
        target_sources(odin4-gui PRIVATE src/gui/app.rc)
    endif()
    if(APPLE)
        set_target_properties(odin4-gui PROPERTIES
            MACOSX_BUNDLE TRUE
            MACOSX_BUNDLE_GUI_IDENTIFIER "com.llucs.odin4"
            MACOSX_BUNDLE_BUNDLE_NAME "Odin4"
            MACOSX_BUNDLE_BUNDLE_VERSION "${ODIN_VERSION_CLEAN}"
            MACOSX_BUNDLE_SHORT_VERSION_STRING "${ODIN_VERSION_CLEAN}"
            MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/packaging/macos/Info.plist"
        )
    endif()
    target_include_directories(odin4-gui PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(odin4-gui PRIVATE odin4_static Qt6::Widgets)
    if(NOT MSVC AND NOT APPLE)
        target_link_options(odin4-gui PRIVATE "-static-libgcc" "-static-libstdc++")
    endif()

    # ── macOS: strip frameworks the SDK no longer ships ────────────────
    # macOS 14+/15+ SDK removed AGL.framework. Qt's imported targets and
    # .prl files may still reference it. Walk EVERY imported target and
    # surgically remove entries that mention a missing framework.
    # -------------------------------------------------------------------
    if(APPLE)
        set(_ODIN4_MISSING_FW "")
        foreach(_fw IN ITEMS AGL)
            find_library(_odin4_probe_${_fw} ${_fw})
            if(NOT _odin4_probe_${_fw})
                list(APPEND _ODIN4_MISSING_FW ${_fw})
                message(STATUS "${_fw}.framework not in SDK -- stripping from all imported targets")
            endif()
            unset(_odin4_probe_${_fw} CACHE)
        endforeach()

        if(_ODIN4_MISSING_FW)
            function(_odin4_strip_fw tgt)
                if(NOT TARGET ${tgt})
                    return()
                endif()
                foreach(prop IN ITEMS INTERFACE_LINK_LIBRARIES INTERFACE_LINK_OPTIONS)
                    get_target_property(_val ${tgt} ${prop})
                    if(NOT _val)
                        continue()
                    endif()
                    set(_orig "${_val}")
                    foreach(_fw IN LISTS _ODIN4_MISSING_FW)
                        string(REPLACE ";-framework ${_fw}" "" _val "${_val}")
                        string(REPLACE "-framework ${_fw};" "" _val "${_val}")
                        string(REPLACE "-framework ${_fw}"  "" _val "${_val}")
                        string(REPLACE ";-framework;${_fw}" "" _val "${_val}")
                        string(REPLACE "-framework;${_fw};" "" _val "${_val}")
                        string(REPLACE "-framework;${_fw}"  "" _val "${_val}")
                    endforeach()
                    if(NOT "${_val}" STREQUAL "${_orig}")
                        message(STATUS "  stripped missing framework(s) from ${tgt}::${prop}")
                    endif()
                    set_target_properties(${tgt} PROPERTIES ${prop} "${_val}")
                endforeach()
            endfunction()

            get_property(_all_imported DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY IMPORTED_TARGETS)
            foreach(_tgt IN LISTS _all_imported)
                _odin4_strip_fw(${_tgt})
            endforeach()
        endif()
    endif()
    # ── end macOS framework fixup ──────────────────────────────────────

    # ── Windows: deploy Qt DLLs via windeployqt ────────────────────────
    if(WIN32)
        set(ODIN4_WINDOWS_ARM64 OFF)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|AARCH64|arm64|aarch64)$"
           OR CMAKE_VS_PLATFORM_NAME STREQUAL "ARM64")
            set(ODIN4_WINDOWS_ARM64 ON)
        endif()

        if(ODIN4_WINDOWS_ARM64)
            message(STATUS "Skipping post-build windeployqt on Windows ARM64; install-time Qt deployment will be used instead.")
        else()
            get_target_property(_qmake_exec Qt6::qmake IMPORTED_LOCATION)
            get_filename_component(_qt_bin_dir "${_qmake_exec}" DIRECTORY)
            find_program(WINDEPLOYQT_EXEC windeployqt HINTS "${_qt_bin_dir}")
        endif()

        if(NOT ODIN4_WINDOWS_ARM64 AND WINDEPLOYQT_EXEC)
            add_custom_command(TARGET odin4-gui POST_BUILD
                COMMAND "${WINDEPLOYQT_EXEC}"
                ARGS --no-translations --no-compiler-runtime "$<TARGET_FILE:odin4-gui>"
                COMMENT "Running windeployqt to deploy Qt libraries..."
            )
        elseif(NOT ODIN4_WINDOWS_ARM64)
            message(WARNING "windeployqt not found! You will need to copy DLLs manually.")
        endif()
    endif()
    # ── end windeployqt ────────────────────────────────────────────────

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
    if(MSVC)
        target_compile_options(odin4_tests PRIVATE /W3)
    else()
        target_compile_options(odin4_tests PRIVATE -Wall -Wextra -Wno-cast-function-type)
    endif()
    add_test(NAME odin4_tests COMMAND $<TARGET_FILE:odin4_tests>)
    list(APPEND ODIN4_ALL_TARGETS odin4_tests)
endif()

# Fuzz library
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
        if(NOT APPLE AND NOT WIN32)
            target_link_options(${target} PRIVATE "SHELL:-z relro" "SHELL:-z now")
        endif()
        if(target STREQUAL "odin4")
            target_compile_options(${target} PRIVATE -fPIE)
            target_link_options(${target} PRIVATE "-pie")
        endif()
    endif()
endforeach()

# Install rules
install(TARGETS odin4_static odin4_shared odin4
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
if(ODIN4_BUILD_GUI)
    if(APPLE)
        qt_generate_deploy_app_script(
            TARGET odin4-gui
            FILENAME_VARIABLE deploy_script
            NO_UNSUPPORTED_PLATFORM_ERROR
        )
        install(SCRIPT ${deploy_script})
    endif()
    install(TARGETS odin4-gui
        RUNTIME DESTINATION bin
        BUNDLE DESTINATION .
    )
endif()
install(FILES include/odin4/odin4.h DESTINATION include/odin4)
install(FILES udev/60-odin4.rules DESTINATION share/odin4)

# CPack for Windows installer and macOS DMG
set(CPACK_PACKAGE_NAME "Odin4")
set(CPACK_PACKAGE_VERSION "${ODIN_VERSION_CLEAN}")
if(WIN32)
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
    set(CPACK_NSIS_DISPLAY_NAME "Odin4")
    set(CPACK_NSIS_CONTACT "Llucs")
    set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/Llucs/odin4")
    set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
    set(CPACK_NSIS_MODIFY_PATH ON)
    set(CPACK_NSIS_MANIFEST_DPI_AWARE TRUE)
    set(CPACK_PACKAGE_EXECUTABLES "odin4-gui" "Odin4")
    set(CPACK_NSIS_INSTALLED_ICON_NAME "bin/odin4-gui.exe")
    set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "")
    if(EXISTS "${CMAKE_SOURCE_DIR}/packaging/windows/odin4.ico")
        set(CPACK_NSIS_MUI_ICON "${CMAKE_SOURCE_DIR}/packaging/windows/odin4.ico")
        set(CPACK_NSIS_MUI_UNIICON "${CMAKE_SOURCE_DIR}/packaging/windows/odin4.ico")
        set(CPACK_NSIS_INSTALL_ICON "${CMAKE_SOURCE_DIR}/packaging/windows/odin4.ico")
        set(CPACK_NSIS_UNINSTALL_ICON "${CMAKE_SOURCE_DIR}/packaging/windows/odin4.ico")
    endif()

    # Bundle VC++ Redistributable
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|AARCH64|arm64|aarch64)$"
       OR CMAKE_VS_PLATFORM_NAME STREQUAL "ARM64")
        set(_vcredist_name "vc_redist.arm64.exe")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_vcredist_name "vc_redist.x64.exe")
    else()
        set(_vcredist_name "vc_redist.x86.exe")
    endif()

    if(DEFINED ENV{VCToolsRedistDir})
        file(TO_CMAKE_PATH "$ENV{VCToolsRedistDir}" _vcredist_dir)
        set(_vcredist_path "${_vcredist_dir}/${_vcredist_name}")
        if(EXISTS "${_vcredist_path}")
            message(STATUS "Found vcredist: ${_vcredist_path}")
            install(FILES "${_vcredist_path}" DESTINATION redist)
            set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "
                ExecWait '\\\"\\$INSTDIR\\\\redist\\\\${_vcredist_name}\\\" /install /quiet /norestart'
                SetOutPath '\\$INSTDIR'
                RMDir /r /REBOOTOK '\\$INSTDIR\\redist'
            ")
        else()
            message(WARNING "VCToolsRedistDir set but ${_vcredist_name} not found at: ${_vcredist_path}")
        endif()
    endif()
endif()
if(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
    set(CPACK_DMG_VOLUME_NAME "Odin4")
    set(CPACK_DMG_DS_STORE_SETUP_SCRIPT "")
endif()
set(CPACK_PACKAGE_FILE_NAME
    "Odin4-${ODIN_VERSION_CLEAN}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}"
)
set(CPACK_VERBATIM_VARIABLES TRUE)
include(CPack)
