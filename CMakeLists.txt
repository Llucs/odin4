cmake_minimum_required(VERSION 3.10)
project(odin4 LANGUAGES C CXX)

# =========================
# C++ Standard
# =========================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# =========================
# Build flags (Otimização Máxima)
# =========================
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# =========================
# Dependencies
# =========================
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

# =========================
# LZ4 static library
# =========================
add_library(lz4_lib STATIC
    lib/lz4/lz4.c
    lib/lz4/lz4frame.c
    lib/lz4/xxhash.c
)
target_include_directories(lz4_lib PUBLIC lib/lz4)

# =========================
# Main executable
# =========================
add_executable(odin4 src/main.cpp)
set_target_properties(odin4 PROPERTIES OUTPUT_NAME "odin4")

# =========================
# Compile options
# =========================
# Removi o -Werror para evitar que avisos bobos parem seu build agora
target_compile_options(odin4 PRIVATE -Wall -Wextra)

# =========================
# Includes & linking
# =========================
target_include_directories(odin4 PRIVATE
    ${LIBUSB_INCLUDE_DIRS}
    lib/lz4
    lib/picohash
)

# ESTA É A PARTE CRUCIAL:
# Forçamos o link estático das bibliotecas padrão do sistema (libgcc e libstdc++)
# e garantimos que a lz4_lib seja embutida.
target_link_libraries(odin4 PRIVATE 
    ${LIBUSB_LIBRARIES} 
    lz4_lib 
    -static-libgcc 
    -static-libstdc++
)

# Se você quiser tentar um binário TOTALMENTE estático (pode exigir libusb-static instalada):
# set(CMAKE_EXE_LINKER_FLAGS "-static")
