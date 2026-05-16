#!/bin/bash
set -eux

# Install dependencies (for the case when they're not in the base image)
apt-get update || true
apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    clang \
    pkg-config \
    libusb-1.0-dev \
    libcrypto++-dev \
    qt6-base-dev \
    qt6-widgets-dev \
    libarchive-dev || true

mkdir -p build
cd build

# Configure with sanitizers enabled
cmake .. \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS_RELEASE="-O1 -g -fsanitize=address,undefined,fuzzer" \
    -DCMAKE_CXX_FLAGS_RELEASE="-O1 -g -fsanitize=address,undefined,fuzzer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined,fuzzer" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined,fuzzer"

# Build core libraries first
cmake --build . --target lz4_lib odin4_static --parallel

# Build fuzz targets
$CXX $CXXFLAGS \
    -std=c++23 \
    -I../include -I../lib \
    ../tests/fuzz_pit.cpp \
    -L. -lodin4_static -llz4_lib \
    -o $OUT/fuzz_pit

$CXX $CXXFLAGS \
    -std=c++23 \
    -I../include -I../lib \
    ../tests/fuzz_thor.cpp \
    -L. -lodin4_static -llz4_lib \
    -o $OUT/fuzz_thor

$CXX $CXXFLAGS \
    -std=c++23 \
    -I../include -I../lib \
    ../tests/fuzz_lz4.cpp \
    -L. -llz4_lib \
    -o $OUT/fuzz_lz4

$CXX $CXXFLAGS \
    -std=c++23 \
    -I../include -I../lib \
    ../tests/fuzz_tar.cpp \
    -L. -lodin4_static -llz4_lib \
    -o $OUT/fuzz_tar