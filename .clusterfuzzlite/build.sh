#!/bin/bash
set -euxo pipefail

export CC=clang
export CXX=clang++

export CXXFLAGS="-O1 -g -std=c++23 -stdlib=libc++"
export CFLAGS="-O1 -g"
export LDFLAGS="-stdlib=libc++"

apt-get update || true
apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    clang \
    pkg-config \
    libusb-1.0-0-dev \
    libcrypto++-dev \
    libarchive-dev \
    zlib1g-dev \
    libc++-dev \
    libc++abi-dev || true

mkdir -p build
cd build

cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DODIN4_BUILD_GUI=OFF \
    -DODIN4_BUILD_TESTS=OFF \
    -DCMAKE_C_FLAGS="-O1 -g" \
    -DCMAKE_CXX_FLAGS="-O1 -g -std=c++23 -stdlib=libc++"

cmake --build . --parallel

mkdir -p "$OUT"

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -I../include \
    ../tests/fuzz_pit.cpp \
    -L. \
    -o $OUT/fuzz_pit

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -I../include \
    ../tests/fuzz_thor.cpp \
    -L. \
    -o $OUT/fuzz_thor

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -I../include \
    ../tests/fuzz_lz4.cpp \
    -L. \
    -o $OUT/fuzz_lz4

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -I../include \
    ../tests/fuzz_tar.cpp \
    -L. \
    -o $OUT/fuzz_tar