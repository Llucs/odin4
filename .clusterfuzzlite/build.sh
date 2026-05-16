#!/bin/bash
set -euxo pipefail

apt-get update || true
apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    clang \
    pkg-config \
    libusb-1.0-0-dev \
    libcrypto++-dev \
    libarchive-dev \
    zlib1g-dev || true

mkdir -p build
cd build

cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-O1 -g" \
    -DCMAKE_CXX_FLAGS="-O1 -g"

cmake --build . --parallel

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -std=c++23 \
    -I../include \
    ../tests/fuzz_pit.cpp \
    -L. \
    -o $OUT/fuzz_pit

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -std=c++23 \
    -I../include \
    ../tests/fuzz_thor.cpp \
    -L. \
    -o $OUT/fuzz_thor

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -std=c++23 \
    -I../include \
    ../tests/fuzz_lz4.cpp \
    -L. \
    -o $OUT/fuzz_lz4

$CXX $CXXFLAGS \
    -fsanitize=fuzzer,address,undefined \
    -std=c++23 \
    -I../include \
    ../tests/fuzz_tar.cpp \
    -L. \
    -o $OUT/fuzz_tar