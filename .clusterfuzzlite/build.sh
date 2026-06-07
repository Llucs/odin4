#!/bin/bash
set -euxo pipefail

export CC=clang
export CXX=clang++

export CXXFLAGS="$CXXFLAGS -std=c++23 -pthread"
export CFLAGS="$CFLAGS -pthread -fPIC"

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

cmake .. -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DODIN4_BUILD_GUI=OFF \
    -DODIN4_BUILD_TESTS=OFF \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="-pthread"

cmake --build . --parallel

mkdir -p "$OUT"

INCLUDES="-I../include -I../src -I../lib -I../lib/lz4"

FUZZ_UTILS="../src/fuzz_utils.cpp"

$CXX $CXXFLAGS -fsanitize=fuzzer,address,undefined \
    -Xclang -dwarf-version=4 \
    $INCLUDES ../tests/fuzz_pit.cpp $FUZZ_UTILS \
    -o $OUT/fuzz_pit

$CXX $CXXFLAGS -fsanitize=fuzzer,address,undefined \
    -Xclang -dwarf-version=4 \
    $INCLUDES ../tests/fuzz_thor.cpp $FUZZ_UTILS \
    -o $OUT/fuzz_thor

$CXX $CXXFLAGS -fsanitize=fuzzer,address,undefined \
    -Xclang -dwarf-version=4 \
    $INCLUDES ../tests/fuzz_lz4.cpp \
    ../build/liblz4_lib.a \
    -o $OUT/fuzz_lz4

$CXX $CXXFLAGS -fsanitize=fuzzer,address,undefined \
    -Xclang -dwarf-version=4 \
    $INCLUDES ../tests/fuzz_tar.cpp \
    -o $OUT/fuzz_tar
