#!/bin/bash
set -eux

mkdir -p build
cd build

cmake ..
make -j$(nproc)

$CXX $CXXFLAGS \
    -std=c++23 \
    ../tests/fuzz_pit.cpp \
    -fsanitize=fuzzer \
    -o $OUT/fuzz_pit