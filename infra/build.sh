#!/bin/bash
set -eu

mkdir build
cd build

cmake ..
make -j$(nproc)

$CXX $CXXFLAGS \
    -std=c++23 \
    ../tests/fuzz_pit.cpp \
    -o $OUT/fuzz_pit