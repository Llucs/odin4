FROM gcr.io/oss-fuzz-base/base-builder@sha256:b2ac08d613b128064d77f5622ac363cbf6818329be6d3f1852a9728a998abd0a

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    clang \
    pkg-config \
    libusb-1.0-dev \
    libcrypto++-dev \
    qt6-base-dev \
    qt6-widgets-dev \
    libarchive-dev

COPY . $SRC/odin4
WORKDIR $SRC/odin4

COPY .clusterfuzzlite/build.sh $SRC/odin4/