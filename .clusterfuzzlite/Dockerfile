FROM gcr.io/oss-fuzz-base/base-builder-jammy

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    clang \
    pkg-config \
    libusb-1.0-0-dev \
    libcrypto++-dev \
    libarchive-dev \
    zlib1g-dev \
    qt6-base-dev \
    qt6-base-dev-tools \
    qt6-qpa-plugins

COPY . $SRC/odin4
WORKDIR $SRC/odin4

COPY .clusterfuzzlite/build.sh $SRC/build.sh