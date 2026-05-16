FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    clang

COPY . $SRC/odin4
WORKDIR $SRC/odin4

COPY .clusterfuzzlite/build.sh $SRC/