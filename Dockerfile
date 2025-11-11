FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libcurl4-openssl-dev \
    libfido2-dev \
    libssl-dev \
    libpam0g-dev \
    libcbor-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /build

WORKDIR /build
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

RUN cmake --build build

FROM ubuntu:22.04
WORKDIR /artifacts
COPY --from=builder /build/build/lib/privacyidea_pam_passkey.so .