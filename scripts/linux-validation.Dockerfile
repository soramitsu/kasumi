# Official Docker Hub rust:1.94.1-bookworm, resolved 2026-09-05.
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang cmake python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
ENV CARGO_TARGET_DIR=/workspace/target/linux-validation
RUN rustup component add clippy rustfmt
