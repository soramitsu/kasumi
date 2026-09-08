# Official Docker Hub rust:1.97.1-bookworm, resolved 2026-09-08.
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang cmake python3 ripgrep \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
ENV CARGO_TARGET_DIR=/workspace/target/linux-validation
RUN rustup component add clippy rustfmt
