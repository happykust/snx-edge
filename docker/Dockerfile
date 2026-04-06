## Stage 1: Build (always x86_64, cross-compiles for target)
FROM --platform=linux/amd64 rust:alpine AS builder

ARG TARGETARCH=amd64

# Install build deps + cross-compiler for ARM64 if needed
RUN apk add --no-cache musl-dev perl make openssl-dev dbus-dev pkgconf git && \
    if [ "$TARGETARCH" = "arm64" ]; then \
      apk add --no-cache aarch64-none-elf-gcc || true; \
      wget -qO- https://musl.cc/aarch64-linux-musl-cross.tgz | tar xz -C /opt; \
      ln -s /opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc /usr/local/bin/aarch64-linux-musl-gcc; \
    fi

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY apps/ apps/
COPY vendor/ vendor/

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Configure linker for cross-compilation
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      mkdir -p .cargo && printf '[target.aarch64-unknown-linux-musl]\nlinker = "aarch64-linux-musl-gcc"\n' > .cargo/config.toml; \
    fi

RUN case "$TARGETARCH" in \
      arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
      arm)   RUST_TARGET="armv7-unknown-linux-musleabihf" ;; \
      *)     RUST_TARGET="x86_64-unknown-linux-musl" ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    cargo build --release \
      --target "$RUST_TARGET" \
      --features snxcore/vendored-openssl,snxcore/vendored-sqlite \
      -p snx-edge-server && \
    cp "target/$RUST_TARGET/release/snx-edge-server" /snx-edge-server && \
    (strip /snx-edge-server 2>/dev/null || true)

## Stage 2: Runtime (target platform)
FROM alpine:3.21

RUN apk add --no-cache ca-certificates iproute2 iptables

COPY --from=builder /snx-edge-server /usr/local/bin/snx-edge-server
COPY docker/config.toml.example /etc/snx-edge/config.toml

RUN mkdir -p /var/lib/snx-edge /var/log/snx-edge /etc/snx-edge/certs

EXPOSE 8080

ENTRYPOINT ["snx-edge-server"]
CMD ["--config", "/etc/snx-edge/config.toml"]
