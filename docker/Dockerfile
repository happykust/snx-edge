ARG ALPINE_VERSION=3.23
ARG RUST_VERSION=1

# ---- Builder ----
# NOTE: We do NOT use --platform=$BUILDPLATFORM here because cross-compiling
# Rust for ARM with musl requires a full target toolchain (linker, libc headers).
# Multi-arch builds are handled by the CI pipeline using the `cross` tool instead.
# This Dockerfile is for native-arch builds only.
FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS builder

# openssl-dev + openssl-libs-static are needed for musl static linking.
# snxcore is an external git dependency and does not expose vendored-openssl
# or vendored-sqlite features, so we rely on system packages instead.
RUN apk add --no-cache musl-dev perl make linux-headers openssl-dev openssl-libs-static
WORKDIR /app
COPY . .
RUN cargo build --release -p snx-edge-server

# ---- Runtime ----
FROM alpine:${ALPINE_VERSION}

# curl is used for the HEALTHCHECK; libcap is required for setcap on the binary;
# dnsmasq is the in-container split-DNS forwarder (started by the init script).
# busybox (Alpine base) already provides `kill`/`pidof` used to (re)load dnsmasq.
RUN apk add --no-cache \
    ca-certificates \
    curl \
    dnsmasq \
    iproute2 \
    iptables \
    ip6tables \
    libcap \
    openrc

# iptables-legacy (nftables does not work in MikroTik containers)
RUN rm -f /usr/sbin/iptables && ln -s /usr/sbin/iptables-legacy /usr/sbin/iptables && \
    rm -f /usr/sbin/ip6tables && ln -s /usr/sbin/ip6tables-legacy /usr/sbin/ip6tables

# ip_forward
RUN echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# OpenRC init (proven pattern from AmneziaWG on MikroTik)
RUN sed -i 's/^\(tty\d\:\:\)/#\1/' /etc/inittab && \
    sed -i \
        -e 's/^#\?rc_env_allow=.*/rc_env_allow="\*"/' \
        -e 's/^#\?rc_sys=.*/rc_sys="docker"/' \
        /etc/rc.conf && \
    sed -i \
        -e 's/VSERVER/DOCKER/' \
        -e 's/checkpath -d "$RC_SVCDIR"/mkdir "$RC_SVCDIR"/' \
        /usr/libexec/rc/sh/init.sh && \
    rm -f /etc/init.d/hwdrivers /etc/init.d/machine-id && \
    sed -i 's/^tty/#tty/' /etc/inittab

# Workaround: OpenRC sysctl crashes if kernel params are already set (MikroTik containers)
RUN sed -i 's/cmd sysctl -q \(.*\?\)=\(.*\)/[[ "$(sysctl -n \1)" != "\2" ]] \&\& \0/' \
    /usr/libexec/rc/sh/init.sh 2>/dev/null || true

# Create dedicated unprivileged user. PID 1 stays root (OpenRC requirement);
# OpenRC drops to this user via `command_user` in /etc/init.d/snx-edge.
RUN addgroup -S snxedge && adduser -S snxedge -G snxedge

# Install binary, then grant the network capabilities the server needs to
# perform iptables/TUN operations as a non-root user.
COPY --from=builder /app/target/release/snx-edge-server /usr/local/bin/
RUN setcap cap_net_admin,cap_net_raw=eip /usr/local/bin/snx-edge-server

# Install OpenRC init script
COPY docker/snx-edge.initd /etc/init.d/snx-edge
RUN chmod +x /etc/init.d/snx-edge && rc-update add snx-edge default

# Static base config for the in-container split-DNS forwarder. dnsmasq is NOT
# added to a runlevel; the snx-edge init script starts it (so it comes up after
# net and the runtime servers-file exists).
COPY docker/dnsmasq.conf /etc/dnsmasq.conf

# Create required directories owned by snxedge
RUN mkdir -p /etc/snx-edge/profiles /var/lib/snx-edge /var/log/snx-edge && \
    chown -R snxedge:snxedge /etc/snx-edge /var/lib/snx-edge /var/log/snx-edge

# Example config (copy to config.toml and customize)
COPY docker/config.toml.example /etc/snx-edge/config.toml.example
RUN chown snxedge:snxedge /etc/snx-edge/config.toml.example

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsSk https://localhost:8080/api/v1/health \
     || curl -fsS http://localhost:8080/api/v1/health || exit 1

# PID 1 must be root for OpenRC; the server process itself runs as `snxedge`
# via `command_user` in the init script.
ENTRYPOINT ["/sbin/init"]
