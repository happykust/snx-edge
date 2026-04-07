ARG ALPINE_VERSION=3.23

# ---- Builder ----
FROM rust:alpine${ALPINE_VERSION} AS builder
RUN apk add --no-cache musl-dev perl make linux-headers openssl-dev openssl-libs-static
WORKDIR /app
COPY . .
RUN cargo build --release -p snx-edge-server

# ---- Runtime ----
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
    ca-certificates \
    iproute2 \
    iptables-legacy \
    ip6tables-legacy \
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

# Install binary
COPY --from=builder /app/target/release/snx-edge-server /usr/local/bin/

# Install OpenRC init script
COPY docker/snx-edge.initd /etc/init.d/snx-edge
RUN chmod +x /etc/init.d/snx-edge && rc-update add snx-edge default

# Create required directories
RUN mkdir -p /etc/snx-edge/profiles /var/lib/snx-edge /var/log/snx-edge

# Example config (copy to config.toml and customize)
COPY docker/config.toml.example /etc/snx-edge/config.toml.example

EXPOSE 8080

ENTRYPOINT ["/sbin/init"]
