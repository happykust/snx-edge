# ============================================================
# snx-edge: MikroTik Container Setup
# ============================================================
#
# This script is executed ONCE manually via RouterOS terminal.
# PBR rules are created automatically by the container via
# POST /api/v1/routing/setup from tray-client or CLI.
#
# Before running, change all values marked CHANGE_ME.
#
# Requirements:
#   - RouterOS 7.4+ with container support enabled
#   - USB storage mounted (usb1) for container root and volumes
#   - ARM64 or x86_64 architecture
#
# ============================================================

# --- 1. Network Infrastructure ---
# Create veth interface for the container
/interface/veth/add name=veth-snx address=172.19.0.2/24 gateway=172.19.0.1

# Create dedicated bridge
/interface/bridge/add name=br-snx
/interface/bridge/port/add bridge=br-snx interface=veth-snx

# Assign gateway IP to bridge
/ip/address/add address=172.19.0.1/24 interface=br-snx

# NAT for container outbound traffic
/ip/firewall/nat/add chain=srcnat src-address=172.19.0.0/24 action=masquerade

# --- 2. RouterOS REST API User ---
# Create a dedicated user group with minimal permissions
/user/group/add name=snx-edge-api \
    policy=read,write,api,!ftp,!local,!ssh,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api

# Create the API user (CHANGE_ME: set a strong password)
/user/add name=snx-edge group=snx-edge-api password="CHANGE_ME"

# --- 3. Container Environment Variables ---
# JWT secret must be at least 32 characters
/container/envs/add name=snx-env key=SNX_EDGE_JWT_SECRET value="CHANGE_ME_MIN_32_CHARS"
/container/envs/add name=snx-env key=SNX_EDGE_ADMIN_USER value="admin"
/container/envs/add name=snx-env key=SNX_EDGE_ADMIN_PASSWORD value="CHANGE_ME"
/container/envs/add name=snx-env key=ROUTEROS_HOST value="172.19.0.1"
/container/envs/add name=snx-env key=ROUTEROS_USER value="snx-edge"
/container/envs/add name=snx-env key=ROUTEROS_PASSWORD value="CHANGE_ME"

# --- 4. Container Volumes ---
# Persistent storage on USB for config, data, and logs
/container/mounts/add name=snx-config src=usb1/snx-edge/config dst=/etc/snx-edge
/container/mounts/add name=snx-data src=usb1/snx-edge/data dst=/var/lib/snx-edge
/container/mounts/add name=snx-logs src=usb1/snx-edge/logs dst=/var/log/snx-edge

# --- 5. Container ---
/container/add \
    remote-image=ghcr.io/happykust/snx-edge-server:latest \
    interface=veth-snx envlist=snx-env \
    root-dir=usb1/snx-edge \
    mounts=snx-config,snx-data,snx-logs \
    start-on-boot=yes logging=yes

# ============================================================
# After the container starts, initialize PBR from your client:
#
#   snx-edge-ctl routing setup
#
# or via the tray application (Routing > Setup PBR).
# ============================================================
