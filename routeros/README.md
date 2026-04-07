# RouterOS Setup for snx-edge

Reference scripts for deploying the snx-edge-server container on MikroTik routers.

## Prerequisites

- MikroTik router with **RouterOS 7.4+**
- Container support enabled (`/system/device-mode/update container=yes`, reboot required)
- USB storage mounted as `usb1` (for container root and volumes)
- ARM64 (hAP ax3, RB5009, etc.) or x86_64 (CHR) architecture

## Setup

### 1. Edit `setup.rsc`

Replace all `CHANGE_ME` values:

| Variable | Description |
|---|---|
| User password (step 2) | Password for the `snx-edge` RouterOS API user |
| `SNX_EDGE_JWT_SECRET` | JWT signing secret, minimum 32 characters |
| `SNX_EDGE_ADMIN_PASSWORD` | Initial admin password for the web API |
| `ROUTEROS_PASSWORD` | Must match the RouterOS user password from step 2 |

### 2. Run the script

Paste the contents of `setup.rsc` into a RouterOS terminal session (WinBox Terminal or SSH).

### 3. Wait for the container to pull and start

```routeros
/container/print
```

The container status should transition from `pulling` to `stopped` to `running`.

### 4. Initialize PBR

Once the container is running, set up Policy-Based Routing from your workstation:

```bash
snx-edge-ctl routing setup
```

Or use the tray application: **Routing > Setup PBR**.

## Network Topology

```
LAN clients
    |
MikroTik Router (172.19.0.1)
    |--- br-snx bridge
    |       |--- veth-snx (172.19.0.2) --> container
    |
    |--- PBR: vpn-clients --> vpn-route table --> 172.19.0.2 --> tun0 --> VPN
```

## Customization

- **Subnet**: If `172.19.0.0/24` conflicts with your network, change both the veth address and the bridge IP in `setup.rsc`, and update `ROUTEROS_HOST` accordingly.
- **Storage**: Replace `usb1` with your storage path (e.g., `disk1` for SATA).
- **Image tag**: Replace `latest` with a specific version tag for production (e.g., `ghcr.io/happykust/snx-edge-server:1.0.0`).
