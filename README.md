# sluss

Unified router management CLI for Linux routers.

A token-efficient CLI designed for both humans and AI agents to manage DNS, DHCP, firewall, VPN, and security on a home router.

**v0.2.0** — generic router CLI (renamed from `shannon`). Works on any Linux router with dnsmasq + systemd.

## Features

- **System Health**: `sluss status` overview, `sluss doctor` diagnostics
- **DNS Management**: Add/remove/list local DNS records
- **DHCP Management**: View leases, add static reservations
- **Firewall**: Port forwarding, IP blocking
- **Security Stack**: CrowdSec IDS, AdGuard Home DNS filtering, WireGuard VPN
- **LLM Security Analysis**: GPT-5-nano hourly triage + Gemini 3 Pro daily deep analysis (~$3/month)
- **Dynamic DNS**: Auto-updates via Loopia API on IP change
- **Web Dashboard**: Mobile-friendly status page with quick actions (`sluss web`)
- **Dual Output**: Plain text for humans, `--json` for AI agents
- **Location-Aware**: Works locally on the router or remotely via SSH

## Installation

### From Source

```bash
cargo build --release

# Copy to router
scp target/release/sluss router:/usr/local/bin/

# Or cross-compile for ARM64
cross build --release --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/sluss router:/usr/local/bin/
```

### Remote Usage

Set `SLUSS_ROUTER` to the SSH host alias for your router (defaults to `router`):

```bash
# Option A: set env var
export SLUSS_ROUTER=shannon
sluss status

# Option B: SSH alias
alias sluss='ssh router sluss'
```

## Usage

```bash
# System health
sluss status              # Overview (WAN IP, memory, services)
sluss doctor              # Run diagnostic checks

# DNS management
sluss dns list            # List all DNS records
sluss dns add myhost 192.168.4.100
sluss dns rm myhost

# DHCP management
sluss dhcp leases         # List all leases
sluss dhcp reserve aa:bb:cc:dd:ee:ff 192.168.4.100 --hostname mydevice
sluss dhcp unreserve aa:bb:cc:dd:ee:ff

# Firewall
sluss fw list             # List port forwards
sluss fw forward 8080 192.168.4.84:80 --proto tcp
sluss fw unforward 8080
sluss fw block 1.2.3.4
sluss fw unblock 1.2.3.4

# Security
sluss sec status          # Health of AdGuard, CrowdSec, WireGuard
sluss sec blocks          # Active CrowdSec decisions (blocked IPs)
sluss sec scan            # Run security analysis
sluss sec report          # View recent findings

# VPN
sluss vpn peers           # WireGuard peers with handshake status
sluss vpn status          # WireGuard interface status

# Dynamic DNS
sluss ddns status         # WAN IP, DNS record, timer status
sluss ddns update         # Check and update if IP changed
sluss ddns update --force # Force DNS update

# Web dashboard
sluss web                 # Start at 0.0.0.0:8080
sluss web -p 80           # Start on port 80
```

### AI Agent Usage

All commands support `--json` for structured output:

```bash
sluss status --json
sluss dhcp leases --json
```

Use `--yes` to skip confirmation prompts for automation:

```bash
sluss fw forward 8080 192.168.4.84:80 --yes
```

## Architecture

```
sluss CLI
├── status         → sysinfo + systemctl
├── doctor         → diagnostic checks
├── dns            → dnsmasq config parsing
├── dhcp           → dnsmasq leases + dhcp-host
├── fw             → nftables rules
├── sec            → CrowdSec + AdGuard adapters
│   ├── status     → combined health
│   └── blocks     → active CrowdSec decisions
├── vpn            → WireGuard adapter
│   ├── peers      → peer list with handshake status
│   └── status     → interface overview
├── ddns           → Dynamic DNS (Loopia API)
│   ├── status     → WAN IP, DNS record, timer
│   └── update     → check and update if changed
└── web            → Dashboard (axum, CircularStd font)
```

## Security Stack

Dual-layer approach complementing CrowdSec's pattern matching with LLM semantic reasoning:

| Service | Port | Purpose |
|---------|------|---------|
| AdGuard Home | 53 (DNS), 3000 (web) | DNS filtering, blocklist rules, DoH upstream |
| CrowdSec | — | IDS with nftables bouncer, SSH monitoring, community blocklist |
| WireGuard | 51820 | VPN (kernel-space), encrypted remote access |

dnsmasq handles DHCP only (`port=0`). All DNS queries go through AdGuard Home.

### LLM Security Analysis (~$3/month)

- **Hourly**: GPT-5-nano triage — categorizes critical/normal/clear
- **Daily**: Gemini 3 Pro deep analysis — pattern correlation, behavioral anomalies, trend detection

Results saved to `/var/log/router-security-analyses/`. Critical findings route to ntfy.

### Dynamic DNS

Auto-updates via Loopia XMLRPC API. Reads WAN IP directly from interface (zero external calls), updates DNS only on change.

| Component | Path |
|-----------|------|
| Update script | `/usr/local/lib/router-security/ddns_update.py` |
| Timer | `router-ddns.timer` (5 min) |
| State | `/var/cache/router-ddns-state.json` |
| Credentials | `/etc/router-security/env` |

## Configuration

Default paths:
- dnsmasq config: `/etc/dnsmasq.conf`
- Custom DNS: `/etc/dnsmasq.d/custom.conf`
- DHCP leases: `/var/lib/misc/dnsmasq.leases`
- LLM scripts: `/usr/local/lib/router-security/`
- LLM logs: `/var/log/router-llm-triage.log`
- Analysis archive: `/var/log/router-security-analyses/`

## Requirements

- Linux with dnsmasq + systemd
- SSH access for remote operation
- Root access on the router

## License

MIT

## Author

Fredrik Bränström
