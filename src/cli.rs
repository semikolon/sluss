//! CLI argument definitions using Clap derive macros

use clap::{Parser, Subcommand};
use std::net::IpAddr;

#[derive(Parser)]
#[command(
    name = "sluss",
    about = "Unified router management CLI",
    version,
    author
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output in JSON format (for AI agents)
    #[arg(long, global = true)]
    pub json: bool,

    /// Skip confirmation prompts
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// System health overview (WAN IP, memory, services)
    Status,

    /// Run diagnostic checks (DNS, gateway, internet, services)
    Doctor,

    /// DNS record management
    Dns {
        #[command(subcommand)]
        action: DnsAction,
    },

    /// DHCP lease and reservation management
    Dhcp {
        #[command(subcommand)]
        action: DhcpAction,
    },

    /// Firewall and port forwarding
    Fw {
        #[command(subcommand)]
        action: FwAction,
    },

    /// Security stack (CrowdSec, AdGuard, WireGuard)
    Sec {
        #[command(subcommand)]
        action: SecAction,
    },

    /// VPN (WireGuard) management
    Vpn {
        #[command(subcommand)]
        action: VpnAction,
    },

    /// Dynamic DNS management
    Ddns {
        #[command(subcommand)]
        action: DdnsAction,
    },

    /// Start the web dashboard (default: 0.0.0.0:8080)
    Web {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
    },
}

// DNS subcommands
#[derive(Subcommand)]
pub enum DnsAction {
    /// List all DNS records
    List,

    /// Add a DNS record
    Add {
        /// Hostname to add
        hostname: String,
        /// IP address to point to
        ip: IpAddr,
    },

    /// Remove a DNS record
    Rm {
        /// Hostname to remove
        hostname: String,
    },
}

// DHCP subcommands
#[derive(Subcommand)]
pub enum DhcpAction {
    /// List all DHCP leases
    Leases,

    /// Add a static DHCP reservation
    Reserve {
        /// MAC address (format: aa:bb:cc:dd:ee:ff)
        mac: String,
        /// IP address to reserve
        ip: IpAddr,
        /// Optional hostname
        #[arg(short, long)]
        hostname: Option<String>,
    },

    /// Remove a DHCP reservation
    Unreserve {
        /// MAC address or IP to unreserve
        target: String,
    },
}

// Firewall subcommands
#[derive(Subcommand)]
pub enum FwAction {
    /// List firewall rules and port forwards
    List,

    /// Add a port forwarding rule
    Forward {
        /// External port to forward
        external_port: u16,
        /// Internal destination (ip:port format)
        internal: String,
        /// Protocol (tcp, udp, or both)
        #[arg(short, long, default_value = "tcp")]
        proto: String,
    },

    /// Remove a port forwarding rule
    Unforward {
        /// External port to stop forwarding
        external_port: u16,
    },

    /// Block an IP address or range
    Block {
        /// IP address or CIDR range to block
        target: String,
    },

    /// Unblock an IP address or range
    Unblock {
        /// IP address or CIDR range to unblock
        target: String,
    },
}

// Security subcommands
#[derive(Subcommand)]
pub enum SecAction {
    /// Combined security stack status (AdGuard + CrowdSec + WireGuard)
    Status,

    /// Show active CrowdSec blocks (banned IPs)
    Blocks,

    /// Run security analysis on logs
    Scan,

    /// Show recent security findings
    Report {
        /// Number of hours to look back (default: 24)
        #[arg(short = 'n', long, default_value = "24")]
        hours: u32,
    },

    /// Silence-first triage digest (only outputs if something noteworthy)
    Findings {
        /// Number of days to look back (default: 14)
        #[arg(short = 'n', long, default_value = "14")]
        days: u32,
    },
}

// VPN subcommands
#[derive(Subcommand)]
pub enum VpnAction {
    /// List WireGuard peers with connection status
    Peers,

    /// Show WireGuard interface status
    Status,
}

// DDNS subcommands
#[derive(Subcommand)]
pub enum DdnsAction {
    /// Show current DDNS status (WAN IP, DNS record, timer)
    Status,

    /// Trigger a DNS update check
    Update {
        /// Force update even if IP hasn't changed
        #[arg(long)]
        force: bool,
    },
}
