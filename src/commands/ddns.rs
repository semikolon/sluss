//! Dynamic DNS management commands
//!
//! Reads state from /var/cache/router-ddns-state.json (written by
//! router-ddns Python script running via systemd timer).
//! Provides `sluss ddns status` and `sluss ddns update` commands.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::process::Command;

use crate::output::print_output;

const STATE_FILE: &str = "/var/cache/router-ddns-state.json";
const DDNS_SCRIPT: &str = "/usr/local/lib/router-security/ddns_update.py";
const WAN_INTERFACE: &str = "enxc84d4421f975";

#[derive(Debug, Serialize, Deserialize)]
pub struct DdnsState {
    pub ip: String,
    pub status: String,
    pub message: String,
    pub timestamp: String,
    pub fqdn: String,
    pub interface: String,
    pub ttl: u32,
}

#[derive(Debug, Serialize)]
pub struct DdnsStatus {
    pub wan_ip: String,
    pub dns_record: String,
    pub fqdn: String,
    pub status: String,
    pub last_check: String,
    pub message: String,
    pub timer_active: bool,
    pub ip_match: bool,
}

impl Display for DdnsStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Dynamic DNS: {}", self.fqdn)?;
        writeln!(f, "  WAN IP:      {}", self.wan_ip)?;
        writeln!(f, "  DNS record:  {}", self.dns_record)?;
        writeln!(f, "  Status:      {}", self.status)?;
        writeln!(f, "  Last check:  {}", self.last_check)?;
        writeln!(f, "  Timer:       {}", if self.timer_active { "active" } else { "inactive" })?;
        if !self.message.is_empty() && self.message != "No change" {
            writeln!(f, "  Message:     {}", self.message)?;
        }
        if !self.ip_match && self.dns_record != "never updated" {
            writeln!(f, "  WARNING:     IP mismatch — DNS needs update")?;
        }
        Ok(())
    }
}

/// Get WAN IP from interface
fn get_wan_ip() -> Option<String> {
    let output = Command::new("ip")
        .args(["-4", "-o", "addr", "show", WAN_INTERFACE])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for part in stdout.split_whitespace() {
        if part.contains('/') && part.contains('.') {
            if let Some(ip) = part.split('/').next() {
                return Some(ip.to_string());
            }
        }
    }
    None
}

/// Check if systemd timer is active
fn timer_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "router-ddns.timer"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Show DDNS status
pub fn status(json: bool) -> Result<()> {
    let wan_ip = get_wan_ip().unwrap_or_else(|| "unknown".to_string());

    let state: Option<DdnsState> = std::fs::read_to_string(STATE_FILE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    let (dns_record, fqdn, status_str, last_check, message) = match &state {
        Some(s) => (
            s.ip.clone(),
            s.fqdn.clone(),
            s.status.clone(),
            s.timestamp.clone(),
            s.message.clone(),
        ),
        None => (
            "never updated".to_string(),
            "shannon.fredrikbranstrom.se".to_string(),
            "unknown".to_string(),
            "never".to_string(),
            String::new(),
        ),
    };

    let ip_match = wan_ip == dns_record;

    let result = DdnsStatus {
        wan_ip,
        dns_record,
        fqdn,
        status: status_str,
        last_check,
        message,
        timer_active: timer_active(),
        ip_match,
    };

    print_output(&result, json);
    Ok(())
}

/// Trigger a DDNS update
pub fn update(force: bool, json: bool) -> Result<()> {
    let mut cmd = Command::new(DDNS_SCRIPT);
    if force {
        cmd.arg("--force");
    }

    let output = cmd.output()
        .context("Failed to run DDNS update script")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if json {
            println!("{{\"error\": \"{}\"}}", stderr.trim().replace('"', "\\\""));
        } else {
            eprintln!("{}", stderr);
        }
        std::process::exit(1);
    }

    // Show updated status
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() && !json {
        eprint!("{}", stderr);
    }

    status(json)
}
