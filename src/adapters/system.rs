//! System metrics and service status

use anyhow::Result;
use std::sync::OnceLock;

use crate::location::execute_shell;

/// Cached WAN interface name (detected once, reused).
static WAN_INTERFACE: OnceLock<String> = OnceLock::new();

/// Detect WAN interface — the one with the default route.
/// Parses `ip route show default` output like:
///   "default via 94.254.88.1 dev enx00e04c680072 proto dhcp ..."
/// Falls back to "unknown" if detection fails.
pub fn detect_wan_interface() -> &'static str {
    WAN_INTERFACE.get_or_init(|| {
        execute_shell("ip route show default 2>/dev/null")
            .ok()
            .and_then(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let parts: Vec<&str> = stdout.split_whitespace().collect();
                parts.iter()
                    .position(|&p| p == "dev")
                    .and_then(|i| parts.get(i + 1))
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "unknown".to_string())
    })
}

#[derive(Debug)]
pub struct SystemMetrics {
    pub uptime: String,
    pub memory_used_percent: f32,
    pub cpu_load: f32,
}

/// Get system metrics (uptime, memory, CPU)
pub fn get_system_metrics() -> Result<SystemMetrics> {
    // Get uptime
    let uptime_output = execute_shell("uptime -p 2>/dev/null || uptime")?;
    let uptime = String::from_utf8_lossy(&uptime_output.stdout)
        .trim()
        .to_string();

    // Get memory info
    let mem_output = execute_shell("free -m | awk '/^Mem:/ {print $3/$2*100}'")?;
    let memory_used_percent: f32 = String::from_utf8_lossy(&mem_output.stdout)
        .trim()
        .parse()
        .unwrap_or(0.0);

    // Get load average
    let load_output = execute_shell("cat /proc/loadavg | awk '{print $1}'")?;
    let cpu_load: f32 = String::from_utf8_lossy(&load_output.stdout)
        .trim()
        .parse()
        .unwrap_or(0.0);

    Ok(SystemMetrics {
        uptime,
        memory_used_percent,
        cpu_load,
    })
}

/// Get WAN IP address
pub fn get_wan_ip() -> Result<String> {
    let iface = detect_wan_interface();
    let output = execute_shell(
        &format!(
            "ip -4 addr show {} 2>/dev/null | grep -oP 'inet \\K[\\d.]+' || \
             curl -s --max-time 2 ifconfig.me 2>/dev/null || \
             echo 'unknown'",
            iface
        )
    )?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Check if a systemd service is active
pub fn get_service_status(service: &str) -> Result<bool> {
    // nftables is a oneshot service — it loads rules and exits.
    // Check if rules are actually loaded instead of service status.
    if service == "nftables" {
        let output = execute_shell("nft list ruleset 2>/dev/null | grep -c 'chain'")?;
        let count: i32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap_or(0);
        return Ok(count > 0);
    }

    let output = execute_shell(&format!("systemctl is-active {} 2>/dev/null", service))?;
    Ok(output.status.success())
}
