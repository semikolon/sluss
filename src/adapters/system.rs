//! System metrics and service status

use anyhow::Result;

use crate::location::execute_shell;

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
    // Try to get external IP from WAN interface
    // On SHANNON, WAN is on enxc84d4421f975 (USB ethernet)
    let output = execute_shell(
        "ip -4 addr show enxc84d4421f975 2>/dev/null | grep -oP 'inet \\K[\\d.]+' || \
         curl -s --max-time 2 ifconfig.me 2>/dev/null || \
         echo 'unknown'"
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
