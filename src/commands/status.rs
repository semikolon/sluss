//! System status and diagnostics

use anyhow::Result;
use serde::Serialize;
use std::fmt::Display;

use crate::adapters::system::{get_service_status, get_system_metrics, get_wan_ip};
use crate::location::execute_shell;
use crate::output::{print_output, LineStatus, StatusLine, StatusReport};

/// System status overview
#[derive(Debug, Serialize)]
pub struct SystemStatus {
    pub wan_ip: String,
    pub uptime: String,
    pub memory_used_percent: f32,
    pub cpu_load: f32,
    pub services: Vec<ServiceStatus>,
}

#[derive(Debug, Serialize)]
pub struct ServiceStatus {
    pub name: String,
    pub active: bool,
}

impl Display for SystemStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = hostname::get()
            .map(|h| h.to_string_lossy().to_uppercase().to_string())
            .unwrap_or_else(|_| "ROUTER".to_string());
        writeln!(f, "{} Router Status", host)?;
        writeln!(f, "{}", "=".repeat(host.len() + 14))?;
        writeln!(f, "WAN IP:     {}", self.wan_ip)?;
        writeln!(f, "Uptime:     {}", self.uptime)?;
        writeln!(f, "Memory:     {:.1}%", self.memory_used_percent)?;
        writeln!(f, "CPU Load:   {:.2}", self.cpu_load)?;
        writeln!(f)?;
        writeln!(f, "Services:")?;
        for svc in &self.services {
            let indicator = if svc.active { "✓" } else { "✗" };
            writeln!(f, "  {} {}", indicator, svc.name)?;
        }
        Ok(())
    }
}

/// Run `sluss status`
pub fn status(json: bool) -> Result<()> {
    let wan_ip = get_wan_ip().unwrap_or_else(|_| "unknown".to_string());
    let metrics = get_system_metrics()?;

    let services = vec!["dnsmasq", "ssh", "crowdsec", "AdGuardHome", "wg-quick@wg0"]
        .into_iter()
        .map(|name| ServiceStatus {
            name: name.to_string(),
            active: get_service_status(name).unwrap_or(false),
        })
        .collect();

    let status = SystemStatus {
        wan_ip,
        uptime: metrics.uptime,
        memory_used_percent: metrics.memory_used_percent,
        cpu_load: metrics.cpu_load,
        services,
    };

    print_output(&status, json);
    Ok(())
}

/// Doctor diagnostics
#[derive(Debug, Serialize)]
pub struct DiagnosticResult {
    pub checks: Vec<DiagnosticCheck>,
    pub all_passed: bool,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

impl Display for DiagnosticResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = hostname::get()
            .map(|h| h.to_string_lossy().to_uppercase().to_string())
            .unwrap_or_else(|_| "ROUTER".to_string());
        writeln!(f, "{} Doctor", host)?;
        writeln!(f, "{}", "=".repeat(host.len() + 7))?;
        for check in &self.checks {
            let indicator = if check.passed { "✓" } else { "✗" };
            writeln!(f, "{} {}: {}", indicator, check.name, check.message)?;
        }
        writeln!(f)?;
        if self.all_passed {
            writeln!(f, "All checks passed!")?;
        } else {
            writeln!(f, "Some checks failed.")?;
        }
        Ok(())
    }
}

/// Run `sluss doctor`
pub fn doctor(json: bool) -> Result<()> {
    let mut checks = Vec::new();

    // Check 1: Gateway ping
    let gateway_check = check_ping("192.168.4.1", "Gateway");
    checks.push(gateway_check);

    // Check 2: DNS resolution
    let dns_check = check_dns();
    checks.push(dns_check);

    // Check 3: Internet connectivity
    let internet_check = check_ping("1.1.1.1", "Internet (1.1.1.1)");
    checks.push(internet_check);

    // Check 4: dnsmasq service
    let dnsmasq_check = DiagnosticCheck {
        name: "dnsmasq service".to_string(),
        passed: get_service_status("dnsmasq").unwrap_or(false),
        message: if get_service_status("dnsmasq").unwrap_or(false) {
            "running".to_string()
        } else {
            "not running".to_string()
        },
    };
    checks.push(dnsmasq_check);

    let all_passed = checks.iter().all(|c| c.passed);

    let result = DiagnosticResult { checks, all_passed };

    print_output(&result, json);

    if !all_passed {
        std::process::exit(1);
    }

    Ok(())
}

fn check_ping(target: &str, name: &str) -> DiagnosticCheck {
    let output = execute_shell(&format!("ping -c 1 -W 2 {}", target));

    match output {
        Ok(out) if out.status.success() => DiagnosticCheck {
            name: name.to_string(),
            passed: true,
            message: "reachable".to_string(),
        },
        Ok(out) => DiagnosticCheck {
            name: name.to_string(),
            passed: false,
            message: format!(
                "unreachable: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        },
        Err(e) => DiagnosticCheck {
            name: name.to_string(),
            passed: false,
            message: format!("error: {}", e),
        },
    }
}

fn check_dns() -> DiagnosticCheck {
    // Use getent or ping to test DNS (nslookup/dig may not be installed)
    let output = execute_shell("getent hosts google.com 2>/dev/null || ping -c 1 -W 2 google.com 2>&1 | grep -q 'bytes from'");

    match output {
        Ok(out) if out.status.success() => DiagnosticCheck {
            name: "DNS resolution".to_string(),
            passed: true,
            message: "working".to_string(),
        },
        Ok(_) => DiagnosticCheck {
            name: "DNS resolution".to_string(),
            passed: false,
            message: "failed to resolve google.com".to_string(),
        },
        Err(e) => DiagnosticCheck {
            name: "DNS resolution".to_string(),
            passed: false,
            message: format!("error: {}", e),
        },
    }
}
