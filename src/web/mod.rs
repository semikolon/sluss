//! Web dashboard for sluss router management
//!
//! Serves a mobile-friendly status page with big buttons for common admin tasks.
//! Designed for LAN-only access (http://internet.home).

use axum::{
    extract::{Path, Query},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tracing::info;

use crate::adapters::system::{get_service_status, get_system_metrics, get_wan_ip};
use crate::location::execute_shell;

pub async fn serve(bind: &str, port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/status", get(api_status))
        .route("/api/findings", get(api_findings))
        .route("/api/action", get(api_action))
        .route("/fonts/{filename}", get(serve_font));

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_uppercase().to_string())
        .unwrap_or_else(|_| "ROUTER".to_string());
    info!("{} dashboard at http://{}:{}", host, bind, port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// --- Data collection ---

struct SecurityFinding {
    timestamp: String,
    category: String,
    summary: String,
    findings: Vec<String>,
}

struct DashboardData {
    wan_ip: String,
    uptime: String,
    memory_pct: f32,
    cpu_load: f32,
    services: Vec<(&'static str, &'static str, &'static str, bool)>, // (id, name, description, active)
    connected_devices: u32,
    blocked_ips: u32,
    dns_queries_today: String,
    wan_speed: String,
    wan_usb_speed: String,
    disk_pct: String,
    recent_security: Vec<SecurityFinding>,
}

fn collect_dashboard_data() -> DashboardData {
    let wan_ip = get_wan_ip().unwrap_or_else(|_| "unknown".into());
    let metrics = get_system_metrics().unwrap_or_else(|_| crate::adapters::system::SystemMetrics {
        uptime: "unknown".into(),
        memory_used_percent: 0.0,
        cpu_load: 0.0,
    });

    // Count connected devices from DHCP leases
    let connected_devices = execute_shell("cat /var/lib/misc/dnsmasq.leases 2>/dev/null | wc -l")
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok())
        .unwrap_or(0);

    // Count CrowdSec blocked IPs
    let blocked_ips = execute_shell("cscli decisions list -o json 2>/dev/null | grep -c '\"value\"' || echo 0")
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok())
        .unwrap_or(0);

    // AdGuard DNS stats
    let dns_queries_today = execute_shell(
        "curl -s http://127.0.0.1:3000/control/stats 2>/dev/null | grep -o '\"num_dns_queries\":[0-9]*' | cut -d: -f2"
    )
    .ok()
    .map(|o| {
        let n = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if n.is_empty() { "N/A".into() } else { n }
    })
    .unwrap_or_else(|| "N/A".into());

    // WAN speed estimate
    let wan_speed = execute_shell("ethtool enxc84d4421f975 2>/dev/null | grep Speed | awk '{print $2}'")
        .ok()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { "Unknown".into() } else { s }
        })
        .unwrap_or_else(|| "Unknown".into());

    // Detect WAN adapter USB bus speed from sysfs
    let wan_usb_speed = execute_shell(
        "cat /sys/class/net/enxc84d4421f975/device/../speed 2>/dev/null"
    )
    .ok()
    .map(|o| {
        let speed = String::from_utf8_lossy(&o.stdout).trim().to_string();
        match speed.as_str() {
            "5000" => "USB 3.0".to_string(),
            "10000" => "USB 3.1".to_string(),
            "480" => "USB 2.0".to_string(),
            s if !s.is_empty() => format!("USB ({}Mbps)", s),
            _ => "USB".to_string(),
        }
    })
    .unwrap_or_else(|| "USB".to_string());

    let services = vec![
        ("dnsmasq", "Network Core", "Assigns IP addresses to all devices and resolves domain names on the local network (DHCP + DNS)", get_service_status("dnsmasq").unwrap_or(false)),
        ("AdGuardHome", "Ad & Tracker Blocker", "Filters out ads, trackers, and malicious domains before they reach any device — like an ad blocker for the entire house", get_service_status("AdGuardHome").unwrap_or(false)),
        ("crowdsec", "Intrusion Detection", "Monitors network traffic and SSH logs for suspicious activity, automatically blocks attackers using community-shared threat intelligence", get_service_status("crowdsec").unwrap_or(false)),
        ("nftables", "Firewall", "Controls which traffic flows in and out — only allows connections you've approved, blocks everything else", get_service_status("nftables").unwrap_or(false)),
        ("wg-quick@wg0", "VPN Tunnel", "Encrypted private tunnel (WireGuard) for secure remote access to the home network from anywhere in the world", get_service_status("wg-quick@wg0").unwrap_or(false)),
        ("wan-watchdog", "Connection Guardian", "Monitors internet connectivity and automatically recovers from outages by resetting the WAN adapter (~90 second recovery)", get_service_status("wan-watchdog").unwrap_or(false)),
        ("ssh", "Remote Access", "Secure shell access for administration — key-only authentication, no passwords accepted", get_service_status("ssh").unwrap_or(false)),
    ];

    // Disk usage
    let disk_pct = execute_shell("df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %'")
        .ok()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { "?".into() } else { format!("{}%", s) }
        })
        .unwrap_or_else(|| "?".into());

    // Recent security findings from daily digest (last 7 days)
    let recent_security = execute_shell(
        "tail -20 /var/log/shannon-daily-digest.jsonl 2>/dev/null"
    )
    .ok()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|line| {
                let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
                let content = parsed.get("content")?;
                Some(SecurityFinding {
                    timestamp: parsed.get("timestamp")?.as_str()?.to_string(),
                    category: content.get("category")?.as_str()?.to_string(),
                    summary: content.get("summary")?.as_str()?.to_string(),
                    findings: content.get("findings")?
                        .as_array()?
                        .iter()
                        .filter_map(|f| f.as_str().map(String::from))
                        .collect(),
                })
            })
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();

    // Also grab recent triage log entries (successful ones only)
    let mut triage_summaries = execute_shell(
        "grep 'TRIAGE:' /var/log/shannon-llm-triage.log 2>/dev/null | tail -10"
    )
    .ok()
    .map(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|line| {
                // Format: 2026-03-06T11:00:18+00:00 TRIAGE: category=normal summary="..."
                let ts = line.split(' ').next()?.to_string();
                let cat_start = line.find("category=")? + 9;
                let cat_end = line[cat_start..].find(' ')? + cat_start;
                let category = line[cat_start..cat_end].to_string();
                let sum_start = line.find("summary=\"")? + 9;
                let sum_end = line.rfind('"')?;
                let summary = line[sum_start..sum_end].to_string();
                Some(SecurityFinding {
                    timestamp: ts,
                    category,
                    summary,
                    findings: vec![],
                })
            })
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();

    // Also read daily analysis JSON files (last 7 days)
    let daily_analyses = execute_shell(
        "ls -t /var/log/shannon-security-analyses/????-??-??.json 2>/dev/null | head -7 | while read f; do echo \"$f\"; cat \"$f\"; echo; done"
    )
    .ok()
    .map(|o| {
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        let mut results = Vec::new();
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            if line.ends_with(".json") {
                // Extract date from filename: .../2026-03-06.json
                let date = line.rsplit('/').next().unwrap_or("").trim_end_matches(".json");
                let ts = format!("{}T06:00:00+00:00", date);
                // Collect JSON lines until empty line or next .json
                let mut json_str = String::new();
                while let Some(jline) = lines.peek() {
                    if jline.is_empty() || jline.ends_with(".json") { break; }
                    json_str.push_str(lines.next().unwrap());
                }
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let severity = parsed.get("severity").and_then(|v| v.as_str()).unwrap_or("green");
                    let category = match severity {
                        "red" => "critical",
                        "yellow" => "warning",
                        _ => "clear",
                    };
                    results.push(SecurityFinding {
                        timestamp: ts,
                        category: format!("daily-{}", category),
                        summary: format!("[Daily] {}", parsed.get("summary").and_then(|v| v.as_str()).unwrap_or("No summary")),
                        findings: parsed.get("recommendations")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|f| f.as_str().map(String::from)).collect())
                            .unwrap_or_default(),
                    });
                }
            }
        }
        results
    })
    .unwrap_or_default();

    // Merge: daily analyses + digest entries (richer) + triage log
    let mut all_security = daily_analyses;
    all_security.extend(recent_security);
    // Only add triage entries whose timestamps aren't already covered
    let existing_timestamps: std::collections::HashSet<&str> = all_security.iter().map(|s| s.timestamp.as_str()).collect();
    triage_summaries.retain(|s| !existing_timestamps.contains(s.timestamp.as_str()));
    all_security.extend(triage_summaries);
    all_security.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    all_security.truncate(10); // Keep last 10

    DashboardData {
        wan_ip,
        uptime: metrics.uptime,
        memory_pct: metrics.memory_used_percent,
        cpu_load: metrics.cpu_load,
        services,
        connected_devices,
        blocked_ips,
        dns_queries_today,
        wan_speed,
        wan_usb_speed,
        disk_pct,
        recent_security: all_security,
    }
}

// --- HTML rendering ---

fn get_host_label() -> (String, String) {
    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_uppercase().to_string())
        .unwrap_or_else(|_| "ROUTER".to_string());
    let platform = std::fs::read_to_string("/sys/firmware/devicetree/base/model")
        .map(|m| m.trim_end_matches('\0').to_string())
        .or_else(|_| {
            std::process::Command::new("sh")
                .args(["-c", "lscpu 2>/dev/null | grep 'Model name' | cut -d: -f2"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_default();
    (host, platform)
}

fn render_dashboard(data: &DashboardData) -> String {
    let services_html: String = data.services.iter().map(|(id, name, desc, active)| {
        let status_class = if *active { "status-ok" } else { "status-down" };
        let status_text = if *active { "Running" } else { "Stopped" };
        let status_dot = if *active { "&#x25CF;" } else { "&#x25CF;" };
        format!(
            r#"<div class="card service-card">
                <div class="service-header">
                    <span class="service-dot {status_class}">{status_dot}</span>
                    <strong>{name}</strong>
                    <span class="service-badge {status_class}">{status_text}</span>
                </div>
                <p class="service-desc">{desc}</p>
                <div class="service-actions">
                    <button class="btn btn-sm" onclick="doAction('restart', '{id}')">Restart</button>
                </div>
            </div>"#
        )
    }).collect();

    let mem_color = if data.memory_pct > 85.0 { "#e74c3c" } else if data.memory_pct > 70.0 { "#f39c12" } else { "#2ecc71" };
    let cpu_color = if data.cpu_load > 2.0 { "#e74c3c" } else if data.cpu_load > 1.0 { "#f39c12" } else { "#2ecc71" };

    // Build security findings HTML
    let security_findings_html = if data.recent_security.is_empty() {
        r#"<p class="service-desc" style="color: var(--text2); font-style: italic">No recent findings.</p>"#.to_string()
    } else {
        let mut html = String::from(r#"<div style="margin-top: 12px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 12px">"#);
        html.push_str(r#"<p class="service-desc" style="margin-bottom: 8px"><strong>Recent Findings</strong></p>"#);
        for finding in &data.recent_security {
            let cat_color = match finding.category.as_str() {
                "critical" | "daily-critical" => "var(--bad)",
                "daily-warning" => "var(--warn)",
                "normal" => "var(--accent)",
                _ => "var(--ok)",
            };
            let ts_short = &finding.timestamp[..16]; // YYYY-MM-DDTHH:MM
            let ts_display = ts_short.replace('T', " ");
            html.push_str(&format!(
                r#"<div style="margin-bottom: 10px"><span style="color:{cat_color};font-size:1.3rem">&#x25CF;</span> <span style="color:var(--text2);font-size:1.3rem">{ts_display}</span><br><span style="font-size:1.5rem">{summary}</span></div>"#,
                cat_color = cat_color,
                ts_display = ts_display,
                summary = finding.summary,
            ));
        }
        html.push_str("</div>");
        html
    };

    format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
<title>Sarpetorp Internet</title>
<style>
@font-face {{
    font-family: 'CircularStd';
    src: url('/fonts/CircularStd-Book.otf') format('opentype');
    font-weight: 400;
    font-style: normal;
    font-display: swap;
}}
@font-face {{
    font-family: 'CircularStd';
    src: url('/fonts/CircularStd-Medium.otf') format('opentype');
    font-weight: 500;
    font-style: normal;
    font-display: swap;
}}
@font-face {{
    font-family: 'CircularStd';
    src: url('/fonts/CircularStd-Bold.otf') format('opentype');
    font-weight: 700;
    font-style: normal;
    font-display: swap;
}}
@font-face {{
    font-family: 'CircularStd';
    src: url('/fonts/CircularStd-Black.otf') format('opentype');
    font-weight: 900;
    font-style: normal;
    font-display: swap;
}}
:root {{
    --bg: #0f1419;
    --surface: #1a2029;
    --surface2: #232d3b;
    --border: #2d3a4a;
    --text: #e8eaed;
    --text2: #9aa0a6;
    --accent: #4fc3f7;
    --ok: #2ecc71;
    --warn: #f39c12;
    --bad: #e74c3c;
    --radius: 16px;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: 'CircularStd', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 32px;
    padding-bottom: 100px;
    font-size: 2rem;
}}
h1 {{
    font-size: 3.2rem;
    font-weight: 700;
    margin-bottom: 8px;
}}
.subtitle {{
    color: var(--text2);
    font-size: 1.8rem;
    margin-bottom: 20px;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
    margin-bottom: 20px;
}}
.card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
}}
.stat-card {{
    text-align: center;
}}
.stat-value {{
    font-size: 3.6rem;
    font-weight: 700;
    line-height: 1.2;
}}
.stat-label {{
    font-size: 1.5rem;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 4px;
}}
.section-title {{
    font-size: 2.2rem;
    font-weight: 600;
    margin: 24px 0 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.service-card {{
    margin-bottom: 10px;
}}
.service-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
}}
.service-dot {{
    font-size: 1.8rem;
}}
.service-badge {{
    font-size: 1.4rem;
    padding: 2px 8px;
    border-radius: 12px;
    margin-left: auto;
    font-weight: 600;
}}
.status-ok {{ color: var(--ok); }}
.status-ok.service-badge {{ background: rgba(46,204,113,0.15); color: var(--ok); }}
.status-down {{ color: var(--bad); }}
.status-down.service-badge {{ background: rgba(231,76,60,0.15); color: var(--bad); }}
.service-desc {{
    font-size: 1.7rem;
    color: var(--text2);
    line-height: 1.4;
    margin-bottom: 10px;
}}
.service-actions {{
    display: flex;
    gap: 8px;
}}
.btn {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 20px 32px;
    font-size: 2rem;
    font-weight: 600;
    border: none;
    border-radius: 12px;
    cursor: pointer;
    transition: transform 0.1s, opacity 0.15s;
    -webkit-tap-highlight-color: transparent;
    touch-action: manipulation;
}}
.btn:active {{ transform: scale(0.96); }}
.btn-sm {{
    padding: 12px 20px;
    font-size: 1.6rem;
    border-radius: 8px;
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
}}
.btn-primary {{
    background: var(--accent);
    color: #000;
}}
.btn-success {{
    background: var(--ok);
    color: #000;
}}
.btn-warning {{
    background: var(--warn);
    color: #000;
}}
.btn-danger {{
    background: var(--bad);
    color: #fff;
}}
.quick-actions {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin-bottom: 20px;
}}
.quick-actions .btn {{
    width: 100%;
    min-height: 90px;
    font-size: 1.9rem;
}}
.toast {{
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: var(--surface2);
    color: var(--text);
    padding: 12px 24px;
    border-radius: 12px;
    border: 1px solid var(--border);
    font-size: 1.8rem;
    z-index: 100;
    opacity: 0;
    transition: opacity 0.3s;
    pointer-events: none;
    max-width: 90%;
    text-align: left;
    white-space: pre-line;
}}
.toast.show {{ opacity: 1; }}
.progress-bar {{
    height: 8px;
    background: var(--surface2);
    border-radius: 4px;
    overflow: hidden;
    margin-top: 8px;
}}
.progress-fill {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s;
}}
.ai-card {{
    background: linear-gradient(135deg, #1a1a3e 0%, #1a2029 100%);
    border: 1px solid #3d2d6b;
}}
.ai-badge {{
    font-size: 1.3rem;
    background: rgba(156,39,176,0.2);
    color: #ce93d8;
    padding: 2px 8px;
    border-radius: 8px;
    font-weight: 600;
}}
footer {{
    text-align: center;
    color: var(--text2);
    font-size: 1.5rem;
    margin-top: 30px;
    padding: 20px 0;
}}
footer a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>

<h1>Sarpetorp Internet</h1>
<p class="subtitle">{host_label} &middot; Your home internet router &middot; {uptime}</p>

<div class="grid">
    <div class="card stat-card">
        <div class="stat-value" style="color: {mem_color}">{memory:.0}%</div>
        <div class="stat-label">Memory</div>
        <div class="progress-bar"><div class="progress-fill" style="width:{memory:.0}%;background:{mem_color}"></div></div>
    </div>
    <div class="card stat-card">
        <div class="stat-value" style="color: {cpu_color}">{cpu:.2}</div>
        <div class="stat-label">CPU Load</div>
    </div>
    <div class="card stat-card">
        <div class="stat-value">{devices}</div>
        <div class="stat-label">Devices</div>
    </div>
    <div class="card stat-card">
        <div class="stat-value">{dns_queries}</div>
        <div class="stat-label">DNS Queries</div>
    </div>
</div>

<div class="grid">
    <div class="card stat-card">
        <div class="stat-value" style="font-size:2rem;word-break:break-all">{wan_ip}</div>
        <div class="stat-label">Public IP</div>
    </div>
    <div class="card stat-card">
        <div class="stat-value" style="color: var(--bad)">{blocked}</div>
        <div class="stat-label">IPs Blocked</div>
    </div>
    <div class="card stat-card">
        <div class="stat-value">{disk}</div>
        <div class="stat-label">Disk Used</div>
    </div>
</div>

<div class="section-title">Quick Actions</div>
<div class="quick-actions">
    <button class="btn btn-primary" onclick="doAction('speedtest')">Speed Test</button>
    <button class="btn btn-success" onclick="doAction('doctor')">Health Check</button>
    <button class="btn btn-warning" onclick="doAction('restart', 'wan')">Restart WAN</button>
    <button class="btn btn-danger" onclick="doAction('reboot')" id="reboot-btn">Reboot Router</button>
    <button class="btn btn-sm" onclick="doAction('flush_dns')">Flush DNS Cache</button>
    <button class="btn btn-sm" onclick="doAction('update_blocklists')">Update Blocklists</button>
    <button class="btn btn-sm" onclick="doAction('show_leases')">Connected Devices</button>
    <button class="btn btn-sm" onclick="doAction('wg_status')">VPN Status</button>
</div>

<div class="section-title">Services &mdash; What runs on this router</div>
{services}

<div class="section-title">AI Security Layer <span class="ai-badge">AI-Powered</span></div>
<div class="card ai-card">
    <div class="service-header">
        <strong>Dual-Layer Threat Analysis</strong>
    </div>
    <p class="service-desc">
        <strong style="color: var(--accent)">Hourly</strong> (GPT-5-nano) &mdash; quick threat classification.
        <strong style="color: #ce93d8">Daily</strong> (Gemini 3.1 Pro) &mdash; deep pattern correlation.
        Cost: ~$3/month.
    </p>
    {security_findings}
</div>

<div class="section-title">Network Info</div>
<div class="card">
    <table style="width:100%; font-size:1.7rem; color: var(--text2)">
        <tr><td style="padding:4px 0">Router</td><td style="text-align:right">192.168.4.1</td></tr>
        <tr><td style="padding:4px 0">Subnet</td><td style="text-align:right">192.168.4.0/24</td></tr>
        <tr><td style="padding:4px 0">DNS</td><td style="text-align:right">AdGuard Home (local)</td></tr>
        <tr><td style="padding:4px 0">WiFi</td><td style="text-align:right">Deco mesh (AP mode)</td></tr>
        <tr><td style="padding:4px 0">ISP</td><td style="text-align:right">Bahnhof 500/500</td></tr>
        <tr><td style="padding:4px 0">WAN adapter</td><td style="text-align:right">RTL8153 ({wan_usb})</td></tr>
        <tr><td style="padding:4px 0">WAN link speed</td><td style="text-align:right">{wan_speed}</td></tr>
    </table>
</div>

<footer>
    {host_label} &middot; Powered by <a href="https://github.com/semikolon/sluss">sluss</a> router management
</footer>

<div class="toast" id="toast"></div>

<script>
function showToast(msg, duration) {{
    const t = document.getElementById('toast');
    if (msg.includes('\\n')) {{
        t.innerHTML = msg.replace(/\\n/g, '<br>');
    }} else {{
        t.textContent = msg;
    }}
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), duration || 3000);
}}

async function doAction(action, target) {{
    if (action === 'reboot' && !confirm('Reboot the router? All devices will briefly lose internet.')) return;
    if (action === 'restart' && target === 'wan' && !confirm('Restart WAN adapter? Internet will drop for ~30 seconds.')) return;

    showToast('Running ' + action + '...', 10000);
    try {{
        const resp = await fetch('/api/action?action=' + action + (target ? '&target=' + target : ''));
        const data = await resp.json();
        const lines = (data.message.match(/\\n/g) || []).length;
        const dur = lines > 2 ? 4000 + lines * 800 : 4000;
        showToast(data.message, dur);
        if (action !== 'reboot') setTimeout(() => location.reload(), Math.max(2000, dur - 1000));
    }} catch(e) {{
        showToast('Error: ' + e.message, 5000);
    }}
}}
</script>

</body>
</html>"##,
        uptime = data.uptime,
        memory = data.memory_pct,
        cpu = data.cpu_load,
        mem_color = mem_color,
        cpu_color = cpu_color,
        devices = data.connected_devices,
        blocked = data.blocked_ips,
        wan_ip = data.wan_ip,
        wan_speed = data.wan_speed,
        dns_queries = data.dns_queries_today,
        services = services_html,
        disk = data.disk_pct,
        security_findings = security_findings_html,
        host_label = {
            let (host, _) = get_host_label();
            host
        },
        wan_usb = data.wan_usb_speed,
    )
}

// --- Route handlers ---

async fn dashboard() -> Html<String> {
    let data = tokio::task::spawn_blocking(collect_dashboard_data)
        .await
        .unwrap();
    Html(render_dashboard(&data))
}

async fn api_status() -> impl IntoResponse {
    let data = tokio::task::spawn_blocking(collect_dashboard_data)
        .await
        .unwrap();

    let json = serde_json::json!({
        "wan_ip": data.wan_ip,
        "uptime": data.uptime,
        "memory_pct": data.memory_pct,
        "cpu_load": data.cpu_load,
        "connected_devices": data.connected_devices,
        "blocked_ips": data.blocked_ips,
        "services": data.services.iter().map(|(id, name, _, active)| {
            serde_json::json!({"id": id, "name": name, "active": active})
        }).collect::<Vec<_>>(),
    });

    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json.to_string())
}

/// Silence-first findings API: returns noteworthy security findings only.
/// Empty `noteworthy` array = everything is fine, nothing to show.
async fn api_findings() -> impl IntoResponse {
    let findings = tokio::task::spawn_blocking(|| {
        crate::commands::sec::collect_noteworthy_findings(14)
    })
    .await
    .unwrap();

    let json = serde_json::json!({
        "noteworthy": findings,
        "days_checked": 14,
    });

    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json.to_string())
}

#[derive(Deserialize)]
struct ActionParams {
    action: String,
    target: Option<String>,
}

async fn serve_font(Path(filename): Path<String>) -> impl IntoResponse {
    // Serve fonts from system font directory
    let font_paths = [
        "/usr/local/share/fonts",
        "/root/.local/share/fonts",
    ];

    for dir in &font_paths {
        let path = std::path::Path::new(dir).join(&filename);
        if path.exists() {
            if let Ok(data) = tokio::fs::read(&path).await {
                let content_type = if filename.ends_with(".otf") {
                    "font/otf"
                } else if filename.ends_with(".ttf") {
                    "font/ttf"
                } else if filename.ends_with(".woff2") {
                    "font/woff2"
                } else {
                    "application/octet-stream"
                };
                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, content_type),
                        (header::CACHE_CONTROL, "public, max-age=31536000"),
                    ],
                    data,
                ).into_response();
            }
        }
    }

    (StatusCode::NOT_FOUND, "Font not found").into_response()
}

async fn api_action(Query(params): Query<ActionParams>) -> impl IntoResponse {
    let result = tokio::task::spawn_blocking(move || {
        match params.action.as_str() {
            "doctor" => {
                let output = execute_shell("sluss doctor 2>&1");
                match output {
                    Ok(o) => {
                        let text = String::from_utf8_lossy(&o.stdout).to_string();
                        if o.status.success() {
                            serde_json::json!({"ok": true, "message": "All checks passed!", "detail": text})
                        } else {
                            serde_json::json!({"ok": false, "message": "Some checks failed", "detail": text})
                        }
                    }
                    Err(e) => serde_json::json!({"ok": false, "message": format!("Error: {}", e)}),
                }
            }
            "speedtest" => {
                let output = execute_shell(
                    "timeout 15 curl -o /dev/null -w '%{speed_download}' http://speedtest.bahnhof.net/10M 2>/dev/null"
                );
                match output {
                    Ok(o) => {
                        let speed_bps: f64 = String::from_utf8_lossy(&o.stdout)
                            .trim().parse().unwrap_or(0.0);
                        let speed_mbps = speed_bps * 8.0 / 1_000_000.0;
                        serde_json::json!({"ok": true, "message": format!("Download: {:.1} Mbit/s", speed_mbps)})
                    }
                    Err(e) => serde_json::json!({"ok": false, "message": format!("Error: {}", e)}),
                }
            }
            "restart" => {
                let target = params.target.as_deref().unwrap_or("");
                match target {
                    "wan" => {
                        let _ = execute_shell("ip link set enxc84d4421f975 down && sleep 2 && ip link set enxc84d4421f975 up");
                        serde_json::json!({"ok": true, "message": "WAN adapter restarted. Reconnecting..."})
                    }
                    service => {
                        let output = execute_shell(&format!("systemctl restart {} 2>&1", service));
                        match output {
                            Ok(o) if o.status.success() => {
                                serde_json::json!({"ok": true, "message": format!("{} restarted", service)})
                            }
                            Ok(o) => {
                                let err = String::from_utf8_lossy(&o.stderr).to_string();
                                serde_json::json!({"ok": false, "message": format!("Failed: {}", err)})
                            }
                            Err(e) => serde_json::json!({"ok": false, "message": format!("Error: {}", e)}),
                        }
                    }
                }
            }
            "reboot" => {
                let _ = execute_shell("shutdown -r +1 'Reboot requested from web dashboard'");
                serde_json::json!({"ok": true, "message": "Rebooting in 1 minute..."})
            }
            "flush_dns" => {
                let _ = execute_shell("curl -s -X POST http://127.0.0.1:3000/control/cache_clear 2>/dev/null");
                serde_json::json!({"ok": true, "message": "DNS cache flushed"})
            }
            "update_blocklists" => {
                let output = execute_shell("curl -s -X POST http://127.0.0.1:3000/control/filtering/refresh 2>/dev/null");
                match output {
                    Ok(_) => serde_json::json!({"ok": true, "message": "Blocklist update triggered"}),
                    Err(e) => serde_json::json!({"ok": false, "message": format!("Error: {}", e)}),
                }
            }
            "show_leases" => {
                let output = execute_shell("cat /var/lib/misc/dnsmasq.leases 2>/dev/null");
                match output {
                    Ok(o) => {
                        let text = String::from_utf8_lossy(&o.stdout);
                        let devices: Vec<String> = text.lines().map(|line| {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 4 {
                                format!("{} — {} ({})", parts[2], parts[3], parts[1])
                            } else {
                                line.to_string()
                            }
                        }).collect();
                        let count = devices.len();
                        let list = devices.join("\n");
                        serde_json::json!({"ok": true, "message": format!("{} devices:\n{}", count, list)})
                    }
                    Err(e) => serde_json::json!({"ok": false, "message": format!("Error: {}", e)}),
                }
            }
            "wg_status" => {
                let output = execute_shell("wg show 2>/dev/null");
                match output {
                    Ok(o) => {
                        let text = String::from_utf8_lossy(&o.stdout).to_string();
                        if text.trim().is_empty() {
                            serde_json::json!({"ok": true, "message": "WireGuard: no active peers"})
                        } else {
                            // Extract peer count and latest handshake
                            let peers = text.matches("peer:").count();
                            serde_json::json!({"ok": true, "message": format!("WireGuard: {} peer(s) configured\n{}", peers, text.trim())})
                        }
                    }
                    Err(e) => serde_json::json!({"ok": false, "message": format!("Error: {}", e)}),
                }
            }
            _ => serde_json::json!({"ok": false, "message": "Unknown action"}),
        }
    }).await.unwrap();

    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], result.to_string())
}
