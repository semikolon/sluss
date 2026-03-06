//! Web dashboard for SHANNON router
//!
//! Serves a mobile-friendly status page with big buttons for common admin tasks.
//! Designed for LAN-only access (http://internet.local:8080).

use axum::{
    extract::Query,
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
        .route("/api/action", get(api_action));

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    info!("SHANNON dashboard at http://{}:{}", bind, port);
    info!("Add 'internet.local' to dnsmasq for friendly access");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// --- Data collection ---

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

    let services = vec![
        ("dnsmasq", "Network Core", "Assigns IP addresses to all devices and resolves domain names on the local network (DHCP + DNS)", get_service_status("dnsmasq").unwrap_or(false)),
        ("AdGuardHome", "Ad & Tracker Blocker", "Filters out ads, trackers, and malicious domains before they reach any device — like an ad blocker for the entire house", get_service_status("AdGuardHome").unwrap_or(false)),
        ("crowdsec", "Intrusion Detection", "Monitors network traffic and SSH logs for suspicious activity, automatically blocks attackers using community-shared threat intelligence", get_service_status("crowdsec").unwrap_or(false)),
        ("nftables", "Firewall", "Controls which traffic flows in and out — only allows connections you've approved, blocks everything else", get_service_status("nftables").unwrap_or(false)),
        ("wg-quick@wg0", "VPN Tunnel", "Encrypted private tunnel (WireGuard) for secure remote access to the home network from anywhere in the world", get_service_status("wg-quick@wg0").unwrap_or(false)),
        ("wan-watchdog", "Connection Guardian", "Monitors internet connectivity and automatically recovers from outages by resetting the WAN adapter (~90 second recovery)", get_service_status("wan-watchdog").unwrap_or(false)),
        ("ssh", "Remote Access", "Secure shell access for administration — key-only authentication, no passwords accepted", get_service_status("ssh").unwrap_or(false)),
    ];

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
    }
}

// --- HTML rendering ---

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

    format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
<title>Sarpetorp Internet</title>
<style>
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
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 16px;
    padding-bottom: 100px;
}}
h1 {{
    font-size: 1.6rem;
    font-weight: 700;
    margin-bottom: 4px;
}}
.subtitle {{
    color: var(--text2);
    font-size: 0.9rem;
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
    font-size: 1.8rem;
    font-weight: 700;
    line-height: 1.2;
}}
.stat-label {{
    font-size: 0.75rem;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 4px;
}}
.section-title {{
    font-size: 1.1rem;
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
    font-size: 0.9rem;
}}
.service-badge {{
    font-size: 0.7rem;
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
    font-size: 0.85rem;
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
    padding: 14px 24px;
    font-size: 1rem;
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
    padding: 8px 14px;
    font-size: 0.8rem;
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
    min-height: 60px;
    font-size: 0.95rem;
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
    font-size: 0.9rem;
    z-index: 100;
    opacity: 0;
    transition: opacity 0.3s;
    pointer-events: none;
    max-width: 90%;
    text-align: center;
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
    font-size: 0.65rem;
    background: rgba(156,39,176,0.2);
    color: #ce93d8;
    padding: 2px 8px;
    border-radius: 8px;
    font-weight: 600;
}}
footer {{
    text-align: center;
    color: var(--text2);
    font-size: 0.75rem;
    margin-top: 30px;
    padding: 20px 0;
}}
footer a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>

<h1>Sarpetorp Internet</h1>
<p class="subtitle">SHANNON Router &middot; Rock Pi 4B &middot; {uptime}</p>

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
        <div class="stat-value" style="font-size:1rem;word-break:break-all">{wan_ip}</div>
        <div class="stat-label">Public IP</div>
    </div>
    <div class="card stat-card">
        <div class="stat-value" style="color: var(--bad)">{blocked}</div>
        <div class="stat-label">IPs Blocked</div>
    </div>
</div>

<div class="section-title">Quick Actions</div>
<div class="quick-actions">
    <button class="btn btn-primary" onclick="doAction('speedtest')">Speed Test</button>
    <button class="btn btn-success" onclick="doAction('doctor')">Health Check</button>
    <button class="btn btn-warning" onclick="doAction('restart', 'wan')">Restart WAN</button>
    <button class="btn btn-danger" onclick="doAction('reboot')" id="reboot-btn">Reboot Router</button>
</div>

<div class="section-title">Services &mdash; What runs on this router</div>
{services}

<div class="section-title">AI Security Layer <span class="ai-badge">AI-Powered</span></div>
<div class="card ai-card">
    <div class="service-header">
        <strong>Dual-Layer Threat Analysis</strong>
    </div>
    <p class="service-desc">
        Two AI models continuously analyze network security:
    </p>
    <p class="service-desc" style="margin-top: 8px">
        <strong style="color: var(--accent)">Hourly triage</strong> (GPT-5-nano) &mdash;
        Scans CrowdSec alerts and classifies threats as critical, notable, or routine. Quick and cheap, catches obvious attacks fast.
    </p>
    <p class="service-desc" style="margin-top: 8px">
        <strong style="color: #ce93d8">Daily deep analysis</strong> (Gemini 3.1 Pro) &mdash;
        Correlates patterns across 24 hours of data. Finds subtle behavioral anomalies that simple rules miss &mdash; like slow port scans or credential stuffing spread across hours.
    </p>
    <p class="service-desc" style="margin-top: 8px; color: var(--text2)">
        Cost: ~$3/month. Alerts delivered via voice narration (Ruby AI assistant).
    </p>
</div>

<div class="section-title">Network Info</div>
<div class="card">
    <table style="width:100%; font-size:0.85rem; color: var(--text2)">
        <tr><td style="padding:4px 0">Router</td><td style="text-align:right">192.168.4.1</td></tr>
        <tr><td style="padding:4px 0">Subnet</td><td style="text-align:right">192.168.4.0/24</td></tr>
        <tr><td style="padding:4px 0">DNS</td><td style="text-align:right">AdGuard Home (local)</td></tr>
        <tr><td style="padding:4px 0">WiFi</td><td style="text-align:right">Deco mesh (AP mode)</td></tr>
        <tr><td style="padding:4px 0">ISP</td><td style="text-align:right">Bahnhof 500/500</td></tr>
        <tr><td style="padding:4px 0">WAN adapter</td><td style="text-align:right">RTL8153 (USB 2.0)</td></tr>
        <tr><td style="padding:4px 0">WAN link speed</td><td style="text-align:right">{wan_speed}</td></tr>
    </table>
</div>

<footer>
    SHANNON &middot; Named after <a href="https://en.wikipedia.org/wiki/Claude_Shannon">Claude Shannon</a>, father of information theory<br>
    Powered by Armbian Linux on Rock Pi 4B SE
</footer>

<div class="toast" id="toast"></div>

<script>
function showToast(msg, duration) {{
    const t = document.getElementById('toast');
    t.textContent = msg;
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
        showToast(data.message, 4000);
        if (action !== 'reboot') setTimeout(() => location.reload(), 2000);
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

#[derive(Deserialize)]
struct ActionParams {
    action: String,
    target: Option<String>,
}

async fn api_action(Query(params): Query<ActionParams>) -> impl IntoResponse {
    let result = tokio::task::spawn_blocking(move || {
        match params.action.as_str() {
            "doctor" => {
                let output = execute_shell("shannon doctor 2>&1");
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
            _ => serde_json::json!({"ok": false, "message": "Unknown action"}),
        }
    }).await.unwrap();

    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], result.to_string())
}
