//! Security analysis and status commands

use anyhow::Result;
use serde::Serialize;
use std::fmt::Display;

use crate::adapters::{adguard, crowdsec, wireguard};
use crate::output::print_output;

/// Combined security stack status
#[derive(Debug, Serialize)]
pub struct SecurityStatus {
    pub adguard: adguard::AdguardStatus,
    pub crowdsec: crowdsec::CrowdsecStatus,
    pub wireguard: wireguard::WireguardStatus,
}

impl Display for SecurityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Security Stack Status")?;
        writeln!(f, "=====================")?;
        write!(f, "{}", self.adguard)?;
        write!(f, "{}", self.crowdsec)?;
        write!(f, "{}", self.wireguard)?;
        Ok(())
    }
}

/// Show combined security status
pub fn status(json: bool) -> Result<()> {
    let result = SecurityStatus {
        adguard: adguard::get_status()?,
        crowdsec: crowdsec::get_status()?,
        wireguard: wireguard::get_status()?,
    };

    print_output(&result, json);
    Ok(())
}

/// Show CrowdSec active decisions (blocked IPs)
pub fn blocks(json: bool) -> Result<()> {
    let decisions = crowdsec::list_decisions()?;

    let result = BlocksResult {
        count: decisions.len() as u32,
        decisions,
    };

    print_output(&result, json);
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct BlocksResult {
    pub count: u32,
    pub decisions: Vec<crowdsec::CrowdsecDecision>,
}

impl Display for BlocksResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CrowdSec Active Blocks")?;
        writeln!(f, "======================")?;
        if self.decisions.is_empty() {
            writeln!(f, "No active blocks.")?;
        } else {
            writeln!(f, "{} blocked IPs:", self.count)?;
            writeln!(f)?;
            for decision in &self.decisions {
                write!(f, "{}", decision)?;
            }
        }
        Ok(())
    }
}

/// Security finding from log analysis
#[derive(Debug, Serialize, Clone)]
pub struct SecurityFinding {
    pub timestamp: String,
    pub severity: String,
    pub category: String,
    pub summary: String,
    pub details: String,
}

impl Display for SecurityFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let indicator = match self.severity.as_str() {
            "critical" | "high" => "🔴",
            "medium" => "🟡",
            _ => "🟢",
        };
        writeln!(f, "{} [{}] {}", indicator, self.severity.to_uppercase(), self.summary)?;
        writeln!(f, "   Category: {}", self.category)?;
        writeln!(f, "   Time: {}", self.timestamp)?;
        if !self.details.is_empty() {
            writeln!(f, "   Details: {}", self.details)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub findings: Vec<SecurityFinding>,
    pub logs_analyzed: usize,
    pub time_window_hours: u32,
}

impl Display for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Security Scan Results")?;
        writeln!(f, "=====================")?;
        writeln!(f, "Analyzed {} log entries (last {} hours)", self.logs_analyzed, self.time_window_hours)?;
        writeln!(f)?;

        if self.findings.is_empty() {
            writeln!(f, "No security issues detected.")?;
        } else {
            writeln!(f, "Found {} issues:", self.findings.len())?;
            writeln!(f)?;
            for finding in &self.findings {
                write!(f, "{}", finding)?;
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

/// Run security scan (LLM-based analysis — placeholder)
pub fn scan(json: bool) -> Result<()> {
    let result = ScanResult {
        findings: vec![],
        logs_analyzed: 0,
        time_window_hours: 1,
    };

    print_output(&result, json);
    println!("\nNote: LLM-based security analysis not yet implemented.");
    println!("Run 'shannon sec blocks' to view active CrowdSec decisions.");

    Ok(())
}

/// Show recent security findings
pub fn report(hours: u32, json: bool) -> Result<()> {
    let result = ScanResult {
        findings: vec![],
        logs_analyzed: 0,
        time_window_hours: hours,
    };

    print_output(&result, json);
    println!("\nNote: No findings stored yet. Run 'shannon sec scan' first.");

    Ok(())
}

/// Silence-first triage digest: only returns noteworthy findings.
/// Reads daily analyses and hourly triage logs, filters out "normal/clear/green".
/// Returns empty string (or empty JSON array) when everything is fine.
#[derive(Debug, Serialize)]
pub struct FindingsResult {
    pub noteworthy: Vec<SecurityFinding>,
    pub days_checked: u32,
}

impl Display for FindingsResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.noteworthy.is_empty() {
            // Silence-first: nothing to report
            return Ok(());
        }
        for finding in &self.noteworthy {
            write!(f, "{}", finding)?;
        }
        Ok(())
    }
}

pub fn findings(days: u32, json: bool) -> Result<()> {
    let noteworthy = collect_noteworthy_findings(days);

    let result = FindingsResult {
        noteworthy,
        days_checked: days,
    };

    print_output(&result, json);
    Ok(())
}

/// Collect noteworthy findings from daily analyses and triage logs.
/// "Noteworthy" = severity is NOT green/normal/clear.
pub fn collect_noteworthy_findings(days: u32) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    // 1. Read daily analysis JSON files
    let analyses_dir = "/var/log/shannon-security-analyses";
    if let Ok(entries) = std::fs::read_dir(analyses_dir) {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .collect();
        files.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

        for entry in files.iter().take(days as usize) {
            let fname = entry.file_name();
            let date_str = fname.to_string_lossy().trim_end_matches(".json").to_string();

            // Parse date to check cutoff
            if let Ok(date) = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
                let dt = date.and_hms_opt(6, 0, 0).unwrap();
                if dt.and_utc() < cutoff {
                    continue;
                }
            }

            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                    let severity = parsed.get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("green");

                    // Skip green/normal — silence-first
                    if severity == "green" {
                        continue;
                    }

                    let summary = parsed.get("summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or("No summary")
                        .to_string();

                    let category = match severity {
                        "red" => "critical",
                        "yellow" => "warning",
                        _ => continue, // skip anything else that's not noteworthy
                    };

                    findings.push(SecurityFinding {
                        timestamp: format!("{}T06:00:00Z", date_str),
                        severity: severity.to_string(),
                        category: category.to_string(),
                        summary,
                        details: parsed.get("recommendations")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter()
                                .filter_map(|f| f.as_str())
                                .collect::<Vec<_>>()
                                .join("; "))
                            .unwrap_or_default(),
                    });
                }
            }
        }
    }

    // 2. Read hourly triage log for non-normal entries
    let triage_path = "/var/log/shannon-llm-triage.log";
    if let Ok(content) = std::fs::read_to_string(triage_path) {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);

        for line in content.lines().rev().take(200) {
            // Skip errors and OK lines
            if line.contains("ERROR:") || line.contains("OK:") {
                continue;
            }

            // Parse: 2026-03-12T22:00:18+00:00 TRIAGE: category=normal summary="..."
            if !line.contains("TRIAGE:") {
                continue;
            }

            // Extract timestamp
            let ts = match line.split(' ').next() {
                Some(ts) => ts,
                None => continue,
            };

            // Check cutoff
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                if dt < cutoff {
                    break; // Log is chronological, stop early
                }
            }

            // Extract category
            let category = line.find("category=")
                .and_then(|start| {
                    let rest = &line[start + 9..];
                    rest.find(' ').map(|end| &rest[..end])
                })
                .unwrap_or("unknown");

            // Skip normal — silence-first
            if category == "normal" || category == "clear" {
                continue;
            }

            // Extract summary
            let summary = line.find("summary=\"")
                .and_then(|start| {
                    let rest = &line[start + 9..];
                    rest.rfind('"').map(|end| &rest[..end])
                })
                .unwrap_or("No summary");

            findings.push(SecurityFinding {
                timestamp: ts.to_string(),
                severity: if category == "critical" { "red".to_string() } else { "yellow".to_string() },
                category: category.to_string(),
                summary: summary.to_string(),
                details: String::new(),
            });
        }
    }

    // Sort newest first
    findings.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    findings
}
