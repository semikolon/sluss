//! Location detection for local vs remote execution
//!
//! Detects whether sluss is running on the router itself (local mode)
//! or on another machine (remote mode via SSH).
//!
//! Remote target: set SLUSS_ROUTER env var or defaults to "router" SSH host.

use anyhow::{Context, Result};
use std::process::{Command, Output, Stdio};

/// Default SSH host alias for the router
const DEFAULT_ROUTER_HOST: &str = "router";

/// Get the configured router SSH host
fn router_host() -> String {
    std::env::var("SLUSS_ROUTER").unwrap_or_else(|_| DEFAULT_ROUTER_HOST.to_string())
}

/// Check if we're running on the router itself
/// (dnsmasq running locally = we're on the router)
pub fn is_local() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "dnsmasq"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Execute a shell command, either locally or via SSH
pub fn execute_shell(cmd: &str) -> Result<Output> {
    if is_local() {
        Command::new("sh")
            .args(["-c", cmd])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute command locally")
    } else {
        Command::new("ssh")
            .args([&router_host(), cmd])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute command via SSH")
    }
}

/// Read a file, either locally or via SSH
pub fn read_file(path: &str) -> Result<String> {
    let output = execute_shell(&format!("cat {}", path))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        anyhow::bail!(
            "Failed to read {}: {}",
            path,
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

/// Write content to a file, either locally or via SSH
pub fn write_file(path: &str, content: &str) -> Result<()> {
    let escaped = content.replace('\'', "'\\''");
    let cmd = format!("printf '%s' '{}' > {}", escaped, path);
    let output = execute_shell(&cmd)?;
    if output.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "Failed to write {}: {}",
            path,
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

/// Append content to a file
pub fn append_file(path: &str, content: &str) -> Result<()> {
    let escaped = content.replace('\'', "'\\''");
    let cmd = format!("printf '%s' '{}' >> {}", escaped, path);
    let output = execute_shell(&cmd)?;
    if output.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "Failed to append to {}: {}",
            path,
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

/// Run systemctl command
pub fn systemctl(action: &str, service: &str) -> Result<()> {
    let output = execute_shell(&format!("systemctl {} {}", action, service))?;
    if output.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "systemctl {} {} failed: {}",
            action,
            service,
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_local_returns_bool() {
        let _ = is_local();
    }

    #[test]
    fn test_router_host_default() {
        std::env::remove_var("SLUSS_ROUTER");
        assert_eq!(router_host(), "router");
    }

    #[test]
    fn test_router_host_env() {
        std::env::set_var("SLUSS_ROUTER", "darwin");
        assert_eq!(router_host(), "darwin");
        std::env::remove_var("SLUSS_ROUTER");
    }
}
