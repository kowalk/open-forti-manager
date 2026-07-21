//! Route and DNS configuration when the VPN tunnel comes up.
//!
//! Currently uses `ip` commands for routing and direct `/etc/resolv.conf`
//! manipulation for DNS.  Future: switch to `rtnetlink` for routing.

use crate::engine::VpnError;
use std::process::Command;

/// Configuration applied when the tunnel is established.
pub struct TunnelConfig {
    /// Assigned VPN IP address (e.g., "10.212.1.100").
    pub ip_address: String,
    /// Primary DNS server.
    pub dns1: Option<String>,
    /// Secondary DNS server.
    pub dns2: Option<String>,
    /// DNS search domain suffix.
    pub dns_suffix: Option<String>,
    /// Split-tunnel routes: (network, netmask) pairs to route via VPN.
    pub routes: Vec<(String, String)>,
    /// PPP interface name (e.g., "ppp0").
    pub iface: String,
}

impl TunnelConfig {
    /// Parse the FortiGate XML config (simplified — full parsing uses quick_xml).
    pub fn from_xml(_xml: &str) -> Result<Self, VpnError> {
        // TODO: Full XML parsing with quick_xml.
        // For now, return a minimal config for testing.
        Ok(Self {
            ip_address: String::new(),
            dns1: None,
            dns2: None,
            dns_suffix: None,
            routes: Vec::new(),
            iface: "ppp0".into(),
        })
    }
}

/// Bring up routes and DNS for the VPN tunnel.
/// Requires root / CAP_NET_ADMIN.
pub fn setup(config: &TunnelConfig) -> Result<(), VpnError> {
    let iface = &config.iface;

    // Add split-tunnel routes
    for (net, mask) in &config.routes {
        let status = Command::new("ip")
            .args(["route", "add", net, "via", mask, "dev", iface])
            .status()
            .map_err(|e| VpnError::Route(format!("route add {}: {}", net, e)))?;
        if !status.success() {
            log::warn!("Route to {}/{} already exists or failed", net, mask);
        }
    }

    // Set DNS via resolv.conf
    if config.dns1.is_some() || config.dns2.is_some() {
        update_resolv_conf(config)?;
    }

    log::info!("Routes and DNS configured for {}", iface);
    Ok(())
}

/// Tear down routes and restore DNS when tunnel goes down.
pub fn teardown(config: &TunnelConfig) {
    let iface = &config.iface;

    for (net, _mask) in &config.routes {
        let _ = Command::new("ip")
            .args(["route", "del", net, "dev", iface])
            .status();
    }

    // Restore original resolv.conf (backup made during setup)
    let backup = "/etc/resolv.conf.bak";
    if std::path::Path::new(backup).exists() {
        let _ = std::fs::copy(backup, "/etc/resolv.conf");
        let _ = std::fs::remove_file(backup);
    }

    log::info!("Routes and DNS torn down for {}", iface);
}

/// Update /etc/resolv.conf with VPN DNS servers.
fn update_resolv_conf(config: &TunnelConfig) -> Result<(), VpnError> {
    let path = "/etc/resolv.conf";

    // Backup existing config
    if std::path::Path::new(path).exists() {
        std::fs::copy(path, "/etc/resolv.conf.bak")
            .map_err(|e| VpnError::Route(format!("backup resolv.conf: {}", e)))?;
    }

    let mut content = String::new();
    if let Some(ref suffix) = config.dns_suffix {
        content.push_str(&format!("search {}\n", suffix));
    }
    if let Some(ref dns1) = config.dns1 {
        content.push_str(&format!("nameserver {}\n", dns1));
    }
    if let Some(ref dns2) = config.dns2 {
        content.push_str(&format!("nameserver {}\n", dns2));
    }

    std::fs::write(path, content)
        .map_err(|e| VpnError::Route(format!("write resolv.conf: {}", e)))?;

    Ok(())
}
