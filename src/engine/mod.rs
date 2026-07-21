//! Native Rust openfortivpn engine — TLS, auth, tunnel relay.
//!
//! This module replaces the external `openfortivpn` binary with a pure-Rust
//! implementation of the Fortinet SSL-VPN protocol.
//!
//! Note: This module is not yet wired into the main application.
//! The `#[allow(dead_code)]` attributes will be removed during integration.

#![allow(dead_code)]

pub mod auth;
pub mod backend;
pub mod gateway;
pub mod hdlc;
pub mod http_server;
pub mod ppp;
pub mod pppstate;
pub mod routes;
pub mod tun;
pub mod tunnel;

use crate::config::VpnProfile;
use std::net::SocketAddr;

/// Result of a VPN gateway connection attempt.
pub struct GatewayConnection {
    /// TLS-wrapped TCP stream to the VPN gateway.
    pub tls_stream: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    /// Gateway address we connected to.
    pub gateway: SocketAddr,
    /// Session cookie returned by the gateway after authentication.
    pub svpn_cookie: Option<String>,
}

/// Dial the VPN gateway and perform a TLS handshake.
pub async fn connect_gateway(profile: &VpnProfile) -> Result<GatewayConnection, VpnError> {
    gateway::connect(profile).await
}

/// Native VPN errors.
#[derive(Debug)]
pub enum VpnError {
    Dns(std::io::Error),
    Tcp(std::io::Error),
    Tls(String),
    Auth(String),
    Io(std::io::Error),
    Route(String),
}

impl std::fmt::Display for VpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnError::Dns(e) => write!(f, "DNS error: {}", e),
            VpnError::Tcp(e) => write!(f, "TCP error: {}", e),
            VpnError::Tls(s) => write!(f, "TLS error: {}", s),
            VpnError::Auth(s) => write!(f, "Auth error: {}", s),
            VpnError::Io(e) => write!(f, "I/O error: {}", e),
            VpnError::Route(s) => write!(f, "Route error: {}", s),
        }
    }
}

impl std::error::Error for VpnError {}

/// Kill any running openfortivpn/pppd processes (shared with legacy backend).
pub fn kill_vpn_processes() {
    let mut pids: Vec<String> = Vec::new();
    for proc in &["openfortivpn", "pppd"] {
        if let Ok(out) = std::process::Command::new("pgrep").arg(proc).output() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                for pid in s.lines() { pids.push(pid.to_string()); }
            }
        }
    }
    if pids.is_empty() { return; }

    let mut args: Vec<String> = vec!["sh".into(), "-c".into()];
    let pids_str = pids.join(" ");
    args.push(format!("kill -INT {}; sleep 0.5; kill -KILL {}", pids_str, pids_str));

    let _ = std::process::Command::new("pkexec")
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut c| c.wait());
}
