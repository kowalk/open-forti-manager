//! Native Fortinet SSL-VPN engine — TLS, auth, PPP/IPCP, tunnel relay.
//!
//! A pure-Rust implementation of the Fortinet SSL-VPN protocol. It is the sole
//! VPN backend (`NativeVpnBackend`); no external `openfortivpn` binary or
//! `pppd` process is used.

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
