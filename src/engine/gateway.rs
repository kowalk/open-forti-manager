//! TLS connection to the Fortinet SSL-VPN gateway.
//!
//! Handles DNS resolution, TCP connect, TLS handshake, and certificate
//! verification including trusted-cert digest matching.

use crate::config::VpnProfile;
use crate::engine::VpnError;
use rustls::pki_types::ServerName;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

/// Connect to the VPN gateway and establish a TLS session (async).
pub async fn connect(profile: &VpnProfile) -> Result<super::GatewayConnection, VpnError> {
    connect_impl(profile)
}

/// Synchronous (blocking) version for use in background threads.
pub fn connect_blocking(profile: &VpnProfile) -> Result<super::GatewayConnection, VpnError> {
    connect_impl(profile)
}

fn connect_impl(profile: &VpnProfile) -> Result<super::GatewayConnection, VpnError> {
    let port = profile.port.unwrap_or(443);
    let host = profile.host.clone();

    // DNS resolution (blocking)
    let addr = format!("{}:{}", host, port);
    let addr: std::net::SocketAddr = addr
        .to_socket_addrs()
        .map_err(VpnError::Dns)?
        .next()
        .ok_or_else(|| VpnError::Dns(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("could not resolve {}", host),
        )))?;

    log::info!("Resolved {} to {}", host, addr);

    // TCP connect using std::net (we'll wrap with TLS)
    let tcp = TcpStream::connect(addr).map_err(VpnError::Tcp)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    log::info!("TCP connected to {}", addr);

    // Build TLS client configuration
    let tls_config = build_tls_config(profile)?;

    // TLS handshake
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| VpnError::Tls(format!("invalid server name: {}", e)))?;

    let client = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
        .map_err(|e| VpnError::Tls(format!("TLS client init: {}", e)))?;

    let mut tls_stream = rustls::StreamOwned::new(client, tcp);

    // Perform the TLS handshake (flush triggers the actual handshake)
    if let Err(e) = tls_stream.flush() {
        return Err(VpnError::Tls(format!("TLS handshake failed: {}", e)));
    }

    log::info!("TLS handshake completed with {}", host);

    // Verify the gateway certificate if a trusted digest is configured
    if profile.trusted_cert.is_some() {
        verify_certificate_digest(&tls_stream, profile)?;
    }

    Ok(super::GatewayConnection {
        tls_stream,
        gateway: addr,
        svpn_cookie: None,
    })
}

/// Build a rustls `ClientConfig` with system CA certs and the VPN profile's
/// certificate settings.
fn build_tls_config(profile: &VpnProfile) -> Result<rustls::ClientConfig, VpnError> {
    let mut root_store = rustls::RootCertStore::empty();

    // Load system CA certificates
    let native_certs = rustls_native_certs::load_native_certs();
    match native_certs {
        Ok(certs) => {
            let (added, skipped) = root_store.add_parsable_certificates(certs);
            log::debug!("Loaded {} system CA certs ({} skipped)", added, skipped);
        }
        Err(e) => {
            log::warn!("Could not load system CA certs: {}", e);
        }
    }

    // Also load webpki roots as fallback (TrustAnchor -> RootCertStore via Extend)
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // If the profile specifies a custom CA file, load it
    if let Some(ref ca_file) = profile.ca_file {
        let ca_pem = std::fs::read(ca_file)
            .map_err(|e| VpnError::Tls(format!("cannot read CA file {}: {}", ca_file, e)))?;
        let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| VpnError::Tls(format!("bad CA file {}: {}", ca_file, e)))?;
        for cert in ca_certs {
            root_store.add(cert).map_err(|e| {
                VpnError::Tls(format!("cannot add CA cert from {}: {:?}", ca_file, e))
            })?;
        }
        log::info!("Loaded CA file: {}", ca_file);
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

/// Verify the server certificate's SHA256 digest matches the trusted-cert.
fn verify_certificate_digest(
    tls_stream: &rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    profile: &VpnProfile,
) -> Result<(), VpnError> {
    let expected = profile.trusted_cert.as_deref().unwrap_or("");
    if expected.is_empty() {
        return Ok(());
    }

    if let Some(certs) = tls_stream.conn.peer_certificates() {
        if let Some(cert) = certs.first() {
            // Compute SHA256 of the DER-encoded certificate
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(cert.as_ref());
            let digest = hasher.finalize();
            let digest_hex = format!("{:x}", digest);

            if digest_hex == expected {
                log::info!("Gateway certificate digest matches trusted-cert");
                return Ok(());
            } else {
                return Err(VpnError::Tls(format!(
                    "Certificate digest mismatch.\n  Expected: {}\n  Got:      {}",
                    expected, digest_hex
                )));
            }
        }
    }

    Err(VpnError::Tls("No peer certificate received".into()))
}
