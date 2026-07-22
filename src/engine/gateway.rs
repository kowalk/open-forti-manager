//! TLS connection to the Fortinet SSL-VPN gateway.
//!
//! Handles DNS resolution, TCP connect, TLS handshake, and certificate
//! verification including trusted-cert digest matching.

use crate::config::VpnProfile;
use crate::engine::VpnError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WantsClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ConfigBuilder, ClientConfig, DigitallySignedStruct, SignatureScheme};
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

    // Trusted-cert pinning (when configured) is enforced during the handshake
    // by PinnedCertVerifier — no post-handshake check needed here.

    Ok(super::GatewayConnection {
        tls_stream,
        gateway: addr,
        svpn_cookie: None,
    })
}

/// Build a rustls `ClientConfig` for the profile.
///
/// If `trusted_cert` is set, the gateway certificate is pinned by SHA256 digest
/// and normal chain validation is bypassed — this matches openfortivpn's
/// `--trusted-cert` and is what makes self-signed FortiGate certs work.
/// Otherwise the system/webpki roots (plus any custom CA file) are used.
/// Client-certificate (mTLS) auth is configured when `user_cert`/`user_key` are set.
fn build_tls_config(profile: &VpnProfile) -> Result<ClientConfig, VpnError> {
    let client_auth = load_client_auth(profile)?;

    let pins = trusted_digests(profile);
    if !pins.is_empty() {
        log::info!("Pinning gateway certificate by SHA256 digest ({} configured)", pins.len());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedCertVerifier { digests: pins, provider: provider.clone() });
        let builder = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        finish_tls_config(builder, client_auth)
    } else {
        let root_store = build_root_store(profile)?;
        let builder = ClientConfig::builder().with_root_certificates(root_store);
        finish_tls_config(builder, client_auth)
    }
}

/// Apply the client-auth stage (mTLS cert, or none) and finalize the config.
fn finish_tls_config(
    builder: ConfigBuilder<ClientConfig, WantsClientCert>,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig, VpnError> {
    match client_auth {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| VpnError::Tls(format!("client certificate rejected: {}", e))),
        None => Ok(builder.with_no_client_auth()),
    }
}

/// Normalize the profile's trusted-cert into a list of lowercase hex SHA256
/// digests (accepts comma/space/colon separators).
fn trusted_digests(profile: &VpnProfile) -> Vec<String> {
    let raw = profile.trusted_cert.as_deref().unwrap_or("");
    raw.split([',', ' ', '\n', '\t'])
        .map(|d| d.replace(':', "").trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

/// Load the client certificate + private key for mTLS if both are configured.
/// Returns an error (never silently ignores) if only one is set or files are bad.
fn load_client_auth(
    profile: &VpnProfile,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, VpnError> {
    let cert = profile.user_cert.as_deref().filter(|s| !s.is_empty());
    let key = profile.user_key.as_deref().filter(|s| !s.is_empty());
    match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)
                .map_err(|e| VpnError::Tls(format!("cannot read user cert {}: {}", cert_path, e)))?;
            let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| VpnError::Tls(format!("bad user cert {}: {}", cert_path, e)))?;
            if certs.is_empty() {
                return Err(VpnError::Tls(format!("no certificate found in {}", cert_path)));
            }
            let key_pem = std::fs::read(key_path)
                .map_err(|e| VpnError::Tls(format!("cannot read user key {}: {}", key_path, e)))?;
            let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
                .map_err(|e| VpnError::Tls(format!("bad user key {}: {}", key_path, e)))?
                .ok_or_else(|| VpnError::Tls(format!("no private key found in {}", key_path)))?;
            log::info!("Using client certificate {} for mTLS", cert_path);
            Ok(Some((certs, key)))
        }
        (Some(_), None) => Err(VpnError::Tls(
            "user certificate is set but user key is missing".into())),
        (None, Some(_)) => Err(VpnError::Tls(
            "user key is set but user certificate is missing".into())),
        (None, None) => Ok(None),
    }
}

/// Build a root store from system + webpki roots and any custom CA file.
fn build_root_store(profile: &VpnProfile) -> Result<rustls::RootCertStore, VpnError> {
    let mut root_store = rustls::RootCertStore::empty();

    let native_certs = rustls_native_certs::load_native_certs();
    match native_certs {
        Ok(certs) => {
            let (added, skipped) = root_store.add_parsable_certificates(certs);
            log::debug!("Loaded {} system CA certs ({} skipped)", added, skipped);
        }
        Err(e) => log::warn!("Could not load system CA certs: {}", e),
    }
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(ref ca_file) = profile.ca_file {
        if !ca_file.is_empty() {
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
    }
    Ok(root_store)
}

/// Certificate verifier that pins the gateway's leaf certificate by SHA256
/// digest, ignoring chain validity (mirrors openfortivpn `--trusted-cert`).
/// Handshake signatures are still verified against the pinned certificate's key.
#[derive(Debug)]
struct PinnedCertVerifier {
    digests: Vec<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let got = format!("{:x}", hasher.finalize());
        if self.digests.iter().any(|d| d == &got) {
            log::info!("Gateway certificate digest matches trusted-cert");
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "gateway certificate digest {} does not match any trusted-cert", got
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
