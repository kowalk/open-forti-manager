//! HTTP-based authentication with the Fortinet SSL-VPN gateway.
//!
//! Implements the login flow from openfortivpn's http.c:
//! 1. POST /remote/logincheck with credentials
//! 2. Extract SVPNCOOKIE from Set-Cookie header
//! 3. Handle SAML redirect if gateway requires it
//! 4. GET /remote/sslvpn-tunnel to switch to tunnel mode

use crate::config::VpnProfile;
use crate::engine::VpnError;
use std::io::{Read, Write};

const MAX_HTTP_RESPONSE: usize = 8 * 1024 * 1024;

/// Read one complete HTTP response from a (blocking) stream.
///
/// A single `read()` is not enough: responses split across TCP segments / TLS
/// records would otherwise be truncated, and — on a keep-alive connection —
/// leftover bytes would corrupt the *next* response. This reads until the
/// headers are complete, then consumes the body per `Content-Length` or the
/// chunked terminator, so every exchange stays framed correctly.
pub(crate) fn read_http_response(stream: &mut impl Read) -> Result<String, VpnError> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    // 1) Read until the end of headers (\r\n\r\n).
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut tmp)
            .map_err(|e| VpnError::Auth(format!("read response: {}", e)))?;
        if n == 0 {
            if buf.is_empty() {
                return Err(VpnError::Auth("empty response from gateway".into()));
            }
            break buf.len(); // connection closed mid-headers; return what we have
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HTTP_RESPONSE {
            return Err(VpnError::Auth("HTTP response exceeded size limit".into()));
        }
    };

    // 2) Read the body to completion.
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    if let Some(clen) = content_length(&headers) {
        while buf.len() - header_end < clen {
            let n = stream.read(&mut tmp)
                .map_err(|e| VpnError::Auth(format!("read body: {}", e)))?;
            if n == 0 { break; }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_HTTP_RESPONSE {
                return Err(VpnError::Auth("HTTP response exceeded size limit".into()));
            }
        }
    } else if headers.contains("transfer-encoding: chunked") {
        // Read until the terminating zero-length chunk "0\r\n\r\n".
        while !ends_with(&buf, b"0\r\n\r\n") && !ends_with(&buf, b"\r\n0\r\n\r\n") {
            let n = stream.read(&mut tmp)
                .map_err(|e| VpnError::Auth(format!("read chunked body: {}", e)))?;
            if n == 0 { break; }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_HTTP_RESPONSE {
                return Err(VpnError::Auth("HTTP response exceeded size limit".into()));
            }
        }
    }
    // else: no body indicated (e.g. redirect with Content-Length: 0) — done.

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Parse the Content-Length value from lowercased header text.
fn content_length(headers_lower: &str) -> Option<usize> {
    for line in headers_lower.lines() {
        if let Some(rest) = line.strip_prefix("content-length:") {
            return rest.trim().parse::<usize>().ok();
        }
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn ends_with(haystack: &[u8], suffix: &[u8]) -> bool {
    haystack.len() >= suffix.len() && &haystack[haystack.len() - suffix.len()..] == suffix
}

/// Result of a successful authentication.
pub struct AuthResult {
    /// The SVPNCOOKIE session token from the gateway.
    pub cookie: String,
    /// Full HTTP response body (may contain tunnel config XML).
    pub body: String,
}

/// Perform the full authentication flow against the gateway.
pub fn authenticate(
    tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
) -> Result<AuthResult, VpnError> {
    if profile.saml_login == Some(true) {
        authenticate_saml(tls_stream, profile)
    } else {
        authenticate_password(tls_stream, profile)
    }
}

/// Password-based login: POST credentials to /remote/logincheck.
fn authenticate_password(
    tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
) -> Result<AuthResult, VpnError> {
    let host = &profile.host;
    let port = profile.port.unwrap_or(443);

    let username = percent_encode(&profile.username);
    let password = percent_encode(profile.password.as_deref().unwrap_or(""));
    let realm = percent_encode(profile.realm.as_deref().unwrap_or(""));

    let form_body = format!(
        "username={}&credential={}&realm={}&ajax=1",
        username, password, realm
    );

    let request = format!(
        "POST /remote/logincheck HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         User-Agent: FortiSSL-VPN/7.0\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {}",
        host, port,
        form_body.len(),
        form_body,
    );

    tls_stream.write_all(request.as_bytes())
        .map_err(|e| VpnError::Auth(format!("login POST failed: {}", e)))?;
    tls_stream.flush().map_err(|e| VpnError::Auth(format!("flush: {}", e)))?;

    let response = read_http_response(tls_stream)?;

    let cookie = extract_cookie(&response)
        .ok_or_else(|| VpnError::Auth("No SVPNCOOKIE in response".into()))?;

    log::info!("Got SVPNCOOKIE: {:.16}...", &cookie);

    Ok(AuthResult { cookie, body: response })
}

/// SAML-based login (two-phase):
/// Phase 1: Open the SAML URL directly in browser (no HTTP connection needed).
/// Phase 2: TLS + /remote/saml/auth_id to exchange session ID for SVPNCOOKIE.
fn authenticate_saml(
    _tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
) -> Result<AuthResult, VpnError> {
    let host = &profile.host;
    let port = profile.port.unwrap_or(443);
    let saml_port = profile.saml_port.unwrap_or(8020);

    // Build the SAML URL directly — same as openfortivpn does
    let saml_url = if profile.realm.as_ref().map_or(true, |r| r.is_empty()) {
        format!("https://{}:{}/remote/saml/start?redirect=1", host, port)
    } else {
        format!(
            "https://{}:{}/remote/saml/start?redirect=1&realm={}",
            host, port, profile.realm.as_deref().unwrap_or("")
        )
    };

    log::info!("SAML URL: {}", saml_url);

    // Open in browser
    let _ = std::process::Command::new("xdg-open")
        .arg(&saml_url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    // Wait for browser callback
    log::info!("Waiting for SAML callback on port {}…", saml_port);
    let session_id = crate::engine::http_server::wait_for_saml_callback(saml_port)?;
    log::info!("Got SAML session ID: {}", session_id);

    // Return session ID — backend will exchange it for SVPNCOOKIE on TLS
    Ok(AuthResult {
        cookie: session_id,
        body: String::new(),
    })
}

/// Extract the SVPNCOOKIE value from an HTTP response.
pub fn extract_cookie(response: &str) -> Option<String> {
    for line in response.lines() {
        if line.to_lowercase().contains("svpncookie=") {
            let start = line.find("SVPNCOOKIE=")
                .or_else(|| line.find("svpncookie="))?;
            let value_start = start + "SVPNCOOKIE=".len();
            let value = line[value_start..]
                .split(';')
                .next()?
                .trim();
            return Some(value.to_string());
        }
    }
    None
}

/// Fetch the VPN configuration XML from the gateway.
/// Returns raw XML string (use quick_xml to parse).
pub fn fetch_config(
    tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
    cookie: &str,
) -> Result<String, VpnError> {
    let host = &profile.host;
    let port = profile.port.unwrap_or(443);

    let req = format!(
        "GET /remote/fortisslvpn_xml HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Cookie: SVPNCOOKIE={}\r\n\
         User-Agent: FortiSSL-VPN/7.0\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        host, port, cookie,
    );
    tls_stream.write_all(req.as_bytes())
        .map_err(|e| VpnError::Auth(format!("config request: {}", e)))?;
    tls_stream.flush().map_err(|e| VpnError::Auth(format!("flush: {}", e)))?;

    let resp = read_http_response(tls_stream)?;

    // Extract body (may be chunked — callers tolerate chunk-size markers).
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    log::info!("Got VPN config ({} bytes)", body.len());
    Ok(body)
}

/// Allocate a VPN tunnel slot on the gateway.
/// Must be called after authentication and before starting tunnel mode.
pub fn allocate_tunnel(
    tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
    cookie: &str,
) -> Result<(), VpnError> {
    let host = &profile.host;
    let port = profile.port.unwrap_or(443);

    // Step 1: GET /remote/index (required by gateway before allocation)
    let req = format!(
        "GET /remote/index HTTP/1.1\r\nHost: {}:{}\r\nCookie: SVPNCOOKIE={}\r\nConnection: keep-alive\r\n\r\n",
        host, port, cookie,
    );
    tls_stream.write_all(req.as_bytes())
        .map_err(|e| VpnError::Auth(format!("index request: {}", e)))?;
    tls_stream.flush().map_err(|e| VpnError::Auth(format!("flush: {}", e)))?;
    // Consume the full response so the keep-alive stream stays framed.
    read_http_response(tls_stream)?;

    // Step 2: GET /remote/fortisslvpn — allocates the tunnel slot
    let req = format!(
        "GET /remote/fortisslvpn HTTP/1.1\r\nHost: {}:{}\r\nCookie: SVPNCOOKIE={}\r\nConnection: keep-alive\r\n\r\n",
        host, port, cookie,
    );
    tls_stream.write_all(req.as_bytes())
        .map_err(|e| VpnError::Auth(format!("alloc request: {}", e)))?;
    tls_stream.flush().map_err(|e| VpnError::Auth(format!("flush: {}", e)))?;
    let resp = read_http_response(tls_stream)?;

    if resp.contains("200") {
        log::info!("Tunnel slot allocated");
        Ok(())
    } else if resp.contains("302") || resp.contains("301") {
        // Follow the redirect with cookie
        let location = resp.lines()
            .find(|l| l.to_lowercase().starts_with("location:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "/remote/login".into());
        log::info!("Following redirect to: {}", location);
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: FortiSSL-VPN/7.0\r\nCookie: SVPNCOOKIE={}\r\nConnection: keep-alive\r\n\r\n",
            location, host, port, cookie,
        );
        tls_stream.write_all(req.as_bytes())
            .map_err(|e| VpnError::Auth(format!("redirect request: {}", e)))?;
        tls_stream.flush().map_err(|e| VpnError::Auth(format!("flush: {}", e)))?;
        let resp2 = read_http_response(tls_stream)?;
        if resp2.contains("200") {
            log::info!("Tunnel slot allocated (after redirect)");
            Ok(())
        } else {
            Err(VpnError::Auth(format!("Allocation failed after redirect: {:.200}", resp2)))
        }
    } else {
        Err(VpnError::Auth(format!("Allocation failed: {:.200}", resp)))
    }
}

/// Send the tunnel-mode upgrade request.
pub fn start_tunnel(
    tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
    cookie: &str,
) -> Result<(), VpnError> {
    let host = &profile.host;
    let port = profile.port.unwrap_or(443);

    let request = format!(
        "GET /remote/sslvpn-tunnel HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Cookie: SVPNCOOKIE={}\r\n\
         Connection: Keep-Alive\r\n\
         \r\n",
        host, port, cookie,
    );

    tls_stream.write_all(request.as_bytes())
        .map_err(|e| VpnError::Auth(format!("tunnel request failed: {}", e)))?;
    tls_stream.flush()
        .map_err(|e| VpnError::Auth(format!("flush failed: {}", e)))?;

    // The gateway switches to raw tunnel mode.  Don't try to read a
    // response — any HTTP headers will be treated as garbage by the
    // HDLC deframer and skipped.  The relay loop handles this.
    log::info!("Tunnel mode established");
    Ok(())
}

/// Send a logout request (best-effort).
pub fn logout(
    tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
    cookie: &str,
) {
    let host = &profile.host;
    let port = profile.port.unwrap_or(443);

    let request = format!(
        "GET /remote/logout HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         Cookie: SVPNCOOKIE={}\r\n\
         Connection: close\r\n\
         \r\n",
        host, port, cookie,
    );

    let _ = tls_stream.write_all(request.as_bytes());
    let _ = tls_stream.flush();
    log::info!("Logout request sent");
}

/// URL-encode a string (RFC 3986 percent-encoding).
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => result.push(byte as char),
            b' ' => result.push('+'),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cookie() {
        let r = "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=abc123def456; path=/; secure\r\n\r\n<body>";
        assert_eq!(extract_cookie(r), Some("abc123def456".into()));
    }

    #[test]
    fn test_extract_cookie_lowercase() {
        assert_eq!(extract_cookie("set-cookie: svpncookie=testval; path=/"), Some("testval".into()));
    }

    #[test]
    fn test_extract_cookie_missing() {
        assert_eq!(extract_cookie("HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello world"), "hello+world");
        assert_eq!(percent_encode("user@domain"), "user%40domain");
        assert_eq!(percent_encode("aBc-123_.~"), "aBc-123_.~");
    }
}
