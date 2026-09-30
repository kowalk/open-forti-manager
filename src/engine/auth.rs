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
use std::sync::atomic::AtomicBool;

const MAX_HTTP_RESPONSE: usize = 8 * 1024 * 1024;

/// Read one complete HTTP response from a (blocking) stream.
///
/// A single `read()` is not enough: responses split across TCP segments / TLS
/// records would otherwise be truncated, and — on a keep-alive connection —
/// leftover bytes would corrupt the *next* response. This reads until the
/// headers are complete, then consumes the body per `Content-Length` or the
/// chunked terminator, so every exchange stays framed correctly.
pub(crate) fn read_http_response(stream: &mut impl Read) -> Result<String, VpnError> {
    read_http_response_bytes(stream).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Like `read_http_response`, but returns the raw bytes (needed to decode a
/// chunked body before any UTF-8 conversion changes its byte lengths).
pub(crate) fn read_http_response_bytes(stream: &mut impl Read) -> Result<Vec<u8>, VpnError> {
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
            // A truncated response must never be parsed as complete.
            return Err(VpnError::Auth("gateway closed the connection in the middle of the response headers".into()));
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
            if n == 0 {
                return Err(VpnError::Auth(format!(
                    "gateway closed the connection after {} of {} body bytes (truncated response)",
                    buf.len() - header_end, clen)));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_HTTP_RESPONSE {
                return Err(VpnError::Auth("HTTP response exceeded size limit".into()));
            }
        }
    } else if headers.contains("transfer-encoding: chunked") {
        // Read until the body decodes completely (terminal chunk + trailer end).
        while !(ends_with(&buf, b"\r\n\r\n") && decode_chunked(&buf[header_end..]).is_some()) {
            let n = stream.read(&mut tmp)
                .map_err(|e| VpnError::Auth(format!("read chunked body: {}", e)))?;
            if n == 0 {
                return Err(VpnError::Auth(
                    "gateway closed the connection before the final chunk (truncated response)".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_HTTP_RESPONSE {
                return Err(VpnError::Auth("HTTP response exceeded size limit".into()));
            }
        }
    } else if connection_delimited(&headers) {
        // No length and not chunked, but the server closes the connection to
        // end the body (RFC 9112 §6.3): read until EOF.
        loop {
            let n = stream.read(&mut tmp)
                .map_err(|e| VpnError::Auth(format!("read body: {}", e)))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_HTTP_RESPONSE {
                return Err(VpnError::Auth("HTTP response exceeded size limit".into()));
            }
        }
    }
    // else: keep-alive without a length — treated as having no body (a
    // bodyless reply such as a redirect); reading on would block until the
    // socket timeout.

    Ok(buf)
}

/// Whether a response without length/chunking ends its body by closing the
/// connection: `Connection: close`, or HTTP/1.0 without `keep-alive`.
/// Bodyless statuses (1xx, 204, 304) never have one.
fn connection_delimited(headers_lower: &str) -> bool {
    let status = headers_lower.lines().next().and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return false;
    }
    let connection = headers_lower.lines()
        .find_map(|l| l.strip_prefix("connection:"))
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    connection.contains("close")
        || (headers_lower.starts_with("http/1.0") && !connection.contains("keep-alive"))
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
    stop: &AtomicBool,
) -> Result<AuthResult, VpnError> {
    if profile.saml_login == Some(true) {
        authenticate_saml(tls_stream, profile, stop)
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
        .ok_or_else(|| VpnError::Auth("login rejected: no SVPNCOOKIE in response (wrong credentials, realm, or 2FA required)".into()))?;

    log::info!("Got SVPNCOOKIE ({} chars)", cookie.len());

    Ok(AuthResult { cookie, body: response })
}

/// SAML-based login (two-phase):
/// Phase 1: Open the SAML URL directly in browser (no HTTP connection needed).
/// Phase 2: TLS + /remote/saml/auth_id to exchange session ID for SVPNCOOKIE.
fn authenticate_saml(
    _tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
    stop: &AtomicBool,
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
            host, port, percent_encode(profile.realm.as_deref().unwrap_or(""))
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
    let session_id = crate::engine::http_server::wait_for_saml_callback(
        saml_port, stop, crate::engine::http_server::SAML_TIMEOUT)?;
    // The session ID is a bearer token — never log it.
    log::info!("Got SAML session ID ({} chars)", session_id.len());

    // Return session ID — backend will exchange it for SVPNCOOKIE on TLS
    Ok(AuthResult {
        cookie: session_id,
        body: String::new(),
    })
}

/// Extract the SVPNCOOKIE value from an HTTP response.
///
/// Only `Set-Cookie` headers count, and an empty value (the gateway clears the
/// cookie with `SVPNCOOKIE=;` on a failed login) is not a session.
pub fn extract_cookie(response: &str) -> Option<String> {
    let headers = response.split("\r\n\r\n").next().unwrap_or(response);
    for line in headers.lines() {
        let Some((name, rest)) = line.split_once(':') else { continue };
        if !name.trim().eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        // RFC 6265 §5.2: the cookie is the first `name=value` pair; the rest
        // are attributes. The name must be exactly SVPNCOOKIE — lookalikes
        // such as NOTSVPNCOOKIE must not be taken as the session token.
        let pair = rest.split(';').next().unwrap_or("");
        let Some((cname, value)) = pair.split_once('=') else { continue };
        let value = value.trim();
        if cname.trim().eq_ignore_ascii_case("SVPNCOOKIE") && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// HTTP status code from the first line of a response.
fn status_code(response: &str) -> Option<u16> {
    response.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// Header value (case-insensitive name) from a raw response.
fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let headers = response.split("\r\n\r\n").next().unwrap_or(response);
    headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) { Some(v.trim()) } else { None }
    })
}

/// Decode an HTTP/1.1 chunked body (RFC 9112 §7.1). Returns None if malformed.
fn decode_chunked(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = pos + find_subsequence(&body[pos..], b"\r\n")?;
        let size_str = std::str::from_utf8(&body[pos..line_end]).ok()?;
        let size_str = size_str.split(';').next()?.trim(); // drop chunk extensions
        let size = usize::from_str_radix(size_str, 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            return Some(out); // trailers (if any) are ignored
        }
        let end = pos.checked_add(size)?;
        if end > body.len() || out.len().checked_add(size)? > MAX_HTTP_RESPONSE {
            return None;
        }
        out.extend_from_slice(&body[pos..end]);
        pos = end;
        if body.get(pos..pos.checked_add(2)?) != Some(b"\r\n") {
            return None;
        }
        pos += 2;
    }
}

/// Exchange the SAML session ID for an SVPNCOOKIE on the gateway.
pub fn exchange_saml_id(
    tls_stream: &mut (impl Read + Write),
    profile: &VpnProfile,
    session_id: &str,
) -> Result<String, VpnError> {
    let req = format!(
        "GET /remote/saml/auth_id?id={} HTTP/1.1\r\n\
         Host: {}:{}\r\n\
         User-Agent: FortiSSL-VPN/7.0\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        percent_encode(session_id), profile.host, profile.port.unwrap_or(443),
    );
    tls_stream.write_all(req.as_bytes()).map_err(|e| VpnError::Auth(format!("saml auth_id: {}", e)))?;
    tls_stream.flush().map_err(|e| VpnError::Auth(format!("flush: {}", e)))?;
    let resp = read_http_response(tls_stream)?;
    extract_cookie(&resp).ok_or_else(|| VpnError::Auth(format!(
        "No SVPNCOOKIE after SAML exchange (HTTP {})",
        status_code(&resp).map(|c| c.to_string()).unwrap_or_else(|| "?".into()))))
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

    let resp = read_http_response_bytes(tls_stream)?;
    let split = find_subsequence(&resp, b"\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
    let head = String::from_utf8_lossy(&resp[..split]);
    match status_code(&head) {
        Some(200) => {}
        code => return Err(VpnError::Auth(format!(
            "config request failed (HTTP {})", code.map(|c| c.to_string()).unwrap_or_else(|| "?".into())))),
    }

    let raw = &resp[split..];
    let chunked = header(&head, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let body = if chunked {
        let decoded = decode_chunked(raw)
            .ok_or_else(|| VpnError::Auth("malformed chunked config response".into()))?;
        String::from_utf8_lossy(&decoded).into_owned()
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
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
    let code = status_code(&resp);

    if code == Some(200) {
        log::info!("Tunnel slot allocated");
        Ok(())
    } else if matches!(code, Some(301) | Some(302) | Some(303) | Some(307) | Some(308)) {
        // Follow the redirect with cookie (absolute URLs are reduced to their path).
        let location = header(&resp, "location")
            .map(redirect_path)
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
        if status_code(&resp2) == Some(200) {
            log::info!("Tunnel slot allocated (after redirect)");
            Ok(())
        } else {
            Err(VpnError::Auth(format!("Allocation failed after redirect: {:.200}", resp2)))
        }
    } else {
        Err(VpnError::Auth(format!("Allocation failed: {:.200}", resp)))
    }
}

/// Reduce a redirect target to an origin-relative path (`https://h/x?y` → `/x?y`).
fn redirect_path(location: &str) -> String {
    let path = match location.find("://") {
        Some(i) => location[i + 3..].find('/').map(|j| &location[i + 3 + j..]).unwrap_or("/"),
        None => location,
    };
    // Never let a header value inject CR/LF or spaces into our request line.
    if path.starts_with('/') && !path.bytes().any(|b| b <= b' ') {
        path.to_string()
    } else {
        "/remote/login".to_string()
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
    fn test_extract_cookie_empty_is_rejected() {
        let r = "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=; path=/; expires=Thu, 01 Jan 1970\r\n\r\nret=0";
        assert_eq!(extract_cookie(r), None);
    }

    #[test]
    fn test_extract_cookie_ignores_body() {
        assert_eq!(extract_cookie("HTTP/1.1 200 OK\r\n\r\nSet-Cookie: SVPNCOOKIE=fake"), None);
        assert_eq!(extract_cookie("HTTP/1.1 200 OK\r\nSet-Cookie: SvpnCookie=MiXed; path=/\r\n\r\n"),
            Some("MiXed".into()));
    }

    #[test]
    fn test_extract_cookie_requires_exact_name() {
        let r = "HTTP/1.1 200 OK\r\nSet-Cookie: NOTSVPNCOOKIE=fake; path=/\r\n\r\n";
        assert_eq!(extract_cookie(r), None);
        let r = "HTTP/1.1 200 OK\r\nSet-Cookie: other=1; SVPNCOOKIE=attr\r\n\r\n";
        assert_eq!(extract_cookie(r), None, "SVPNCOOKIE as an attribute is not the cookie");
        let r = "HTTP/1.1 200 OK\r\nSet-Cookie: x=1\r\nSet-Cookie: SVPNCOOKIE=a=b==; Secure\r\n\r\n";
        assert_eq!(extract_cookie(r), Some("a=b==".into()), "value keeps embedded '=' and case");
    }

    #[test]
    fn test_status_and_redirect() {
        assert_eq!(status_code("HTTP/1.1 302 Found\r\nX: 200\r\n\r\n"), Some(302));
        assert_eq!(status_code("HTTP/1.1 404 Not Found\r\n\r\n<p>200</p>"), Some(404));
        assert_eq!(redirect_path("https://gw.example:443/remote/index?x=1"), "/remote/index?x=1");
        assert_eq!(redirect_path("/remote/fortisslvpn"), "/remote/fortisslvpn");
        assert_eq!(redirect_path("javascript:alert(1)"), "/remote/login");
    }

    fn read(raw: &[u8]) -> Result<Vec<u8>, VpnError> {
        read_http_response_bytes(&mut std::io::Cursor::new(raw.to_vec()))
    }

    #[test]
    fn truncated_responses_are_errors() {
        // Regression (Copilot): EOF before Content-Length / final chunk / end of
        // headers was accepted, so a truncated config could lose its routes.
        assert!(read(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n<ipv4>").is_err());
        assert!(read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<ipv\r\n").is_err());
        assert!(read(b"HTTP/1.1 200 OK\r\nContent-Le").is_err());
    }

    #[test]
    fn complete_and_delimited_responses() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n<ipv4>";
        assert_eq!(read(ok).unwrap(), ok.to_vec());
        // Connection-close delimited body: read to EOF.
        let close = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<sslvpn-tunnel/>";
        assert_eq!(read(close).unwrap(), close.to_vec());
        // Keep-alive without a length, and 204 even with Connection: close:
        // no further read after the headers (on a live socket it would block).
        struct HeadersOnly(Option<&'static [u8]>);
        impl std::io::Read for HeadersOnly {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let chunk = self.0.take().expect("must not read past the headers");
                buf[..chunk.len()].copy_from_slice(chunk);
                Ok(chunk.len())
            }
        }
        for head in [&b"HTTP/1.1 302 Found\r\nLocation: /remote/index\r\n\r\n"[..],
                     &b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"[..]] {
            assert_eq!(read_http_response_bytes(&mut HeadersOnly(Some(head))).unwrap(), head.to_vec());
        }
    }

    #[test]
    fn test_decode_chunked() {
        let body = b"4\r\n<ipv\r\n5;ext=1\r\n4 a='\r\n0\r\nTrailer: x\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"<ipv4 a='");
        assert!(decode_chunked(b"zz\r\nabc").is_none());
        // Overflowing size must not panic.
        assert!(decode_chunked(b"ffffffffffffffff\r\nabc\r\n0\r\n\r\n").is_none());
        // A multi-byte UTF-8 char split across chunks decodes intact.
        let e = "é".as_bytes();
        let mut split = b"1\r\n".to_vec();
        split.extend_from_slice(&e[..1]);
        split.extend_from_slice(b"\r\n1\r\n");
        split.extend_from_slice(&e[1..]);
        split.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(decode_chunked(&split).unwrap(), e);
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
