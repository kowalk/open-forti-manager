//! Local HTTP server for SAML SSO redirect handling.
//!
//! Binds on localhost and waits for the browser-based SAML callback,
//! then extracts the session ID from the request URL.

use crate::engine::VpnError;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

/// Wait for a SAML callback on the given port.
/// Returns the session ID extracted from the callback URL.
pub fn wait_for_saml_callback(port: u16) -> Result<String, VpnError> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| VpnError::Auth(format!("SAML server bind {}: {}", addr, e)))?;
    log::info!("SAML server listening on {}", addr);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut reader = BufReader::new(&mut stream);

                // Read the first line of the HTTP request
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }

                // Parse: GET /?id=SESSION_ID HTTP/1.1
                // or:    GET /?auth_id=SESSION_ID&user=... HTTP/1.1
                log::debug!("SAML callback: {}", line.trim());

                let id = extract_session_id(&line);

                // Send a response back to the browser
                let response = if id.is_some() {
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                     <html><body><h1>SAML login successful</h1>\
                     <p>You can close this window.</p></body></html>"
                } else {
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n\
                     <html><body><h1>Error</h1><p>No session ID found.</p></body></html>"
                };
                let _ = stream.write_all(response.as_bytes());

                if let Some(id) = id {
                    return Ok(id);
                }
            }
            Err(_) => break,
        }
    }

    Err(VpnError::Auth("SAML callback timed out".into()))
}

/// Extract the SAML session ID from the HTTP request line.
fn extract_session_id(request_line: &str) -> Option<String> {
    // The URL is something like: GET /?id=SESSION_ID HTTP/1.1
    let url = request_line.split_whitespace().nth(1)?;

    // Try different query parameter names
    for param_name in &["id=", "auth_id="] {
        if let Some(start) = url.find(param_name) {
            let value_start = start + param_name.len();
            let value = url[value_start..]
                .split('&')
                .next()?
                .split_whitespace()
                .next()?;
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_id() {
        assert_eq!(
            extract_session_id("GET /?id=abc123 HTTP/1.1"),
            Some("abc123".into())
        );
    }

    #[test]
    fn test_extract_auth_id() {
        assert_eq!(
            extract_session_id("GET /?auth_id=xyz789&user=test HTTP/1.1"),
            Some("xyz789".into())
        );
    }

    #[test]
    fn test_no_id() {
        assert_eq!(extract_session_id("GET / HTTP/1.1"), None);
    }
}
