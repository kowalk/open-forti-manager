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

                // Send a response back to the browser.
                let (status, body) = if id.is_some() {
                    ("200 OK", success_page())
                } else {
                    ("400 Bad Request",
                     "<html><body><h1>Error</h1><p>No session ID found.</p></body></html>".to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n\
                     Content-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {len}\r\n\
                     Connection: close\r\n\r\n{body}",
                    len = body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();

                if let Some(id) = id {
                    return Ok(id);
                }
            }
            Err(_) => break,
        }
    }

    Err(VpnError::Auth("SAML callback timed out".into()))
}

/// Success page shown in the browser after the SAML callback. Tries to close
/// the tab automatically; browsers that refuse to close a tab not opened by a
/// script fall back to a clear "you can close this tab" message.
fn success_page() -> String {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>VPN login</title>\
     <style>body{font-family:system-ui,sans-serif;text-align:center;padding:3rem;color:#222}\
     h1{color:#1a7f37}p{color:#555}</style></head>\
     <body>\
     <h1>&#10003; VPN login successful</h1>\
     <p id=\"m\">This tab will close automatically&hellip;</p>\
     <script>\
     (function(){\
       function bye(){try{window.open('','_self');window.close();}catch(e){}}\
       bye();\
       setTimeout(bye,200);\
       setTimeout(function(){document.getElementById('m').textContent='You can close this tab now.';},600);\
     })();\
     </script>\
     </body></html>".to_string()
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
