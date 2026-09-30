//! Local HTTP server for SAML SSO redirect handling.
//!
//! Binds on localhost and waits for the browser-based SAML callback,
//! then extracts the session ID from the request URL.

use crate::engine::VpnError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long to wait for the user to finish SAML login in the browser.
pub const SAML_TIMEOUT: Duration = Duration::from_secs(300);

/// Wait for a SAML callback on the given port.
/// Returns the session ID extracted from the callback URL.
///
/// Gives up after `timeout` or as soon as `stop` is set (user pressed
/// Disconnect), so a cancelled login never leaves the port bound.
pub fn wait_for_saml_callback(port: u16, stop: &AtomicBool, timeout: Duration) -> Result<String, VpnError> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| VpnError::Auth(format!("SAML server bind {}: {}", addr, e)))?;
    listener.set_nonblocking(true)
        .map_err(|e| VpnError::Auth(format!("SAML server: {}", e)))?;
    log::info!("SAML server listening on {}", addr);
    let deadline = Instant::now() + timeout;

    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(VpnError::Auth("SAML login cancelled".into()));
        }
        if Instant::now() > deadline {
            return Err(VpnError::Auth(format!("SAML login not completed within {}s", timeout.as_secs())));
        }
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(VpnError::Auth(format!("SAML server accept: {}", e))),
        };
        // A stalled or trickling local client must not block the login: the
        // whole request line gets 5 s total, and cancellation is honored.
        let Some(line) = read_request_line(&mut stream, stop, Instant::now() + Duration::from_secs(5)) else {
            continue;
        };
        let id = extract_session_id(&line);

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
}

/// Read the first line of an HTTP request within `deadline` (total, not per
/// read), giving up early if `stop` is set. Lines over 8 KiB are rejected.
fn read_request_line(stream: &mut std::net::TcpStream, stop: &AtomicBool, deadline: Instant) -> Option<String> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut buf = Vec::new();
    let mut byte = [0u8; 512];
    loop {
        if stop.load(Ordering::Relaxed) || Instant::now() > deadline || buf.len() > 8192 {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&byte[..n]);
                if let Some(end) = buf.iter().position(|&b| b == b'\n') {
                    return Some(String::from_utf8_lossy(&buf[..end]).into_owned());
                }
            }
            Err(ref e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {}
            Err(_) => return None,
        }
    }
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
///
/// Only exact `id` / `auth_id` query parameters are accepted, and the value
/// must be a plain token — it is later placed in a request line, so anything
/// that could smuggle extra HTTP syntax is refused.
fn extract_session_id(request_line: &str) -> Option<String> {
    // The URL is something like: GET /?id=SESSION_ID HTTP/1.1
    let url = request_line.split_whitespace().nth(1)?;
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else { continue };
        if (key == "id" || key == "auth_id")
            && !value.is_empty()
            && value.len() <= 512
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b))
        {
            return Some(value.to_string());
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
    fn test_rejects_lookalike_and_unsafe_ids() {
        assert_eq!(extract_session_id("GET /?userid=abc HTTP/1.1"), None);
        assert_eq!(extract_session_id("GET /?id=a%0d%0aX HTTP/1.1"), None);
        assert_eq!(extract_session_id("GET /?x=1&id=3-fa92_ok HTTP/1.1"), Some("3-fa92_ok".into()));
    }

    #[test]
    fn test_no_id() {
        assert_eq!(extract_session_id("GET / HTTP/1.1"), None);
    }
}
