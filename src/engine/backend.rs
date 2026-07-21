//! Native VPN backend — replaces the external openfortivpn binary.
//!
//! Implements `VpnBackend` using our pure-Rust engine: TLS → Auth → PPP → Tunnel.

use crate::config::VpnProfile;
use crate::engine::{self, auth, gateway, ppp, routes, tunnel, VpnError};
use crate::vpn::{ConnectionState, VpnBackend};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

/// Extract assigned IP from FortiGate XML (attribute form: ipv4='x.x.x.x').
fn parse_vpn_ip(xml: &str) -> String {
    // <assigned-addr ipv4='172.16.72.2' />
    for attr in &["ipv4='", "ipv4=\""] {
        if let Some(start) = xml.find(attr) {
            let start = start + attr.len();
            let end_delim = if attr.contains('\'') { '\'' } else { '"' };
            if let Some(end) = xml[start..].find(end_delim) {
                return xml[start..start + end].to_string();
            }
        }
    }
    "0.0.0.0".to_string()
}

/// Extract split-tunnel routes from XML (<addr ip='x.x.x.x' mask='y.y.y.y' />).
fn parse_split_routes(xml: &str) -> Vec<(String, String)> {
    let mut routes = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find("<addr ") {
        let abs = pos + start;
        let end = xml[abs..].find("/>").unwrap_or(xml[abs..].len());
        let tag = &xml[abs..abs + end];
        let ip = extract_attr(tag, "ip");
        let mask = extract_attr(tag, "mask");
        if let (Some(ip), Some(mask)) = (ip, mask) {
            // Convert netmask to CIDR prefix length
            if let Ok(m) = mask.parse::<std::net::Ipv4Addr>() {
                let prefix = m.octets().iter().map(|b| b.count_ones()).sum::<u32>();
                routes.push((ip, prefix.to_string()));
            }
        }
        pos = abs + end + 2;
    }
    routes
}

fn extract_attr(tag: &str, name: &str) -> Option<String> {
    for quote in &["'", "\""] {
        let pat = format!("{}={}", name, quote);
        if let Some(s) = tag.find(&pat) {
            let start = s + pat.len();
            if let Some(e) = tag[start..].find(*quote) {
                return Some(tag[start..start + e].to_string());
            }
        }
    }
    None
}

/// Extract DNS servers from XML (<dns ip='x.x.x.x' />).
fn parse_vpn_dns(xml: &str) -> Vec<String> {
    let mut dns = Vec::new();
    for attr in &["ip='", "ip=\""] {
        let mut search_from = 0;
        while let Some(pos) = xml[search_from..].find("<dns ") {
            let abs = search_from + pos;
            if let Some(start) = xml[abs..].find(attr) {
                let start = abs + start + attr.len();
                let end_delim = if attr.contains('\'') { '\'' } else { '"' };
                if let Some(end) = xml[start..].find(end_delim) {
                    let addr = &xml[start..start + end];
                    if !addr.is_empty() && !dns.contains(&addr.to_string()) {
                        dns.push(addr.to_string());
                    }
                }
            }
            search_from = abs + 1;
        }
    }
    dns
}

/// Extract split-DNS domains from XML (<split-dns domains='a.com,b.com' .../>).
/// These are the domains whose lookups must go to the VPN DNS servers.
fn parse_split_dns_domains(xml: &str) -> Vec<String> {
    let mut domains = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find("<split-dns ") {
        let abs = pos + start;
        let end = xml[abs..].find("/>").map(|e| abs + e).unwrap_or(xml.len());
        let tag = &xml[abs..end];
        if let Some(list) = extract_attr(tag, "domains") {
            for d in list.split([',', ';', ' ']) {
                let d = d.trim();
                if !d.is_empty() && !domains.contains(&d.to_string()) {
                    domains.push(d.to_string());
                }
            }
        }
        pos = end + 2;
    }
    domains
}

/// Run a shell script with the privileges required for network configuration
/// (routes, DNS). Tries, in order: run directly if already root, passwordless
/// `sudo -n`, then a single graphical `pkexec` prompt. Returns the method used
/// alongside the command output so the caller can report success/failure.
fn run_privileged(script: &str) -> std::io::Result<(&'static str, std::process::Output)> {
    use std::process::{Command, Stdio};

    // Already root (e.g. launched via sudo/pkexec)?
    if unsafe { libc::geteuid() } == 0 {
        return Command::new("sh").args(["-c", script]).output().map(|o| ("root", o));
    }

    // Passwordless sudo available?
    let sudo_ok = Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if sudo_ok {
        return Command::new("sudo").args(["-n", "sh", "-c", script]).output().map(|o| ("sudo", o));
    }

    // Fall back to a single graphical polkit prompt covering the whole batch.
    Command::new("pkexec").args(["sh", "-c", script]).output().map(|o| ("pkexec", o))
}

/// Native VPN backend that speaks the Fortinet SSL-VPN protocol directly.
pub struct NativeVpnBackend {
    state: ConnectionState,
    log: Vec<String>,
    log_tx: Option<Sender<String>>,
    log_rx: Option<Receiver<String>>,
    /// Handle to the relay thread (used to check liveness).
    relay_handle: Option<thread::JoinHandle<()>>,
    /// Tunnel config for teardown.
    tunnel_config: Option<routes::TunnelConfig>,
}

impl NativeVpnBackend {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            log: Vec::new(),
            log_tx: None,
            log_rx: None,
            relay_handle: None,
            tunnel_config: None,
        }
    }

    fn push_log(&mut self, msg: &str) {
        self.log.push(msg.to_string());
        if let Some(ref tx) = self.log_tx {
            let _ = tx.send(msg.to_string());
        }
    }
}

impl VpnBackend for NativeVpnBackend {
    fn connect(&mut self, profile: &VpnProfile) -> Result<(), String> {
        self.state = ConnectionState::Connecting;
        self.log.clear();

        let (log_tx, log_rx) = mpsc::channel();
        self.log_tx = Some(log_tx.clone());
        self.log_rx = Some(log_rx);

        let tx = log_tx;
        let profile = profile.clone();

        self.push_log(&format!("Connecting to {}…", profile.host));

        let handle = thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                connect_inner(&profile, &tx);
            }));
            if let Err(e) = result {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    format!("[engine] PANIC: {}", s)
                } else if let Some(s) = e.downcast_ref::<&str>() {
                    format!("[engine] PANIC: {}", s)
                } else {
                    "[engine] PANIC: unknown error".into()
                };
                let _ = tx.send(msg);
            }
        });
        self.relay_handle = Some(handle);

        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), String> {
        self.state = ConnectionState::Disconnecting;
        self.push_log("Disconnecting…");

        // Teardown routes if configured
        if let Some(ref cfg) = self.tunnel_config.take() {
            routes::teardown(cfg);
        }

        // Kill any openfortivpn/pppd processes (belt and suspenders)
        engine::kill_vpn_processes();

        self.state = ConnectionState::Disconnected;
        self.push_log("Disconnected.");
        Ok(())
    }

    fn check_status(&mut self) {
        // Check relay thread liveness
        if let Some(ref handle) = self.relay_handle {
            if handle.is_finished() {
                self.relay_handle = None;
                if self.state == ConnectionState::Connected {
                    self.state = ConnectionState::Disconnected;
                    self.push_log("Tunnel closed.");
                } else if self.state == ConnectionState::Connecting {
                    // Thread finished without sending "Tunnel UP!" — check for errors
                    if !self.log.iter().any(|l| l.contains("Tunnel UP!") || l.contains("ERROR:")) {
                        self.state = ConnectionState::Error("Connection failed (no output)".into());
                    }
                }
            }
        }

        // Scan already-drained log for state transitions
        for line in &self.log {
            if line.contains("Tunnel UP!") && self.state == ConnectionState::Connecting {
                self.state = ConnectionState::Connected;
            }
            if line.contains("ERROR:") && self.state == ConnectionState::Connecting {
                self.state = ConnectionState::Error(line.clone());
            }
        }
    }

    fn state(&self) -> &ConnectionState {
        &self.state
    }

    fn set_state(&mut self, s: ConnectionState) {
        self.state = s;
    }

    fn is_running_global() -> bool {
        std::process::Command::new("pgrep")
            .args(["openfortivpn"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn drain_log(&mut self) -> Vec<String> {
        let mut new = Vec::new();
        if let Some(ref rx) = self.log_rx {
            while let Ok(line) = rx.try_recv() {
                self.log.push(line.clone());
                new.push(line);
            }
        }
        if self.log.len() > 1000 {
            self.log.drain(0..self.log.len() - 500);
        }
        new
    }
}

/// The actual connection logic — runs in a background thread.
fn connect_inner(profile: &VpnProfile, log: &Sender<String>) {
    let result = connect_inner_impl(profile, log);
    match result {
        Ok(_) => {
            let _ = log.send("[engine] Tunnel closed.".into());
        }
        Err(e) => {
            let _ = log.send(format!("[engine] ERROR: {}", e));
        }
    }
}

fn connect_inner_impl(
    profile: &VpnProfile,
    log: &Sender<String>,
) -> Result<(), VpnError> {
    let _ = log.send("[engine] TLS handshake…".into());
    let conn = gateway::connect_blocking(profile)?;
    let (mut tls_stream, _gateway) = (conn.tls_stream, conn.gateway);
    let _ = log.send("[engine] TLS established.".into());

    let _ = log.send("[engine] Authenticating…".into());
    let auth_result = auth::authenticate(&mut tls_stream, profile)?;
    let _ = log.send("[engine] Authenticated.".into());

    // If SAML, we have a session ID, not a cookie — exchange it now
    let cookie = if profile.saml_login == Some(true) {
        let _ = log.send("[engine] Exchanging SAML session ID…".into());
        let req = format!(
            "GET /remote/saml/auth_id?id={} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             User-Agent: FortiSSL-VPN/7.0\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            auth_result.cookie, profile.host, profile.port.unwrap_or(443),
        );
        use std::io::Write;
        tls_stream.write_all(req.as_bytes()).map_err(|e| VpnError::Auth(format!("saml auth_id: {}", e)))?;
        tls_stream.flush().map_err(|e| VpnError::Auth(format!("flush: {}", e)))?;
        let mut buf = vec![0u8; 65536];
        use std::io::Read;
        let n = tls_stream.read(&mut buf).map_err(|e| VpnError::Auth(format!("saml auth_id read: {}", e)))?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        auth::extract_cookie(&resp)
            .ok_or_else(|| VpnError::Auth("No SVPNCOOKIE after SAML exchange".into()))?
    } else {
        auth_result.cookie
    };
    let _ = log.send("[engine] Got session cookie.".into());

    let _ = log.send("[engine] Allocating tunnel slot…".into());
    auth::allocate_tunnel(&mut tls_stream, profile, &cookie)?;
    let _ = log.send("[engine] Tunnel slot allocated.".into());

    // Fetch VPN config from gateway
    let _ = log.send("[engine] Fetching VPN config…".into());
    let config_xml = auth::fetch_config(&mut tls_stream, profile, &cookie)?;
    let _ = log.send(format!("[engine] Config XML ({} bytes): {:.500}", config_xml.len(), config_xml));
    let vpn_ip = parse_vpn_ip(&config_xml);
    let vpn_dns = parse_vpn_dns(&config_xml);
    let vpn_routes = parse_split_routes(&config_xml);
    let vpn_domains = parse_split_dns_domains(&config_xml);
    let _ = log.send(format!("[engine] IP: {}, DNS: {:?}, Domains: {:?}, Routes: {}",
        vpn_ip, vpn_dns, vpn_domains, vpn_routes.len()));

    let _ = log.send("[engine] Starting tunnel mode…".into());
    auth::start_tunnel(&mut tls_stream, profile, &cookie)?;

    let _ = log.send("[engine] Creating TUN interface…".into());
    let pppd = ppp::PppDaemon::spawn()?;
    let _ = log.send(format!("[engine] TUN {} ready", pppd.iface_name()));

    // Assign IP and set up routes
    if let Err(e) = pppd.configure(&vpn_ip) {
        let _ = log.send(format!("[engine] WARNING: Failed to set IP: {}", e));
    }
    let _ = log.send(format!("[engine] TUN {} configured with {}", pppd.iface_name(), vpn_ip));

    // Add split-tunnel routes and DNS in one batched sudo call
    let ifname = pppd.iface_name();
    if !vpn_routes.is_empty() || !vpn_dns.is_empty() {
        let mut script = String::new();
        for (net, mask) in &vpn_routes {
            script.push_str(&format!("ip route add {}/{} dev {} 2>/dev/null\n", net, mask, ifname));
        }
        if !vpn_dns.is_empty() {
            script.push_str(&format!("resolvectl dns {} {}\n", ifname, vpn_dns.join(" ")));
            // Route the split-DNS domains to the VPN DNS servers. The '~' prefix
            // marks them as routing-only domains so *.domain lookups use vpn0's DNS.
            // Fall back to a wildcard so all lookups prefer the VPN DNS if the
            // gateway didn't advertise any split-DNS domains.
            let domain_args: Vec<String> = if vpn_domains.is_empty() {
                vec!["~.".to_string()]
            } else {
                vpn_domains.iter().map(|d| format!("~{}", d)).collect()
            };
            script.push_str(&format!("resolvectl domain {} {}\n", ifname, domain_args.join(" ")));
        }
        let log2 = log.clone();
        std::thread::spawn(move || {
            match run_privileged(&script) {
                Ok((method, out)) if out.status.success() => {
                    let _ = log2.send(format!("[engine] Routes + DNS applied via {}.", method));
                }
                Ok((method, out)) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    let err = err.trim();
                    let _ = log2.send(format!(
                        "[engine] WARNING: network setup via {} failed{}. Routes/DNS not applied — internal hosts may not resolve.",
                        method,
                        if err.is_empty() { String::new() } else { format!(": {}", err) },
                    ));
                }
                Err(e) => {
                    let _ = log2.send(format!("[engine] WARNING: could not elevate for network setup: {}", e));
                }
            }
        });
        let _ = log.send(format!("[engine] Applying {} routes + DNS ({} domains) — a privilege prompt may appear…",
            vpn_routes.len(), vpn_domains.len()));
    }
    let ppp_in = pppd.writer();
    let ppp_out = pppd.reader();

    // Set TLS non-blocking for polling
    use std::os::unix::io::AsRawFd;
    let tls_fd = tls_stream.get_ref().as_raw_fd();
    unsafe { libc::fcntl(tls_fd, libc::F_SETFL, libc::O_NONBLOCK); }

    let _ = log.send("[engine] Tunnel UP! (native TUN)".into());
    let _ = log.send("[engine] Entering relay loop…".into());

    let local_ip: std::net::Ipv4Addr = vpn_ip.split('/').next().unwrap_or(&vpn_ip)
        .parse()
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

    let _alive = pppd;
    tunnel::run_relay(tls_stream, ppp_in, ppp_out, local_ip, Some(log.clone()));
    Ok(())
}
