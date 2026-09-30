//! Native VPN backend — replaces the external openfortivpn binary.
//!
//! Implements `VpnBackend` using our pure-Rust engine: TLS → Auth → PPP → Tunnel.

use crate::config::VpnProfile;
use crate::engine::netcfg::{self, Prefix};
use crate::engine::{auth, gateway, ppp, tunnel, VpnError};
use crate::vpn::{ConnectionState, VpnBackend};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Extract assigned IP from FortiGate XML (<assigned-addr ipv4='x.x.x.x' />).
/// Returns 0.0.0.0 when absent — IPCP then asks the gateway for an address.
fn parse_vpn_ip(xml: &str) -> Ipv4Addr {
    xml.find("<assigned-addr")
        .and_then(|start| {
            let end = xml[start..].find("/>").map(|e| start + e).unwrap_or(xml.len());
            extract_attr(&xml[start..end], "ipv4")
        })
        .and_then(|ip| ip.trim().parse().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// Extract split-tunnel routes from XML (<addr ip='x.x.x.x' mask='y.y.y.y' />),
/// normalized to network addresses. Entries with an unparsable address or a
/// non-contiguous mask are returned separately (as their raw tag) so the
/// caller can report them — malformed policy must not look like "no routes".
fn parse_split_routes(xml: &str) -> (Vec<Prefix>, Vec<String>) {
    let mut routes = Vec::new();
    let mut malformed = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find("<addr ") {
        let abs = pos + start;
        let end = xml[abs..].find("/>").unwrap_or(xml[abs..].len());
        let tag = &xml[abs..abs + end];
        let ip = extract_attr(tag, "ip").and_then(|s| s.trim().parse::<Ipv4Addr>().ok());
        let len = extract_attr(tag, "mask")
            .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
            .and_then(netcfg::mask_to_len);
        match (ip, len) {
            (Some(ip), Some(len)) => {
                let p = Prefix::new(ip, len);
                if !routes.contains(&p) {
                    routes.push(p);
                }
            }
            _ => malformed.push(tag.trim().to_string()),
        }
        pos = abs + end + 2;
    }
    (routes, malformed)
}

fn extract_attr(tag: &str, name: &str) -> Option<String> {
    for quote in &["'", "\""] {
        // Leading whitespace: `ip=` must not match inside e.g. `gwip=`.
        let pat = format!(" {}={}", name, quote);
        let found = tag.find(&pat).or_else(|| {
            tag.find(&format!("\t{}={}", name, quote)).or_else(|| tag.find(&format!("\n{}={}", name, quote)))
        });
        if let Some(s) = found {
            let start = s + pat.len();
            if let Some(e) = tag[start..].find(*quote) {
                return Some(tag[start..start + e].to_string());
            }
        }
    }
    None
}

/// Iterate the attribute text of every `<name ...>` tag.
fn tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{} ", name);
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(start) = xml[pos..].find(&open) {
        let abs = pos + start;
        let end = xml[abs..].find('>').map(|e| abs + e).unwrap_or(xml.len());
        out.push(&xml[abs..end]);
        pos = end;
    }
    out
}

/// Extract DNS servers from XML (<dns ip='x.x.x.x' />), IPv4 only.
fn parse_vpn_dns(xml: &str) -> Vec<Ipv4Addr> {
    let mut dns = Vec::new();
    for tag in tags(xml, "dns") {
        if let Some(addr) = extract_attr(tag, "ip").and_then(|s| s.trim().parse::<Ipv4Addr>().ok()) {
            if !addr.is_unspecified() && !dns.contains(&addr) {
                dns.push(addr);
            }
        }
    }
    dns
}

/// Extract DNS search suffixes from XML (<dns domain='corp.example' />).
fn parse_dns_suffixes(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tag in tags(xml, "dns") {
        if let Some(list) = extract_attr(tag, "domain") {
            for d in list.split([',', ';', ' ']).map(str::trim).filter(|d| !d.is_empty()) {
                if !out.iter().any(|x: &String| x == d) {
                    out.push(d.to_string());
                }
            }
        }
    }
    out
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

/// Native VPN backend that speaks the Fortinet SSL-VPN protocol directly.
pub struct NativeVpnBackend {
    state: ConnectionState,
    log: Vec<String>,
    log_tx: Option<Sender<String>>,
    log_rx: Option<Receiver<String>>,
    /// Handle to the relay thread (used to check liveness).
    relay_handle: Option<thread::JoinHandle<()>>,
    /// Signals the relay loop to shut down the tunnel.
    stop_flag: Option<Arc<AtomicBool>>,
    /// Profile of the active session (for logout on disconnect).
    active_profile: Option<VpnProfile>,
    /// SVPNCOOKIE of the active session, filled by the relay thread once known.
    session_cookie: Arc<Mutex<Option<String>>>,
}

impl NativeVpnBackend {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            log: Vec::new(),
            log_tx: None,
            log_rx: None,
            relay_handle: None,
            stop_flag: None,
            active_profile: None,
            session_cookie: Arc::new(Mutex::new(None)),
        }
    }

    fn push_log(&mut self, msg: &str) {
        self.log.push(msg.to_string());
        if let Some(ref tx) = self.log_tx {
            let _ = tx.send(msg.to_string());
        }
    }

    /// Release the gateway session (best-effort, in the background): open a
    /// fresh TLS connection and `GET /remote/logout`, so an immediate reconnect
    /// isn't refused while the gateway still holds the old session. Idempotent —
    /// clears the stored session so it runs at most once per connection.
    fn logout_session(&mut self) {
        let cookie = self.session_cookie.lock().ok().and_then(|mut c| c.take());
        let profile = self.active_profile.take();
        if let (Some(profile), Some(cookie)) = (profile, cookie) {
            let tx = self.log_tx.clone();
            thread::spawn(move || {
                match gateway::connect_blocking(&profile) {
                    Ok(conn) => {
                        let mut tls = conn.tls_stream;
                        auth::logout(&mut tls, &profile, &cookie);
                        if let Some(tx) = tx {
                            let _ = tx.send("[engine] Logged out of gateway.".into());
                        }
                    }
                    Err(e) => log::warn!("logout: could not reconnect to gateway: {}", e),
                }
            });
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
        self.active_profile = Some(profile.clone());

        // Fresh cookie slot for this session; the relay thread fills it.
        let cookie_slot = Arc::new(Mutex::new(None));
        self.session_cookie = cookie_slot.clone();

        let stop = Arc::new(AtomicBool::new(false));
        self.stop_flag = Some(stop.clone());

        self.push_log(&format!("Connecting to {}…", profile.host));

        let handle = thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                connect_inner(&profile, &tx, stop, cookie_slot);
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

        // Signal the relay loop to stop; it closes the TLS stream and TUN
        // device when it exits, which also removes the per-link routes/DNS.
        if let Some(stop) = self.stop_flag.take() {
            stop.store(true, Ordering::Relaxed);
        }

        // Wait briefly for the relay thread to wind down (it polls every ≤10ms).
        if let Some(handle) = self.relay_handle.take() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(25));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                // Still in a blocking phase (e.g. auth); it will notice the
                // stop flag before entering the relay loop.
                self.relay_handle = Some(handle);
            }
        }

        self.logout_session();

        self.state = ConnectionState::Disconnected;
        self.push_log("Disconnected.");
        Ok(())
    }

    fn check_status(&mut self) {
        // A disconnect (manual or already-finished) is authoritative — never
        // revert it from log/thread state.
        if matches!(self.state, ConnectionState::Disconnecting | ConnectionState::Disconnected) {
            return;
        }

        // While connecting, promote based on log signals: an error wins,
        // otherwise "Tunnel UP!" means the tunnel reached the relay loop.
        if self.state == ConnectionState::Connecting {
            if let Some(err) = self.log.iter().find(|l| l.contains("ERROR:") || l.contains("PANIC:")) {
                self.state = ConnectionState::Error(err.clone());
            } else if self.log.iter().any(|l| l.contains("Tunnel UP!")) {
                self.state = ConnectionState::Connected;
            }
        }

        // The relay thread ending is the authoritative "tunnel is down" signal.
        // Handle it AFTER the promotion above so a fast connect→fail can't get
        // stuck showing "Connected".
        let relay_finished = self.relay_handle.as_ref().map(|h| h.is_finished()).unwrap_or(false);
        if relay_finished {
            self.relay_handle = None;
            if let Some(err) = self.log.iter().rev().find(|l| l.contains("ERROR:") || l.contains("PANIC:")).cloned() {
                self.state = ConnectionState::Error(err);
            } else {
                // Only log "Tunnel closed." once, on the transition.
                if self.state != ConnectionState::Disconnected {
                    self.push_log("Tunnel closed.");
                }
                self.state = ConnectionState::Disconnected;
            }
            // The tunnel dropped on its own — release the gateway session so a
            // reconnect isn't refused while the old session lingers.
            self.logout_session();
        }
    }

    fn state(&self) -> &ConnectionState {
        &self.state
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
fn connect_inner(
    profile: &VpnProfile,
    log: &Sender<String>,
    stop: Arc<AtomicBool>,
    cookie_slot: Arc<Mutex<Option<String>>>,
) {
    let result = connect_inner_impl(profile, log, stop, cookie_slot);
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
    stop: Arc<AtomicBool>,
    cookie_slot: Arc<Mutex<Option<String>>>,
) -> Result<(), VpnError> {
    // A gateway pin left by an earlier session (e.g. via a router from another
    // network) could keep the gateway unreachable: clear it before connecting.
    // Without passwordless privilege this prompts only for *harmful* pins.
    let attempt = netcfg::Attempt::begin();
    let (pending_pins, removed) = netcfg::cleanup_stale_pins_before_connect(attempt.as_ref());
    if removed > 0 {
        let _ = log.send(format!("[engine] Removed {} stale gateway host route(s) from a previous session.", removed));
    }
    if !pending_pins.is_empty() {
        let _ = log.send(format!("[engine] {} stale gateway host route(s) will be removed during network setup.",
            pending_pins.len()));
    }

    let _ = log.send("[engine] TLS handshake…".into());
    let conn = match gateway::connect_blocking(profile) {
        Ok(conn) => conn,
        // Last resort: a stale pin we did not judge harmful may still be what
        // breaks the path to the gateway. Only for TCP-connect failures (not
        // DNS/TLS — e.g. being offline must not prompt), and never for an
        // attempt the user already cancelled (a newer session may own the
        // route by now). Remove it (prompting if needed) and retry once.
        Err(e @ VpnError::Tcp(_)) if !pending_pins.is_empty() && !stop.load(Ordering::Relaxed) => {
            let _ = log.send(format!("[engine] Connection failed ({}) — removing stale gateway route(s) and retrying…", e));
            let left = netcfg::remove_pins(&pending_pins, attempt.as_ref());
            // Cancelled or superseded while the prompt was open: stop here.
            if stop.load(Ordering::Relaxed) || !attempt.as_ref().map(|a| a.is_current()).unwrap_or(true) {
                let _ = log.send("[engine] Connection attempt cancelled.".into());
                return Ok(());
            }
            let gone: Vec<netcfg::PinRecord> = pending_pins.iter().filter(|p| !left.contains(p)).cloned().collect();
            let _ = netcfg::forget_absent(&gone);
            gateway::connect_blocking(profile)?
        }
        Err(e) => return Err(e),
    };
    let (mut tls_stream, gateway_addr) = (conn.tls_stream, conn.gateway);
    let _ = log.send("[engine] TLS established.".into());

    let _ = log.send("[engine] Authenticating…".into());
    let auth_result = auth::authenticate(&mut tls_stream, profile, &stop)?;
    let _ = log.send("[engine] Authenticated.".into());

    // If SAML, we have a session ID, not a cookie — exchange it now
    let cookie = if profile.saml_login == Some(true) {
        let _ = log.send("[engine] Exchanging SAML session ID…".into());
        auth::exchange_saml_id(&mut tls_stream, profile, &auth_result.cookie)?
    } else {
        auth_result.cookie
    };
    // Publish the cookie so disconnect() can log out this session cleanly.
    if let Ok(mut slot) = cookie_slot.lock() {
        *slot = Some(cookie.clone());
    }
    let _ = log.send("[engine] Got session cookie.".into());

    let _ = log.send("[engine] Allocating tunnel slot…".into());
    auth::allocate_tunnel(&mut tls_stream, profile, &cookie)?;
    let _ = log.send("[engine] Tunnel slot allocated.".into());

    // Fetch VPN config from gateway
    let _ = log.send("[engine] Fetching VPN config…".into());
    let config_xml = auth::fetch_config(&mut tls_stream, profile, &cookie)?;
    let _ = log.send(format!("[engine] Config XML ({} bytes): {:.500}", config_xml.len(), config_xml));
    let xml_ip = parse_vpn_ip(&config_xml);
    let vpn_dns = parse_vpn_dns(&config_xml);
    let (vpn_routes, malformed_routes) = parse_split_routes(&config_xml);
    let vpn_domains = parse_split_dns_domains(&config_xml);
    let vpn_suffixes = parse_dns_suffixes(&config_xml);
    let _ = log.send(format!("[engine] IP: {}, DNS: {:?}, Domains: {:?}, Search: {:?}, Routes: {}",
        xml_ip, vpn_dns, vpn_domains, vpn_suffixes, vpn_routes.len()));

    // Malformed split routes: warn and continue if some are valid; fail if
    // none are (an empty list would otherwise be taken as a full tunnel).
    if !malformed_routes.is_empty() && profile.set_routes != Some(false) {
        let sample: Vec<&str> = malformed_routes.iter().take(5).map(|s| s.as_str()).collect();
        if vpn_routes.is_empty() {
            return Err(VpnError::Route(format!(
                "the gateway advertised {} split route(s) but none could be parsed (e.g. {:?}); \
                 refusing to guess the routing policy", malformed_routes.len(), sample)));
        }
        let _ = log.send(format!(
            "[engine] WARNING: skipped {} malformed split route(s) from the gateway — those networks \
             will NOT go through the VPN: {:?}", malformed_routes.len(), sample));
    }

    if stop.load(Ordering::Relaxed) {
        let _ = log.send("[engine] Disconnect requested during setup — aborting.".into());
        return Ok(());
    }

    let _ = log.send("[engine] Starting tunnel mode…".into());
    auth::start_tunnel(&mut tls_stream, profile, &cookie)?;

    let _ = log.send("[engine] Creating TUN interface…".into());
    let tun = ppp::TunHandle::open()?;
    let ifname = tun.iface_name();
    let _ = log.send(format!("[engine] TUN {} ready — negotiating PPP…", ifname));

    // Honor the profile's Set-DNS / Set-Routes / Half-Internet options.
    // "Default" (None) keeps the historical always-on behavior; only an explicit
    // "No" disables, and Half-Internet is opt-in.
    let want_routes = profile.set_routes != Some(false);
    let want_dns = profile.set_dns != Some(false);
    let half_internet = profile.half_internet_routes == Some(true);
    let gateway_ip = match gateway_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };

    // Filled by the network-setup worker once routes are in place, so the
    // pinned gateway route can be removed on the way out.
    let gw_pin: Arc<Mutex<Option<netcfg::PinRecord>>> = Arc::new(Mutex::new(None));

    // Runs once IPCP completes: configure the interface with the *negotiated*
    // address and MTU, then apply routes/DNS. "Tunnel UP!" (which flips the UI
    // to Connected) is only sent after all of that succeeded.
    let on_network = |ppp_state: &crate::engine::pppstate::PppState| -> Result<(), String> {
        let ip = ppp_state.local_ip;
        if !xml_ip.is_unspecified() && ip != xml_ip {
            let _ = log.send(format!("[engine] Gateway assigned {} via IPCP (config said {}) — using the negotiated address.", ip, xml_ip));
        }
        tun.configure(ip).map_err(|e| format!("failed to set the tunnel IP address: {}", e))?;
        // The MTU must not exceed what the gateway accepts, or large packets
        // are black-holed ("connected but sites don't load"). If setting it
        // fails, continue only when the interface is already within the limit.
        let mtu = ppp_state.tun_mtu();
        if let Err(e) = tun.set_mtu(mtu) {
            match tun.mtu() {
                Some(actual) if actual <= mtu => {
                    let _ = log.send(format!(
                        "[engine] WARNING: could not set MTU {} on {} ({}); current MTU {} is within the gateway's limit — continuing.",
                        mtu, ifname, e, actual));
                }
                actual => return Err(format!(
                    "could not set the tunnel MTU to {} (interface MTU is {}): {}",
                    mtu, actual.map(|a| a.to_string()).unwrap_or_else(|| "unknown".into()), e)),
            }
        }
        let applied_mtu = tun.mtu().map(|m| m.to_string()).unwrap_or_else(|| "?".into());
        let _ = log.send(format!("[engine] TUN {} configured with {} (MTU {})", ifname, ip, applied_mtu));

        // Always carried (even with Set Routes off) so no recorded pin is forgotten.
        let stale_pins: Vec<netcfg::PinRecord> = netcfg::load_pin_state().into_iter().filter(|p| p.present()).collect();
        let plan = netcfg::plan(
            &netcfg::PlanInput {
                ifname: &ifname,
                gateway: gateway_ip,
                split: &vpn_routes,
                dns: &vpn_dns,
                routing_domains: &vpn_domains,
                search_domains: &vpn_suffixes,
                want_routes,
                want_dns,
                half_internet,
                stale_pins: &stale_pins,
                dns_backend: netcfg::resolved_active(),
            },
            netcfg::route_get,
        )?;

        // Gateway-pin ownership (identity = dest + via + dev). A route matching
        // one of *our* stale records is ours: this plan deletes and re-adds it.
        // Otherwise ownership is tentative — unknown presence counts as ours so
        // a crash mid-setup still leaves the pin tracked — and the kernel's
        // answer to the add decides: EEXIST means the route is the user's.
        let owned_pin = plan.gw_pin.clone().filter(|pin| stale_pins.contains(pin) || pin.presence() != Some(true));
        let attempt_tag = attempt.as_ref().map(|a| a.id().to_string()).unwrap_or_default();
        if let Some(pin) = &owned_pin {
            // The record must be durable *before* the route is installed: an
            // unrecorded pin could never be found and removed later.
            netcfg::record_pin(pin, &attempt_tag).map_err(|e| format!(
                "cannot record ownership of gateway route {} ({}); refusing to install it", pin.dest, e))?;
        }
        if let Some(pin) = &owned_pin {
            if let Ok(mut slot) = gw_pin.lock() {
                *slot = Some(pin.clone());
            }
        }
        for note in &plan.notes {
            let _ = log.send(format!("[engine] {}", note));
        }

        if want_routes && !plan.full_tunnel {
            let table = netcfg::read_route_table();
            for (vpn, local, dev) in netcfg::shadowed_ranges(&vpn_routes, &ifname, &table) {
                let _ = log.send(format!(
                    "[engine] WARNING: VPN range {} is partly shadowed by local route {} on {} — hosts in {} will NOT go through the VPN.", vpn, local, dev, local));
            }
        }
        if plan.cmds.is_empty() {
            let _ = log.send("[engine] Skipping route/DNS setup (disabled in profile).".into());
            let _ = log.send("[engine] Tunnel UP! (native TUN)".into());
            return Ok(());
        }

        let _ = log.send(format!(
            "[engine] Applying {} route(s){}{} — a privilege prompt may appear if no sudoers rule is installed…",
            plan.route_count,
            if plan.full_tunnel { " [full tunnel]" } else { "" },
            if want_dns && !vpn_dns.is_empty() { " + DNS" } else { "" },
        ));

        // Apply off the relay thread: a pkexec prompt can take a while and the
        // relay must keep answering LCP echoes meanwhile. The worker is bound
        // to this session via the stop flag and the interface index.
        let log2 = log.clone();
        let stop2 = stop.clone();
        let ifname2 = ifname.clone();
        let ifindex = tun.ifindex();
        let dns_check = vpn_dns.clone();
        let gw_pin2 = gw_pin.clone();
        let attempt2 = attempt.clone();
        let attempt_tag2 = attempt_tag.clone();
        thread::spawn(move || {
            let result = netcfg::apply(&plan.cmds, &ifname2, ifindex, attempt2.as_ref(), &stop2);
            // Kernel said the pin already existed and it isn't one of ours:
            // it belongs to the user — never track or delete it.
            let preexisting = match &result {
                Ok(applied) => &applied.preexisting,
                Err(err) => &err.preexisting,
            };
            // Record changes are tagged deltas, never snapshots. Retracting our
            // own tentative claim is always allowed (even if superseded);
            // other entries are dropped only when confirmed gone and not
            // owned by the current attempt.
            if let Some(pin) = &owned_pin {
                if preexisting.contains(&pin.dest) && !stale_pins.contains(pin) {
                    if let Ok(mut slot) = gw_pin2.lock() {
                        *slot = None;
                    }
                    let _ = netcfg::forget_own(std::slice::from_ref(pin), &attempt_tag2);
                }
            }
            let _ = netcfg::forget_absent(&stale_pins);
            match result {
                Ok(applied) => {
                    if stop2.load(Ordering::Relaxed) {
                        return;
                    }
                    let _ = log2.send(format!("[engine] Routes + DNS applied via {}.", applied.method));
                    for dns in &dns_check {
                        if let Some((_, dev)) = netcfg::route_get(*dns) {
                            if dev != ifname2 && want_routes {
                                let _ = log2.send(format!(
                                    "[engine] WARNING: VPN DNS server {} is routed via {} instead of {}.", dns, dev, ifname2));
                            }
                        }
                    }
                    let _ = log2.send("[engine] Tunnel UP! (native TUN)".into());
                }
                Err(e) => {
                    if stop2.load(Ordering::Relaxed) && e.msg.starts_with("cancelled") {
                        return;
                    }
                    let _ = log2.send(format!("[engine] ERROR: network setup failed — {}", e));
                    // A tunnel without its routes is not a working connection:
                    // tear it down so the UI shows the error, not "Connected".
                    stop2.store(true, Ordering::Relaxed);
                }
            }
        });
        Ok(())
    };

    let ppp_in = tun.writer();
    let ppp_out = tun.reader();

    // Set TLS non-blocking for polling (preserving the other file flags).
    use std::os::unix::io::AsRawFd;
    let tls_fd = tls_stream.get_ref().as_raw_fd();
    unsafe {
        let flags = libc::fcntl(tls_fd, libc::F_GETFL, 0);
        libc::fcntl(tls_fd, libc::F_SETFL, if flags < 0 { libc::O_NONBLOCK } else { flags | libc::O_NONBLOCK });
    }
    let fds = tunnel::RelayFds { tls: tls_fd, tun: tun.raw_fd() };
    // Bound rustls' unsent-TLS buffer explicitly (this is also its default):
    // together with the relay's own queue it caps outbound backlog, so TUN
    // reads stop under backpressure instead of buffering without limit.
    tls_stream.conn.set_buffer_limit(Some(tunnel::TLS_SEND_BUFFER));

    let _ = log.send("[engine] Entering relay loop…".into());
    let result = tunnel::run_relay(
        tls_stream, ppp_in, ppp_out, Some(fds), xml_ip, Some(log.clone()), stop.clone(), on_network);

    // Clean up the gateway host route (it lives on the physical interface).
    let pin = gw_pin.lock().ok().and_then(|p| p.clone());
    if let Some(pin) = pin {
        match netcfg::remove_gateway_pin(&pin) {
            Ok(()) => {
                if pin.presence() == Some(false) {
                    let tag = attempt.as_ref().map(|a| a.id().to_string()).unwrap_or_default();
                    let _ = netcfg::forget_own(std::slice::from_ref(&pin), &tag);
                }
                let _ = log.send(format!("[engine] Removed gateway host route {}.", pin.dest));
            }
            Err(e) => {
                let _ = log.send(format!("[engine] WARNING: {} — it will be removed on the next connect.", e));
            }
        }
    }
    drop(tun);
    result.map_err(VpnError::Tunnel)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = "<?xml version='1.0' encoding='utf-8'?><sslvpn-tunnel ver='2' dtls='1' patch='1'>\
        <ipv4><dns ip='172.16.5.53' /><dns ip='192.168.200.53' /><dns domain='corp.example' />\
        <split-dns domains='example.com,example.internal' dnsserver1='172.16.5.53' />\
        <assigned-addr ipv4='10.66.1.2' />\
        <split-tunnel-info><addr ip='10.0.0.0' mask='255.0.0.0' /><addr ip='172.16.5.1' mask='255.240.0.0' />\
        <addr ip='bad' mask='255.0.0.0' /><addr ip='10.0.0.0' mask='255.0.0.0' /></split-tunnel-info></ipv4></sslvpn-tunnel>";

    #[test]
    fn parses_gateway_config() {
        assert_eq!(parse_vpn_ip(XML), Ipv4Addr::new(10, 66, 1, 2));
        assert_eq!(parse_vpn_dns(XML), vec![Ipv4Addr::new(172, 16, 5, 53), Ipv4Addr::new(192, 168, 200, 53)]);
        assert_eq!(parse_dns_suffixes(XML), vec!["corp.example".to_string()]);
        assert_eq!(parse_split_dns_domains(XML), vec!["example.com".to_string(), "example.internal".to_string()]);
        let (routes, malformed) = parse_split_routes(XML);
        let routes: Vec<String> = routes.iter().map(|p| p.to_string()).collect();
        assert_eq!(routes, vec!["10.0.0.0/8", "172.16.0.0/12"]);
        assert_eq!(malformed.len(), 1, "the bad entry is reported, not silently dropped");
    }

    #[test]
    fn attribute_names_match_whole_words() {
        assert_eq!(extract_attr("<addr gwip='1.1.1.1' ip='10.0.0.0'", "ip"), Some("10.0.0.0".into()));
        assert_eq!(extract_attr("<dns gwip='1.1.1.1'", "ip"), None);
    }

    #[test]
    fn all_malformed_routes_are_distinguishable_from_none() {
        let (routes, malformed) = parse_split_routes("<split-tunnel-info><addr ip='x' mask='255.0.0.0' /></split-tunnel-info>");
        assert!(routes.is_empty());
        assert_eq!(malformed.len(), 1);
        let (routes, malformed) = parse_split_routes("<ipv4></ipv4>");
        assert!(routes.is_empty() && malformed.is_empty(), "no split-tunnel-info = genuinely no routes");
    }

    #[test]
    fn missing_assigned_addr_is_unspecified() {
        assert_eq!(parse_vpn_ip("<sslvpn-tunnel></sslvpn-tunnel>"), Ipv4Addr::UNSPECIFIED);
    }
}
