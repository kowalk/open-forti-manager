//! Route + DNS configuration for the tunnel interface.
//!
//! Planning (pure, unit-tested) is separated from applying (privileged
//! `ip`/`resolvectl` commands). Every failure is classified and reported —
//! nothing is silently ignored, so "Connected" only appears when the routes
//! the gateway advertised actually point into the tunnel.

use std::fmt;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

// Absolute paths the app invokes for network config. These must match the
// Cmnd entries in the packaged sudoers drop-in (debian/open-forti-manager.sudoers)
// so that `sudo -n` succeeds non-interactively without granting a root shell.
pub const IP_BIN: &str = "/usr/sbin/ip";
pub const RESOLVECTL_BIN: &str = "/usr/bin/resolvectl";

/// An IPv4 prefix, always normalized to its network address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub net: Ipv4Addr,
    pub len: u8,
}

impl Prefix {
    pub fn new(addr: Ipv4Addr, len: u8) -> Self {
        let len = len.min(32);
        Self { net: Ipv4Addr::from(u32::from(addr) & Self::mask(len)), len }
    }

    fn mask(len: u8) -> u32 {
        if len == 0 { 0 } else { u32::MAX << (32 - len as u32) }
    }

    /// Parse `a.b.c.d/n`, `a.b.c.d` (= /32) or `default` (= /0).
    pub fn parse(s: &str) -> Option<Self> {
        if s == "default" {
            return Some(Self::new(Ipv4Addr::UNSPECIFIED, 0));
        }
        match s.split_once('/') {
            Some((a, l)) => Some(Self::new(a.parse().ok()?, l.parse().ok().filter(|l| *l <= 32)?)),
            None => Some(Self::new(s.parse().ok()?, 32)),
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & Self::mask(self.len) == u32::from(self.net)
    }

    /// True when `other` lies entirely inside `self`.
    pub fn covers(&self, other: &Prefix) -> bool {
        other.len >= self.len && self.contains(other.net)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.len)
    }
}

/// Convert a dotted netmask to a prefix length; None for non-contiguous masks.
pub fn mask_to_len(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let len = m.leading_ones();
    if m.checked_shl(len).unwrap_or(0) == 0 { Some(len as u8) } else { None }
}

/// One privileged command; `route` is set for `ip route add` entries.
#[derive(Debug, Clone)]
pub struct NetCmd {
    pub argv: Vec<String>,
    pub route: Option<Prefix>,
    /// Failure is expected/harmless (e.g. deleting a route that may be gone).
    pub best_effort: bool,
}

impl NetCmd {
    fn route_add(dest: Prefix, via: Option<&str>, dev: &str) -> Self {
        let mut argv = vec![IP_BIN.into(), "route".into(), "add".into(), dest.to_string()];
        if let Some(via) = via {
            argv.push("via".into());
            argv.push(via.into());
        }
        argv.push("dev".into());
        argv.push(dev.into());
        Self { argv, route: Some(dest), best_effort: false }
    }

    fn other(argv: Vec<String>) -> Self {
        Self { argv, route: None, best_effort: false }
    }

    /// Device named after `dev` in the argv (for route commands).
    fn dev(&self) -> Option<&str> {
        self.argv.iter().position(|a| a == "dev").and_then(|i| self.argv.get(i + 1)).map(|s| s.as_str())
    }

    fn display(&self) -> String {
        self.argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" ")
    }
}

/// A gateway host route this app installed, with its full identity so that
/// cleanup deletes exactly that route and never a replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinRecord {
    pub dest: Prefix,
    pub via: Option<Ipv4Addr>,
    pub dev: String,
}

impl PinRecord {
    fn to_line(&self) -> String {
        format!("{} {} {}", self.dest, self.via.map(|v| v.to_string()).unwrap_or_else(|| "-".into()), self.dev)
    }

    /// Parse `dest via|- dev`. Legacy prefix-only lines are rejected (their
    /// identity is unknown, so they must not be deleted blindly).
    fn parse(line: &str) -> Option<Self> {
        let mut t = line.split_whitespace();
        let dest = Prefix::parse(t.next()?)?;
        let via = match t.next()? {
            "-" => None,
            v => Some(v.parse().ok()?),
        };
        let dev = t.next()?.to_string();
        if !valid_ifname(&dev) || t.next().is_some() {
            return None;
        }
        Some(Self { dest, via, dev })
    }

    /// `ip route del` constrained to this exact route. An on-link pin (no
    /// next hop) is also constrained to `scope link`, so a gateway route that
    /// replaced it on the same device (scope global) is never matched.
    fn del_argv(&self) -> Vec<String> {
        let mut argv = vec![IP_BIN.into(), "route".into(), "del".into(), self.dest.to_string()];
        match self.via {
            Some(via) => {
                argv.push("via".into());
                argv.push(via.to_string());
            }
            None => {
                argv.push("scope".into());
                argv.push("link".into());
            }
        }
        argv.push("dev".into());
        argv.push(self.dev.clone());
        argv
    }

    /// Whether this exact route exists: Some(true/false), or None when the
    /// routing table could not be queried.
    pub fn presence(&self) -> Option<bool> {
        let out = Command::new(IP_BIN)
            .args(["-4", "route", "show", "exact", &self.dest.to_string()])
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        Some(route_entries(&String::from_utf8_lossy(&out.stdout)).iter().any(|e| e.matches(self)))
    }

    /// Conservative presence: an unknown answer counts as present, so a
    /// failed query never makes us forget a record or claim a route.
    pub fn present(&self) -> bool {
        self.presence().unwrap_or(true)
    }

    /// A stale pin is harmful when its next hop is not a current default
    /// path (e.g. the router of a network we have since left): it would send
    /// the TLS connection to the gateway nowhere.
    pub fn is_harmful(&self, defaults: &[RouteEntry]) -> bool {
        !defaults.iter().any(|d| d.via == self.via && d.dev == self.dev)
    }
}

/// Linux interface-name rules (net/core/dev.c `dev_valid_name`): 1–15 bytes,
/// not `.`/`..`, no `/`, `:` or whitespace. Names are always shell-quoted.
fn valid_ifname(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name != "." && name != ".."
        && !name.bytes().any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace())
}

/// One parsed routing-table entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub dest: Prefix,
    pub via: Option<Ipv4Addr>,
    pub dev: String,
}

impl RouteEntry {
    fn matches(&self, pin: &PinRecord) -> bool {
        self.dest == pin.dest && self.via == pin.via && self.dev == pin.dev
    }
}

/// Parse `ip -4 route show` output (destination, next hop, device).
pub fn route_entries(text: &str) -> Vec<RouteEntry> {
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let dest = Prefix::parse(tokens.first()?)?;
            let after = |key: &str| tokens.iter().position(|&t| t == key).and_then(|i| tokens.get(i + 1));
            let dev = after("dev")?.to_string();
            let via = after("via").and_then(|v| v.parse().ok());
            Some(RouteEntry { dest, via, dev })
        })
        .collect()
}

/// Current default routes (the physical paths out of this host).
pub fn default_routes() -> Vec<RouteEntry> {
    Command::new(IP_BIN)
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()
        .map(|o| route_entries(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

pub struct PlanInput<'a> {
    pub ifname: &'a str,
    pub gateway: Ipv4Addr,
    pub split: &'a [Prefix],
    pub dns: &'a [Ipv4Addr],
    pub routing_domains: &'a [String],
    pub search_domains: &'a [String],
    pub want_routes: bool,
    pub want_dns: bool,
    pub half_internet: bool,
    /// Gateway pins left behind by earlier sessions that could not remove them.
    pub stale_pins: &'a [PinRecord],
    /// Whether per-link DNS can take effect (systemd-resolved in use).
    pub dns_backend: bool,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub cmds: Vec<NetCmd>,
    /// Host route pinning the gateway to the physical path (removed on disconnect).
    pub gw_pin: Option<PinRecord>,
    pub full_tunnel: bool,
    pub route_count: usize,
    pub notes: Vec<String>,
}

/// Build the command list. `physical_route` resolves the current next hop to
/// an address as `(via, dev)`; it is injected so planning stays testable.
pub fn plan(
    input: &PlanInput<'_>,
    physical_route: impl Fn(Ipv4Addr) -> Option<(Option<String>, String)>,
) -> Result<Plan, String> {
    let mut plan = Plan::default();
    let ifname = input.ifname;

    // Clean up a pin an earlier session had to leave behind (we are elevating
    // now anyway, so this costs no extra prompt). It may already be gone.
    for stale in input.stale_pins {
        plan.cmds.push(NetCmd { argv: stale.del_argv(), route: None, best_effort: true });
        plan.notes.push(format!("Removing stale gateway host route {} from a previous session.", stale.to_line()));
    }

    let mut split: Vec<Prefix> = Vec::new();
    for p in input.split {
        if !split.contains(p) {
            split.push(*p);
        }
    }

    if input.want_routes {
        let advertises_default = split.iter().any(|p| p.len == 0);
        plan.full_tunnel = input.half_internet || split.is_empty() || advertises_default;
        if plan.full_tunnel && !input.half_internet {
            plan.notes.push(if advertises_default {
                "Gateway advertises a default route — sending all traffic through the VPN.".into()
            } else {
                "Gateway advertised no split routes (full-tunnel policy) — sending all traffic through the VPN.".into()
            });
        }

        // The TLS transport must never be routed into its own tunnel.
        let need_pin = plan.full_tunnel || split.iter().any(|p| p.contains(input.gateway));
        if need_pin {
            let (via, dev) = physical_route(input.gateway).ok_or_else(|| format!(
                "cannot determine the physical route to gateway {}; refusing to install \
                 routes that would capture the VPN connection itself", input.gateway))?;
            if dev == ifname {
                return Err(format!("gateway {} is already routed into {}", input.gateway, ifname));
            }
            let pin = Prefix::new(input.gateway, 32);
            plan.cmds.push(NetCmd::route_add(pin, via.as_deref(), &dev));
            plan.gw_pin = Some(PinRecord { dest: pin, via: via.as_deref().and_then(|v| v.parse().ok()), dev });
        }

        if plan.full_tunnel {
            for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                let p = Prefix::parse(half).expect("static prefix");
                plan.cmds.push(NetCmd::route_add(p, None, ifname));
                plan.route_count += 1;
            }
        }
        // Explicit prefixes are kept even in full-tunnel mode: they can be more
        // specific than a local LAN route that the /1 halves would lose to.
        for p in &split {
            if p.len == 0 || (p.len == 32 && p.net == input.gateway) {
                continue; // covered by the /1 halves / pinned to the physical path
            }
            plan.cmds.push(NetCmd::route_add(*p, None, ifname));
            plan.route_count += 1;
        }
        if !plan.full_tunnel {
            // VPN DNS servers must be reachable through the tunnel too — except
            // the gateway itself, which must stay on the physical path.
            if input.want_dns {
                for dns in input.dns {
                    if *dns != input.gateway && !split.iter().any(|p| p.contains(*dns)) {
                        plan.cmds.push(NetCmd::route_add(Prefix::new(*dns, 32), None, ifname));
                        plan.route_count += 1;
                        plan.notes.push(format!("Added a host route for VPN DNS server {}.", dns));
                    }
                }
            }
        }
    }

    if input.want_dns && !input.dns.is_empty() && !input.dns_backend {
        plan.notes.push("WARNING: systemd-resolved is not the system resolver — skipping VPN DNS \
            setup; internal hostnames may not resolve (IP access still works).".into());
    }
    if input.want_dns && !input.dns.is_empty() && input.dns_backend {
        let mut dns_cmd = vec![RESOLVECTL_BIN.into(), "dns".into(), ifname.into()];
        dns_cmd.extend(input.dns.iter().map(|d| d.to_string()));
        plan.cmds.push(NetCmd::other(dns_cmd));

        // '~' marks routing-only domains (lookups for *.domain go to the VPN
        // DNS); plain entries are search suffixes. With neither, prefer the VPN
        // DNS for everything.
        let mut domains: Vec<String> = input.routing_domains.iter().map(|d| format!("~{}", d)).collect();
        for d in input.search_domains {
            if !domains.contains(d) {
                domains.push(d.clone());
            }
        }
        if domains.is_empty() || plan.full_tunnel {
            domains.push("~.".into());
        }
        let mut dom_cmd = vec![RESOLVECTL_BIN.into(), "domain".into(), ifname.into()];
        dom_cmd.extend(domains);
        plan.cmds.push(NetCmd::other(dom_cmd));
    }

    Ok(plan)
}

/// Parse `ip -4 route show` output into (destination, device) pairs.
pub fn parse_route_table(text: &str) -> Vec<(Prefix, String)> {
    route_entries(text).into_iter().map(|e| (e.dest, e.dev)).collect()
}

/// Local routes that are more specific than an advertised VPN range and would
/// therefore win over it (e.g. Docker bridges inside 172.16.0.0/12).
pub fn shadowed_ranges(vpn: &[Prefix], ifname: &str, table: &[(Prefix, String)]) -> Vec<(Prefix, Prefix, String)> {
    let mut out = Vec::new();
    for v in vpn {
        for (local, dev) in table {
            if dev != ifname && local.len > v.len && v.covers(local) {
                out.push((*v, *local, dev.clone()));
            }
        }
    }
    out
}

/// Read the main IPv4 routing table (no privileges needed).
pub fn read_route_table() -> Vec<(Prefix, String)> {
    Command::new(IP_BIN)
        .args(["-4", "route", "show", "table", "main"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_route_table(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// Current next hop to `ip` via `ip route get`: `(via, dev)`. Read-only.
pub fn route_get(ip: Ipv4Addr) -> Option<(Option<String>, String)> {
    let out = Command::new(IP_BIN).args(["route", "get", &ip.to_string()]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let via = tokens.iter().position(|&t| t == "via").and_then(|i| tokens.get(i + 1)).map(|s| s.to_string());
    let dev = tokens.iter().position(|&t| t == "dev").and_then(|i| tokens.get(i + 1)).map(|s| s.to_string())?;
    Some((via, dev))
}

/// Whether an identical route (same destination and device) already exists.
pub fn route_exists(dest: Prefix, dev: &str) -> bool {
    Command::new(IP_BIN)
        .args(["-4", "route", "show", "exact", &dest.to_string()])
        .output()
        .ok()
        .map(|o| parse_route_table(&String::from_utf8_lossy(&o.stdout)).iter().any(|(p, d)| *p == dest && d == dev))
        .unwrap_or(false)
}

pub fn current_ifindex(ifname: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", ifname)).ok()?.trim().parse().ok()
}

/// Whether per-link DNS set with `resolvectl` takes effect: resolved must be
/// running (with its CLI installed), and applications must reach it — via a
/// resolv.conf that is resolved's file / points at its stub listener, or via
/// the `resolve` NSS module.
pub fn resolved_active() -> bool {
    let running = std::path::Path::new("/run/systemd/resolve/io.systemd.Resolve").exists()
        && std::path::Path::new(RESOLVECTL_BIN).exists();
    if !running {
        return false;
    }
    let nss = std::fs::read_to_string("/etc/nsswitch.conf")
        .map(|c| c.lines().any(|l| {
            let l = l.trim_start();
            l.starts_with("hosts:") && l.split_whitespace().any(|t| t == "resolve")
        }))
        .unwrap_or(false);
    let linked = std::fs::read_link("/etc/resolv.conf")
        .map(|t| t.to_string_lossy().contains("systemd/resolve"))
        .unwrap_or(false);
    let stub = std::fs::read_to_string("/etc/resolv.conf")
        .map(|c| c.lines().any(|l| {
            let mut t = l.split_whitespace();
            t.next() == Some("nameserver") && t.next() == Some("127.0.0.53")
        }))
        .unwrap_or(false);
    linked || stub || nss
}

/// Where gateway pins that could not be removed yet are remembered.
fn pin_state_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))?;
    Some(base.join("open-forti-manager").join("gateway-pin"))
}

/// Routes don't survive a reboot, so records are scoped to the current boot.
fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Parse the state file: `boot <id>` header, then one pin per line. Records
/// from another boot, legacy prefix-only lines and malformed lines are dropped.
fn parse_pin_state(text: &str, current_boot: &str) -> Vec<PinRecord> {
    let mut lines = text.lines();
    match lines.next().and_then(|l| l.strip_prefix("boot ")) {
        Some(id) if id.trim() == current_boot && !current_boot.is_empty() => {}
        _ => return Vec::new(),
    }
    let mut out: Vec<PinRecord> = Vec::new();
    for rec in lines.filter_map(PinRecord::parse) {
        if !out.contains(&rec) {
            out.push(rec);
        }
    }
    out
}

/// Gateway pins this app installed but has not yet removed.
pub fn load_pin_state() -> Vec<PinRecord> {
    pin_state_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| parse_pin_state(&t, &boot_id()))
        .unwrap_or_default()
}

/// Replace the recorded set of pins (empty = remove the state file).
pub fn save_pin_state(pins: &[PinRecord]) {
    let Some(path) = pin_state_path() else { return };
    if pins.is_empty() {
        let _ = std::fs::remove_file(path);
        return;
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut text = format!("boot {}\n", boot_id());
    let mut seen: Vec<&PinRecord> = Vec::new();
    for p in pins {
        if !seen.contains(&p) {
            seen.push(p);
            text.push_str(&p.to_line());
            text.push('\n');
        }
    }
    let _ = std::fs::write(path, text);
}

/// A connection attempt's identity, persisted so that privileged cleanup
/// started by an *older* attempt (e.g. a pkexec prompt approved after the
/// user cancelled and reconnected) can tell it is stale and do nothing —
/// the newer session may own an identical route by then.
pub struct Attempt {
    id: String,
    path: std::path::PathBuf,
}

impl Attempt {
    /// Start a new attempt, superseding any earlier one.
    pub fn begin() -> Option<Self> {
        let path = pin_state_path()?.with_file_name("attempt");
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let id = format!("{}-{}", std::process::id(), nanos);
        std::fs::write(&path, &id).ok()?;
        Some(Self { id, path })
    }

    /// Whether no newer attempt has started since this one.
    pub fn is_current(&self) -> bool {
        std::fs::read_to_string(&self.path).map(|s| s.trim() == self.id).unwrap_or(false)
    }

    /// Shell test that is true only while this attempt is current (checked
    /// inside the privileged script, i.e. *after* the prompt was approved).
    fn shell_guard(&self) -> String {
        format!("[ \"$(cat {} 2>/dev/null)\" = {} ] || exit 4",
            shell_quote(&self.path.to_string_lossy()), shell_quote(&self.id))
    }
}

/// Delete the given pins (each constrained to its exact identity). Uses
/// passwordless privilege when available; otherwise prompts via pkexec only
/// when an `attempt` is given (and only acts if that attempt is still the
/// current one once the prompt is approved). Returns the pins still present.
pub fn remove_pins(pins: &[PinRecord], attempt: Option<&Attempt>) -> Vec<PinRecord> {
    let present: Vec<PinRecord> = pins.iter().filter(|p| p.present()).cloned().collect();
    if present.is_empty() {
        return present;
    }
    let current = || attempt.map(|a| a.is_current()).unwrap_or(true);
    match detect_elevation() {
        Elevation::Root => {
            for p in present.iter().take_while(|_| current()) {
                let argv = p.del_argv();
                let _ = Command::new(&argv[0]).args(&argv[1..]).status();
            }
        }
        Elevation::SudoPerCmd => {
            for p in present.iter().take_while(|_| current()) {
                let _ = Command::new("sudo").arg("-n").args(p.del_argv()).stdin(Stdio::null()).status();
            }
        }
        Elevation::Pkexec => {
            let Some(attempt) = attempt else { return present };
            let guard = attempt.shell_guard();
            let script = present.iter()
                .map(|p| format!("{}\n{} 2>/dev/null", guard,
                    p.del_argv().iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")))
                .collect::<Vec<_>>()
                .join("\n");
            let _ = Command::new("pkexec").args(["sh", "-c", &script]).status();
        }
    }
    // Keep everything not *confirmed* gone.
    present.into_iter().filter(|p| p.presence() != Some(false)).collect()
}

/// Before connecting: forget pins that are already gone, remove the rest if
/// that needs no prompt, and — without passwordless privilege — prompt up
/// front only for *harmful* pins (next hop no longer a default path), since
/// those could keep the gateway unreachable. Harmless ones stay deferred to
/// the route-setup elevation. Returns (still outstanding, removed count).
pub fn cleanup_stale_pins_before_connect(attempt: Option<&Attempt>) -> (Vec<PinRecord>, usize) {
    let present: Vec<PinRecord> = load_pin_state().into_iter().filter(|p| p.present()).collect();
    if present.is_empty() {
        save_pin_state(&[]);
        return (Vec::new(), 0);
    }
    let remaining = if detect_elevation() == Elevation::Pkexec {
        let defaults = default_routes();
        let (harmful, harmless): (Vec<_>, Vec<_>) = present.iter().cloned().partition(|p| p.is_harmful(&defaults));
        let mut left = remove_pins(&harmful, attempt);
        left.extend(harmless);
        left
    } else {
        remove_pins(&present, attempt)
    };
    let removed = present.len() - remaining.len();
    save_pin_state(&remaining);
    (remaining, removed)
}

/// How network configuration commands should be elevated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// Already root — run directly.
    Root,
    /// Narrow passwordless sudo (packaged sudoers rule) — run each command via `sudo -n`.
    SudoPerCmd,
    /// No standing privilege — run the batch once behind a graphical pkexec prompt.
    Pkexec,
}

/// Probe whether our exact `ip route` command runs non-interactively.
pub fn detect_elevation() -> Elevation {
    if unsafe { libc::geteuid() } == 0 {
        return Elevation::Root;
    }
    let can_sudo = Command::new("sudo")
        .args(["-n", IP_BIN, "route", "show"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if can_sudo { Elevation::SudoPerCmd } else { Elevation::Pkexec }
}

/// Single-quote an argument for safe inclusion in an `sh -c` batch.
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Decide whether a failed command is benign; returns the error text if not.
/// How a failed command should be treated.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// Expected/harmless (best-effort command).
    Benign,
    /// `ip route add` hit an identical, already-present route: fine, but that
    /// route is not ours — the kernel's EEXIST is the authoritative signal.
    Preexisting(Prefix),
    Fatal(String),
}

fn classify_failure(cmd: &NetCmd, stderr: &str) -> Failure {
    if cmd.best_effort {
        return Failure::Benign;
    }
    let stderr = stderr.trim();
    if let (Some(dest), Some(dev)) = (cmd.route, cmd.dev()) {
        if stderr.contains("File exists") {
            if route_exists(dest, dev) {
                return Failure::Preexisting(dest);
            }
            return Failure::Fatal(format!("{}: a route to {} already exists via another interface", cmd.display(), dest));
        }
    }
    Failure::Fatal(format!("{}: {}", cmd.display(), if stderr.is_empty() { "failed" } else { stderr }))
}

/// Result of a successful `apply`.
#[derive(Debug)]
pub struct Applied {
    pub method: &'static str,
    /// Route destinations whose add found an identical route already present.
    pub preexisting: Vec<Prefix>,
}

/// Failed `apply`. Still reports pre-existing routes seen before the failure,
/// so ownership is decided correctly even when setup fails half-way.
#[derive(Debug)]
pub struct ApplyError {
    pub msg: String,
    pub preexisting: Vec<Prefix>,
}

impl From<String> for ApplyError {
    fn from(msg: String) -> Self {
        Self { msg, preexisting: Vec::new() }
    }
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

/// Fold one command's failure into the running lists.
fn record_failure(f: Failure, failures: &mut Vec<String>, preexisting: &mut Vec<Prefix>) {
    match f {
        Failure::Benign => {}
        Failure::Preexisting(p) => preexisting.push(p),
        Failure::Fatal(msg) => failures.push(msg),
    }
}

/// Apply the command list with the least privilege available.
///
/// `ifindex` binds the batch to this session's interface: if the device was
/// replaced (disconnect + reconnect reused the name) nothing is applied.
pub fn apply(cmds: &[NetCmd], ifname: &str, ifindex: Option<u32>, stop: &AtomicBool) -> Result<Applied, ApplyError> {
    let ifindex = ifindex.ok_or_else(|| ApplyError::from(format!("cannot read the interface index of {}", ifname)))?;
    let elevation = detect_elevation();
    let still_ours = || current_ifindex(ifname) == Some(ifindex);

    match elevation {
        Elevation::SudoPerCmd => {
            let mut failures = Vec::new();
            let mut preexisting = Vec::new();
            for cmd in cmds {
                if stop.load(Ordering::Relaxed) {
                    return Err(ApplyError::from(String::from("cancelled: disconnect requested during network setup")));
                }
                if !still_ours() {
                    return Err(ApplyError::from(format!("{} was replaced by a newer session; not applying stale config", ifname)));
                }
                match Command::new("sudo").arg("-n").args(&cmd.argv).stdin(Stdio::null()).output() {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => record_failure(classify_failure(cmd, &String::from_utf8_lossy(&o.stderr)), &mut failures, &mut preexisting),
                    Err(e) => failures.push(format!("{}: {}", cmd.display(), e)),
                }
            }
            if failures.is_empty() { Ok(Applied { method: "sudo", preexisting }) } else { Err(ApplyError { msg: failures.join("; "), preexisting }) }
        }
        Elevation::Root | Elevation::Pkexec => {
            if stop.load(Ordering::Relaxed) {
                return Err(ApplyError::from(String::from("cancelled: disconnect requested during network setup")));
            }
            // Re-check ownership before *every* command: a stalled command must
            // not let later ones land on a replacement interface.
            let guard = format!(
                "[ \"$(cat {} 2>/dev/null)\" = \"{}\" ] || {{ echo OFM_ABORT >&2; exit 3; }}\n",
                shell_quote(&format!("/sys/class/net/{}/ifindex", ifname)), ifindex);
            let mut script = String::from("set -u\n");
            for (i, cmd) in cmds.iter().enumerate() {
                let line = cmd.argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ");
                script.push_str(&guard);
                script.push_str(&format!(
                    "if ! out=$({} 2>&1); then printf 'OFM_FAIL %d ' {} >&2; printf '%s' \"$out\" | tr '\\n' ' ' >&2; echo >&2; fi\n",
                    line, i));
            }
            let (method, out) = match elevation {
                Elevation::Root => ("root", Command::new("sh").args(["-c", &script]).output()),
                _ => ("pkexec", Command::new("pkexec").args(["sh", "-c", &script]).output()),
            };
            let out = out.map_err(|e| ApplyError::from(format!("{}: {}", method, e)))?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("OFM_ABORT") {
                return Err(ApplyError::from(format!("{} was replaced by a newer session; not applying stale config", ifname)));
            }
            if method == "pkexec" && matches!(out.status.code(), Some(126) | Some(127)) {
                return Err(ApplyError::from(String::from("the administrator prompt was dismissed or authorization failed — no routes or DNS were applied")));
            }
            let mut failures = Vec::new();
            let mut preexisting = Vec::new();
            for line in stderr.lines() {
                if let Some(rest) = line.strip_prefix("OFM_FAIL ") {
                    let (idx, msg) = rest.split_once(' ').unwrap_or((rest, ""));
                    if let Some(cmd) = idx.parse::<usize>().ok().and_then(|i| cmds.get(i)) {
                        record_failure(classify_failure(cmd, msg), &mut failures, &mut preexisting);
                    }
                }
            }
            if !out.status.success() && failures.is_empty() {
                failures.push(format!("{} exited with {}: {}", method, out.status, stderr.trim()));
            }
            if failures.is_empty() { Ok(Applied { method, preexisting }) } else { Err(ApplyError { msg: failures.join("; "), preexisting }) }
        }
    }
}

/// Remove this session's gateway pin on disconnect (it lives on the physical
/// interface, so deleting the TUN device does not clean it up). Only without
/// prompting; otherwise it is left recorded for the next connect.
pub fn remove_gateway_pin(pin: &PinRecord) -> Result<(), String> {
    if detect_elevation() == Elevation::Pkexec {
        return Err(format!("no passwordless privilege; host route {} left in place", pin.dest));
    }
    if remove_pins(std::slice::from_ref(pin), None).is_empty() {
        Ok(())
    } else {
        Err(format!("could not remove host route {}", pin.to_line()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix { Prefix::parse(s).unwrap() }
    fn ip(s: &str) -> Ipv4Addr { s.parse().unwrap() }

    fn input<'a>(split: &'a [Prefix], dns: &'a [Ipv4Addr]) -> PlanInput<'a> {
        PlanInput {
            ifname: "vpn0",
            gateway: ip("198.51.100.7"),
            split,
            dns,
            routing_domains: &[],
            search_domains: &[],
            want_routes: true,
            want_dns: true,
            half_internet: false,
            stale_pins: &[],
            dns_backend: true,
        }
    }

    fn phys(_: Ipv4Addr) -> Option<(Option<String>, String)> {
        Some((Some("192.168.10.1".into()), "wlan0".into()))
    }

    fn dests(plan: &Plan) -> Vec<String> {
        plan.cmds.iter().filter_map(|c| c.route.map(|r| r.to_string())).collect()
    }

    #[test]
    fn prefix_normalizes_host_bits() {
        // `ip route add 10.1.2.3/8` fails with "Invalid prefix"; we normalize.
        assert_eq!(p("10.1.2.3/8").to_string(), "10.0.0.0/8");
        assert_eq!(p("default").len, 0);
        assert!(p("172.16.0.0/12").covers(&p("172.18.0.0/16")));
        assert!(!p("172.16.0.0/12").covers(&p("172.32.0.0/16")));
    }

    #[test]
    fn mask_conversion() {
        assert_eq!(mask_to_len(ip("255.240.0.0")), Some(12));
        assert_eq!(mask_to_len(ip("255.255.255.255")), Some(32));
        assert_eq!(mask_to_len(ip("0.0.0.0")), Some(0));
        assert_eq!(mask_to_len(ip("255.0.255.0")), None);
    }

    #[test]
    fn split_routes_plus_dns_host_route() {
        let split = [p("10.0.0.0/8"), p("172.16.0.0/12"), p("10.0.0.0/8")];
        let dns = [ip("172.16.5.53"), ip("192.168.200.53")];
        let plan = plan(&input(&split, &dns), phys).unwrap();
        assert!(!plan.full_tunnel);
        assert_eq!(dests(&plan), vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.200.53/32"]);
        assert!(plan.gw_pin.is_none());
    }

    #[test]
    fn empty_split_means_full_tunnel_with_gateway_pin() {
        let plan = plan(&input(&[], &[]), phys).unwrap();
        assert!(plan.full_tunnel);
        assert_eq!(dests(&plan), vec!["198.51.100.7/32", "0.0.0.0/1", "128.0.0.0/1"]);
        assert_eq!(plan.cmds[0].dev(), Some("wlan0"));
    }

    #[test]
    fn advertised_default_route_means_full_tunnel_but_keeps_specifics() {
        let plan = plan(&input(&[p("0.0.0.0/0"), p("192.168.10.50/32")], &[]), phys).unwrap();
        assert!(plan.full_tunnel);
        assert_eq!(dests(&plan), vec!["198.51.100.7/32", "0.0.0.0/1", "128.0.0.0/1", "192.168.10.50/32"]);
    }

    #[test]
    fn dns_equal_to_gateway_is_not_routed_into_tunnel() {
        let dns = [ip("198.51.100.7")];
        let plan = plan(&input(&[p("10.0.0.0/8")], &dns), phys).unwrap();
        assert_eq!(dests(&plan), vec!["10.0.0.0/8"]);
    }

    #[test]
    fn stale_pin_is_removed_first() {
        let split = [p("10.0.0.0/8")];
        let stale = [PinRecord { dest: p("198.51.100.7/32"), via: Some(ip("10.9.9.1")), dev: "eth1".into() }];
        let mut i = input(&split, &[]);
        i.stale_pins = &stale;
        let plan = plan(&i, phys).unwrap();
        // Deletion is constrained to the recorded identity, never the bare prefix.
        assert_eq!(&plan.cmds[0].argv[1..], &["route", "del", "198.51.100.7/32", "via", "10.9.9.1", "dev", "eth1"]);
        assert!(plan.cmds[0].best_effort);
    }

    #[test]
    fn plan_records_pin_identity() {
        let plan = plan(&input(&[], &[]), phys).unwrap();
        assert_eq!(plan.gw_pin, Some(PinRecord {
            dest: p("198.51.100.7/32"), via: Some(ip("192.168.10.1")), dev: "wlan0".into() }));
    }

    #[test]
    fn pin_record_roundtrip_and_validation() {
        let r = PinRecord { dest: p("198.51.100.7/32"), via: Some(ip("192.168.10.1")), dev: "wlan0".into() };
        assert_eq!(PinRecord::parse(&r.to_line()), Some(r.clone()));
        let onlink = PinRecord { dest: p("1.2.3.4/32"), via: None, dev: "eth0".into() };
        assert_eq!(PinRecord::parse(&onlink.to_line()), Some(onlink.clone()));
        assert_eq!(&onlink.del_argv()[1..], &["route", "del", "1.2.3.4/32", "scope", "link", "dev", "eth0"]);
        // Legacy prefix-only lines and unsafe device names are rejected.
        assert_eq!(PinRecord::parse("198.51.100.7/32"), None);
        assert_eq!(PinRecord::parse("1.2.3.4/32 - eth0 extra"), None);
        assert_eq!(PinRecord::parse("1.2.3.4/32 - eth:0"), None);
        assert_eq!(PinRecord::parse("1.2.3.4/32 - averyveryverylongname"), None);
        // Valid Linux names beyond [A-Za-z0-9-_] round-trip.
        let plus = PinRecord { dest: p("1.2.3.4/32"), via: None, dev: "wan+0".into() };
        assert_eq!(PinRecord::parse(&plus.to_line()), Some(plus));
        assert_eq!(PinRecord::parse("1.2.3.4/32 notanip eth0"), None);
    }

    #[test]
    fn pin_state_is_scoped_to_boot() {
        let text = "boot abc\n198.51.100.7/32 192.168.10.1 wlan0\n198.51.100.7/32\ngarbage\n";
        assert_eq!(parse_pin_state(text, "abc").len(), 1, "legacy/garbage lines dropped");
        assert!(parse_pin_state(text, "other-boot").is_empty(), "records from another boot ignored");
        assert!(parse_pin_state("198.51.100.7/32\n", "abc").is_empty(), "legacy file without header ignored");
    }

    #[test]
    fn attempt_guard_detects_newer_attempt() {
        let dir = std::env::temp_dir().join(format!("ofm-attempt-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("attempt");
        std::fs::write(&path, "old").unwrap();
        let old = Attempt { id: "old".into(), path: path.clone() };
        assert!(old.is_current());
        std::fs::write(&path, "new").unwrap(); // a newer attempt began
        assert!(!old.is_current());
        // The same check runs inside the privileged script.
        let ok = |a: &Attempt| Command::new("sh").args(["-c", &format!("{}; exit 0", a.shell_guard())])
            .status().unwrap().success();
        assert!(!ok(&old));
        assert!(ok(&Attempt { id: "new".into(), path: path.clone() }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn classify_best_effort_and_fatal() {
        let del = NetCmd { argv: vec![IP_BIN.into(), "route".into(), "del".into(), "1.2.3.4/32".into()], route: None, best_effort: true };
        assert_eq!(classify_failure(&del, "RTNETLINK answers: No such process"), Failure::Benign);
        let add = NetCmd::route_add(Prefix::parse("203.0.113.9/32").unwrap(), None, "ofm-test-nodev0");
        assert!(matches!(classify_failure(&add, "Cannot find device"), Failure::Fatal(_)));
        let mut failures = Vec::new();
        let mut pre = Vec::new();
        record_failure(Failure::Preexisting(Prefix::parse("1.2.3.4/32").unwrap()), &mut failures, &mut pre);
        assert!(failures.is_empty());
        assert_eq!(pre, vec![Prefix::parse("1.2.3.4/32").unwrap()]);
    }

    #[test]
    fn harmful_pin_detection() {
        let defaults = route_entries("default via 192.168.10.1 dev wlan0 proto dhcp metric 600\n");
        let current = PinRecord { dest: p("198.51.100.7/32"), via: Some(ip("192.168.10.1")), dev: "wlan0".into() };
        let old_network = PinRecord { dest: p("198.51.100.7/32"), via: Some(ip("10.0.0.1")), dev: "wlan0".into() };
        assert!(!current.is_harmful(&defaults));
        assert!(old_network.is_harmful(&defaults));
        assert!(current.is_harmful(&[]), "no default route at all: pin can't be right");
    }

    #[test]
    fn split_covering_gateway_pins_it() {
        let plan = plan(&input(&[p("198.51.0.0/16")], &[]), phys).unwrap();
        assert_eq!(dests(&plan), vec!["198.51.100.7/32", "198.51.0.0/16"]);
    }

    #[test]
    fn full_tunnel_without_physical_route_is_refused() {
        assert!(plan(&input(&[], &[]), |_| None).is_err());
    }

    #[test]
    fn dns_domains() {
        let rd = ["example.com".to_string()];
        let sd = ["corp.local".to_string()];
        let dns = [ip("172.16.5.53")];
        let split = [p("172.16.0.0/12")];
        let mut i = input(&split, &dns);
        i.routing_domains = &rd;
        i.search_domains = &sd;
        let plan = plan(&i, phys).unwrap();
        let dom = plan.cmds.last().unwrap();
        assert_eq!(&dom.argv[3..], &["~example.com", "corp.local"]);
    }

    #[test]
    fn dns_skipped_without_resolved() {
        let dns = [ip("172.16.5.53")];
        let split = [p("172.16.0.0/12")];
        let mut i = input(&split, &dns);
        i.dns_backend = false;
        let plan = plan(&i, phys).unwrap();
        assert!(plan.cmds.iter().all(|c| c.argv[0] != RESOLVECTL_BIN));
        assert!(plan.notes.iter().any(|n| n.contains("systemd-resolved")));
    }

    #[test]
    fn routes_disabled_only_dns() {
        let dns = [ip("172.16.5.53")];
        let split = [p("172.16.0.0/12")];
        let mut i = input(&split, &dns);
        i.want_routes = false;
        let plan = plan(&i, phys).unwrap();
        assert!(dests(&plan).is_empty());
        assert_eq!(plan.cmds.len(), 2);
    }

    #[test]
    fn detects_docker_shadowing() {
        let table = parse_route_table(
            "default via 192.168.10.1 dev wlan0 proto dhcp metric 600\n\
             172.18.0.0/16 dev br-79188871ee2d proto kernel scope link src 172.18.0.1\n\
             172.16.0.0/12 dev vpn0 scope link\n\
             10.200.0.0/24 dev docker0 proto kernel scope link src 10.200.0.1 linkdown\n");
        let shadowed = shadowed_ranges(&[p("172.16.0.0/12"), p("10.0.0.0/8")], "vpn0", &table);
        let pairs: Vec<(String, String)> = shadowed.iter().map(|(v, l, _)| (v.to_string(), l.to_string())).collect();
        assert_eq!(pairs, vec![
            ("172.16.0.0/12".into(), "172.18.0.0/16".into()),
            ("10.0.0.0/8".into(), "10.200.0.0/24".into()),
        ]);
    }
}
