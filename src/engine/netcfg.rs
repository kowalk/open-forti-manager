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

use crate::engine::nethelper::{attempt_path, valid_ifname, Op, Request, Response, HELPER_BIN, ROUTE_PROTO};

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

/// One privileged operation for the helper. `argv` is the equivalent command
/// line, kept for logs and tests; `route` is set for route additions.
#[derive(Debug, Clone)]
pub struct NetCmd {
    pub op: Op,
    pub argv: Vec<String>,
    pub route: Option<Prefix>,
    /// Failure is expected/harmless (e.g. deleting a route that may be gone).
    pub best_effort: bool,
}

impl NetCmd {
    /// Route `dest` into the session's TUN device.
    fn tun_route(dest: Prefix, ifname: &str) -> Self {
        let argv = vec![IP_BIN.into(), "route".into(), "add".into(), dest.to_string(), "dev".into(), ifname.into()];
        Self { op: Op::RouteAdd { dest: dest.to_string() }, argv, route: Some(dest), best_effort: false }
    }

    fn pin_add(pin: &PinRecord) -> Self {
        let mut argv = vec![IP_BIN.into(), "route".into(), "add".into(), pin.dest.to_string()];
        if let Some(via) = pin.via {
            argv.push("via".into());
            argv.push(via.to_string());
        }
        argv.push("dev".into());
        argv.push(pin.dev.clone());
        Self { op: pin.op(false), argv, route: Some(pin.dest), best_effort: false }
    }

    fn pin_del(pin: &PinRecord) -> Self {
        Self { op: pin.op(true), argv: pin.del_argv(), route: None, best_effort: true }
    }

    fn dns(ifname: &str, servers: &[Ipv4Addr]) -> Self {
        let mut argv = vec![RESOLVECTL_BIN.into(), "dns".into(), ifname.into()];
        argv.extend(servers.iter().map(|d| d.to_string()));
        let op = Op::Dns { servers: servers.iter().map(|d| d.to_string()).collect() };
        Self { op, argv, route: None, best_effort: false }
    }

    fn domain(ifname: &str, domains: Vec<String>) -> Self {
        let mut argv = vec![RESOLVECTL_BIN.into(), "domain".into(), ifname.into()];
        argv.extend(domains.iter().cloned());
        Self { op: Op::Domain { domains }, argv, route: None, best_effort: false }
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
        parse_pin_entry(line).map(|(p, _)| p)
    }

    /// The helper operation that adds (`del == false`) or deletes this pin.
    fn op(&self, del: bool) -> Op {
        let (dest, via, dev) = (self.dest.to_string(), self.via.map(|v| v.to_string()), self.dev.clone());
        if del { Op::PinDel { dest, via, dev } } else { Op::PinAdd { dest, via, dev } }
    }

    /// Equivalent `ip route del`: constrained to this exact route and to the
    /// app's route marker. An on-link pin (no next hop) is also constrained to
    /// `scope link`, so a gateway route that replaced it is never matched.
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
        argv.extend(["dev".into(), self.dev.clone(), "proto".into(), ROUTE_PROTO.into()]);
        argv
    }

    /// Whether this exact route exists: Some(true/false), or None when the
    /// routing table could not be queried.
    pub fn presence(&self) -> Option<bool> {
        // -N: print the protocol as a number (the marker would otherwise be
        // shown by name if it ever gets one).
        let out = Command::new(IP_BIN)
            .args(["-N", "-4", "route", "show", "exact", &self.dest.to_string()])
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

/// One parsed routing-table entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub dest: Prefix,
    pub via: Option<Ipv4Addr>,
    pub dev: String,
    /// Routing protocol (`proto` field), e.g. `186` for routes this app added.
    pub proto: Option<String>,
}

impl RouteEntry {
    /// Our pin: same identity *and* carrying the app's route marker.
    fn matches(&self, pin: &PinRecord) -> bool {
        self.dest == pin.dest && self.via == pin.via && self.dev == pin.dev
            && self.proto.as_deref() == Some(ROUTE_PROTO)
    }
}

/// Parse `ip -4 route show` output (destination, next hop, device, proto).
pub fn route_entries(text: &str) -> Vec<RouteEntry> {
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let dest = Prefix::parse(tokens.first()?)?;
            let after = |key: &str| tokens.iter().position(|&t| t == key).and_then(|i| tokens.get(i + 1));
            let dev = after("dev")?.to_string();
            let via = after("via").and_then(|v| v.parse().ok());
            let proto = after("proto").map(|p| p.to_string());
            Some(RouteEntry { dest, via, dev, proto })
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
        plan.cmds.push(NetCmd::pin_del(stale));
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
            let pin = PinRecord { dest: Prefix::new(input.gateway, 32), via: via.as_deref().and_then(|v| v.parse().ok()), dev };
            plan.cmds.push(NetCmd::pin_add(&pin));
            plan.gw_pin = Some(pin);
        }

        if plan.full_tunnel {
            for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                let p = Prefix::parse(half).expect("static prefix");
                plan.cmds.push(NetCmd::tun_route(p, ifname));
                plan.route_count += 1;
            }
        }
        // Explicit prefixes are kept even in full-tunnel mode: they can be more
        // specific than a local LAN route that the /1 halves would lose to.
        for p in &split {
            if p.len == 0 || (p.len == 32 && p.net == input.gateway) {
                continue; // covered by the /1 halves / pinned to the physical path
            }
            plan.cmds.push(NetCmd::tun_route(*p, ifname));
            plan.route_count += 1;
        }
        if !plan.full_tunnel {
            // VPN DNS servers must be reachable through the tunnel too — except
            // the gateway itself, which must stay on the physical path.
            if input.want_dns {
                for dns in input.dns {
                    if *dns != input.gateway && !split.iter().any(|p| p.contains(*dns)) {
                        plan.cmds.push(NetCmd::tun_route(Prefix::new(*dns, 32), ifname));
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
        plan.cmds.push(NetCmd::dns(ifname, input.dns));

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
        plan.cmds.push(NetCmd::domain(ifname, domains));
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

/// Whether an identical route (same destination and device) already exists:
/// Some(true/false), or None when the routing table could not be queried.
pub fn route_exists(dest: Prefix, dev: &str) -> Option<bool> {
    let out = Command::new(IP_BIN)
        .args(["-4", "route", "show", "exact", &dest.to_string()])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(parse_route_table(&String::from_utf8_lossy(&out.stdout)).iter().any(|(p, d)| *p == dest && d == dev))
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

/// Parse one state line: `dest via|- dev [attempt]`. The attempt tag records
/// which connection attempt created the entry.
fn parse_pin_entry(line: &str) -> Option<(PinRecord, String)> {
    let mut t = line.split_whitespace();
    let dest = Prefix::parse(t.next()?)?;
    let via = match t.next()? {
        "-" => None,
        v => Some(v.parse().ok()?),
    };
    let dev = t.next()?.to_string();
    let tag = t.next().unwrap_or("").to_string();
    let tag_ok = tag.len() <= 64 && tag.bytes().all(|b| b.is_ascii_digit() || b == b'-');
    if !valid_ifname(&dev) || !tag_ok || t.next().is_some() {
        return None;
    }
    Some((PinRecord { dest, via, dev }, tag))
}

/// Parse the state file: `boot <id>` header, then one entry per line. Entries
/// from another boot, legacy prefix-only lines and malformed lines are dropped.
fn parse_pin_entries(text: &str, current_boot: &str) -> Vec<(PinRecord, String)> {
    let mut lines = text.lines();
    match lines.next().and_then(|l| l.strip_prefix("boot ")) {
        Some(id) if id.trim() == current_boot && !current_boot.is_empty() => {}
        _ => return Vec::new(),
    }
    let mut out: Vec<(PinRecord, String)> = Vec::new();
    for (rec, tag) in lines.filter_map(parse_pin_entry) {
        out.retain(|(r, _)| *r != rec); // a later line for the same pin wins
        out.push((rec, tag));
    }
    out
}

fn parse_pin_state(text: &str, current_boot: &str) -> Vec<PinRecord> {
    parse_pin_entries(text, current_boot).into_iter().map(|(p, _)| p).collect()
}

/// Gateway pins this app installed but has not yet removed.
pub fn load_pin_state() -> Vec<PinRecord> {
    pin_state_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| parse_pin_state(&t, &boot_id()))
        .unwrap_or_default()
}

fn render_pin_entries(entries: &[(PinRecord, String)], boot: &str) -> String {
    let mut text = format!("boot {}\n", boot);
    for (p, tag) in entries {
        text.push_str(&p.to_line());
        if !tag.is_empty() {
            text.push(' ');
            text.push_str(tag);
        }
        text.push('\n');
    }
    text
}

/// Read-modify-write the pin entries at `path` under an exclusive lock, so
/// concurrent sessions apply *changes* instead of overwriting each other's
/// snapshot. The new content goes to a temp file that is renamed into place
/// (atomic). Only a missing file counts as "no entries"; any other read error
/// is returned, so unreadable state is never silently replaced. Errors are
/// returned to the caller: a pin must not be installed without its record.
fn update_pin_state_at(path: &std::path::Path, boot: &str,
                       f: impl FnOnce(&mut Vec<(PinRecord, String)>)) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let dir = path.parent().ok_or("invalid pin state path")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    let lock_path = path.with_extension("lock");
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path)
        .map_err(|e| format!("open {}: {}", lock_path.display(), e))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!("lock {}: {}", lock_path.display(), std::io::Error::last_os_error()));
    }
    // The lock is released when `lock` is dropped at the end of this function.

    let mut entries = match std::fs::read_to_string(path) {
        Ok(t) => parse_pin_entries(&t, boot),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("read {}: {}", path.display(), e)),
    };
    f(&mut entries);

    if entries.is_empty() {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {}", path.display(), e)),
        };
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(render_pin_entries(&entries, boot).as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("write {}: {}", path.display(), e)
    })
}

fn update_pin_state(f: impl FnOnce(&mut Vec<(PinRecord, String)>)) -> Result<(), String> {
    let path = pin_state_path().ok_or("no cache directory (HOME/XDG_CACHE_HOME unset)")?;
    update_pin_state_at(&path, &boot_id(), f)
}

/// Record a pin this attempt is about to install (must succeed before
/// installing it). Re-recording an existing identity re-tags it — unless the
/// entry belongs to the *current* attempt and we are not it: a superseded
/// attempt must never take over a newer attempt's pending record.
pub fn record_pin(pin: &PinRecord, tag: &str) -> Result<(), String> {
    update_pin_state(|v| {
        let current = Attempt::current_id().unwrap_or_default();
        retag(v, pin, tag, &current);
    })
}

fn retag(entries: &mut Vec<(PinRecord, String)>, pin: &PinRecord, tag: &str, current: &str) {
    if let Some((_, t)) = entries.iter().find(|(p, _)| p == pin) {
        if !current.is_empty() && t == current && t != tag {
            return; // owned by the current (newer) attempt
        }
    }
    entries.retain(|(p, _)| p != pin);
    entries.push((pin.clone(), tag.to_string()));
}

/// Forget this attempt's own entries for `pins`. Always allowed, even after
/// the attempt was superseded — e.g. to retract a tentative ownership claim.
pub fn forget_own(pins: &[PinRecord], tag: &str) -> Result<(), String> {
    if pins.is_empty() {
        return Ok(());
    }
    update_pin_state(|v| v.retain(|(p, t)| !(pins.contains(p) && t == tag)))
}

/// Which entries `forget_absent` may drop: listed, confirmed gone, and not
/// tagged with the *current* attempt (whose entries may be recorded ahead of
/// installation — e.g. while its pkexec prompt is open).
fn retain_unless_obsolete(entries: &mut Vec<(PinRecord, String)>, pins: &[PinRecord], current: &str,
                          presence: impl Fn(&PinRecord) -> Option<bool>) {
    entries.retain(|(p, t)| {
        let obsolete = pins.contains(p) && (current.is_empty() || t != current) && presence(p) == Some(false);
        !obsolete
    })
}

/// Forget entries for `pins` whose routes are confirmed gone, except entries
/// of the current attempt (see `retain_unless_obsolete`).
pub fn forget_absent(pins: &[PinRecord]) -> Result<(), String> {
    if pins.is_empty() {
        return Ok(());
    }
    update_pin_state(|v| {
        let current = Attempt::current_id().unwrap_or_default();
        retain_unless_obsolete(v, pins, &current, |p| p.presence());
    })
}

/// A connection attempt's identity, persisted so that privileged operations
/// started by an *older* attempt (e.g. a pkexec prompt approved after the
/// user cancelled and reconnected) can tell it is stale and do nothing.
/// The helper checks it too, from the same uid-derived path.
#[derive(Clone)]
pub struct Attempt {
    id: String,
}

impl Attempt {
    fn path() -> std::path::PathBuf {
        attempt_path(unsafe { libc::getuid() })
    }

    /// Start a new attempt, superseding any earlier one. None when the user's
    /// runtime directory (/run/user/<uid>) is unavailable.
    pub fn begin() -> Option<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let path = Self::path();
        let dir = path.parent()?;
        if !dir.parent()?.is_dir() {
            return None;
        }
        let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let id = format!("{}-{}", std::process::id(), nanos);
        std::fs::write(&path, &id).ok()?;
        Some(Self { id })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// The id of the most recently started attempt, if any.
    pub fn current_id() -> Option<String> {
        std::fs::read_to_string(Self::path()).ok().map(|s| s.trim().to_string())
    }

    /// Whether no newer attempt has started since this one.
    pub fn is_current(&self) -> bool {
        Self::current_id().as_deref() == Some(self.id.as_str())
    }
}

/// Delete the given pins via the helper (each constrained to its exact
/// identity and the app's route marker). Without passwordless privilege it
/// prompts via pkexec only when an `attempt` is given — and the helper then
/// acts only while that attempt is still current. Returns the pins still present.
pub fn remove_pins(pins: &[PinRecord], attempt: Option<&Attempt>) -> Vec<PinRecord> {
    let present: Vec<PinRecord> = pins.iter().filter(|p| p.present()).cloned().collect();
    if present.is_empty() {
        return present;
    }
    let elevation = detect_elevation();
    if elevation == Elevation::Pkexec && attempt.is_none() {
        return present;
    }
    let req = Request {
        ifname: None,
        ifindex: None,
        attempt: attempt.map(|a| a.id().to_string()),
        ops: present.iter().map(|p| p.op(true)).collect(),
    };
    let _ = run_helper(&req, elevation);
    // Keep everything not *confirmed* gone.
    present.into_iter().filter(|p| p.presence() != Some(false)).collect()
}

/// Before connecting: forget pins that are already gone, remove the rest if
/// that needs no prompt, and — without passwordless privilege — prompt up
/// front only for *harmful* pins (next hop no longer a default path), since
/// those could keep the gateway unreachable. Harmless ones stay deferred to
/// the route-setup elevation. Returns (still outstanding, removed count).
pub fn cleanup_stale_pins_before_connect(attempt: Option<&Attempt>) -> (Vec<PinRecord>, usize) {
    let (present, gone): (Vec<PinRecord>, Vec<PinRecord>) =
        load_pin_state().into_iter().partition(|p| p.presence() != Some(false));
    let _ = forget_absent(&gone);
    if present.is_empty() {
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
    let removed: Vec<PinRecord> = present.iter().filter(|p| !remaining.contains(p)).cloned().collect();
    let _ = forget_absent(&removed);
    (remaining, removed.len())
}

/// How the helper is run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Elevation {
    /// Already root — run the helper directly.
    Root,
    /// Packaged sudoers rule — `sudo -n` the helper (no arguments, no prompt).
    Sudo,
    /// No standing privilege — run the helper behind a graphical pkexec prompt.
    Pkexec,
}

impl Elevation {
    fn name(self) -> &'static str {
        match self {
            Elevation::Root => "root",
            Elevation::Sudo => "sudo",
            Elevation::Pkexec => "pkexec",
        }
    }
}

/// Probe whether the helper runs non-interactively via the sudoers rule.
pub fn detect_elevation() -> Elevation {
    if unsafe { libc::geteuid() } == 0 {
        return Elevation::Root;
    }
    if run_helper(&Request::default(), Elevation::Sudo).is_ok() { Elevation::Sudo } else { Elevation::Pkexec }
}

/// Error text returned when the pkexec prompt was dismissed.
const PROMPT_DISMISSED: &str = "the administrator prompt was dismissed or authorization failed";

/// Send one request to the privileged helper and parse its response.
pub fn run_helper(req: &Request, elevation: Elevation) -> Result<Response, String> {
    use std::io::Write;
    if !std::path::Path::new(HELPER_BIN).exists() {
        return Err(format!("network helper {} is not installed", HELPER_BIN));
    }
    let mut cmd = match elevation {
        Elevation::Root => {
            // A GUI started via sudo inherits SUDO_UID; the helper would then
            // act for that user while the TUN is owned by root. Run as root.
            let mut c = Command::new(HELPER_BIN);
            c.env_remove("SUDO_UID").env_remove("PKEXEC_UID");
            c
        }
        Elevation::Sudo => {
            let mut c = Command::new("sudo");
            c.args(["-n", HELPER_BIN]);
            c
        }
        Elevation::Pkexec => {
            let mut c = Command::new("pkexec");
            c.arg(HELPER_BIN);
            c
        }
    };
    let json = serde_json::to_string(req).map_err(|e| e.to_string())?;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {}", elevation.name(), e))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(json.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| format!("{}: {}", elevation.name(), e))?;
    if elevation == Elevation::Pkexec && matches!(out.status.code(), Some(126) | Some(127)) {
        return Err(PROMPT_DISMISSED.into());
    }
    if !out.status.success() {
        return Err(format!("{} helper exited with {}: {}", elevation.name(), out.status,
            String::from_utf8_lossy(&out.stderr).trim()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("invalid helper response: {}", e))
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
    /// EEXIST, but the existing route differs or could not be verified: a
    /// setup failure — and still evidence that the route is not ours.
    PreexistingConflict(Prefix, String),
    Fatal(String),
}

fn classify_failure(cmd: &NetCmd, stderr: &str) -> Failure {
    if cmd.best_effort {
        return Failure::Benign;
    }
    let stderr = stderr.trim();
    if let (Some(dest), Some(dev)) = (cmd.route, cmd.dev()) {
        if stderr.contains("File exists") {
            return match route_exists(dest, dev) {
                Some(true) => Failure::Preexisting(dest),
                Some(false) => Failure::PreexistingConflict(dest,
                    format!("{}: a route to {} already exists via another interface", cmd.display(), dest)),
                None => Failure::PreexistingConflict(dest,
                    format!("{}: a route to {} already exists and could not be verified", cmd.display(), dest)),
            };
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
        Failure::PreexistingConflict(p, msg) => {
            preexisting.push(p);
            failures.push(msg);
        }
        Failure::Fatal(msg) => failures.push(msg),
    }
}

/// Apply the command list through the privileged helper.
///
/// `ifindex` binds the batch to this session's interface: the helper checks
/// it before every interface operation, so nothing lands on a replacement
/// device. With `attempt`, the helper also stops once a newer attempt starts.
pub fn apply(cmds: &[NetCmd], ifname: &str, ifindex: Option<u32>, attempt: Option<&Attempt>,
             stop: &AtomicBool) -> Result<Applied, ApplyError> {
    let ifindex = ifindex.ok_or_else(|| ApplyError::from(format!("cannot read the interface index of {}", ifname)))?;
    if stop.load(Ordering::Relaxed) {
        return Err(ApplyError::from(String::from("cancelled: disconnect requested during network setup")));
    }
    if current_ifindex(ifname) != Some(ifindex) {
        return Err(ApplyError::from(format!("{} was replaced by a newer session; not applying stale config", ifname)));
    }
    let elevation = detect_elevation();
    let req = Request {
        ifname: Some(ifname.to_string()),
        ifindex: Some(ifindex),
        attempt: attempt.map(|a| a.id().to_string()),
        ops: cmds.iter().map(|c| c.op.clone()).collect(),
    };
    let resp = run_helper(&req, elevation).map_err(|e| {
        if e == PROMPT_DISMISSED {
            ApplyError::from(format!("{} — no routes or DNS were applied", PROMPT_DISMISSED))
        } else {
            ApplyError::from(e)
        }
    })?;

    let mut failures = Vec::new();
    let mut preexisting = Vec::new();
    for (cmd, res) in cmds.iter().zip(resp.results.iter()) {
        if !res.ok {
            record_failure(classify_failure(cmd, &res.stderr), &mut failures, &mut preexisting);
        }
    }
    if let Some(reason) = resp.aborted {
        return Err(ApplyError { msg: format!("network setup stopped: {}", reason), preexisting });
    }
    if resp.results.len() < cmds.len() {
        failures.push(format!("helper ran only {} of {} operations", resp.results.len(), cmds.len()));
    }
    if failures.is_empty() {
        Ok(Applied { method: elevation.name(), preexisting })
    } else {
        Err(ApplyError { msg: failures.join("; "), preexisting })
    }
}

/// Run TUN-device operations (address/MTU/up) through the helper without
/// ever prompting — only a fallback for when the in-process ioctl fails.
pub fn tun_ops_noninteractive(ifname: &str, ifindex: Option<u32>, ops: Vec<Op>) -> Result<(), String> {
    let elevation = detect_elevation();
    if elevation == Elevation::Pkexec {
        return Err("no CAP_NET_ADMIN and no passwordless helper access".into());
    }
    let n = ops.len();
    let req = Request { ifname: Some(ifname.to_string()), ifindex, attempt: None, ops };
    let resp = run_helper(&req, elevation)?;
    if let Some(r) = resp.aborted {
        return Err(r);
    }
    match resp.results.iter().find(|r| !r.ok) {
        Some(r) => Err(r.stderr.clone()),
        None if resp.results.len() == n => Ok(()),
        None => Err("helper did not run every operation".into()),
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
        assert_eq!(&plan.cmds[0].argv[1..], &["route", "del", "198.51.100.7/32", "via", "10.9.9.1", "dev", "eth1", "proto", "157"]);
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
        assert_eq!(&onlink.del_argv()[1..], &["route", "del", "1.2.3.4/32", "scope", "link", "dev", "eth0", "proto", "157"]);
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
    fn forget_absent_rules_protect_current_attempt() {
        // Regression (Astra): an older worker's "absent" cleanup erased a newer
        // session's entry recorded ahead of installation.
        let gone = |_: &PinRecord| Some(false);
        let mut v = vec![(pin(1), "old".to_string()), (pin(2), "cur".to_string()), (pin(3), "old".to_string())];
        retain_unless_obsolete(&mut v, &[pin(1), pin(2)], "cur", gone);
        assert_eq!(v, vec![(pin(2), "cur".to_string()), (pin(3), "old".to_string())],
            "absent + not current -> dropped; current attempt's entry kept; unlisted untouched");
        // Presence unknown or still present: kept.
        let mut v = vec![(pin(1), "old".to_string())];
        retain_unless_obsolete(&mut v, &[pin(1)], "cur", |_| None);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn superseded_attempt_cannot_take_over_current_record() {
        // Regression (Astra): an older attempt re-tagged a newer attempt's
        // pending record, then its cleanup removed it.
        let mut v = vec![(pin(1), "200-2".to_string())];
        retag(&mut v, &pin(1), "100-1", "200-2");
        assert_eq!(v, vec![(pin(1), "200-2".to_string())]);
        // The current attempt may take over a stale (older) entry.
        let mut v = vec![(pin(1), "100-1".to_string())];
        retag(&mut v, &pin(1), "200-2", "200-2");
        assert_eq!(v, vec![(pin(1), "200-2".to_string())]);
    }

    #[test]
    fn route_entries_parse_numeric_proto() {
        let e = route_entries("198.51.100.7 via 192.168.10.1 dev wlan0 proto 157 \n");
        let pin = PinRecord { dest: p("198.51.100.7/32"), via: Some(ip("192.168.10.1")), dev: "wlan0".into() };
        assert!(e[0].matches(&pin));
        // Same identity without our marker (e.g. the user's own route) is not ours.
        let e = route_entries("198.51.100.7 via 192.168.10.1 dev wlan0 proto 4 \n");
        assert!(!e[0].matches(&pin));
    }

    #[test]
    fn tagged_entries_roundtrip_and_retag() {
        let text = render_pin_entries(&[(pin(1), "123-456".into()), (pin(2), String::new())], "b1");
        let back = parse_pin_entries(&text, "b1");
        assert_eq!(back, vec![(pin(1), "123-456".into()), (pin(2), String::new())]);
        // A later line for the same identity wins (retagging).
        let text = format!("{}{} 999-1\n", text, pin(1).to_line());
        assert_eq!(parse_pin_entries(&text, "b1").iter().find(|(p, _)| *p == pin(1)).unwrap().1, "999-1");
        assert!(parse_pin_entry("198.51.100.1/32 - eth0 not-a-tag!").is_none());
    }

    #[test]
    fn classify_best_effort_and_fatal() {
        let del = NetCmd::pin_del(&pin(1));
        assert_eq!(classify_failure(&del, "RTNETLINK answers: No such process"), Failure::Benign);
        let add = NetCmd::tun_route(Prefix::parse("203.0.113.9/32").unwrap(), "ofm-test-nodev0");
        assert!(matches!(classify_failure(&add, "Cannot find device"), Failure::Fatal(_)));
        let mut failures = Vec::new();
        let mut pre = Vec::new();
        record_failure(Failure::Preexisting(Prefix::parse("1.2.3.4/32").unwrap()), &mut failures, &mut pre);
        assert!(failures.is_empty());
        assert_eq!(pre, vec![Prefix::parse("1.2.3.4/32").unwrap()]);
    }

    fn pin(n: u8) -> PinRecord {
        PinRecord { dest: p(&format!("198.51.100.{}/32", n)), via: Some(ip("192.168.10.1")), dev: "wlan0".into() }
    }

    #[test]
    fn pin_state_updates_are_deltas_not_snapshots() {
        // Regression: an older session saving its snapshot erased a newer
        // session's record. Deltas from two sessions must both survive.
        let dir = std::env::temp_dir().join(format!("ofm-pinstate-{}", std::process::id()));
        let path = dir.join("gateway-pin");
        let _ = std::fs::remove_dir_all(&dir);
        update_pin_state_at(&path, "b1", |v| v.push((pin(1), "100-1".into()))).unwrap(); // session A
        update_pin_state_at(&path, "b1", |v| v.push((pin(2), "200-2".into()))).unwrap(); // session B
        update_pin_state_at(&path, "b1", |v| v.retain(|(x, _)| *x != pin(1))).unwrap(); // A forgets only its own
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(parse_pin_state(&text, "b1"), vec![pin(2)]);
        // Removing the last record removes the file; no temp file is left behind.
        update_pin_state_at(&path, "b1", |v| v.clear()).unwrap();
        assert!(!path.exists());
        let leftovers = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pin_state_write_failure_is_reported() {
        // A parent that is a *file* cannot be created: this must be an error,
        // so setup refuses to install a pin it could not record.
        let file = std::env::temp_dir().join(format!("ofm-notadir-{}", std::process::id()));
        std::fs::write(&file, "x").unwrap();
        let r = update_pin_state_at(&file.join("gateway-pin"), "b1", |v| v.push((pin(1), String::new())));
        assert!(r.is_err());
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn unreadable_state_is_an_error_not_empty() {
        // Regression (Astra): a read error other than NotFound must not be
        // treated as "no entries" and overwritten.
        let dir = std::env::temp_dir().join(format!("ofm-unreadable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("gateway-pin")).unwrap(); // a directory: read fails with EISDIR
        let r = update_pin_state_at(&dir.join("gateway-pin"), "b1", |v| v.push((pin(1), String::new())));
        assert!(r.unwrap_err().starts_with("read "));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn eexist_conflict_is_fatal_but_still_preexisting() {
        let mut failures = Vec::new();
        let mut pre = Vec::new();
        record_failure(Failure::PreexistingConflict(p("198.51.100.7/32"), "conflict".into()), &mut failures, &mut pre);
        assert_eq!(failures, vec!["conflict".to_string()]);
        assert_eq!(pre, vec![p("198.51.100.7/32")]);
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
