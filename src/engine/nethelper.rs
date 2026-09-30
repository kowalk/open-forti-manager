//! Privileged network helper: protocol, validation and execution.
//!
//! The GUI never runs `ip`/`resolvectl` as root itself. It sends one typed
//! JSON [`Request`] on stdin to `/usr/libexec/open-forti-manager-net`, which
//! runs as root (via `sudo -n` with no arguments, or `pkexec`) and executes
//! only operations it can validate:
//!
//! - VPN-interface operations must target a TUN device named `vpn*`, owned
//!   by the calling user (the app sets TUNSETOWNER) and still carrying the
//!   interface index given in the request.
//! - Gateway pins may only be added during the caller's live session (valid
//!   TUN as above), must be a /32 on a physical interface, and must replicate
//!   the destination's current path, so they cannot redirect traffic.
//! - A pin can only be deleted if the helper itself installed it *for the same
//!   caller*: it keeps a root-owned registry (`/var/lib/open-forti-manager`).
//!   Routes also carry the private [`ROUTE_PROTO`] marker, as defence in depth.
//! - After each command on the session TUN, ownership and interface index are
//!   verified again; if the device changed underneath, execution stops.
//! - With an attempt id, each operation first checks that the attempt is
//!   still current (a pkexec prompt approved late must not act for a
//!   superseded connection attempt).
//!
//! Validation is pure over a [`SysView`] so it is unit-tested without root.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::engine::netcfg::Prefix;

/// Installed path of the helper (see debian/ and the sudoers rule).
pub const HELPER_BIN: &str = "/usr/libexec/open-forti-manager-net";
/// Route protocol number marking routes installed by this app. Unassigned in
/// the kernel's RTPROT_* list and iproute2's rt_protos (186 would be BGP).
/// Only a marker: authorization for deletion comes from the pin registry.
pub const ROUTE_PROTO: &str = "157";

const IP_BIN: &str = "/usr/sbin/ip";
const RESOLVECTL_BIN: &str = "/usr/bin/resolvectl";
const MAX_OPS: usize = 512;

/// One privileged operation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Route `dest` into the session's TUN device.
    RouteAdd { dest: String },
    /// Pin a gateway /32 to its current physical path.
    PinAdd { dest: String, via: Option<String>, dev: String },
    /// Delete a gateway pin this app installed (exact identity + marker).
    PinDel { dest: String, via: Option<String>, dev: String },
    /// Per-link DNS servers on the session's TUN device.
    Dns { servers: Vec<String> },
    /// Per-link DNS domains (`~` = routing-only) on the session's TUN device.
    Domain { domains: Vec<String> },
    /// Replace the TUN device's address with `ip`/32.
    Addr { ip: String },
    /// Set the TUN device's MTU.
    Mtu { mtu: u16 },
    /// Bring the TUN device up.
    LinkUp,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Request {
    /// Session TUN device (required for VPN-interface operations).
    pub ifname: Option<String>,
    /// Its interface index when the session started.
    pub ifindex: Option<u32>,
    /// Connection-attempt id; operations are skipped once it is superseded.
    pub attempt: Option<String>,
    pub ops: Vec<Op>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpResult {
    pub ok: bool,
    pub stderr: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Response {
    /// One result per executed operation, in order.
    pub results: Vec<OpResult>,
    /// Set when execution stopped early (remaining operations not run).
    pub aborted: Option<String>,
}

/// What the helper needs to know about the system (injected for tests).
pub trait SysView {
    /// `None` if `ifname` is not a TUN device; `Some(owner)` otherwise,
    /// where `owner` is `None` when no owner is set.
    fn tun_owner(&self, ifname: &str) -> Option<Option<u32>>;
    fn ifindex(&self, ifname: &str) -> Option<u32>;
    fn iface_exists(&self, ifname: &str) -> bool;
    /// Current path to `ip`: (next hop, device).
    fn route_get(&self, ip: Ipv4Addr) -> Option<(Option<Ipv4Addr>, String)>;
    /// Whether attempt `id` is still the caller's current attempt.
    fn attempt_current(&self, id: &str) -> bool;
    /// Whether the helper installed pin `key` for `uid`.
    fn pin_registered(&self, uid: u32, key: &str) -> bool;
    fn register_pin(&self, uid: u32, key: &str) -> Result<(), String>;
    fn unregister_pin(&self, uid: u32, key: &str);
}

/// Registry key of a pin: `dest via|- dev`.
fn pin_key(dest: Prefix, via: Option<Ipv4Addr>, dev: &str) -> String {
    format!("{} {} {}", dest, via.map(|v| v.to_string()).unwrap_or_else(|| "-".into()), dev)
}

/// Linux interface-name rules (`dev_valid_name`): 1–15 bytes, not `.`/`..`,
/// no `/`, `:` or whitespace.
pub fn valid_ifname(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name != "." && name != ".."
        && !name.bytes().any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace())
}

/// A DNS domain for resolvectl: optional `~` prefix, then `.` or LDH labels.
fn valid_domain(d: &str) -> bool {
    let body = d.strip_prefix('~').unwrap_or(d);
    if body == "." {
        return d.starts_with('~');
    }
    let body = body.strip_suffix('.').unwrap_or(body);
    !body.is_empty() && body.len() <= 253
        && body.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn parse_v4(s: &str, what: &str) -> Result<Ipv4Addr, String> {
    s.parse().map_err(|_| format!("invalid {} {:?}", what, s))
}

/// Resolve and validate the session TUN device for a VPN-interface operation.
fn session_tun<'a>(req: &'a Request, caller: u32, sys: &impl SysView) -> Result<(&'a str, u32), String> {
    let name = req.ifname.as_deref().ok_or("no session interface given")?;
    if !valid_ifname(name) || !name.starts_with("vpn") {
        return Err(format!("{:?} is not a VPN interface name", name));
    }
    match sys.tun_owner(name) {
        None => return Err(format!("{} is not a TUN device", name)),
        Some(owner) if owner != Some(caller) => {
            return Err(format!("{} is not owned by the calling user", name));
        }
        Some(_) => {}
    }
    let want = req.ifindex.ok_or("no interface index given")?;
    if sys.ifindex(name) != Some(want) {
        return Err(format!("{} was replaced (interface index changed)", name));
    }
    Ok((name, want))
}

/// Whether an operation acts on the session TUN (and needs re-verification
/// after each command).
fn uses_session_tun(op: &Op) -> bool {
    !matches!(op, Op::PinDel { .. })
}

/// Validate a gateway pin's fields: a /32 on an existing non-TUN device.
fn pin_fields(dest: &str, via: &Option<String>, dev: &str, sys: &impl SysView)
    -> Result<(Prefix, Option<Ipv4Addr>), String> {
    let p = Prefix::parse(dest).filter(|p| p.len == 32 && dest.contains('/'))
        .ok_or_else(|| format!("pin destination must be a /32, got {:?}", dest))?;
    let via = via.as_deref().map(|v| parse_v4(v, "next hop")).transpose()?;
    if !valid_ifname(dev) || !sys.iface_exists(dev) {
        return Err(format!("unknown interface {:?}", dev));
    }
    if sys.tun_owner(dev).is_some() {
        return Err(format!("gateway pins must use a physical interface, not {}", dev));
    }
    Ok((p, via))
}

fn route_argv(verb: &str, dest: Prefix, via: Option<Ipv4Addr>, dev: &str) -> Vec<String> {
    let mut argv = vec![IP_BIN.into(), "route".into(), verb.into(), dest.to_string()];
    match via {
        Some(v) => {
            argv.push("via".into());
            argv.push(v.to_string());
        }
        None if verb == "del" => {
            argv.push("scope".into());
            argv.push("link".into());
        }
        None => {}
    }
    argv.extend(["dev".into(), dev.to_string(), "proto".into(), ROUTE_PROTO.into()]);
    argv
}

/// Validate one operation and return the command(s) that implement it.
pub fn plan_op(op: &Op, req: &Request, caller: u32, sys: &impl SysView) -> Result<Vec<Vec<String>>, String> {
    match op {
        Op::RouteAdd { dest } => {
            let (tun, _) = session_tun(req, caller, sys)?;
            let p = Prefix::parse(dest).ok_or_else(|| format!("invalid route {:?}", dest))?;
            Ok(vec![route_argv("add", p, None, tun)])
        }
        Op::PinAdd { dest, via, dev } => {
            // Only during the caller's live session (e.g. not from a pkexec
            // prompt approved after disconnecting).
            session_tun(req, caller, sys)?;
            let (p, via) = pin_fields(dest, via, dev, sys)?;
            // Only replicate the current physical path — never redirect.
            match sys.route_get(p.net) {
                Some((cur_via, cur_dev)) if cur_via == via && cur_dev == *dev => {}
                other => return Err(format!(
                    "pin {} via {:?} dev {} does not match the current path {:?}", p, via, dev, other)),
            }
            Ok(vec![route_argv("add", p, via, dev)])
        }
        Op::PinDel { dest, via, dev } => {
            let (p, via) = pin_fields(dest, via, dev, sys)?;
            if !sys.pin_registered(caller, &pin_key(p, via, dev)) {
                return Err(format!("pin {} was not installed by this helper for the caller", p));
            }
            Ok(vec![route_argv("del", p, via, dev)])
        }
        Op::Dns { servers } => {
            // resolvectl takes the interface *index*, binding the change to the
            // device that was just verified (not to a name looked up again).
            let (_, idx) = session_tun(req, caller, sys)?;
            if servers.is_empty() || servers.len() > 8 {
                return Err("between 1 and 8 DNS servers required".into());
            }
            let mut argv = vec![RESOLVECTL_BIN.into(), "dns".into(), idx.to_string()];
            for s in servers {
                argv.push(parse_v4(s, "DNS server")?.to_string());
            }
            Ok(vec![argv])
        }
        Op::Domain { domains } => {
            let (_, idx) = session_tun(req, caller, sys)?;
            if domains.is_empty() || domains.len() > 32 {
                return Err("between 1 and 32 DNS domains required".into());
            }
            let mut argv = vec![RESOLVECTL_BIN.into(), "domain".into(), idx.to_string()];
            for d in domains {
                if !valid_domain(d) {
                    return Err(format!("invalid DNS domain {:?}", d));
                }
                argv.push(d.clone());
            }
            Ok(vec![argv])
        }
        Op::Addr { ip } => {
            let (tun, _) = session_tun(req, caller, sys)?;
            let a = parse_v4(ip, "address")?;
            if a.is_unspecified() || a.is_multicast() || a.is_broadcast() {
                return Err(format!("invalid address {}", a));
            }
            Ok(vec![
                vec![IP_BIN.into(), "addr".into(), "flush".into(), "dev".into(), tun.to_string()],
                vec![IP_BIN.into(), "addr".into(), "add".into(), format!("{}/32", a), "dev".into(), tun.to_string()],
            ])
        }
        Op::Mtu { mtu } => {
            let (tun, _) = session_tun(req, caller, sys)?;
            if !(576..=1500).contains(mtu) {
                return Err(format!("MTU {} out of range 576..=1500", mtu));
            }
            Ok(vec![vec![IP_BIN.into(), "link".into(), "set".into(), "dev".into(), tun.to_string(),
                "mtu".into(), mtu.to_string()]])
        }
        Op::LinkUp => {
            let (tun, _) = session_tun(req, caller, sys)?;
            Ok(vec![vec![IP_BIN.into(), "link".into(), "set".into(), "dev".into(), tun.to_string(), "up".into()]])
        }
    }
}

/// Execute a request: validate each operation right before running it.
/// `run` executes one argv and returns (success, stderr).
pub fn execute(req: &Request, caller: u32, sys: &impl SysView,
               mut run: impl FnMut(&[String]) -> (bool, String)) -> Response {
    let mut resp = Response::default();
    if req.ops.len() > MAX_OPS {
        resp.aborted = Some(format!("too many operations ({})", req.ops.len()));
        return resp;
    }
    for op in &req.ops {
        if let Some(id) = &req.attempt {
            if !sys.attempt_current(id) {
                resp.aborted = Some("superseded: a newer connection attempt started".into());
                break;
            }
        }
        let mut changed_underneath = false;
        let result = match plan_op(op, req, caller, sys) {
            Err(e) => OpResult { ok: false, stderr: format!("rejected: {}", e) },
            Ok(cmds) => {
                let mut res = OpResult { ok: true, stderr: String::new() };
                for argv in &cmds {
                    let (ok, err) = run(argv);
                    // `ip` resolves the device name again: make sure it still
                    // is the caller's verified device.
                    if uses_session_tun(op) {
                        if let Err(e) = session_tun(req, caller, sys) {
                            res = OpResult { ok: false, stderr: format!("interface changed during operation: {}", e) };
                            changed_underneath = true;
                            break;
                        }
                    }
                    if !ok {
                        res = OpResult { ok: false, stderr: err };
                        break;
                    }
                }
                res
            }
        };
        // Pin registry bookkeeping (only after the kernel accepted/removed it).
        match op {
            Op::PinAdd { dest, via, dev } if result.ok => {
                if let (Some(p), Ok(v)) = (Prefix::parse(dest), via.as_deref().map(|v| v.parse()).transpose()) {
                    if let Err(e) = sys.register_pin(caller, &pin_key(p, v, dev)) {
                        resp.results.push(OpResult { ok: false, stderr: format!("pin added but not registered: {}", e) });
                        continue;
                    }
                }
            }
            Op::PinDel { dest, via, dev } if result.ok || result.stderr.contains("No such process") => {
                if let (Some(p), Ok(v)) = (Prefix::parse(dest), via.as_deref().map(|v| v.parse()).transpose()) {
                    sys.unregister_pin(caller, &pin_key(p, v, dev));
                }
            }
            _ => {}
        }
        resp.results.push(result);
        if changed_underneath {
            resp.aborted = Some("the session interface changed during execution".into());
            break;
        }
    }
    resp
}

/// Where a user's current connection-attempt id lives. Derived from the
/// caller's uid only (never from environment variables, which the root
/// helper must not trust): `/run/user/<uid>` is created by logind and owned
/// by that user.
pub fn attempt_path(uid: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/user/{}/open-forti-manager/attempt", uid))
}

/// The real system, as seen by the root helper acting for `caller`.
pub struct RealSys {
    pub caller: u32,
}

impl SysView for RealSys {
    fn tun_owner(&self, ifname: &str) -> Option<Option<u32>> {
        if !valid_ifname(ifname) {
            return None;
        }
        let base = std::path::Path::new("/sys/class/net").join(ifname);
        // tun_flags exists for TUN *and* TAP devices: require IFF_TUN (0x1)
        // and not IFF_TAP (0x2).
        let flags = std::fs::read_to_string(base.join("tun_flags")).ok()
            .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())?;
        (flags & 0x1 != 0 && flags & 0x2 == 0).then(|| {
            std::fs::read_to_string(base.join("owner")).ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .filter(|o| *o >= 0)
                .map(|o| o as u32)
        })
    }

    fn ifindex(&self, ifname: &str) -> Option<u32> {
        if !valid_ifname(ifname) {
            return None;
        }
        std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", ifname)).ok()?.trim().parse().ok()
    }

    fn iface_exists(&self, ifname: &str) -> bool {
        valid_ifname(ifname) && std::path::Path::new("/sys/class/net").join(ifname).exists()
    }

    fn route_get(&self, ip: Ipv4Addr) -> Option<(Option<Ipv4Addr>, String)> {
        let out = std::process::Command::new(IP_BIN)
            .args(["-4", "route", "get", &ip.to_string()])
            .env_clear()
            .output().ok()
            .filter(|o| o.status.success())?;
        let text = String::from_utf8_lossy(&out.stdout);
        let t: Vec<&str> = text.split_whitespace().collect();
        let after = |k: &str| t.iter().position(|&x| x == k).and_then(|i| t.get(i + 1)).copied();
        Some((after("via").and_then(|v| v.parse().ok()), after("dev")?.to_string()))
    }

    fn attempt_current(&self, id: &str) -> bool {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let Ok(mut f) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(attempt_path(self.caller)) else { return false };
        // Must be a regular file owned by the caller.
        match f.metadata() {
            Ok(m) if m.is_file() && m.uid() == self.caller => {}
            _ => return false,
        }
        let mut buf = [0u8; 128];
        let n = f.read(&mut buf).unwrap_or(0);
        std::str::from_utf8(&buf[..n]).map(|s| s.trim() == id).unwrap_or(false)
    }

    fn pin_registered(&self, uid: u32, key: &str) -> bool {
        registry::with(|entries| entries.iter().any(|(u, k)| *u == uid && k == key)).unwrap_or(false)
    }

    fn register_pin(&self, uid: u32, key: &str) -> Result<(), String> {
        registry::update(|entries| {
            if !entries.iter().any(|(u, k)| *u == uid && k == key) {
                entries.push((uid, key.to_string()));
            }
        })
    }

    fn unregister_pin(&self, uid: u32, key: &str) {
        let _ = registry::update(|entries| entries.retain(|(u, k)| !(*u == uid && k == key)));
    }
}

/// Root-owned registry of pins the helper installed, per caller uid, scoped
/// to the current boot (routes do not survive a reboot).
mod registry {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    const DIR: &str = "/var/lib/open-forti-manager";

    fn boot_id() -> String {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_default()
    }

    fn locked<T>(f: impl FnOnce(&std::path::Path) -> Result<T, String>) -> Result<T, String> {
        let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(DIR);
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW)
            .open(format!("{}/pins.lock", DIR)).map_err(|e| format!("registry lock: {}", e))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!("registry lock: {}", std::io::Error::last_os_error()));
        }
        f(std::path::Path::new(&format!("{}/pins", DIR)))
    }

    fn read(path: &std::path::Path) -> Result<Vec<(u32, String)>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("registry read: {}", e)),
        };
        let mut lines = text.lines();
        if lines.next().and_then(|l| l.strip_prefix("boot ")) != Some(boot_id().as_str()) {
            return Ok(Vec::new());
        }
        Ok(lines.filter_map(|l| {
            let (uid, key) = l.split_once(' ')?;
            Some((uid.parse().ok()?, key.to_string()))
        }).collect())
    }

    pub fn with<T>(f: impl FnOnce(&[(u32, String)]) -> T) -> Result<T, String> {
        locked(|path| read(path).map(|e| f(&e)))
    }

    pub fn update(f: impl FnOnce(&mut Vec<(u32, String)>)) -> Result<(), String> {
        locked(|path| {
            let mut entries = read(path)?;
            f(&mut entries);
            let tmp = path.with_extension("tmp");
            let mut text = format!("boot {}\n", boot_id());
            for (u, k) in &entries {
                text.push_str(&format!("{} {}\n", u, k));
            }
            let mut file = std::fs::OpenOptions::new().create(true).truncate(true).write(true)
                .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)
                .map_err(|e| format!("registry write: {}", e))?;
            file.write_all(text.as_bytes()).and_then(|_| file.sync_all())
                .map_err(|e| format!("registry write: {}", e))?;
            std::fs::rename(&tmp, path).map_err(|e| format!("registry write: {}", e))
        })
    }
}

/// Run one argv as the helper: absolute program path, empty environment
/// except a fixed PATH, no shell.
pub fn run_argv(argv: &[String]) -> (bool, String) {
    let Some((prog, args)) = argv.split_first() else { return (false, "empty command".into()) };
    match std::process::Command::new(prog)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => (false, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeSys {
        tun_owner: Option<u32>,
        ifindex: RefCell<u32>,
        current_attempt: RefCell<String>,
        registry: RefCell<Vec<(u32, String)>>,
    }

    impl SysView for FakeSys {
        fn tun_owner(&self, ifname: &str) -> Option<Option<u32>> {
            if ifname == "vpn0" { Some(self.tun_owner) } else { None }
        }
        fn ifindex(&self, ifname: &str) -> Option<u32> {
            if ifname == "vpn0" { Some(*self.ifindex.borrow()) } else { Some(2) }
        }
        fn iface_exists(&self, ifname: &str) -> bool {
            ["vpn0", "wlan0", "eth0"].contains(&ifname)
        }
        fn route_get(&self, _ip: Ipv4Addr) -> Option<(Option<Ipv4Addr>, String)> {
            Some((Some("192.168.10.1".parse().unwrap()), "wlan0".into()))
        }
        fn attempt_current(&self, id: &str) -> bool {
            *self.current_attempt.borrow() == id
        }
        fn pin_registered(&self, uid: u32, key: &str) -> bool {
            self.registry.borrow().iter().any(|(u, k)| *u == uid && k == key)
        }
        fn register_pin(&self, uid: u32, key: &str) -> Result<(), String> {
            self.registry.borrow_mut().push((uid, key.to_string()));
            Ok(())
        }
        fn unregister_pin(&self, uid: u32, key: &str) {
            self.registry.borrow_mut().retain(|(u, k)| !(*u == uid && k == key));
        }
    }

    fn sys() -> FakeSys {
        FakeSys { tun_owner: Some(1000), ifindex: RefCell::new(42), current_attempt: RefCell::new("a1".into()),
                  registry: RefCell::new(Vec::new()) }
    }

    fn req(ops: Vec<Op>) -> Request {
        Request { ifname: Some("vpn0".into()), ifindex: Some(42), attempt: None, ops }
    }

    fn plan(op: Op) -> Result<Vec<Vec<String>>, String> {
        plan_op(&op, &req(vec![]), 1000, &sys())
    }

    #[test]
    fn route_add_targets_session_tun_with_marker() {
        let cmds = plan(Op::RouteAdd { dest: "10.1.2.3/8".into() }).unwrap();
        assert_eq!(cmds, vec![vec!["/usr/sbin/ip", "route", "add", "10.0.0.0/8", "dev", "vpn0", "proto", "157"]]);
    }

    #[test]
    fn rejects_foreign_interfaces_and_owners() {
        // Not the session TUN: a physical interface.
        let mut r = req(vec![]);
        r.ifname = Some("eth0".into());
        assert!(plan_op(&Op::LinkUp, &r, 1000, &sys()).is_err());
        // TUN owned by someone else, or with no owner set.
        let mut s = sys();
        s.tun_owner = Some(0);
        assert!(plan_op(&Op::LinkUp, &req(vec![]), 1000, &s).is_err());
        s.tun_owner = None;
        assert!(plan_op(&Op::LinkUp, &req(vec![]), 1000, &s).is_err());
        // Replaced device (ifindex changed).
        let mut r = req(vec![]);
        r.ifindex = Some(43);
        assert!(plan_op(&Op::LinkUp, &r, 1000, &sys()).is_err());
    }

    #[test]
    fn argument_smuggling_is_impossible() {
        // Values are single argv elements and are parsed, never spliced.
        assert!(plan(Op::RouteAdd { dest: "10.0.0.0/8 dev eth0".into() }).is_err());
        assert!(plan(Op::Dns { servers: vec!["1.1.1.1 --interface eth0".into()] }).is_err());
        assert!(plan(Op::Domain { domains: vec!["corp.example eth0".into()] }).is_err());
        assert!(plan(Op::Domain { domains: vec!["-x".into()] }).is_err());
        assert!(plan(Op::Mtu { mtu: 9000 }).is_err());
    }

    #[test]
    fn domains_and_dns_validation() {
        let cmds = plan(Op::Domain { domains: vec!["~example.com".into(), "corp.example".into(), "~.".into()] }).unwrap();
        assert_eq!(&cmds[0][3..], &["~example.com", "corp.example", "~."]);
        assert!(plan(Op::Domain { domains: vec![".".into()] }).is_err(), "bare '.' is not a search domain");
        // DNS is bound to the verified interface *index*, not the name.
        let cmds = plan(Op::Dns { servers: vec!["172.16.5.53".into()] }).unwrap();
        assert_eq!(cmds[0], vec!["/usr/bin/resolvectl", "dns", "42", "172.16.5.53"]);
    }

    #[test]
    fn pin_add_must_match_current_path() {
        let ok = plan(Op::PinAdd { dest: "198.51.100.7/32".into(), via: Some("192.168.10.1".into()), dev: "wlan0".into() }).unwrap();
        assert_eq!(ok[0], vec!["/usr/sbin/ip", "route", "add", "198.51.100.7/32", "via", "192.168.10.1",
            "dev", "wlan0", "proto", "157"]);
        // A different next hop would redirect traffic: rejected.
        assert!(plan(Op::PinAdd { dest: "198.51.100.7/32".into(), via: Some("192.168.10.66".into()), dev: "wlan0".into() }).is_err());
        // Only /32, only physical interfaces.
        assert!(plan(Op::PinAdd { dest: "198.51.100.0/24".into(), via: Some("192.168.10.1".into()), dev: "wlan0".into() }).is_err());
        assert!(plan(Op::PinAdd { dest: "198.51.100.7/32".into(), via: None, dev: "vpn0".into() }).is_err());
    }

    #[test]
    fn pin_del_requires_marker_and_scope() {
        // Registered for the caller (as if the helper had installed them).
        let s = sys();
        s.register_pin(1000, "198.51.100.7/32 10.9.9.1 eth0").unwrap();
        s.register_pin(1000, "198.51.100.7/32 - eth0").unwrap();
        let plan = |op: Op| plan_op(&op, &req(vec![]), 1000, &s);
        let with_via = plan(Op::PinDel { dest: "198.51.100.7/32".into(), via: Some("10.9.9.1".into()), dev: "eth0".into() }).unwrap();
        assert_eq!(with_via[0], vec!["/usr/sbin/ip", "route", "del", "198.51.100.7/32", "via", "10.9.9.1",
            "dev", "eth0", "proto", "157"]);
        let onlink = plan(Op::PinDel { dest: "198.51.100.7/32".into(), via: None, dev: "eth0".into() }).unwrap();
        assert_eq!(onlink[0], vec!["/usr/sbin/ip", "route", "del", "198.51.100.7/32", "scope", "link",
            "dev", "eth0", "proto", "157"]);
    }

    #[test]
    fn pin_del_only_for_pins_the_helper_installed_for_the_caller() {
        // Regression (Astra, High): any matching route could be deleted.
        let s = sys();
        let del = Op::PinDel { dest: "198.51.100.7/32".into(), via: Some("192.168.10.1".into()), dev: "wlan0".into() };
        assert!(plan_op(&del, &req(vec![]), 1000, &s).is_err(), "not installed by the helper");
        s.register_pin(1001, "198.51.100.7/32 192.168.10.1 wlan0").unwrap();
        assert!(plan_op(&del, &req(vec![]), 1000, &s).is_err(), "installed for another user");
        // Installed for this caller through the helper: then deletable, and
        // the registry entry is dropped afterwards.
        let add = Op::PinAdd { dest: "198.51.100.7/32".into(), via: Some("192.168.10.1".into()), dev: "wlan0".into() };
        let resp = execute(&req(vec![add, del.clone()]), 1000, &s, |_| (true, String::new()));
        assert!(resp.results.iter().all(|r| r.ok), "{:?}", resp);
        assert!(!s.pin_registered(1000, "198.51.100.7/32 192.168.10.1 wlan0"));
    }

    #[test]
    fn pin_add_requires_live_session() {
        // Regression (Astra): a pkexec prompt approved after disconnect added
        // the pin; also pins for arbitrary destinations without a session.
        let add = Op::PinAdd { dest: "198.51.100.7/32".into(), via: Some("192.168.10.1".into()), dev: "wlan0".into() };
        let mut r = req(vec![]);
        r.ifname = None;
        assert!(plan_op(&add, &r, 1000, &sys()).is_err());
        let mut r = req(vec![]);
        r.ifindex = Some(99); // TUN gone / replaced
        assert!(plan_op(&add, &r, 1000, &sys()).is_err());
    }

    #[test]
    fn device_replaced_during_execution_stops() {
        // Regression (Astra): validation happened before `ip` resolved the
        // name again. A swap detected after a command aborts the batch.
        let s = sys();
        let r = req(vec![Op::RouteAdd { dest: "10.0.0.0/8".into() }, Op::RouteAdd { dest: "10.1.0.0/16".into() }]);
        let mut n = 0;
        let resp = execute(&r, 1000, &s, |_| {
            n += 1;
            *s.ifindex.borrow_mut() = 77; // another device took the name
            (true, String::new())
        });
        assert_eq!(n, 1, "second op never runs");
        assert!(!resp.results[0].ok);
        assert!(resp.aborted.is_some());
    }

    #[test]
    fn addr_and_mtu() {
        let cmds = plan(Op::Addr { ip: "10.66.1.2".into() }).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[1], vec!["/usr/sbin/ip", "addr", "add", "10.66.1.2/32", "dev", "vpn0"]);
        assert!(plan(Op::Addr { ip: "0.0.0.0".into() }).is_err());
        assert_eq!(plan(Op::Mtu { mtu: 1354 }).unwrap()[0][6], "1354");
    }

    #[test]
    fn execute_reports_per_op_and_stops_when_superseded() {
        let s = sys();
        let mut r = req(vec![
            Op::RouteAdd { dest: "10.0.0.0/8".into() },
            Op::RouteAdd { dest: "bogus".into() },
            Op::LinkUp,
        ]);
        r.attempt = Some("a1".into());
        let mut ran = Vec::new();
        let resp = execute(&r, 1000, &s, |argv| {
            ran.push(argv.to_vec());
            if argv.contains(&"up".to_string()) { (false, "RTNETLINK answers: busy".into()) } else { (true, String::new()) }
        });
        assert_eq!(resp.results.len(), 3);
        assert!(resp.results[0].ok);
        assert!(resp.results[1].stderr.starts_with("rejected:"));
        assert_eq!(resp.results[2].stderr, "RTNETLINK answers: busy");
        assert_eq!(ran.len(), 2, "the rejected op never runs a command");

        // A newer attempt started: nothing runs.
        *s.current_attempt.borrow_mut() = "a2".into();
        let resp = execute(&r, 1000, &s, |_| panic!("must not run"));
        assert!(resp.results.is_empty());
        assert!(resp.aborted.unwrap().starts_with("superseded"));
    }

    #[test]
    fn protocol_roundtrip() {
        let r = req(vec![Op::PinDel { dest: "198.51.100.7/32".into(), via: None, dev: "eth0".into() }, Op::LinkUp]);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""op":"pin_del""#));
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ops, r.ops);
        assert!(serde_json::from_str::<Request>(r#"{"ops":[{"op":"shell","cmd":"id"}]}"#).is_err());
    }
}
