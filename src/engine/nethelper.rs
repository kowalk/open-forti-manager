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
//! - Every route the helper adds carries the private [`ROUTE_PROTO`] marker;
//!   gateway-pin deletion requires it, so a route the helper did not create
//!   can never be deleted.
//! - A gateway pin must be a /32 on a physical (non-TUN) interface whose next
//!   hop equals the destination's current path, so it cannot redirect traffic.
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
/// Route protocol number marking routes installed by this app.
pub const ROUTE_PROTO: &str = "186";

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
fn session_tun<'a>(req: &'a Request, caller: u32, sys: &impl SysView) -> Result<&'a str, String> {
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
    Ok(name)
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
            let tun = session_tun(req, caller, sys)?;
            let p = Prefix::parse(dest).ok_or_else(|| format!("invalid route {:?}", dest))?;
            Ok(vec![route_argv("add", p, None, tun)])
        }
        Op::PinAdd { dest, via, dev } => {
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
            Ok(vec![route_argv("del", p, via, dev)])
        }
        Op::Dns { servers } => {
            let tun = session_tun(req, caller, sys)?;
            if servers.is_empty() || servers.len() > 8 {
                return Err("between 1 and 8 DNS servers required".into());
            }
            let mut argv = vec![RESOLVECTL_BIN.into(), "dns".into(), tun.to_string()];
            for s in servers {
                argv.push(parse_v4(s, "DNS server")?.to_string());
            }
            Ok(vec![argv])
        }
        Op::Domain { domains } => {
            let tun = session_tun(req, caller, sys)?;
            if domains.is_empty() || domains.len() > 32 {
                return Err("between 1 and 32 DNS domains required".into());
            }
            let mut argv = vec![RESOLVECTL_BIN.into(), "domain".into(), tun.to_string()];
            for d in domains {
                if !valid_domain(d) {
                    return Err(format!("invalid DNS domain {:?}", d));
                }
                argv.push(d.clone());
            }
            Ok(vec![argv])
        }
        Op::Addr { ip } => {
            let tun = session_tun(req, caller, sys)?;
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
            let tun = session_tun(req, caller, sys)?;
            if !(576..=1500).contains(mtu) {
                return Err(format!("MTU {} out of range 576..=1500", mtu));
            }
            Ok(vec![vec![IP_BIN.into(), "link".into(), "set".into(), "dev".into(), tun.to_string(),
                "mtu".into(), mtu.to_string()]])
        }
        Op::LinkUp => {
            let tun = session_tun(req, caller, sys)?;
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
        let result = match plan_op(op, req, caller, sys) {
            Err(e) => OpResult { ok: false, stderr: format!("rejected: {}", e) },
            Ok(cmds) => {
                let mut res = OpResult { ok: true, stderr: String::new() };
                for argv in &cmds {
                    let (ok, err) = run(argv);
                    if !ok {
                        res = OpResult { ok: false, stderr: err };
                        break;
                    }
                }
                res
            }
        };
        resp.results.push(result);
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
        base.join("tun_flags").exists().then(|| {
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
        ifindex: u32,
        current_attempt: RefCell<String>,
    }

    impl SysView for FakeSys {
        fn tun_owner(&self, ifname: &str) -> Option<Option<u32>> {
            if ifname == "vpn0" { Some(self.tun_owner) } else { None }
        }
        fn ifindex(&self, ifname: &str) -> Option<u32> {
            if ifname == "vpn0" { Some(self.ifindex) } else { Some(2) }
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
    }

    fn sys() -> FakeSys {
        FakeSys { tun_owner: Some(1000), ifindex: 42, current_attempt: RefCell::new("a1".into()) }
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
        assert_eq!(cmds, vec![vec!["/usr/sbin/ip", "route", "add", "10.0.0.0/8", "dev", "vpn0", "proto", "186"]]);
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
        let cmds = plan(Op::Dns { servers: vec!["172.16.5.53".into()] }).unwrap();
        assert_eq!(cmds[0], vec!["/usr/bin/resolvectl", "dns", "vpn0", "172.16.5.53"]);
    }

    #[test]
    fn pin_add_must_match_current_path() {
        let ok = plan(Op::PinAdd { dest: "198.51.100.7/32".into(), via: Some("192.168.10.1".into()), dev: "wlan0".into() }).unwrap();
        assert_eq!(ok[0], vec!["/usr/sbin/ip", "route", "add", "198.51.100.7/32", "via", "192.168.10.1",
            "dev", "wlan0", "proto", "186"]);
        // A different next hop would redirect traffic: rejected.
        assert!(plan(Op::PinAdd { dest: "198.51.100.7/32".into(), via: Some("192.168.10.66".into()), dev: "wlan0".into() }).is_err());
        // Only /32, only physical interfaces.
        assert!(plan(Op::PinAdd { dest: "198.51.100.0/24".into(), via: Some("192.168.10.1".into()), dev: "wlan0".into() }).is_err());
        assert!(plan(Op::PinAdd { dest: "198.51.100.7/32".into(), via: None, dev: "vpn0".into() }).is_err());
    }

    #[test]
    fn pin_del_requires_marker_and_scope() {
        let with_via = plan(Op::PinDel { dest: "198.51.100.7/32".into(), via: Some("10.9.9.1".into()), dev: "eth0".into() }).unwrap();
        assert_eq!(with_via[0], vec!["/usr/sbin/ip", "route", "del", "198.51.100.7/32", "via", "10.9.9.1",
            "dev", "eth0", "proto", "186"]);
        let onlink = plan(Op::PinDel { dest: "198.51.100.7/32".into(), via: None, dev: "eth0".into() }).unwrap();
        assert_eq!(onlink[0], vec!["/usr/sbin/ip", "route", "del", "198.51.100.7/32", "scope", "link",
            "dev", "eth0", "proto", "186"]);
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
