//! open-forti-manager-net — privileged network helper.
//!
//! Runs as root via `sudo -n /usr/libexec/open-forti-manager-net` (the
//! packaged sudoers rule allows exactly that, with no arguments) or via
//! pkexec. Reads one JSON request on stdin, performs only validated
//! operations on the caller's own VPN interface and its gateway pins, and
//! prints a JSON response. See `engine::nethelper` for the rules.

use open_forti_manager::engine::nethelper::{execute, run_argv, RealSys, Request};
use std::io::Read;

const MAX_REQUEST: u64 = 64 * 1024;

fn main() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("open-forti-manager-net: must run as root (via sudo or pkexec)");
        std::process::exit(1);
    }
    if std::env::args_os().len() > 1 {
        eprintln!("open-forti-manager-net: takes no arguments; send a JSON request on stdin");
        std::process::exit(1);
    }

    // The user the request is made for. sudo and pkexec set these; when root
    // runs the helper directly, the caller is root.
    let caller = ["SUDO_UID", "PKEXEC_UID"]
        .iter()
        .find_map(|k| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok()))
        .unwrap_or_else(|| unsafe { libc::getuid() });

    let mut input = String::new();
    if let Err(e) = std::io::stdin().take(MAX_REQUEST).read_to_string(&mut input) {
        eprintln!("open-forti-manager-net: cannot read request: {}", e);
        std::process::exit(2);
    }
    let req: Request = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("open-forti-manager-net: invalid request: {}", e);
            std::process::exit(2);
        }
    };

    let resp = execute(&req, caller, &RealSys { caller }, run_argv);
    match serde_json::to_string(&resp) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("open-forti-manager-net: cannot encode response: {}", e);
            std::process::exit(3);
        }
    }
}
