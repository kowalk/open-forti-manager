use crate::config::VpnProfile;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;

/// Current state of the VPN connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error(String),
}

impl ConnectionState {
    pub fn label(&self) -> &str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::Connecting => "Connecting\u{2026}",
            ConnectionState::Connected => "Connected",
            ConnectionState::Disconnecting => "Disconnecting\u{2026}",
            ConnectionState::Error(_) => "Error",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, ConnectionState::Connecting | ConnectionState::Connected)
    }
}

// ---------------------------------------------------------------------------
// VpnBackend trait
// ---------------------------------------------------------------------------

pub trait VpnBackend {
    fn connect(&mut self, profile: &VpnProfile) -> Result<(), String>;
    fn disconnect(&mut self) -> Result<(), String>;
    fn check_status(&mut self);
    fn state(&self) -> &ConnectionState;
    fn drain_log(&mut self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// ProcessHandle
// ---------------------------------------------------------------------------

struct ProcessHandle {
    child: Child,
    log_rx: Receiver<String>,
    stop_flag: Arc<AtomicBool>,
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let _ = self.child.kill();
        let _ = self.child.try_wait();
    }
}

// ---------------------------------------------------------------------------
// VpnManager — core methods
// ---------------------------------------------------------------------------

pub struct VpnManager {
    process: Option<ProcessHandle>,
    state: ConnectionState,
    log: Vec<String>,
}

impl VpnManager {
    pub fn new() -> Self {
        Self { process: None, state: ConnectionState::Disconnected, log: Vec::new() }
    }

    pub fn set_state(&mut self, s: ConnectionState) { self.state = s; }

    pub fn is_running_global() -> bool {
        std::process::Command::new("pgrep")
            .args(["openfortivpn"])
            .stdout(Stdio::null()).stderr(Stdio::null())
            .status().map(|s| s.success()).unwrap_or(false)
    }

    /// Synchronous disconnect — blocks until pkexec kills complete.
    /// Use before app exit to ensure the VPN is actually killed.
    #[allow(dead_code)]
    pub fn disconnect_sync(&mut self) -> Result<(), String> {
        let _ = <Self as VpnBackend>::disconnect(self);
        self.state = ConnectionState::Disconnecting;
        kill_vpn_processes();
        self.state = ConnectionState::Disconnected;
        Ok(())
    }
}

/// Kill any running openfortivpn + pppd via a single pkexec call.
fn kill_vpn_processes() {
    // pgrep to find PIDs, then one pkexec to kill them all
    let mut pids: Vec<String> = Vec::new();
    for proc in &["openfortivpn", "pppd"] {
        if let Ok(out) = Command::new("pgrep").arg(proc).output() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                for pid in s.lines() { pids.push(pid.to_string()); }
            }
        }
    }
    if pids.is_empty() { return; }

    // SIGINT first for graceful shutdown, then SIGKILL
    let mut args: Vec<String> = vec!["sh".into(), "-c".into()];
    let pids_str = pids.join(" ");
    args.push(format!("kill -INT {}; sleep 0.5; kill -KILL {}", pids_str, pids_str));

    let _ = Command::new("pkexec")
        .args(&args)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().and_then(|mut c| c.wait());
}

// ---------------------------------------------------------------------------
// VpnBackend impl
// ---------------------------------------------------------------------------

impl VpnBackend for VpnManager {
    fn connect(&mut self, profile: &VpnProfile) -> Result<(), String> {
        if self.process.is_some() {
            return Err("Already connected. Disconnect first.".into());
        }
        self.state = ConnectionState::Connecting;
        self.log.clear();
        self.log.push(format!("Connecting to {}…", profile.host));

        let args = profile.to_args();
        log::info!("Spawning openfortivpn via pkexec, args: {:?}", args);

        let mut cmd = Command::new("pkexec");
        cmd.arg("/usr/local/bin/openfortivpn");
        cmd.args(&args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.stdin(Stdio::null());

        let mut child = cmd.spawn()
            .map_err(|e| format!("Failed to start openfortivpn: {}", e))?;

        let (log_tx, log_rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));

        if let Some(stdout) = child.stdout.take() {
            let tx = log_tx.clone();
            let stop = stop_flag.clone();
            thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if stop.load(Ordering::Relaxed) { break; }
                    if let Ok(l) = line { let _ = tx.send(format!("[out] {}", l)); }
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let stop = stop_flag.clone();
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines() {
                    if stop.load(Ordering::Relaxed) { break; }
                    if let Ok(l) = line { let _ = log_tx.send(format!("[err] {}", l)); }
                }
            });
        }

        self.process = Some(ProcessHandle { child, log_rx, stop_flag });
        self.log.push("VPN process spawned…".into());
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), String> {
        self.state = ConnectionState::Disconnecting;
        self.log.push("Disconnecting…".into());

        if let Some(ref mut handle) = self.process.take() {
            handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = handle.child.kill();
            let _ = handle.child.try_wait();
        }

        // Background kill for orphans (non-blocking)
        thread::spawn(|| kill_vpn_processes());
        Ok(())
    }

    fn check_status(&mut self) {
        if let Some(ref mut handle) = self.process {
            match handle.child.try_wait() {
                Ok(Some(_)) => {
                    self.process = None;
                    if Self::is_running_global() {
                        if self.state == ConnectionState::Connecting {
                            self.state = ConnectionState::Connected;
                            self.log.push("Tunnel established!".into());
                        }
                    } else {
                        self.log.push("VPN process exited.".into());
                        self.state = ConnectionState::Disconnected;
                    }
                }
                Ok(None) => {
                    if self.state == ConnectionState::Connecting {
                        self.state = ConnectionState::Connected;
                        self.log.push("Tunnel established!".into());
                    }
                }
                Err(e) => {
                    self.process = None;
                    let msg = format!("Status check error: {}", e);
                    self.log.push(msg.clone());
                    self.state = ConnectionState::Error(msg);
                }
            }
        } else if self.state == ConnectionState::Connecting && Self::is_running_global() {
            self.state = ConnectionState::Connected;
            self.log.push("Detected running VPN connection.".into());
        } else if self.state == ConnectionState::Disconnecting && !Self::is_running_global() {
            self.state = ConnectionState::Disconnected;
            self.log.push("VPN connection closed.".into());
        }
    }

    fn state(&self) -> &ConnectionState { &self.state }

    fn drain_log(&mut self) -> Vec<String> {
        let mut new = Vec::new();
        if let Some(ref handle) = self.process {
            while let Ok(line) = handle.log_rx.try_recv() {
                self.log.push(line.clone());
                new.push(line);
            }
        }
        if self.log.len() > 1000 { self.log.drain(0..self.log.len() - 500); }
        new
    }
}
