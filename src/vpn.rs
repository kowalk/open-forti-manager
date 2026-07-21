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
    /// No active connection
    Disconnected,
    /// Connecting to VPN gateway
    Connecting,
    /// Tunnel is established
    Connected,
    /// Disconnecting from VPN
    Disconnecting,
    /// An error occurred
    Error(String),
}

impl ConnectionState {
    /// Human-readable label for the UI.
    pub fn label(&self) -> &str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::Connecting => "Connecting…",
            ConnectionState::Connected => "Connected",
            ConnectionState::Disconnecting => "Disconnecting…",
            ConnectionState::Error(_) => "Error",
        }
    }

    /// Whether the connection is active (connected or in transition).
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ConnectionState::Connecting | ConnectionState::Connected
        )
    }
}

/// Manages the lifecycle of an openfortivpn child process.
pub struct VpnManager {
    /// Handle to the running pkexec/openfortivpn process.
    process: Option<Child>,
    /// Current connection state.
    state: ConnectionState,
    /// Accumulated log lines from openfortivpn output.
    log: Vec<String>,
    /// Receiver for log lines from the reader threads.
    log_rx: Option<Receiver<String>>,
    /// Signal to reader threads to stop.
    stop_flag: Option<Arc<AtomicBool>>,
}

impl VpnManager {
    pub fn new() -> Self {
        Self {
            process: None,
            state: ConnectionState::Disconnected,
            log: Vec::new(),
            log_rx: None,
            stop_flag: None,
        }
    }

    /// Current connection state.
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    /// Set connection state directly (e.g. when detecting existing connection).
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    /// Accumulated log lines.
    #[allow(dead_code)]
    pub fn log_lines(&self) -> &[String] {
        &self.log
    }

    /// Check if openfortivpn is running (even from a previous instance).
    pub fn is_running() -> bool {
        std::process::Command::new("pgrep")
            .args(["openfortivpn"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Drain new log lines from the reader threads.
    pub fn drain_log(&mut self) -> Vec<String> {
        let mut new = Vec::new();
        if let Some(ref rx) = self.log_rx {
            while let Ok(line) = rx.try_recv() {
                self.log.push(line.clone());
                new.push(line);
            }
        }
        // Keep log bounded
        if self.log.len() > 1000 {
            self.log.drain(0..self.log.len() - 500);
        }
        new
    }

    /// Spawn openfortivpn with the given profile configuration.
    /// Returns Ok on successful spawn (process may still fail later).
    pub fn connect(&mut self, profile: &VpnProfile) -> Result<(), String> {
        if self.process.is_some() {
            return Err("A connection is already active. Disconnect first.".into());
        }

        self.state = ConnectionState::Connecting;
        self.log.clear();
        self.log.push(format!(
            "Connecting to {} as {}…",
            profile.host, profile.username
        ));

        let args = profile.to_args();
        log::info!("Spawning openfortivpn with pkexec, args: {:?}", args);

        // Run via pkexec to get root privileges with a GUI password prompt
        let mut cmd = Command::new("pkexec");
        cmd.arg("/usr/local/bin/openfortivpn");
        cmd.args(&args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.stdin(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| {
                let msg = format!("Failed to start openfortivpn: {}", e);
                if e.kind() == std::io::ErrorKind::NotFound {
                    format!("{} (pkexec not found — install polkit)", msg)
                } else {
                    msg
                }
            })?;

        // Spawn reader threads for stdout and stderr.
        let (log_tx, log_rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));

        // stdout reader
        if let Some(stdout) = child.stdout.take() {
            let tx = log_tx.clone();
            let stop = stop_flag.clone();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match line {
                        Ok(l) => {
                            let _ = tx.send(format!("[out] {}", l));
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        // stderr reader
        if let Some(stderr) = child.stderr.take() {
            let tx = log_tx;
            let stop = stop_flag.clone();
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match line {
                        Ok(l) => {
                            let _ = tx.send(format!("[err] {}", l));
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        self.process = Some(child);
        self.log_rx = Some(log_rx);
        self.stop_flag = Some(stop_flag);
        self.log.push("VPN process spawned…".into());

        Ok(())
    }

    /// Disconnect the VPN: kill the openfortivpn process.
    pub fn disconnect(&mut self) -> Result<(), String> {
        self.state = ConnectionState::Disconnecting;
        self.log.push("Disconnecting…".into());

        // Kill our child process if we spawned it
        if let Some(ref mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.try_wait();
        }

        // For existing/leftover sessions, send SIGINT first (graceful
        // shutdown — lets openfortivpn clean up routes and kill pppd).
        // Then after a delay, SIGKILL as fallback.
        // We do this in a background thread to avoid blocking the UI.
        std::thread::spawn(|| {
            // Helper: send signal to process by name via pkexec
            let send_signal = |proc: &str, sig: i32| -> bool {
                if let Ok(output) = std::process::Command::new("pgrep")
                    .arg(proc).output()
                {
                    if let Ok(pids) = String::from_utf8(output.stdout) {
                        let pids: Vec<&str> = pids.lines().collect();
                        if !pids.is_empty() {
                            let sig_arg = format!("-{}", sig);
                            let mut args: Vec<&str> = vec!["kill", &sig_arg];
                            args.extend(&pids);
                            let _ = std::process::Command::new("pkexec")
                                .args(&args)
                                .stdin(Stdio::null())
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .spawn()
                                .and_then(|mut c| c.wait());
                            return true;
                        }
                    }
                }
                false
            };

            // 1. Graceful shutdown via SIGINT (Ctrl+C)
            send_signal("openfortivpn", 2); // SIGINT
            // Give it time to clean up
            std::thread::sleep(std::time::Duration::from_secs(3));

            // 2. If still alive, SIGKILL both openfortivpn and pppd
            send_signal("openfortivpn", 9);
            send_signal("pppd", 9);
        });

        // Signal reader threads to stop
        if let Some(ref flag) = self.stop_flag {
            flag.store(true, Ordering::Relaxed);
        }
        self.stop_flag = None;
        self.state = ConnectionState::Disconnected;
        self.log.push("Disconnected.".into());
        Ok(())
    }

    /// Check whether the VPN is still alive.
    /// Call this periodically (e.g., every frame in the UI).
    pub fn check_status(&mut self) {
        if let Some(ref mut child) = self.process {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Our child (pkexec) exited.  But openfortivpn may
                    // still be running as a daemon reparented to systemd.
                    self.process = None;
                    if Self::is_running() {
                        // VPN is still alive — pkexec just detached
                        if self.state == ConnectionState::Connecting {
                            self.state = ConnectionState::Connected;
                            self.log.push("Tunnel established!".into());
                        }
                    } else {
                        // VPN actually exited
                        self.log.push("VPN process exited.".into());
                        self.state = ConnectionState::Disconnected;
                    }
                }
                Ok(None) => {
                    // Still running — if we were connecting, mark as connected
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
        } else if self.state == ConnectionState::Connecting && Self::is_running() {
            // No child process but VPN is running (e.g., started manually
            // or by a previous instance)
            self.state = ConnectionState::Connected;
            self.log.push("Detected running VPN connection.".into());
        }
    }
}

impl Drop for VpnManager {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.try_wait();
        }
        // Fire and forget — can't block in drop
    }
}
