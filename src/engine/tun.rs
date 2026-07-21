//! TUN interface — lightweight Linux TUN via raw ioctl + ip commands.

use crate::engine::VpnError;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 24],
}

fn set_name(ifr: &mut IfReq, name: &str) {
    let b = name.as_bytes();
    let len = b.len().min(IFNAMSIZ - 1);
    ifr.name[..len].copy_from_slice(&b[..len]);
}

pub struct TunDevice {
    file: std::fs::File,
    name: String,
}

impl TunDevice {
    pub fn create(name: &str) -> Result<Self, VpnError> {
        let f = OpenOptions::new().read(true).write(true)
            .open("/dev/net/tun").map_err(VpnError::Io)?;
        let fd = f.as_raw_fd();
        let mut ifr = IfReq { name: [0u8; IFNAMSIZ], flags: IFF_TUN | IFF_NO_PI, _pad: [0u8; 24] };
        set_name(&mut ifr, name);
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const IfReq as *const libc::c_void) };
        if ret < 0 { return Err(VpnError::Io(io::Error::last_os_error())); }
        let actual = String::from_utf8_lossy(&ifr.name).trim_end_matches('\0').to_string();
        // Non-blocking so the relay loop can poll TUN + TLS without stalling.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        }
        log::info!("TUN {} created (non-blocking)", actual);
        Ok(Self { file: f, name: actual })
    }

    pub fn name(&self) -> &str { &self.name }

    /// Bring UP and assign IP. Uses sudo (with NOPASSWD) as the ioctl
    /// approach is unreliable across kernel versions.
    pub fn configure(&self, ip: &str) -> Result<(), VpnError> {
        let name = self.name.clone();
        let addr = format!("{}/32", ip);

        // Try ioctl first (if caps are set)
        let ioctl_result: Result<(), VpnError> = (|| {
            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if sock < 0 { return Err(VpnError::Io(io::Error::last_os_error())); }
            let mut ifr = IfReq { name: [0u8; IFNAMSIZ], flags: 0, _pad: [0u8; 24] };
            set_name(&mut ifr, &name);
            let ret = unsafe { libc::ioctl(sock, 0x8914, &ifr as *const IfReq as *const libc::c_void) };
            if ret < 0 { unsafe { libc::close(sock); } return Err(VpnError::Io(io::Error::last_os_error())); }
            ifr.flags |= 0x1; // IFF_UP
            let ret = unsafe { libc::ioctl(sock, 0x8914, &ifr as *const IfReq as *const libc::c_void) };
            unsafe { libc::close(sock); }
            if ret < 0 { return Err(VpnError::Io(io::Error::last_os_error())); }
            log::info!("TUN {} UP (ioctl)", name);
            Ok(())
        })();
        match ioctl_result {
            Ok(_) => log::info!("TUN {} UP via ioctl", name),
            Err(e) => log::warn!("TUN UP via ioctl failed: {} — trying sudo", e),
        }

        // Set IP via sudo (most reliable)
        let output = std::process::Command::new("sudo")
            .args(["-n", "ip", "addr", "add", &addr, "dev", &name])
            .output();
        match &output {
            Ok(o) if o.status.success() => {
                log::info!("TUN {} addr {} (sudo ip)", name, ip);
                return Ok(());
            }
            Ok(o) => log::warn!("sudo ip failed: {} {}", o.status, String::from_utf8_lossy(&o.stderr)),
            Err(e) => log::warn!("sudo ip error: {}", e),
        }

        // Fallback: try without sudo
        let output2 = std::process::Command::new("ip")
            .args(["addr", "add", &addr, "dev", &name])
            .output();
        match &output2 {
            Ok(o) if o.status.success() => {
                log::info!("TUN {} addr {} (ip)", name, ip);
                Ok(())
            }
            Ok(o) => {
                let sudo_err = output.as_ref().map(|o| String::from_utf8_lossy(&o.stderr).to_string()).unwrap_or_default();
                log::error!("ALL IP METHODS FAILED. sudo={} direct={}", sudo_err, String::from_utf8_lossy(&o.stderr));
                Err(VpnError::Route("Failed to set TUN IP address".into()))
            }
            Err(e) => Err(VpnError::Route(format!("ip command error: {}", e))),
        }
    }
}

impl Read for TunDevice {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> { self.file.read(b) }
}
impl Write for TunDevice {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> { self.file.write(b) }
    fn flush(&mut self) -> io::Result<()> { self.file.flush() }
}
