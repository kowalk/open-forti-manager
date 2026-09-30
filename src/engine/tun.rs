//! TUN interface — lightweight Linux TUN via raw ioctl + ip commands.

use crate::engine::nethelper::Op;
use crate::engine::VpnError;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

// ioctl request codes (linux/sockios.h)
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891C;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const SIOCSIFMTU: libc::c_ulong = 0x8922;
const IFF_UP: libc::c_short = 0x1;

#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 24],
}

/// `struct ifreq` variant carrying a sockaddr_in, padded to the full 40-byte
/// size the kernel copies for SIOCSIFADDR / SIOCSIFNETMASK.
#[repr(C)]
struct IfReqAddr {
    name: [u8; IFNAMSIZ],
    addr: libc::sockaddr_in,
    _pad: [u8; 8],
}

/// `struct ifreq` variant carrying `ifr_mtu` (an int), padded to 40 bytes.
#[repr(C)]
struct IfReqMtu {
    name: [u8; IFNAMSIZ],
    mtu: libc::c_int,
    _pad: [u8; 20],
}

fn set_name(ifr: &mut IfReq, name: &str) {
    let b = name.as_bytes();
    let len = b.len().min(IFNAMSIZ - 1);
    ifr.name[..len].copy_from_slice(&b[..len]);
}

fn set_name_addr(ifr: &mut IfReqAddr, name: &str) {
    let b = name.as_bytes();
    let len = b.len().min(IFNAMSIZ - 1);
    ifr.name[..len].copy_from_slice(&b[..len]);
}

fn sockaddr_in(ip: Ipv4Addr) -> libc::sockaddr_in {
    // Safe zero-init; fill the fields the kernel reads.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr.s_addr = u32::from(ip).to_be(); // network byte order
    sa
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
        // Mark the device as ours: the privileged helper only touches TUN
        // devices owned by the calling user.
        let uid = unsafe { libc::getuid() } as libc::c_ulong;
        if unsafe { libc::ioctl(fd, TUNSETOWNER, uid) } < 0 {
            return Err(VpnError::Io(io::Error::last_os_error()));
        }
        // Non-blocking so the relay loop can poll TUN + TLS without stalling.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        }
        log::info!("TUN {} created (non-blocking)", actual);
        Ok(Self { file: f, name: actual })
    }

    pub fn name(&self) -> &str { &self.name }

    pub fn raw_fd(&self) -> std::os::fd::RawFd { self.file.as_raw_fd() }

    /// Kernel interface index (used to prove a later command targets *this*
    /// session's device and not a newer one that reused the name).
    pub fn ifindex(&self) -> Option<u32> {
        std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", self.name))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Bring the interface UP and assign the /32 address (replacing any
    /// previous one, so this is also used to re-address after IPCP).
    ///
    /// Primary path is in-process `ioctl`, which works with CAP_NET_ADMIN (the
    /// capability the .deb grants) and needs no sudo/exec. Falls back to
    /// `sudo -n /usr/sbin/ip` (absolute path, matching the packaged sudoers
    /// rule) for the no-capability case.
    pub fn configure(&self, ip: Ipv4Addr) -> Result<(), VpnError> {
        let name = self.name.clone();
        if ip.is_unspecified() {
            return Err(VpnError::Route("no IP address assigned by the gateway".into()));
        }

        match self.ioctl_configure(&name, ip) {
            Ok(()) => {
                log::info!("TUN {} configured {} via ioctl", name, ip);
                return Ok(());
            }
            Err(e) => log::warn!("TUN ioctl configure failed: {} — trying sudo ip", e),
        }

        crate::engine::netcfg::tun_ops_noninteractive(&name, self.ifindex(), vec![
            Op::Addr { ip: ip.to_string() },
            Op::LinkUp,
        ]).map_err(|e| VpnError::Route(format!("Failed to set TUN IP address: {}", e)))?;
        log::info!("TUN {} addr {} (helper)", name, ip);
        Ok(())
    }

    /// Current interface MTU as the kernel reports it.
    pub fn mtu(&self) -> Option<u16> {
        std::fs::read_to_string(format!("/sys/class/net/{}/mtu", self.name))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Set the interface MTU (ioctl first, `sudo ip link` fallback).
    pub fn set_mtu(&self, mtu: u16) -> Result<(), VpnError> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock >= 0 {
            let mut req = IfReqMtu { name: [0u8; IFNAMSIZ], mtu: mtu as libc::c_int, _pad: [0u8; 20] };
            let b = self.name.as_bytes();
            let len = b.len().min(IFNAMSIZ - 1);
            req.name[..len].copy_from_slice(&b[..len]);
            let rc = unsafe { libc::ioctl(sock, SIOCSIFMTU, &req as *const _ as *const libc::c_void) };
            let err = io::Error::last_os_error();
            unsafe { libc::close(sock); }
            if rc == 0 {
                log::info!("TUN {} MTU {} via ioctl", self.name, mtu);
                return Ok(());
            }
            log::warn!("SIOCSIFMTU failed: {} — trying sudo ip", err);
        }
        crate::engine::netcfg::tun_ops_noninteractive(&self.name, self.ifindex(), vec![Op::Mtu { mtu }])
            .map_err(|e| VpnError::Route(format!("Failed to set TUN MTU: {}", e)))
    }

    /// Assign the /32 address and bring the interface UP using ioctls.
    /// Requires CAP_NET_ADMIN (or root); returns the OS error otherwise.
    fn ioctl_configure(&self, name: &str, ip: Ipv4Addr) -> Result<(), VpnError> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(VpnError::Io(io::Error::last_os_error()));
        }
        // Ensure the socket is closed on every return path.
        let result = (|| {
            // Set interface address.
            let mut areq = IfReqAddr { name: [0u8; IFNAMSIZ], addr: sockaddr_in(ip), _pad: [0u8; 8] };
            set_name_addr(&mut areq, name);
            if unsafe { libc::ioctl(sock, SIOCSIFADDR, &areq as *const _ as *const libc::c_void) } < 0 {
                return Err(VpnError::Io(io::Error::last_os_error()));
            }
            // Set netmask 255.255.255.255 (/32 point-to-point).
            let mut nreq = IfReqAddr {
                name: [0u8; IFNAMSIZ],
                addr: sockaddr_in(Ipv4Addr::new(255, 255, 255, 255)),
                _pad: [0u8; 8],
            };
            set_name_addr(&mut nreq, name);
            // Netmask failure is non-fatal for a /32 host route; log and continue.
            if unsafe { libc::ioctl(sock, SIOCSIFNETMASK, &nreq as *const _ as *const libc::c_void) } < 0 {
                log::debug!("SIOCSIFNETMASK failed (non-fatal): {}", io::Error::last_os_error());
            }
            // Bring the interface UP: read flags, OR IFF_UP, write back.
            let mut freq = IfReq { name: [0u8; IFNAMSIZ], flags: 0, _pad: [0u8; 24] };
            set_name(&mut freq, name);
            if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &freq as *const _ as *const libc::c_void) } < 0 {
                return Err(VpnError::Io(io::Error::last_os_error()));
            }
            freq.flags |= IFF_UP;
            if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &freq as *const _ as *const libc::c_void) } < 0 {
                return Err(VpnError::Io(io::Error::last_os_error()));
            }
            Ok(())
        })();
        unsafe { libc::close(sock); }
        result
    }
}

impl Read for TunDevice {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> { self.file.read(b) }
}
impl Write for TunDevice {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> { self.file.write(b) }
    fn flush(&mut self) -> io::Result<()> { self.file.flush() }
}
