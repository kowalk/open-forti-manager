//! Shared TUN device handle carrying PPP frames.
//!
//! This is the native data path — there is no external `pppd`; the app owns
//! the TUN device directly. Creating it needs root or CAP_NET_ADMIN.

use crate::engine::tun::TunDevice;
use crate::engine::VpnError;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Shared TUN device handle (supports concurrent read/write via Mutex).
pub struct TunHandle {
    tun: Arc<Mutex<TunDevice>>,
}

impl TunHandle {
    /// Create and open a TUN device. Needs root or CAP_NET_ADMIN.
    pub fn open() -> Result<Self, VpnError> {
        let tun = TunDevice::create("vpn%d")?;
        log::info!("TUN device {} created", tun.name());
        Ok(Self { tun: Arc::new(Mutex::new(tun)) })
    }

    /// Clone the TUN handle for reading.
    pub fn reader(&self) -> TunReader {
        TunReader { inner: self.tun.clone() }
    }

    /// Clone the TUN handle for writing.
    pub fn writer(&self) -> TunWriter {
        TunWriter { inner: self.tun.clone() }
    }

    pub fn configure(&self, ip: &str) -> Result<(), VpnError> {
        self.tun.lock().unwrap().configure(ip)
    }

    pub fn iface_name(&self) -> String {
        self.tun.lock().unwrap().name().to_string()
    }
}

pub struct TunReader { inner: Arc<Mutex<TunDevice>> }
pub struct TunWriter { inner: Arc<Mutex<TunDevice>> }

impl Read for TunReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
}

impl Write for TunWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().unwrap().flush()
    }
}
