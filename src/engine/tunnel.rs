//! VPN tunnel relay — drives the native PPP state machine.
//!
//! Flow: gateway <--tunnel framing--> PppState <--raw IP--> TUN device.

use crate::engine::hdlc;
use crate::engine::pppstate::{Phase, PppState};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const READ_BUF: usize = 8192;

pub fn run_relay(
    mut tls: (impl Read + Write),
    mut tun_w: impl Write,
    mut tun_r: impl Read,
    local_ip: Ipv4Addr,
    log_tx: Option<std::sync::mpsc::Sender<String>>,
    stop: Arc<AtomicBool>,
) {
    let log = |msg: &str| {
        log::info!("{}", msg);
        if let Some(ref tx) = log_tx { let _ = tx.send(msg.to_string()); }
    };

    let magic = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() & 0xFFFF_FFFF) as u32;
    let mut ppp = PppState::new(local_ip, magic);

    // Kick off LCP negotiation.
    ppp.start();
    flush_outbox(&mut ppp, &mut tls, &log);
    log("PPP: LCP Configure-Request sent, negotiating…");

    let mut tmp = [0u8; READ_BUF];
    let mut acc: Vec<u8> = Vec::with_capacity(READ_BUF);
    let mut iter: u64 = 0;
    let mut recv_count: u64 = 0;
    let mut announced_network = false;
    let mut idle = 0u32;

    // Negotiation must reach the NETWORK phase within this window, or we abort
    // instead of showing "Connecting…" forever when the gateway stalls.
    const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(25);
    let started = SystemTime::now();

    loop {
        if stop.load(Ordering::Relaxed) {
            log("Disconnect requested — closing tunnel.");
            break;
        }
        // Enforce the PPP negotiation deadline (only until NETWORK is reached).
        if ppp.phase != Phase::Network
            && started.elapsed().map(|e| e > NEGOTIATION_TIMEOUT).unwrap_or(false)
        {
            log("PPP negotiation timed out — the gateway did not complete LCP/IPCP. Aborting.");
            break;
        }
        iter += 1;
        let mut did_work = false;

        // --- gateway → PPP ---
        match tls.read(&mut tmp) {
            Ok(0) => { log(&format!("TLS closed by gateway (iter {})", iter)); break; }
            Ok(n) => {
                did_work = true;
                acc.extend_from_slice(&tmp[..n]);

                // Guard against an HTTP error reply where a PPP frame is expected.
                if acc.len() >= 6 && &acc[..6] == b"HTTP/1" {
                    log("Gateway returned HTTP instead of a PPP frame — tunnel mode likely not allowed (check realm).");
                    break;
                }

                // Pop every complete frame currently buffered.
                loop {
                    match hdlc::pop_frame(&acc) {
                        Some((frame, consumed)) => {
                            acc.drain(..consumed);
                            if frame.is_empty() { continue; } // bad header, skipped a byte
                            recv_count += 1;
                            if recv_count <= 40 {
                                let proto = u16::from_be_bytes([frame[0], frame[1]]);
                                log(&format!("PPP recv #{} proto=0x{:04x} len={} phase={:?}",
                                    recv_count, proto, frame.len(), ppp.phase));
                            }
                            if let Some(ip) = ppp.handle(&frame) {
                                let _ = tun_w.write_all(&ip);
                            }
                        }
                        None => break,
                    }
                }
                flush_outbox(&mut ppp, &mut tls, &log);

                if ppp.phase == Phase::Network && !announced_network {
                    announced_network = true;
                    log("PPP: NETWORK phase reached — tunnel is fully established!");
                }
                if ppp.phase == Phase::Dead { log("PPP: link terminated by gateway"); break; }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => { log(&format!("TLS read error: {}", e)); break; }
        }

        // --- TUN → gateway (only once IP is up) ---
        if ppp.phase == Phase::Network {
            match tun_r.read(&mut tmp) {
                Ok(0) => {}
                Ok(n) if n > 0 => {
                    did_work = true;
                    if tmp[0] >> 4 == 4 {
                        let frame = hdlc::frame_packet(&tmp[..n]);
                        if tls.write_all(&frame).is_err() { log("TLS write failed"); break; }
                        let _ = tls.flush();
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => { log(&format!("TUN read error: {}", e)); break; }
            }
        }

        if did_work {
            idle = 0;
        } else {
            idle = idle.saturating_add(1);
            // Back off gently when quiet to avoid busy-spinning.
            std::thread::sleep(Duration::from_millis(if idle > 20 { 10 } else { 2 }));
        }
    }

    log(&format!("Relay stopped after {} iterations, {} frames received", iter, recv_count));
}

/// Send all queued PPP frames to the gateway (with tunnel framing).
fn flush_outbox(ppp: &mut PppState, tls: &mut (impl Read + Write), log: &impl Fn(&str)) {
    let frames: Vec<Vec<u8>> = ppp.outbox.drain(..).collect();
    for frame in frames {
        let wire = hdlc::frame_raw(&frame);
        if tls.write_all(&wire).is_err() {
            log("PPP: failed to send frame");
            return;
        }
    }
    let _ = tls.flush();
}
