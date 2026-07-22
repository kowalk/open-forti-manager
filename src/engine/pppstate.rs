//! Native PPP state machine — LCP + IPCP negotiation (RFC 1661, 1332).
//!
//! Implements the client side of PPP over the Fortinet SSL-VPN tunnel:
//! - LCP: link establishment (MRU, magic number, auth rejection)
//! - IPCP: IP address + DNS negotiation
//!
//! No external pppd needed. Frames are exchanged as raw PPP packets
//! (protocol + payload) — the caller handles HDLC framing.

use std::net::Ipv4Addr;

// PPP protocol numbers
pub const PROTO_LCP: u16 = 0xC021;
pub const PROTO_IPCP: u16 = 0x8021;
pub const PROTO_IPV4: u16 = 0x0021;

// PPP/LCP/IPCP codes
const CODE_CONF_REQ: u8 = 1;
const CODE_CONF_ACK: u8 = 2;
const CODE_CONF_NAK: u8 = 3;
const CODE_CONF_REJ: u8 = 4;
const CODE_TERM_REQ: u8 = 5;
const CODE_TERM_ACK: u8 = 6;
const CODE_CODE_REJ: u8 = 7;
const CODE_ECHO_REQ: u8 = 9;
const CODE_ECHO_REP: u8 = 10;

// LCP option types
const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_AUTH: u8 = 3;
const LCP_OPT_MAGIC: u8 = 5;

// IPCP option types
const IPCP_OPT_ADDR: u8 = 3;
const IPCP_OPT_DNS1: u8 = 129;
const IPCP_OPT_DNS2: u8 = 131;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Lcp,
    Ipcp,
    Network, // Ready — IP traffic can flow
    Dead,
}

/// PPP negotiation state machine.
pub struct PppState {
    pub phase: Phase,
    magic: u32,
    ident: u8,
    lcp_acked_local: bool,   // gateway acked our LCP Config-Request
    lcp_acked_remote: bool,  // we acked gateway's LCP Config-Request
    ipcp_acked_local: bool,
    ipcp_acked_remote: bool,
    /// Our assigned IP (from config or IPCP negotiation).
    pub local_ip: Ipv4Addr,
    pub dns1: Ipv4Addr,
    pub dns2: Ipv4Addr,
    /// Outgoing PPP frames queued by the state machine.
    pub outbox: Vec<Vec<u8>>,
    /// Bounded Configure-Request counters to prevent NAK/REJ ping-pong loops.
    lcp_reqs: u32,
    ipcp_reqs: u32,
}

/// Max Configure-Requests per protocol before giving up (RFC 1661 Max-Configure).
const MAX_CONF_REQ: u32 = 10;

impl PppState {
    pub fn new(local_ip: Ipv4Addr, magic: u32) -> Self {
        Self {
            phase: Phase::Lcp,
            magic,
            ident: 1,
            lcp_acked_local: false,
            lcp_acked_remote: false,
            ipcp_acked_local: false,
            ipcp_acked_remote: false,
            local_ip,
            dns1: Ipv4Addr::UNSPECIFIED,
            dns2: Ipv4Addr::UNSPECIFIED,
            outbox: Vec::new(),
            lcp_reqs: 0,
            ipcp_reqs: 0,
        }
    }

    fn next_id(&mut self) -> u8 {
        let id = self.ident;
        self.ident = self.ident.wrapping_add(1);
        id
    }

    /// Kick off negotiation: send LCP Configure-Request.
    pub fn start(&mut self) {
        self.send_lcp_conf_req();
    }

    /// Build our LCP Configure-Request (MRU + magic number). Bounded so a
    /// NAK/REJ storm can't ping-pong forever — after MAX_CONF_REQ the link dies.
    fn send_lcp_conf_req(&mut self) {
        self.lcp_reqs += 1;
        if self.lcp_reqs > MAX_CONF_REQ {
            log::warn!("LCP: exceeded {} Configure-Requests, giving up", MAX_CONF_REQ);
            self.phase = Phase::Dead;
            return;
        }
        let id = self.next_id();
        let magic = self.magic.to_be_bytes();
        let opts = vec![
            LCP_OPT_MRU, 4, 0x05, 0xDC,                     // MRU 1500
            LCP_OPT_MAGIC, 6, magic[0], magic[1], magic[2], magic[3],
        ];
        self.outbox.push(build_ppp(PROTO_LCP, CODE_CONF_REQ, id, &opts));
    }

    /// Build our IPCP Configure-Request (request our IP + DNS). Bounded, as above.
    fn send_ipcp_conf_req(&mut self) {
        self.ipcp_reqs += 1;
        if self.ipcp_reqs > MAX_CONF_REQ {
            log::warn!("IPCP: exceeded {} Configure-Requests, giving up", MAX_CONF_REQ);
            self.phase = Phase::Dead;
            return;
        }
        let id = self.next_id();
        let ip = self.local_ip.octets();
        let opts = vec![
            IPCP_OPT_ADDR, 6, ip[0], ip[1], ip[2], ip[3],
            IPCP_OPT_DNS1, 6, 0, 0, 0, 0,
            IPCP_OPT_DNS2, 6, 0, 0, 0, 0,
        ];
        self.outbox.push(build_ppp(PROTO_IPCP, CODE_CONF_REQ, id, &opts));
    }

    /// Process an incoming PPP frame (protocol + payload).
    /// Returns Some(ip_packet) if this is IP data for the TUN.
    pub fn handle(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < 2 { return None; }
        let proto = u16::from_be_bytes([frame[0], frame[1]]);
        let payload = &frame[2..];

        match proto {
            PROTO_LCP => { self.handle_lcp(payload); None }
            PROTO_IPCP => { self.handle_ipcp(payload); None }
            PROTO_IPV4 => Some(payload.to_vec()),
            _ => None,
        }
    }

    fn handle_lcp(&mut self, pkt: &[u8]) {
        if pkt.len() < 4 { return; }
        let code = pkt[0];
        let id = pkt[1];
        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let body = &pkt[4..len.min(pkt.len())];

        match code {
            CODE_CONF_REQ => {
                // Gateway wants to configure the link — ACK its options
                // (we accept whatever it asks; strip auth if present).
                let mut acceptable = Vec::new();
                let mut reject = Vec::new();
                let mut i = 0;
                while i + 2 <= body.len() {
                    let opt = body[i];
                    let olen = body[i + 1] as usize;
                    if olen < 2 || i + olen > body.len() { break; }
                    let chunk = &body[i..i + olen];
                    if opt == LCP_OPT_AUTH {
                        // Reject auth — we don't do PAP/CHAP
                        reject.extend_from_slice(chunk);
                    } else {
                        acceptable.extend_from_slice(chunk);
                    }
                    i += olen;
                }
                if !reject.is_empty() {
                    self.outbox.push(build_ppp(PROTO_LCP, CODE_CONF_REJ, id, &reject));
                } else {
                    self.outbox.push(build_ppp(PROTO_LCP, CODE_CONF_ACK, id, &acceptable));
                    self.lcp_acked_remote = true;
                }
            }
            CODE_CONF_ACK => {
                self.lcp_acked_local = true;
            }
            CODE_CONF_NAK | CODE_CONF_REJ => {
                // Retry with a simpler request
                self.send_lcp_conf_req();
            }
            CODE_ECHO_REQ => {
                let magic = self.magic.to_be_bytes();
                self.outbox.push(build_ppp(PROTO_LCP, CODE_ECHO_REP, id, &magic));
            }
            CODE_TERM_REQ => {
                self.outbox.push(build_ppp(PROTO_LCP, CODE_TERM_ACK, id, &[]));
                self.phase = Phase::Dead;
            }
            _ => {}
        }

        // Both directions acked → move to IPCP
        if self.lcp_acked_local && self.lcp_acked_remote && self.phase == Phase::Lcp {
            self.phase = Phase::Ipcp;
            self.send_ipcp_conf_req();
        }
    }

    fn handle_ipcp(&mut self, pkt: &[u8]) {
        if pkt.len() < 4 { return; }
        let code = pkt[0];
        let id = pkt[1];
        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let body = &pkt[4..len.min(pkt.len())];

        match code {
            CODE_CONF_REQ => {
                // Gateway's IPCP request — ACK it
                self.outbox.push(build_ppp(PROTO_IPCP, CODE_CONF_ACK, id, body));
                self.ipcp_acked_remote = true;
            }
            CODE_CONF_ACK => {
                self.ipcp_acked_local = true;
            }
            CODE_CONF_NAK => {
                // Gateway suggests values — adopt them
                let mut i = 0;
                while i + 2 <= body.len() {
                    let opt = body[i];
                    let olen = body[i + 1] as usize;
                    if olen < 2 || i + olen > body.len() { break; }
                    if olen == 6 {
                        let addr = Ipv4Addr::new(body[i+2], body[i+3], body[i+4], body[i+5]);
                        match opt {
                            IPCP_OPT_ADDR => self.local_ip = addr,
                            IPCP_OPT_DNS1 => self.dns1 = addr,
                            IPCP_OPT_DNS2 => self.dns2 = addr,
                            _ => {}
                        }
                    }
                    i += olen;
                }
                // Re-request with the NAK'd values
                self.send_ipcp_conf_req();
            }
            CODE_CONF_REJ => {
                // Options rejected — request just our address
                let id = self.next_id();
                let ip = self.local_ip.octets();
                let opts = vec![IPCP_OPT_ADDR, 6, ip[0], ip[1], ip[2], ip[3]];
                self.outbox.push(build_ppp(PROTO_IPCP, CODE_CONF_REQ, id, &opts));
            }
            _ => {}
        }

        if self.ipcp_acked_local && self.ipcp_acked_remote && self.phase == Phase::Ipcp {
            self.phase = Phase::Network;
        }
    }
}

/// Build a PPP frame: protocol(2) + code(1) + id(1) + length(2) + options.
fn build_ppp(proto: u16, code: u8, id: u8, options: &[u8]) -> Vec<u8> {
    let len = (4 + options.len()) as u16;
    let mut frame = Vec::with_capacity(2 + len as usize);
    frame.extend_from_slice(&proto.to_be_bytes());
    frame.push(code);
    frame.push(id);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(options);
    frame
}

/// Wrap a raw IP packet in a PPP IPv4 frame.
pub fn wrap_ip(ip: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + ip.len());
    frame.extend_from_slice(&PROTO_IPV4.to_be_bytes());
    frame.extend_from_slice(ip);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_sends_lcp() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 0x12345678);
        ppp.start();
        assert_eq!(ppp.outbox.len(), 1);
        let frame = &ppp.outbox[0];
        assert_eq!(u16::from_be_bytes([frame[0], frame[1]]), PROTO_LCP);
        assert_eq!(frame[2], CODE_CONF_REQ);
    }

    #[test]
    fn test_lcp_conf_req_acked() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 0x12345678);
        // Gateway sends LCP Config-Request with MRU
        let gw_req = build_ppp(PROTO_LCP, CODE_CONF_REQ, 1, &[LCP_OPT_MRU, 4, 0x05, 0xDC]);
        ppp.handle(&gw_req);
        // We should ACK it
        assert!(ppp.lcp_acked_remote);
        assert!(ppp.outbox.iter().any(|f| f[2] == CODE_CONF_ACK));
    }

    #[test]
    fn test_ip_passthrough() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 0x12345678);
        let ip_frame = wrap_ip(b"\x45\x00test");
        let result = ppp.handle(&ip_frame);
        assert_eq!(result, Some(b"\x45\x00test".to_vec()));
    }
}
