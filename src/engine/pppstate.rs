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
const CODE_PROTO_REJ: u8 = 8;
const CODE_ECHO_REQ: u8 = 9;
const CODE_ECHO_REP: u8 = 10;

// LCP option types
const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_ACCM: u8 = 2;
const LCP_OPT_AUTH: u8 = 3;
const LCP_OPT_MAGIC: u8 = 5;
const LCP_OPT_PFC: u8 = 7;
const LCP_OPT_ACFC: u8 = 8;

// IPCP option types
const IPCP_OPT_ADDR: u8 = 3;
const IPCP_OPT_DNS1: u8 = 129;
const IPCP_OPT_DNS2: u8 = 131;

/// MRU we request, and the TUN MTU used when the gateway does not advertise one.
/// Matches openfortivpn's `mru 1354`, which is proven against FortiGate.
pub const DEFAULT_MRU: u16 = 1354;

/// Unanswered LCP Echo-Requests tolerated before the link is declared dead.
pub const MAX_ECHO_OUTSTANDING: u32 = 4;

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
    /// Identifiers of our outstanding Configure-Requests (ACKs must match).
    lcp_req_id: u8,
    ipcp_req_id: u8,
    /// MRU we ask for; adjusted by a gateway NAK, dropped after a REJ.
    our_mru: Option<u16>,
    /// Whether the magic-number option is still being requested.
    send_magic: bool,
    /// Whether to keep requesting DNS options (false once the gateway rejects them).
    request_dns: bool,
    /// MRU advertised by the gateway (max frame it accepts); None = not advertised.
    pub peer_mru: Option<u16>,
    /// Echo-Requests sent without a matching Echo-Reply.
    pub echo_outstanding: u32,
    /// Whether the gateway has ever answered an Echo-Request. Dead-peer
    /// detection is only enforced once it has, so gateways that ignore LCP
    /// echoes are not disconnected.
    pub echo_supported: bool,
    /// Options of our last Configure-Requests, to validate ACKs against.
    lcp_req_opts: Vec<u8>,
    ipcp_req_opts: Vec<u8>,
    /// Non-fatal protocol oddities for the caller to surface.
    pub warnings: Vec<String>,
    /// Human-readable reason when the link goes Dead.
    pub dead_reason: Option<String>,
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
            lcp_req_id: 0,
            ipcp_req_id: 0,
            our_mru: Some(DEFAULT_MRU),
            send_magic: true,
            request_dns: true,
            peer_mru: None,
            echo_outstanding: 0,
            echo_supported: false,
            lcp_req_opts: Vec::new(),
            ipcp_req_opts: Vec::new(),
            warnings: Vec::new(),
            dead_reason: None,
        }
    }

    fn die(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        log::warn!("PPP: {}", reason);
        self.dead_reason = Some(reason);
        self.phase = Phase::Dead;
    }

    /// MTU to apply to the TUN device: the gateway's advertised MRU, else the default.
    pub fn tun_mtu(&self) -> u16 {
        self.peer_mru.unwrap_or(DEFAULT_MRU).clamp(576, 1500)
    }

    /// Send an LCP Echo-Request (keepalive / dead-peer detection).
    /// Returns false once too many requests went unanswered (link is dead).
    pub fn send_echo_request(&mut self) -> bool {
        if self.echo_outstanding >= MAX_ECHO_OUTSTANDING {
            if self.echo_supported {
                self.die(format!("gateway stopped answering LCP echo requests ({} unanswered)", MAX_ECHO_OUTSTANDING));
                return false;
            }
            // Gateway never answered: it doesn't do echoes; don't count that as dead.
            return true;
        }
        self.echo_outstanding += 1;
        let id = self.next_id();
        let magic = self.echo_magic();
        self.outbox.push(build_ppp(PROTO_LCP, CODE_ECHO_REQ, id, &magic));
        true
    }

    /// Magic number to put in echo packets: zero unless it was negotiated
    /// (RFC 1661 §5.8).
    fn echo_magic(&self) -> [u8; 4] {
        if self.send_magic { self.magic.to_be_bytes() } else { [0; 4] }
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
            self.die(format!("LCP: exceeded {} Configure-Requests, giving up", MAX_CONF_REQ));
            return;
        }
        let id = self.next_id();
        self.lcp_req_id = id;
        let mut opts = Vec::new();
        if let Some(mru) = self.our_mru {
            let m = mru.to_be_bytes();
            opts.extend_from_slice(&[LCP_OPT_MRU, 4, m[0], m[1]]);
        }
        if self.send_magic {
            let magic = self.magic.to_be_bytes();
            opts.extend_from_slice(&[LCP_OPT_MAGIC, 6, magic[0], magic[1], magic[2], magic[3]]);
        }
        self.lcp_req_opts = opts.clone();
        self.outbox.push(build_ppp(PROTO_LCP, CODE_CONF_REQ, id, &opts));
    }

    /// Build our IPCP Configure-Request (request our IP + DNS). Bounded, as above.
    fn send_ipcp_conf_req(&mut self) {
        self.ipcp_reqs += 1;
        if self.ipcp_reqs > MAX_CONF_REQ {
            self.die(format!("IPCP: exceeded {} Configure-Requests, giving up", MAX_CONF_REQ));
            return;
        }
        let id = self.next_id();
        self.ipcp_req_id = id;
        let ip = self.local_ip.octets();
        let mut opts = vec![IPCP_OPT_ADDR, 6, ip[0], ip[1], ip[2], ip[3]];
        if self.request_dns {
            // Re-send whatever the gateway NAK'd us (0.0.0.0 = "please tell me").
            let d1 = self.dns1.octets();
            let d2 = self.dns2.octets();
            opts.extend_from_slice(&[IPCP_OPT_DNS1, 6, d1[0], d1[1], d1[2], d1[3]]);
            opts.extend_from_slice(&[IPCP_OPT_DNS2, 6, d2[0], d2[1], d2[2], d2[3]]);
        }
        self.ipcp_req_opts = opts.clone();
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
            PROTO_IPV4 if self.phase == Phase::Network => Some(payload.to_vec()),
            PROTO_IPV4 => None,
            _ => {
                // RFC 1661 §5.7: answer unknown protocols (e.g. IPV6CP, CCP) with
                // an LCP Protocol-Reject so the gateway stops retrying them.
                if self.phase != Phase::Lcp && self.phase != Phase::Dead {
                    let id = self.next_id();
                    let mut body = frame.to_vec();
                    body.truncate(1500);
                    self.outbox.push(build_ppp(PROTO_LCP, CODE_PROTO_REJ, id, &body));
                }
                None
            }
        }
    }

    /// Split a control packet into (code, id, body), validating the length field.
    fn parse_ctrl(pkt: &[u8]) -> Option<(u8, u8, &[u8])> {
        if pkt.len() < 4 { return None; }
        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if len < 4 || len > pkt.len() { return None; }
        Some((pkt[0], pkt[1], &pkt[4..len]))
    }

    /// Parse a Configure-Request's options strictly: None if any option is
    /// shorter than 2 bytes or overruns the packet (RFC 1661 §6: discard).
    fn options_strict(body: &[u8]) -> Option<Vec<(u8, &[u8])>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < body.len() {
            if i + 2 > body.len() {
                return None;
            }
            let olen = body[i + 1] as usize;
            if olen < 2 || i + olen > body.len() {
                return None;
            }
            out.push((body[i], &body[i..i + olen]));
            i += olen;
        }
        Some(out)
    }

    /// Iterate well-formed (type, full option bytes) entries of an options list.
    fn options(body: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 2 <= body.len() {
            let olen = body[i + 1] as usize;
            if olen < 2 || i + olen > body.len() { break; }
            out.push((body[i], &body[i..i + olen]));
            i += olen;
        }
        out
    }

    fn handle_lcp(&mut self, pkt: &[u8]) {
        let Some((code, id, body)) = Self::parse_ctrl(pkt) else { return; };

        match code {
            CODE_CONF_REQ => {
                // Options in the gateway's request describe what *it* can
                // receive (RFC 1661 §6): ACKing PFC/ACFC/ACCM only permits us
                // to use them toward the gateway, which we simply never do.
                // Everything we do not understand — auth included — is
                // rejected; recognized options with bad values are NAK'd.
                let Some(opts) = Self::options_strict(body) else {
                    return; // malformed: silently discard
                };
                let mut reject = Vec::new();
                let mut nak = Vec::new();
                let mut peer_mru = None;
                for (opt, chunk) in opts {
                    match (opt, chunk.len()) {
                        (LCP_OPT_MRU, 4) => {
                            let mru = u16::from_be_bytes([chunk[2], chunk[3]]);
                            if mru >= 576 {
                                peer_mru = Some(mru);
                            } else {
                                nak.extend_from_slice(&[LCP_OPT_MRU, 4, 0x05, 0xDC]); // suggest 1500
                            }
                        }
                        (LCP_OPT_MAGIC, 6) => {
                            let m = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                            if m == 0 || m == self.magic {
                                // Zero is invalid; equal to ours suggests a looped-back link.
                                let suggest = (self.magic.rotate_left(7) ^ 0x5A5A_A5A5).max(1);
                                nak.extend_from_slice(&[LCP_OPT_MAGIC, 6]);
                                nak.extend_from_slice(&suggest.to_be_bytes());
                            }
                        }
                        (LCP_OPT_ACCM, 6) | (LCP_OPT_PFC, 2) | (LCP_OPT_ACFC, 2) => {}
                        // Recognized options with a wrong length: NAK with the
                        // correct form (RFC 1661 §6), not Reject.
                        (LCP_OPT_MRU, _) => nak.extend_from_slice(&[LCP_OPT_MRU, 4, 0x05, 0xDC]),
                        (LCP_OPT_MAGIC, _) => {
                            let suggest = (self.magic.rotate_left(7) ^ 0x5A5A_A5A5).max(1);
                            nak.extend_from_slice(&[LCP_OPT_MAGIC, 6]);
                            nak.extend_from_slice(&suggest.to_be_bytes());
                        }
                        (LCP_OPT_ACCM, _) => nak.extend_from_slice(&[LCP_OPT_ACCM, 6, 0, 0, 0, 0]),
                        (LCP_OPT_PFC, _) => nak.extend_from_slice(&[LCP_OPT_PFC, 2]),
                        (LCP_OPT_ACFC, _) => nak.extend_from_slice(&[LCP_OPT_ACFC, 2]),
                        _ => reject.extend_from_slice(chunk),
                    }
                }
                if !reject.is_empty() {
                    self.outbox.push(build_ppp(PROTO_LCP, CODE_CONF_REJ, id, &reject));
                    self.lcp_acked_remote = false;
                } else if !nak.is_empty() {
                    self.outbox.push(build_ppp(PROTO_LCP, CODE_CONF_NAK, id, &nak));
                    self.lcp_acked_remote = false;
                } else {
                    // An ACK must echo the request's options verbatim.
                    self.outbox.push(build_ppp(PROTO_LCP, CODE_CONF_ACK, id, body));
                    self.peer_mru = peer_mru;
                    self.lcp_acked_remote = true;
                }
            }
            CODE_CONF_ACK if id == self.lcp_req_id => {
                // RFC 1661 wants mismatched ACKs discarded, but some FortiGate
                // firmware sends them; accept (interop) and surface a warning.
                if body != self.lcp_req_opts.as_slice() {
                    self.warnings.push("LCP Configure-Ack options differ from our request (accepted)".into());
                }
                self.lcp_acked_local = true;
            }
            CODE_CONF_NAK if id == self.lcp_req_id => {
                for (opt, chunk) in Self::options(body) {
                    match opt {
                        // Adopt the MRU the gateway suggests.
                        LCP_OPT_MRU if chunk.len() == 4 => {
                            self.our_mru = Some(u16::from_be_bytes([chunk[2], chunk[3]]));
                        }
                        // NAK'd magic = loop suspected: pick a new one (RFC 1661 §6.4).
                        LCP_OPT_MAGIC => {
                            self.magic = self.magic.rotate_left(13) ^ 0x9E37_79B9;
                            if self.magic == 0 { self.magic = 1; }
                        }
                        _ => {}
                    }
                }
                self.send_lcp_conf_req();
            }
            CODE_CONF_REJ if id == self.lcp_req_id => {
                // Stop requesting whatever the gateway refused.
                for (opt, _) in Self::options(body) {
                    match opt {
                        LCP_OPT_MRU => self.our_mru = None,
                        LCP_OPT_MAGIC => self.send_magic = false,
                        _ => {}
                    }
                }
                self.send_lcp_conf_req();
            }
            CODE_ECHO_REQ => {
                let magic = self.echo_magic();
                self.outbox.push(build_ppp(PROTO_LCP, CODE_ECHO_REP, id, &magic));
            }
            CODE_ECHO_REP => {
                self.echo_outstanding = 0;
                self.echo_supported = true;
            }
            CODE_TERM_REQ => {
                self.outbox.push(build_ppp(PROTO_LCP, CODE_TERM_ACK, id, &[]));
                self.die("LCP: gateway terminated the link");
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
        let Some((code, id, body)) = Self::parse_ctrl(pkt) else { return; };

        match code {
            CODE_CONF_REQ => {
                // Gateway's IPCP request: only a well-formed IP-Address option
                // is ACKed; anything else (e.g. IP-Compression-Protocol, which
                // would only permit *us* to compress, RFC 1332 §4) is rejected.
                // A malformed IP-Address is rejected rather than NAK'd: a NAK
                // would have to suggest the gateway's own address, which only
                // the gateway knows.
                let Some(opts) = Self::options_strict(body) else {
                    return; // malformed: silently discard
                };
                let mut reject = Vec::new();
                for (opt, chunk) in opts {
                    if !(opt == IPCP_OPT_ADDR && chunk.len() == 6) {
                        reject.extend_from_slice(chunk);
                    }
                }
                if reject.is_empty() {
                    self.outbox.push(build_ppp(PROTO_IPCP, CODE_CONF_ACK, id, body));
                    self.ipcp_acked_remote = true;
                } else {
                    self.outbox.push(build_ppp(PROTO_IPCP, CODE_CONF_REJ, id, &reject));
                    self.ipcp_acked_remote = false;
                }
            }
            CODE_CONF_ACK if id == self.ipcp_req_id => {
                if body != self.ipcp_req_opts.as_slice() {
                    // Interop: accept, but the address the gateway ACKed is the
                    // one it will route to us — adopt it.
                    for (opt, chunk) in Self::options(body) {
                        if opt == IPCP_OPT_ADDR && chunk.len() == 6 {
                            self.local_ip = Ipv4Addr::new(chunk[2], chunk[3], chunk[4], chunk[5]);
                        }
                    }
                    self.warnings.push(format!(
                        "IPCP Configure-Ack options differ from our request (accepted; using {})", self.local_ip));
                }
                self.ipcp_acked_local = true;
            }
            CODE_CONF_NAK if id == self.ipcp_req_id => {
                // Gateway suggests values — adopt them and re-request.
                for (opt, chunk) in Self::options(body) {
                    if chunk.len() == 6 {
                        let addr = Ipv4Addr::new(chunk[2], chunk[3], chunk[4], chunk[5]);
                        match opt {
                            IPCP_OPT_ADDR => self.local_ip = addr,
                            IPCP_OPT_DNS1 => self.dns1 = addr,
                            IPCP_OPT_DNS2 => self.dns2 = addr,
                            _ => {}
                        }
                    }
                }
                self.send_ipcp_conf_req();
            }
            CODE_CONF_REJ if id == self.ipcp_req_id => {
                // DNS options rejected → stop asking for them (the XML config
                // carries DNS anyway). A rejected address cannot be recovered.
                for (opt, _) in Self::options(body) {
                    match opt {
                        IPCP_OPT_DNS1 | IPCP_OPT_DNS2 => self.request_dns = false,
                        IPCP_OPT_ADDR => {
                            self.die("IPCP: gateway rejected the IP-Address option");
                            return;
                        }
                        _ => {}
                    }
                }
                self.send_ipcp_conf_req();
            }
            CODE_TERM_REQ => {
                self.outbox.push(build_ppp(PROTO_IPCP, CODE_TERM_ACK, id, &[]));
                self.die("IPCP: gateway closed the IP layer");
            }
            _ => {}
        }

        if self.ipcp_acked_local && self.ipcp_acked_remote && self.phase == Phase::Ipcp {
            if self.local_ip.is_unspecified() {
                self.die("IPCP: negotiation finished without an assigned IP address");
                return;
            }
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
        // Not forwarded before the IP layer is up.
        assert_eq!(ppp.handle(&ip_frame), None);
        ppp.phase = Phase::Network;
        assert_eq!(ppp.handle(&ip_frame), Some(b"\x45\x00test".to_vec()));
    }

    /// Drive LCP to Opened so IPCP starts; returns the IPCP request id.
    fn open_lcp(ppp: &mut PppState) -> u8 {
        ppp.start();
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 7, &[LCP_OPT_MRU, 4, 0x05, 0x46]));
        let id = ppp.lcp_req_id;
        let opts = ppp.lcp_req_opts.clone();
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_ACK, id, &opts));
        assert_eq!(ppp.phase, Phase::Ipcp);
        assert!(ppp.warnings.is_empty());
        ppp.ipcp_req_id
    }

    fn last_ipcp_opts(ppp: &PppState) -> Vec<u8> {
        let f = ppp.outbox.iter().rev()
            .find(|f| u16::from_be_bytes([f[0], f[1]]) == PROTO_IPCP && f[2] == CODE_CONF_REQ)
            .expect("ipcp request");
        f[6..].to_vec()
    }

    #[test]
    fn test_lcp_records_peer_mru_and_acks_verbatim() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        open_lcp(&mut ppp);
        assert_eq!(ppp.peer_mru, Some(1350));
        assert_eq!(ppp.tun_mtu(), 1350);
        let ack = ppp.outbox.iter().find(|f| f[2] == CODE_CONF_ACK).unwrap();
        assert_eq!(&ack[6..], &[LCP_OPT_MRU, 4, 0x05, 0x46]);
    }

    #[test]
    fn test_default_mtu_without_peer_mru() {
        let ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        assert_eq!(ppp.tun_mtu(), DEFAULT_MRU);
    }

    #[test]
    fn test_ipcp_dns_nak_converges() {
        // Regression: NAK'd DNS values used to be re-sent as 0.0.0.0 forever.
        let mut ppp = PppState::new(Ipv4Addr::new(10, 66, 1, 2), 1);
        let id = open_lcp(&mut ppp);
        let nak = [IPCP_OPT_DNS1, 6, 172, 16, 5, 53, IPCP_OPT_DNS2, 6, 192, 168, 200, 53];
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_NAK, id, &nak));
        let opts = last_ipcp_opts(&ppp);
        assert_eq!(&opts[6..], &nak);
        // Gateway now ACKs; with its own request ACKed we reach Network.
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_REQ, 9, &[IPCP_OPT_ADDR, 6, 1, 1, 1, 1]));
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_ACK, ppp.ipcp_req_id, &opts));
        assert_eq!(ppp.phase, Phase::Network);
        assert_eq!(ppp.ipcp_reqs, 2);
    }

    #[test]
    fn test_ipcp_nak_changes_address() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 66, 1, 2), 1);
        let id = open_lcp(&mut ppp);
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_NAK, id, &[IPCP_OPT_ADDR, 6, 172, 16, 72, 9]));
        assert_eq!(ppp.local_ip, Ipv4Addr::new(172, 16, 72, 9));
    }

    #[test]
    fn test_ipcp_dns_reject_stops_asking() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let id = open_lcp(&mut ppp);
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_REJ, id,
            &[IPCP_OPT_DNS1, 6, 0, 0, 0, 0, IPCP_OPT_DNS2, 6, 0, 0, 0, 0]));
        assert_eq!(last_ipcp_opts(&ppp), vec![IPCP_OPT_ADDR, 6, 10, 0, 0, 1]);
        // A later NAK must not re-add the rejected DNS options.
        let id = ppp.ipcp_req_id;
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_NAK, id, &[IPCP_OPT_ADDR, 6, 10, 0, 0, 2]));
        assert_eq!(last_ipcp_opts(&ppp), vec![IPCP_OPT_ADDR, 6, 10, 0, 0, 2]);
    }

    #[test]
    fn test_stale_ack_ignored() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let id = open_lcp(&mut ppp);
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_ACK, id.wrapping_add(5), &[]));
        assert!(!ppp.ipcp_acked_local);
    }

    #[test]
    fn test_lcp_reject_drops_options() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 0xAABBCCDD);
        ppp.start();
        let id = ppp.lcp_req_id;
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REJ, id, &[LCP_OPT_MAGIC, 6, 0xAA, 0xBB, 0xCC, 0xDD]));
        let req = ppp.outbox.last().unwrap();
        assert_eq!(&req[6..], &[LCP_OPT_MRU, 4, 0x05, 0x4A]);
    }

    #[test]
    fn test_ipcp_terminate_kills_link() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        ppp.phase = Phase::Network;
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_TERM_REQ, 3, &[]));
        assert_eq!(ppp.phase, Phase::Dead);
        assert!(ppp.dead_reason.is_some());
    }

    #[test]
    fn test_short_control_packet_does_not_panic() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        // Declared length 3 (< header size) used to panic on slicing.
        ppp.handle(&[0xC0, 0x21, CODE_CONF_REQ, 1, 0, 3]);
        ppp.handle(&[0x80, 0x21, CODE_CONF_REQ, 1, 0, 2, 9]);
        ppp.handle(&[0xC0]);
    }

    #[test]
    fn test_echo_keepalive() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        ppp.phase = Phase::Network;
        for _ in 0..MAX_ECHO_OUTSTANDING { assert!(ppp.send_echo_request()); }
        assert!(!ppp.echo_supported);
        ppp.handle(&build_ppp(PROTO_LCP, CODE_ECHO_REP, 1, &[0, 0, 0, 0]));
        assert_eq!(ppp.echo_outstanding, 0);
        for _ in 0..MAX_ECHO_OUTSTANDING { assert!(ppp.send_echo_request()); }
        assert!(!ppp.send_echo_request());
        assert_eq!(ppp.phase, Phase::Dead);
    }

    #[test]
    fn test_mismatched_ipcp_ack_adopts_address() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let id = open_lcp(&mut ppp);
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_REQ, 9, &[IPCP_OPT_ADDR, 6, 1, 1, 1, 1]));
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_ACK, id, &[IPCP_OPT_ADDR, 6, 10, 0, 0, 7]));
        assert_eq!(ppp.phase, Phase::Network);
        assert_eq!(ppp.local_ip, Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(ppp.warnings.len(), 1);
    }

    #[test]
    fn test_rejected_magic_means_zero_echo_magic() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 0xAABBCCDD);
        ppp.start();
        let id = ppp.lcp_req_id;
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REJ, id, &[LCP_OPT_MAGIC, 6, 0xAA, 0xBB, 0xCC, 0xDD]));
        ppp.send_echo_request();
        assert_eq!(&ppp.outbox.last().unwrap()[6..], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_nak_magic_picks_new_value() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 0xAABBCCDD);
        ppp.start();
        let id = ppp.lcp_req_id;
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_NAK, id, &[LCP_OPT_MAGIC, 6, 0xAA, 0xBB, 0xCC, 0xDD]));
        assert_ne!(ppp.magic, 0xAABBCCDD);
    }

    #[test]
    fn test_gateway_without_echo_support_not_killed() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        ppp.phase = Phase::Network;
        for _ in 0..20 { assert!(ppp.send_echo_request()); }
        assert_eq!(ppp.phase, Phase::Network);
    }

    fn last(ppp: &PppState) -> (u8, Vec<u8>) {
        let f = ppp.outbox.last().expect("response");
        (f[2], f[6..].to_vec())
    }

    #[test]
    fn test_lcp_acks_receive_side_options_it_never_uses() {
        // PFC/ACFC/ACCM in the gateway's request only permit *us* to use them.
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let opts = [LCP_OPT_MAGIC, 6, 1, 2, 3, 4, LCP_OPT_PFC, 2, LCP_OPT_ACFC, 2, LCP_OPT_ACCM, 6, 0, 0, 0, 0];
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 4, &opts));
        assert_eq!(last(&ppp), (CODE_CONF_ACK, opts.to_vec()));
        assert!(ppp.lcp_acked_remote);
    }

    #[test]
    fn test_lcp_rejects_unknown_and_naks_bad_values() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 0x1111_1111);
        // Callback (13) is unsupported: rejected, alone.
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 1, &[LCP_OPT_MAGIC, 6, 1, 2, 3, 4, 13, 3, 6]));
        assert_eq!(last(&ppp), (CODE_CONF_REJ, vec![13, 3, 6]));
        assert!(!ppp.lcp_acked_remote);
        // MRU below 576 and a zero magic are NAK'd with suggestions.
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 2, &[LCP_OPT_MRU, 4, 0, 100, LCP_OPT_MAGIC, 6, 0, 0, 0, 0]));
        let (code, body) = last(&ppp);
        assert_eq!(code, CODE_CONF_NAK);
        assert_eq!(&body[..4], &[LCP_OPT_MRU, 4, 0x05, 0xDC]);
        assert_eq!(&body[4..6], &[LCP_OPT_MAGIC, 6]);
        assert_ne!(&body[6..10], &[0, 0, 0, 0]);
        // Recognized options with a bad length are NAK'd with the correct
        // form (not silently ACKed, not rejected).
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 3, &[LCP_OPT_PFC, 3, 0]));
        assert_eq!(last(&ppp), (CODE_CONF_NAK, vec![LCP_OPT_PFC, 2]));
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 4, &[LCP_OPT_ACCM, 4, 0, 0]));
        assert_eq!(last(&ppp), (CODE_CONF_NAK, vec![LCP_OPT_ACCM, 6, 0, 0, 0, 0]));
        // Unknown options still win: any reject is sent before NAKs.
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 5, &[LCP_OPT_PFC, 3, 0, 13, 3, 6]));
        assert_eq!(last(&ppp), (CODE_CONF_REJ, vec![13, 3, 6]));
    }

    #[test]
    fn test_malformed_option_list_is_discarded() {
        // Regression (Astra): an overrunning tail used to be truncated and the
        // rest ACKed. RFC 1661 §6: discard the packet.
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        ppp.handle(&build_ppp(PROTO_LCP, CODE_CONF_REQ, 1, &[LCP_OPT_MAGIC, 6, 1, 2, 3, 4, LCP_OPT_MRU, 9, 5]));
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_REQ, 1, &[IPCP_OPT_ADDR, 6, 1, 1, 1, 1, 2, 1]));
        assert!(ppp.outbox.is_empty());
        assert!(!ppp.lcp_acked_remote && !ppp.ipcp_acked_remote);
    }

    #[test]
    fn test_ipcp_acks_only_address() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        // IP-Compression-Protocol (2, VJ) is rejected; the flag stays false.
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_REQ, 5,
            &[IPCP_OPT_ADDR, 6, 1, 1, 1, 1, 2, 6, 0x00, 0x2d, 0x0f, 0x01]));
        assert_eq!(last(&ppp), (CODE_CONF_REJ, vec![2, 6, 0x00, 0x2d, 0x0f, 0x01]));
        assert!(!ppp.ipcp_acked_remote);
        // The retried address-only request is ACKed.
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_REQ, 6, &[IPCP_OPT_ADDR, 6, 1, 1, 1, 1]));
        assert_eq!(last(&ppp).0, CODE_CONF_ACK);
        assert!(ppp.ipcp_acked_remote);
        // A later request that we reject clears a stale ACKed state.
        ppp.handle(&build_ppp(PROTO_IPCP, CODE_CONF_REQ, 7, &[IPCP_OPT_ADDR, 4, 1, 1]));
        assert!(!ppp.ipcp_acked_remote);
    }

    #[test]
    fn test_unknown_protocol_rejected() {
        let mut ppp = PppState::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        ppp.phase = Phase::Network;
        ppp.handle(&[0x80, 0x57, 1, 1, 0, 4]);
        let rej = ppp.outbox.last().unwrap();
        assert_eq!(rej[2], CODE_PROTO_REJ);
        assert_eq!(&rej[6..8], &[0x80, 0x57]);
    }
}
