//! Fortinet SSL-VPN tunnel framing.
//!
//! On the TLS wire, each PPP packet is prefixed with a 6-byte header.
//! IMPORTANT: there is **no** HDLC byte-stuffing on the TLS side — HDLC only
//! exists between openfortivpn and pppd's pty. Since we run native PPP over a
//! TUN device, we exchange raw PPP frames (protocol + payload) directly.
//!
//! Header layout (see openfortivpn src/io.c ssl_read/ssl_write):
//!   [0..1]  total length  = 6 + payload_len   (big-endian u16)
//!   [2..3]  magic         = 0x50 0x50
//!   [4..5]  payload length = payload_len       (big-endian u16)
//!   [6..]   raw PPP frame  (protocol(2) + data)

pub const TUNNEL_MAGIC: [u8; 2] = [0x50, 0x50];
pub const HEADER_LEN: usize = 6;

/// Wrap a raw PPP frame (protocol + payload) in a tunnel frame.
pub fn frame_raw(ppp_data: &[u8]) -> Vec<u8> {
    let size = ppp_data.len();
    let total = size + HEADER_LEN;
    let mut frame = Vec::with_capacity(total);
    frame.push((total >> 8) as u8);
    frame.push((total & 0xff) as u8);
    frame.push(TUNNEL_MAGIC[0]);
    frame.push(TUNNEL_MAGIC[1]);
    frame.push((size >> 8) as u8);
    frame.push((size & 0xff) as u8);
    frame.extend_from_slice(ppp_data);
    frame
}

/// Wrap a raw IP packet as a tunnel frame with a PPP IPv4/IPv6 protocol header.
pub fn frame_packet(ip_data: &[u8]) -> Vec<u8> {
    let proto: [u8; 2] = if ip_data.first() == Some(&0x60) { [0x00, 0x57] } else { [0x00, 0x21] };
    let mut ppp = Vec::with_capacity(2 + ip_data.len());
    ppp.extend_from_slice(&proto);
    ppp.extend_from_slice(ip_data);
    frame_raw(&ppp)
}

/// Try to pop one complete PPP frame from the front of `buf`.
///
/// Returns `Some((ppp_frame, consumed_bytes))` when a full frame is present,
/// or `None` when more bytes are needed. `ppp_frame` is the raw PPP frame
/// (protocol + payload) with the 6-byte header stripped.
pub fn pop_frame(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < HEADER_LEN { return None; }
    let total = ((buf[0] as usize) << 8) | buf[1] as usize;
    let magic = [buf[2], buf[3]];
    let size = ((buf[4] as usize) << 8) | buf[5] as usize;

    if magic != TUNNEL_MAGIC || total < 7 || total - HEADER_LEN != size {
        // Bad/desynced header — skip one byte and let the caller retry.
        return Some((Vec::new(), 1));
    }
    if buf.len() < HEADER_LEN + size { return None; } // need more bytes
    let ppp = buf[HEADER_LEN..HEADER_LEN + size].to_vec();
    Some((ppp, HEADER_LEN + size))
}

/// Extract the full PPP frame from a single tunnel frame (test/util helper).
pub fn deframe_packet(frame: &[u8]) -> Option<Vec<u8>> {
    pop_frame(frame).and_then(|(ppp, _)| if ppp.is_empty() { None } else { Some(ppp) })
}

/// Extract just the IP payload (strip 2-byte PPP protocol header).
pub fn deframe_ip(frame: &[u8]) -> Option<Vec<u8>> {
    deframe_packet(frame).and_then(|ppp| if ppp.len() >= 2 { Some(ppp[2..].to_vec()) } else { None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_layout() {
        let frame = frame_raw(b"\xc0\x21test");
        // total = 6 + 6 = 12
        assert_eq!(frame[0], 0x00);
        assert_eq!(frame[1], 12);
        assert_eq!(frame[2], 0x50);
        assert_eq!(frame[3], 0x50);
        // payload size = 6
        assert_eq!(frame[4], 0x00);
        assert_eq!(frame[5], 6);
        assert_eq!(&frame[6..], b"\xc0\x21test");
    }

    #[test]
    fn test_roundtrip() {
        let frame = frame_packet(b"ip data");
        let ppp = deframe_packet(&frame).expect("deframe");
        assert_eq!(&ppp[..2], &[0x00, 0x21]);
        assert_eq!(&ppp[2..], b"ip data");
    }

    #[test]
    fn test_pop_multiple_frames() {
        let mut wire = frame_raw(b"\xc0\x21one");
        wire.extend_from_slice(&frame_raw(b"\x80\x21two"));

        let (f1, c1) = pop_frame(&wire).expect("first");
        assert_eq!(f1, b"\xc0\x21one");
        let (f2, c2) = pop_frame(&wire[c1..]).expect("second");
        assert_eq!(f2, b"\x80\x21two");
        assert_eq!(c1 + c2, wire.len());
    }

    #[test]
    fn test_partial_frame() {
        let frame = frame_raw(b"\xc0\x21hello");
        // Only the header + 2 bytes present
        assert!(pop_frame(&frame[..8]).is_none());
    }

    #[test]
    fn test_bad_header_skips_byte() {
        let (ppp, consumed) = pop_frame(b"XXXXXXXX").expect("skip");
        assert!(ppp.is_empty());
        assert_eq!(consumed, 1);
    }
}
