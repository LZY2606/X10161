// Frame input model: normalized frames plus datagram/segment parsing outcomes.

#[derive(Debug, Clone)]
pub struct Frame {
    pub idx: usize,
    pub ts_us: i128,
    pub wire_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet = 1,
    LinuxSll = 113,
    RawIpv4 = 228,
    RawIpv6 = 31,
}

impl LinkType {
    pub fn from_u32(v: u32) -> Option<LinkType> {
        Some(match v {
            1 => LinkType::Ethernet,
            113 => LinkType::LinuxSll,
            228 => LinkType::RawIpv4,
            31 => LinkType::RawIpv6,
            _ => return None,
        })
    }
    pub fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone)]
pub struct IpPacket {
    pub frame_idx: usize,
    pub ip_version: u8,
    pub src: String,
    pub dst: String,
    pub ip_id: u32,
    pub proto: u8,
    pub frag_off: usize,
    pub mf: bool,
    /// L4 segment when this is an unfragmented packet or the first fragment;
    /// raw fragment bytes otherwise.
    pub l4: Vec<u8>,
    pub tcp: Option<TcpSeg>,
}

#[derive(Debug, Clone)]
pub struct TcpSeg {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

// ---- IP packet extraction from a full frame ----

pub fn extract_packet(idx: usize, link: LinkType, frame: &[u8]) -> Option<IpPacket> {
    let (ip, version) = strip_link(link, frame)?;
    if version == 4 {
        parse_ipv4(idx, ip)
    } else {
        parse_ipv6_first_frag(idx, ip)
    }
}

fn strip_link(link: LinkType, frame: &[u8]) -> Option<(&[u8], u8)> {
    match link {
        LinkType::Ethernet => {
            if frame.len() < 14 {
                return None;
            }
            let mut off = 14;
            let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            while ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100 {
                if frame.len() < off + 4 {
                    return None;
                }
                ethertype = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
                off += 4;
            }
            let rest = &frame[off..];
            match ethertype {
                0x0800 => Some((rest, 4)),
                0x86dd => Some((rest, 6)),
                _ => None,
            }
        }
        LinkType::LinuxSll => {
            if frame.len() < 16 {
                return None;
            }
            let proto = u16::from_be_bytes([frame[14], frame[15]]);
            let rest = &frame[16..];
            match proto {
                0x0800 => Some((rest, 4)),
                0x86dd => Some((rest, 6)),
                _ => None,
            }
        }
        LinkType::RawIpv4 => Some((frame, 4)),
        LinkType::RawIpv6 => Some((frame, 6)),
    }
}

fn parse_ipv4(idx: usize, ip: &[u8]) -> Option<IpPacket> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let payload_end = total.min(ip.len());
    let id = u16::from_be_bytes([ip[4], ip[5]]) as u32;
    let frag_word = u16::from_be_bytes([ip[6], ip[7]]);
    let mf = frag_word & 0x2000 != 0;
    let frag_off = (frag_word & 0x1fff) as usize * 8;
    let proto = ip[9];
    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let payload = &ip[ihl..payload_end];
    if mf || frag_off != 0 {
        // Fragment: TCP header present only in the first fragment (off 0).
        let l4 = payload.to_vec();
        let tcp = if frag_off == 0 && proto == 6 {
            parse_tcp(payload)
        } else {
            None
        };
        return Some(IpPacket {
            frame_idx: idx,
            ip_version: 4,
            src,
            dst,
            ip_id: id,
            proto,
            frag_off,
            mf,
            l4,
            tcp,
        });
    }
    let tcp = if proto == 6 { parse_tcp(payload) } else { None };
    let l4 = payload.to_vec();
    Some(IpPacket {
        frame_idx: idx,
        ip_version: 4,
        src,
        dst,
        ip_id: id,
        proto,
        frag_off: 0,
        mf: false,
        l4,
        tcp,
    })
}

fn parse_ipv6_first_frag(idx: usize, ip: &[u8]) -> Option<IpPacket> {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }
    let src = fmt_ipv6(&ip[8..24]);
    let dst = fmt_ipv6(&ip[24..40]);
    let mut next = ip[6];
    let mut off = 40usize;
    let mut frag: Option<(u32, usize, bool)> = None; // (id, offset, MF)

    // Walk extension headers until the final protocol (TCP=6) or a fragment.
    loop {
        match next {
            0 | 43 | 60 => {
                // hop-by-hop / routing / destination options
                if ip.len() < off + 2 {
                    return None;
                }
                let hlen = (ip[off + 1] as usize + 1) * 8;
                if ip.len() < off + hlen {
                    return None;
                }
                next = ip[off];
                off += hlen;
            }
            44 => {
                if ip.len() < off + 8 {
                    return None;
                }
                let id = u32::from_be_bytes([ip[off + 4], ip[off + 5], ip[off + 6], ip[off + 7]]);
                let fo = u16::from_be_bytes([ip[off + 2], ip[off + 3]]);
                let mf = fo & 1 != 0;
                let frag_off = ((fo >> 3) as usize) * 8;
                next = ip[off];
                off += 8;
                frag = Some((id, frag_off, mf));
                break;
            }
            _ => break,
        }
    }

    if off > ip.len() {
        return None;
    }
    let payload = &ip[off..];

    if let Some((id, frag_off, mf)) = frag {
        let l4 = payload.to_vec();
        // After a fragment header the "next" value is the protocol of the
        // original datagram; the TCP header exists only in offset-0 fragments.
        let tcp = if frag_off == 0 && next == 6 {
            parse_tcp(payload)
        } else {
            None
        };
        return Some(IpPacket {
            frame_idx: idx,
            ip_version: 6,
            src,
            dst,
            ip_id: id,
            proto: next,
            frag_off,
            mf,
            l4,
            tcp,
        });
    }

    let tcp = if next == 6 { parse_tcp(payload) } else { None };
    Some(IpPacket {
        frame_idx: idx,
        ip_version: 6,
        src,
        dst,
        ip_id: 0,
        proto: next,
        frag_off: 0,
        mf: false,
        l4: payload.to_vec(),
        tcp,
    })
}

fn fmt_ipv6(b: &[u8]) -> String {
    let groups: Vec<String> = (0..8)
        .map(|i| format!("{:x}", u16::from_be_bytes([b[i * 2], b[i * 2 + 1]])))
        .collect();
    // Compress longest zero run.
    let mut best = 0usize;
    let mut best_len = 0usize;
    let mut i = 0;
    while i < 8 {
        if groups[i] == "0" {
            let mut j = i;
            while j < 8 && groups[j] == "0" {
                j += 1;
            }
            if j - i > best_len {
                best = i;
                best_len = j - i;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    if best_len >= 2 {
        let mut s = String::new();
        s.push_str(&groups[..best].join(":"));
        s.push_str("::");
        s.push_str(&groups[best + best_len..].join(":"));
        s
    } else {
        groups.join(":")
    }
}

fn parse_tcp(p: &[u8]) -> Option<TcpSeg> {
    if p.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([p[0], p[1]]);
    let dport = u16::from_be_bytes([p[2], p[3]]);
    let seq = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    let ack = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
    let doff = ((p[12] >> 4) as usize) * 4;
    if doff < 20 || p.len() < doff {
        return None;
    }
    let flags = p[13] & 0x1f;
    Some(TcpSeg {
        sport,
        dport,
        seq,
        ack,
        flags,
        payload: p[doff..].to_vec(),
    })
}

pub fn parse_tcp_pub(p: &[u8]) -> Option<TcpSeg> {
    parse_tcp(p)
}
