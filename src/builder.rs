use std::net::Ipv4Addr;

pub fn ipv4(address: [u8; 4]) -> Ipv4Addr {
    Ipv4Addr::from(address)
}

pub fn ethernet(payload: &[u8], ether_type: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn ipv4_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
    identification: u16,
    fragment_offset_bytes: u16,
    more_fragments: bool,
) -> Vec<u8> {
    assert!(fragment_offset_bytes % 8 == 0);
    let total_length = (20 + payload.len()) as u16;
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&total_length.to_be_bytes());
    packet.extend_from_slice(&identification.to_be_bytes());
    let flags_fragment = (fragment_offset_bytes / 8) | if more_fragments { 0x2000 } else { 0 };
    packet.extend_from_slice(&flags_fragment.to_be_bytes());
    packet.push(64);
    packet.push(protocol);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    let checksum = ipv4_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

pub fn tcp_segment(
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&acknowledgment.to_be_bytes());
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&65535u16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

pub fn tcp_frame(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp = tcp_segment(
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        flags,
        payload,
    );
    let ip = ipv4_packet(source, destination, 6, &tcp, 0x4e20, 0, false);
    ethernet(&ip, 0x0800)
}

pub fn fixture_json(frames: &[(i64, Vec<u8>)]) -> Vec<u8> {
    let mut out = String::from("{\"frames\":[");
    for (index, (timestamp, bytes)) in frames.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"frame_index\":");
        out.push_str(&index.to_string());
        out.push_str(",\"timestamp_ns\":");
        out.push_str(&timestamp.to_string());
        out.push_str(",\"hex\":\"");
        out.push_str(&crate::util::hex_lower(bytes));
        out.push_str("\"}");
    }
    out.push_str("]}");
    out.into_bytes()
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            (chunk[0] as u16) << 8
        };
        sum += value as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
