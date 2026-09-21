//! 简化 pcap 读取：经典 pcap 全局头 + 记录，链路类型 Ethernet(1)。
//! 支持 usec/nsec 两种精度与大小端。不访问任何实时网卡。

use crate::model::Frame;

pub fn parse_pcap(data: &[u8]) -> Result<Vec<Frame>, String> {
    if data.len() < 24 {
        return Err("pcap 太短：缺少全局头".to_string());
    }
    let magic = &data[0..4];
    let (le, nsec) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("无法识别的 pcap magic".to_string()),
    };
    let u16b = |b: &[u8]| -> u16 {
        if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let u32b = |b: &[u8]| -> u32 {
        if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let linktype = u16b(&data[20..22]);
    if linktype != 1 {
        return Err(format!("仅支持 Ethernet 链路类型(1)，得到 {linktype}"));
    }
    let mut frames = Vec::new();
    let mut off = 24usize;
    let mut index = 0u32;
    while off + 16 <= data.len() {
        let ts_sec = u32b(&data[off..off + 4]) as i64;
        let ts_frac = u32b(&data[off + 4..off + 8]) as i64;
        let incl = u32b(&data[off + 8..off + 12]) as usize;
        off += 16;
        if off + incl > data.len() {
            return Err(format!("帧 {index} 数据截断"));
        }
        let ts_ns = ts_sec * 1_000_000_000 + if nsec { ts_frac } else { ts_frac * 1000 };
        frames.push(Frame {
            index,
            ts_ns,
            data: data[off..off + incl].to_vec(),
        });
        off += incl;
        index += 1;
    }
    Ok(frames)
}
