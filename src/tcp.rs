use std::collections::HashMap;

use crate::common::{NetParseError, Netparse};
use crate::ip::Ipv4Addr;

#[derive(Debug)]
pub struct TcpPacket<'a> {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    is_ack: bool,
    is_psh: bool,
    is_rst: bool,
    is_syn: bool,
    is_fin: bool,
    urg_pointer: Option<u16>,
    window_size: u16,
    data: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn from_be_bytes_slice(bytes: &'a [u8]) -> Result<Self, NetParseError> {
        let src_port = u16::from_be_slice(&bytes[..2])?;
        let dst_port = u16::from_be_slice(&bytes[2..4])?;

        let seq_num = u32::from_be_slice(&bytes[4..8])?;
        let ack_num = u32::from_be_slice(&bytes[8..12])?;

        // data offset comes in number of 32 bits, so get len in bytes
        let data_offset = 4 * (bytes[12] >> 4) as usize;
        let data = &bytes[data_offset..];

        // 6 bits reserved and must be zero
        let reserved_start = bytes[12] & 0x0F;
        let reserved_end = bytes[13] >> 6;
        if reserved_start + reserved_end != 0 {
            return Err(NetParseError::MalformedPacket(format!(
                "Reserved bits were not zero: {reserved_start:b}{reserved_end:b}"
            )));
        }

        let is_urg = bytes[13] & 0b0010_0000 != 0;
        let is_ack = bytes[13] & 0b0001_0000 != 0;
        let is_psh = bytes[13] & 0b0000_1000 != 0;
        let is_rst = bytes[13] & 0b0000_0100 != 0;
        let is_syn = bytes[13] & 0b0000_0010 != 0;
        let is_fin = bytes[13] & 0b0000_0001 != 0;

        let window_size = u16::from_be_slice(&bytes[14..16])?;

        // TODO handle 2-byte checksum

        let urg_pointer = if is_urg {
            Some(u16::from_be_slice(&bytes[18..20])?)
        } else {
            None
        };

        // TODO handle options
        Ok(Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            is_ack,
            is_psh,
            is_rst,
            is_syn,
            is_fin,
            urg_pointer,
            window_size,
            data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpConnectionIdent {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

pub struct TcpState {}
pub struct TcpConnections(HashMap<TcpConnectionIdent, TcpState>);

pub enum TcpProcessError {}

impl TcpConnections {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn process_packet(packet: TcpPacket) -> Result<(), TcpProcessError> {
        Ok(())
    }
}
