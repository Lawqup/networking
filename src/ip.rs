use std::fmt;

use crate::common::{NetParseError, Netparse};

#[derive(Debug, Clone, Copy)]
pub enum InternetProto {
    Icmp = 0o1,
    Tcp = 0o6,
    Udp = 0o21,
}

impl InternetProto {
    pub fn from_byte(b: u8) -> Result<Self, NetParseError> {
        match b {
            0o1 => Ok(Self::Icmp),
            0o2 => Err(NetParseError::UnhandledVariant(
                "unassigned IP protocol".to_string(),
            )),
            0o6 => Ok(Self::Tcp),
            0o21 => Ok(Self::Udp),
            _ => Err(NetParseError::UnhandledVariant(format!(
                "IP protocol 0o{b:0o}"
            ))),
        }
    }
}

impl fmt::Display for InternetProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            InternetProto::Icmp => "ICMP",
            InternetProto::Tcp => "TCP",
            InternetProto::Udp => "UDP",
        };

        write!(f, "{name}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Addr([u8; 4]);

impl Ipv4Addr {
    pub fn from_be_bytes(bs: [u8; 4]) -> Self {
        Self(bs)
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pretty = self
            .0
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(".");

        write!(f, "{pretty}")
    }
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    proto: InternetProto,
    time_to_live: u8,
    data: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn from_be_bytes_slice(bytes: &'a [u8]) -> Result<Self, NetParseError> {
        let version = bytes[0] >> 4;

        if version != 4 {
            return Err(NetParseError::IncorrectVariant(
                "tried parsing IPv{version} packet as IPv4".to_string(),
            ));
        }

        // header len comes in number of 32 bits, so get len in bytes
        let header_len_bytes = 4 * (bytes[0] & 0x0F) as usize;

        // skip over Type of Service (1 byte)
        let total_len_bytes = u16::from_be_slice(&bytes[2..4])? as usize;
        let data = &bytes[header_len_bytes..total_len_bytes];

        // don't handle fragmentation yet (skip 2 byte fragment identification, then 13 bits after 3 bit flags)
        let flags = (bytes[6] & 0b1110_0000) >> 5;

        // First bit must be 0, second doesn't matter if not worrying
        // about fragments, third must be 0 = last fragment, since we
        // aren't handling fragments
        if flags != 0b010 && flags != 0b000 {
            return Err(NetParseError::UnhandledVariant(format!(
                "fragmented IPv4 packet, flags: 0b{flags:b}"
            )));
        }

        // Decrement ttl after processing (stop infinte loops)
        let time_to_live = bytes[8] - 1;

        let proto = InternetProto::from_byte(bytes[9])?;

        // Skip checksum (2 bytes)
        let src_addr = Ipv4Addr::from_be_slice(&bytes[12..16])?;
        let dst_addr = Ipv4Addr::from_be_slice(&bytes[16..20])?;

        // Skip options (variable size)
        Ok(Self {
            src_addr,
            dst_addr,
            proto,
            time_to_live,
            data,
        })
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        self.src_addr
    }

    pub fn dst_addr(&self) -> Ipv4Addr {
        self.dst_addr
    }

    pub fn proto(&self) -> InternetProto {
        self.proto
    }

    pub fn time_to_live(&self) -> u8 {
        self.time_to_live
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl fmt::Display for Ipv4Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{} -> {}] protocol: {}, ttl: {}, {} payload size",
            self.src_addr(),
            self.dst_addr(),
            self.proto(),
            self.time_to_live(),
            self.data().len()
        )
    }
}
