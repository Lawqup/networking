use thiserror::Error;

use crate::ip::Ipv4Addr;

#[derive(Error, Debug)]
pub enum NetParseError {
    #[error("Malformed packet: {0}")]
    MalformedPacket(String),
    #[error("Unhandled variant: {0}")]
    UnhandledVariant(String),
    #[error("Incorrect variant: {0}")]
    IncorrectVariant(String),
    #[error("{0}")]
    Other(String),
}

pub trait Netparse
where
    Self: Sized,
{
    fn from_be_slice(bytes: &[u8]) -> Result<Self, NetParseError>;
}

impl Netparse for u16 {
    fn from_be_slice(bytes: &[u8]) -> Result<Self, NetParseError> {
        Ok(u16::from_be_bytes(bytes.try_into().map_err(|err| {
            NetParseError::MalformedPacket(format!("Could't parse u16: {err}"))
        })?))
    }
}

impl Netparse for u32 {
    fn from_be_slice(bytes: &[u8]) -> Result<Self, NetParseError> {
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|err| {
            NetParseError::MalformedPacket(format!("Could't parse u32: {err}"))
        })?))
    }
}

impl Netparse for Ipv4Addr {
    fn from_be_slice(bytes: &[u8]) -> Result<Self, NetParseError> {
        Ok(Ipv4Addr::from_be_bytes(bytes.try_into().map_err(
            |err| NetParseError::MalformedPacket(format!("Could't parse IPv4 addr: {err}")),
        )?))
    }
}
