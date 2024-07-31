use anyhow::bail;
use common::NetParseError;
use ip::Ipv4Packet;

use crate::{ip::InternetProto, tcp::TcpPacket};

mod common;
mod ip;
mod tcp;

const PACKET_SIZE: usize = 1500 + 4;
const IPV4_ETHERTYPE: u16 = 0x800;

fn main() -> anyhow::Result<()> {
    let nic = tun_tap::Iface::new("", tun_tap::Mode::Tun).expect("Couldn't initialize tun device, make sure Linux has loaded the tun module");

    loop {
        let mut buf = [0u8; PACKET_SIZE];
        let n_bytes_recv = nic.recv(&mut buf[..])?;
        // tuntap ethernet frame starts with flags + proto
        let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);
        if proto != IPV4_ETHERTYPE {
            continue;
        }

        match Ipv4Packet::from_be_bytes_slice(&buf[4..n_bytes_recv]) {
            Ok(ip_packet) => {
                println!("{ip_packet}");
                match ip_packet.proto() {
                    InternetProto::Tcp => {
                        let tcp_packet = TcpPacket::from_be_bytes_slice(ip_packet.data())?;
                        println!("{tcp_packet:?}")
                    }
                    proto => println!("Dropping {proto} packet"),
                }
            }
            Err(NetParseError::UnhandledVariant(msg)) => {
                println!("Dropping unhandled packet: {msg}")
            }
            Err(e) => bail!(e),
        }
    }
}
