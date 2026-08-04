//! The decoded network and transport layers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cybersentinel_common::event::Protocol;

/// The decoded network layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// IPv4.
    Ipv4(Ipv4Info),
    /// IPv6.
    Ipv6(Ipv6Info),
}

/// IPv4 header fields the rest of the pipeline needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Info {
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// Next protocol number.
    pub protocol: u8,
    /// Time to live.
    pub ttl: u8,
    /// Fragment identification, used to group fragments in Phase 2.
    pub identification: u16,
    /// Fragment offset in 8-byte units.
    pub fragment_offset: u16,
    /// The "more fragments" flag.
    pub more_fragments: bool,
    /// Header length in bytes, including options.
    pub header_len: usize,
    /// The header's `total_len` field.
    pub total_len: u16,
}

impl Ipv4Info {
    /// Whether this packet carries part of a fragmented datagram.
    ///
    /// Phase 2 reassembles these; Phase 1 records them and does not attempt to
    /// read a transport header from a non-initial fragment.
    #[must_use]
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }
}

/// IPv6 header fields the rest of the pipeline needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Info {
    /// Source address.
    pub source: Ipv6Addr,
    /// Destination address.
    pub destination: Ipv6Addr,
    /// Protocol number after walking the extension chain.
    pub protocol: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// The header's `payload_length` field.
    pub payload_length: u16,
    /// Total bytes of fixed header plus extension headers.
    pub header_len: usize,
    /// Whether a fragment extension header was present.
    pub is_fragment: bool,
}

impl Network {
    /// Source address.
    #[must_use]
    pub fn source(&self) -> IpAddr {
        match self {
            Self::Ipv4(ip) => IpAddr::V4(ip.source),
            Self::Ipv6(ip) => IpAddr::V6(ip.source),
        }
    }

    /// Destination address.
    #[must_use]
    pub fn destination(&self) -> IpAddr {
        match self {
            Self::Ipv4(ip) => IpAddr::V4(ip.destination),
            Self::Ipv6(ip) => IpAddr::V6(ip.destination),
        }
    }

    /// Next protocol number.
    #[must_use]
    pub fn protocol(&self) -> u8 {
        match self {
            Self::Ipv4(ip) => ip.protocol,
            Self::Ipv6(ip) => ip.protocol,
        }
    }

    /// Whether the packet is a fragment.
    #[must_use]
    pub fn is_fragment(&self) -> bool {
        match self {
            Self::Ipv4(ip) => ip.is_fragment(),
            Self::Ipv6(ip) => ip.is_fragment,
        }
    }
}

/// TCP control flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    /// FIN.
    pub fin: bool,
    /// SYN.
    pub syn: bool,
    /// RST.
    pub rst: bool,
    /// PSH.
    pub psh: bool,
    /// ACK.
    pub ack: bool,
    /// URG.
    pub urg: bool,
    /// ECE.
    pub ece: bool,
    /// CWR.
    pub cwr: bool,
}

impl TcpFlags {
    /// The flags as their wire byte, for compact reporting.
    #[must_use]
    pub fn bits(self) -> u8 {
        u8::from(self.fin)
            | u8::from(self.syn) << 1
            | u8::from(self.rst) << 2
            | u8::from(self.psh) << 3
            | u8::from(self.ack) << 4
            | u8::from(self.urg) << 5
            | u8::from(self.ece) << 6
            | u8::from(self.cwr) << 7
    }

    /// The conventional short form, e.g. `SA` for a SYN/ACK.
    #[must_use]
    pub fn to_short_string(self) -> String {
        let mut out = String::new();
        for (flag, letter) in [
            (self.fin, 'F'),
            (self.syn, 'S'),
            (self.rst, 'R'),
            (self.psh, 'P'),
            (self.ack, 'A'),
            (self.urg, 'U'),
            (self.ece, 'E'),
            (self.cwr, 'C'),
        ] {
            if flag {
                out.push(letter);
            }
        }
        out
    }
}

/// The decoded transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TCP.
    Tcp(TcpInfo),
    /// UDP.
    Udp(UdpInfo),
    /// ICMP or ICMPv6.
    Icmp(IcmpInfo),
    /// An IP protocol with no port-bearing header the decoder reads.
    Other {
        /// The IP protocol number.
        protocol: u8,
    },
}

/// TCP header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpInfo {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// Sequence number.
    pub sequence_number: u32,
    /// Acknowledgement number.
    pub acknowledgment_number: u32,
    /// Advertised window.
    pub window_size: u16,
    /// Control flags.
    pub flags: TcpFlags,
    /// Header length in bytes, including options.
    pub header_len: usize,
}

/// UDP header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpInfo {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// The header's `length` field, including the 8-byte header.
    pub length: u16,
}

/// ICMP header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpInfo {
    /// Message type.
    pub icmp_type: u8,
    /// Message code.
    pub code: u8,
    /// Whether this is ICMPv6 rather than ICMPv4.
    pub is_v6: bool,
}

impl Transport {
    /// Source port, for the protocols that have one.
    #[must_use]
    pub fn source_port(&self) -> Option<u16> {
        match self {
            Self::Tcp(tcp) => Some(tcp.source_port),
            Self::Udp(udp) => Some(udp.source_port),
            Self::Icmp(_) | Self::Other { .. } => None,
        }
    }

    /// Destination port, for the protocols that have one.
    #[must_use]
    pub fn destination_port(&self) -> Option<u16> {
        match self {
            Self::Tcp(tcp) => Some(tcp.destination_port),
            Self::Udp(udp) => Some(udp.destination_port),
            Self::Icmp(_) | Self::Other { .. } => None,
        }
    }

    /// How this maps onto the event schema's protocol field.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Tcp(_) => Protocol::Tcp,
            Self::Udp(_) => Protocol::Udp,
            Self::Icmp(_) => Protocol::Icmp,
            Self::Other { .. } => Protocol::Ip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flag_bits_match_the_wire_layout() {
        let syn_ack = TcpFlags {
            syn: true,
            ack: true,
            ..TcpFlags::default()
        };
        assert_eq!(syn_ack.bits(), 0b0001_0010);
        assert_eq!(syn_ack.to_short_string(), "SA");

        assert_eq!(TcpFlags::default().bits(), 0);
        assert_eq!(TcpFlags::default().to_short_string(), "");
    }

    #[test]
    fn a_non_initial_fragment_is_recognised() {
        let mut info = Ipv4Info {
            source: Ipv4Addr::LOCALHOST,
            destination: Ipv4Addr::LOCALHOST,
            protocol: 6,
            ttl: 64,
            identification: 1,
            fragment_offset: 0,
            more_fragments: false,
            header_len: 20,
            total_len: 40,
        };
        assert!(!info.is_fragment());

        info.more_fragments = true;
        assert!(
            info.is_fragment(),
            "the first fragment of a set is still a fragment"
        );

        info.more_fragments = false;
        info.fragment_offset = 185;
        assert!(
            info.is_fragment(),
            "the last fragment has no MF flag but a non-zero offset"
        );
    }

    #[test]
    fn ports_are_absent_for_icmp() {
        let icmp = Transport::Icmp(IcmpInfo {
            icmp_type: 8,
            code: 0,
            is_v6: false,
        });
        assert!(icmp.source_port().is_none());
        assert_eq!(icmp.protocol(), Protocol::Icmp);
    }
}
