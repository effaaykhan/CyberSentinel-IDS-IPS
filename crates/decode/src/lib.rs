//! L2–L4 packet decoding (**Phase 1**).
//!
//! Turns a captured frame into a 5-tuple, a payload range, and a list of
//! **decoder anomalies**. Header parsing uses `etherparse`, but the decoder
//! drives it layer by layer rather than through the all-in-one slicer, so every
//! length check — and every anomaly that check implies — is explicit and ours.
//!
//! # Design
//!
//! **Decoding never fails.** [`decode`] always returns a [`Decoded`]; problems
//! are recorded in [`Decoded::anomalies`] rather than thrown away as an error.
//! A packet that is malformed at layer 4 still has a usable layer 3, and the
//! malformation is itself signal worth alerting on.
//!
//! **No copies.** [`Decoded::payload`] is a byte range into the original frame.
//! Sub-slice offsets are computed by comparing addresses as integers, which
//! needs no `unsafe`.
//!
//! **Bounded work.** Stacked headers are capped ([`MAX_VLAN_TAGS`],
//! [`MAX_IPV6_EXTENSION_HEADERS`]) and anomalies per frame are capped. A frame
//! cannot make the decoder loop or allocate without limit.
//!
//! # Snap-length truncation is not an anomaly
//!
//! A frame clipped by the capture snap length legitimately holds fewer bytes
//! than its headers describe. The decoder only raises
//! [`AnomalyKind::LengthMismatch`] when the frame was captured **in full** and
//! a length field still overruns it — that is a header lying about itself,
//! which is what evasion looks like. Conflating the two would bury real
//! anomalies under noise from every snapped packet.

pub mod anomaly;
pub mod layers;

use std::ops::Range;

use cybersentinel_common::event::{NetTuple, Protocol};
use etherparse::{
    EtherType, Ethernet2Header, IpNumber, Ipv4Header, Ipv6Header, SingleVlanHeader, TcpHeader,
    UdpHeader,
};

pub use anomaly::{Anomaly, AnomalyKind, AnomalySet, Layer};
pub use layers::{IcmpInfo, Ipv4Info, Ipv6Info, Network, TcpFlags, TcpInfo, Transport, UdpInfo};

/// VLAN tags the decoder will follow. Two covers 802.1ad QinQ; anything deeper
/// is treated as [`AnomalyKind::TooManyLayers`].
pub const MAX_VLAN_TAGS: usize = 2;

/// IPv6 extension headers the decoder will walk before giving up.
pub const MAX_IPV6_EXTENSION_HEADERS: usize = 8;

/// Smallest well-formed ICMP/ICMPv6 header.
const ICMP_HEADER_LEN: usize = 8;

/// A decoded frame.
#[derive(Debug, Clone)]
pub struct Decoded<'a> {
    /// The frame as captured.
    pub frame: &'a [u8],
    /// Length on the wire before snap-length clipping.
    pub original_len: usize,
    /// EtherType after any VLAN tags, if the frame got that far.
    pub ether_type: Option<u16>,
    /// VLAN ids, outermost first.
    pub vlan_ids: [Option<u16>; MAX_VLAN_TAGS],
    /// The network layer, if one was decoded.
    pub network: Option<Network>,
    /// The transport layer, if one was decoded.
    pub transport: Option<Transport>,
    /// Byte range of the transport payload within [`Decoded::frame`].
    pub payload: Range<usize>,
    /// Byte range of the **network** payload — everything after the IP header,
    /// clipped to the IP length.
    ///
    /// This is what IP defragmentation reassembles, and it is deliberately not
    /// the same as [`Decoded::payload`]: for the first fragment of a datagram
    /// the transport header is itself part of the data being reassembled, so
    /// handing over the post-transport payload would lose it and misalign every
    /// later fragment.
    pub network_payload: Range<usize>,
    /// Structural problems found while decoding.
    pub anomalies: AnomalySet,
}

impl<'a> Decoded<'a> {
    fn new(frame: &'a [u8], original_len: usize) -> Self {
        Self {
            frame,
            original_len,
            ether_type: None,
            vlan_ids: [None; MAX_VLAN_TAGS],
            network: None,
            transport: None,
            payload: 0..0,
            network_payload: 0..0,
            anomalies: AnomalySet::default(),
        }
    }

    /// Whether the capture snap length clipped this frame.
    #[must_use]
    pub fn is_snapped(&self) -> bool {
        self.original_len > self.frame.len()
    }

    /// The transport payload bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &'a [u8] {
        self.frame.get(self.payload.clone()).unwrap_or(&[])
    }

    /// The network payload bytes: everything after the IP header.
    #[must_use]
    pub fn network_payload_bytes(&self) -> &'a [u8] {
        self.frame.get(self.network_payload.clone()).unwrap_or(&[])
    }

    /// Payload length in bytes.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// The 5-tuple, if the frame carried an IP packet.
    ///
    /// Ports are `None` for protocols that have none.
    #[must_use]
    pub fn five_tuple(&self) -> Option<NetTuple> {
        let network = self.network.as_ref()?;
        let (src_port, dest_port, proto) = match &self.transport {
            Some(transport) => (
                transport.source_port(),
                transport.destination_port(),
                transport.protocol(),
            ),
            None => (None, None, Protocol::Ip),
        };
        Some(NetTuple {
            src_ip: network.source(),
            src_port,
            dest_ip: network.destination(),
            dest_port,
            proto,
        })
    }
}

/// Running totals over decoded frames.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeCounters {
    /// Frames decoded.
    pub packets: u64,
    /// Frames carrying IPv4.
    pub ipv4: u64,
    /// Frames carrying IPv6.
    pub ipv6: u64,
    /// TCP segments.
    pub tcp: u64,
    /// UDP datagrams.
    pub udp: u64,
    /// ICMP/ICMPv6 messages.
    pub icmp: u64,
    /// IP packets whose protocol has no header the decoder reads.
    pub other_transport: u64,
    /// Frames with no IP layer at all — ARP, LLDP, and friends. Normal traffic,
    /// not an anomaly.
    pub non_ip: u64,
    /// IP fragments seen. Reassembled from Phase 2.
    pub fragments: u64,
    /// Frames clipped by the snap length.
    pub snapped: u64,
    /// Frames with at least one anomaly.
    pub anomalous: u64,
    /// Anomalies recorded, across all frames.
    pub anomalies: u64,
}

impl DecodeCounters {
    /// Fold one decoded frame into the totals.
    pub fn record(&mut self, decoded: &Decoded<'_>) {
        self.packets += 1;
        if decoded.is_snapped() {
            self.snapped += 1;
        }
        if !decoded.anomalies.is_empty() {
            self.anomalous += 1;
            self.anomalies += decoded.anomalies.len() as u64;
        }
        match &decoded.network {
            Some(Network::Ipv4(_)) => self.ipv4 += 1,
            Some(Network::Ipv6(_)) => self.ipv6 += 1,
            None => self.non_ip += 1,
        }
        if decoded.network.as_ref().is_some_and(Network::is_fragment) {
            self.fragments += 1;
        }
        match &decoded.transport {
            Some(Transport::Tcp(_)) => self.tcp += 1,
            Some(Transport::Udp(_)) => self.udp += 1,
            Some(Transport::Icmp(_)) => self.icmp += 1,
            Some(Transport::Other { .. }) => self.other_transport += 1,
            None => {}
        }
    }
}

/// Decode one frame.
///
/// `original_len` is the wire length before snap-length clipping; pass
/// `frame.len()` when the frame is known to be complete.
#[must_use]
pub fn decode(frame: &[u8], original_len: usize) -> Decoded<'_> {
    let mut decoded = Decoded::new(frame, original_len);

    if frame.is_empty() {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ethernet, AnomalyKind::EmptyFrame));
        return decoded;
    }

    let Ok((ethernet, mut rest)) = Ethernet2Header::from_slice(frame) else {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ethernet, AnomalyKind::TruncatedHeader));
        return decoded;
    };

    let mut ether_type = ethernet.ether_type;

    // VLAN tags, outermost first.
    let mut tags = 0;
    while is_vlan(ether_type) {
        if tags >= MAX_VLAN_TAGS {
            decoded
                .anomalies
                .push(Anomaly::new(Layer::Vlan, AnomalyKind::TooManyLayers));
            return decoded;
        }
        let Ok((vlan, remainder)) = SingleVlanHeader::from_slice(rest) else {
            decoded
                .anomalies
                .push(Anomaly::new(Layer::Vlan, AnomalyKind::TruncatedHeader));
            return decoded;
        };
        decoded.vlan_ids[tags] = Some(u16::from(vlan.vlan_id));
        ether_type = vlan.ether_type;
        rest = remainder;
        tags += 1;
    }

    decoded.ether_type = Some(u16::from(ether_type));

    match ether_type {
        EtherType::IPV4 => decode_ipv4(&mut decoded, rest),
        EtherType::IPV6 => decode_ipv6(&mut decoded, rest),
        // ARP, LLDP, and everything else: not an anomaly, just not ours.
        _ => {}
    }

    decoded
}

fn is_vlan(ether_type: EtherType) -> bool {
    matches!(
        ether_type,
        EtherType::VLAN_TAGGED_FRAME
            | EtherType::PROVIDER_BRIDGING
            | EtherType::VLAN_DOUBLE_TAGGED_FRAME
    )
}

/// Byte offset of `sub` within `whole`.
///
/// `sub` is always a sub-slice of `whole` here — every caller passes the
/// remainder returned by a header parser. Comparing the addresses as integers
/// is a safe operation; no pointer is dereferenced.
fn offset_of(whole: &[u8], sub: &[u8]) -> usize {
    (sub.as_ptr() as usize).saturating_sub(whole.as_ptr() as usize)
}

fn decode_ipv4(decoded: &mut Decoded<'_>, slice: &[u8]) {
    let start = offset_of(decoded.frame, slice);

    // Read version and IHL by hand first: etherparse reports these as one
    // generic error, and the difference between "not IPv4 at all" and "IPv4
    // claiming a 12-byte header" matters to an analyst.
    let Some(&first) = slice.first() else {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::TruncatedHeader));
        return;
    };
    if first >> 4 != 4 {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::UnknownIpVersion));
        return;
    }
    let ihl = usize::from(first & 0x0f);
    if ihl < 5 {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::ImpossibleLength));
        return;
    }
    let header_len = ihl * 4;
    if slice.len() < header_len {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::TruncatedHeader));
        return;
    }

    let Ok((header, after_header)) = Ipv4Header::from_slice(slice) else {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::TruncatedHeader));
        return;
    };

    if header.header_checksum != header.calc_header_checksum() {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::BadIpv4Checksum));
    }

    let total_len = usize::from(header.total_len);
    // `total_len` shorter than the header it sits in is impossible.
    if total_len < header_len {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::ImpossibleLength));
    } else if total_len > slice.len() && !decoded.is_snapped() {
        // The frame arrived whole and the header still overruns it.
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv4, AnomalyKind::LengthMismatch));
    }

    let info = Ipv4Info {
        source: header.source.into(),
        destination: header.destination.into(),
        protocol: header.protocol.0,
        ttl: header.time_to_live,
        identification: header.identification,
        fragment_offset: header.fragment_offset.value(),
        more_fragments: header.more_fragments,
        header_len,
        total_len: header.total_len,
    };
    let is_fragment = info.is_fragment();
    let fragment_offset = info.fragment_offset;
    decoded.network = Some(Network::Ipv4(info));

    // The IP packet ends at total_len, clipped to what was actually captured.
    let claimed_end = start.saturating_add(total_len.max(header_len));
    let end = claimed_end.min(decoded.frame.len());
    let transport_start = offset_of(decoded.frame, after_header);
    decoded.network_payload = clamp_range(transport_start, end, decoded.frame.len());

    // A non-initial fragment carries no transport header — the ports live in
    // the first fragment only. Phase 2 reassembles; Phase 1 must not invent a
    // transport layer from payload bytes.
    if is_fragment && fragment_offset != 0 {
        decoded.payload = clamp_range(transport_start, end, decoded.frame.len());
        return;
    }

    decode_transport(decoded, header.protocol, transport_start, end);
}

fn decode_ipv6(decoded: &mut Decoded<'_>, slice: &[u8]) {
    let start = offset_of(decoded.frame, slice);

    let Some(&first) = slice.first() else {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv6, AnomalyKind::TruncatedHeader));
        return;
    };
    if first >> 4 != 6 {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv6, AnomalyKind::UnknownIpVersion));
        return;
    }

    let Ok((header, after_header)) = Ipv6Header::from_slice(slice) else {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv6, AnomalyKind::TruncatedHeader));
        return;
    };

    let payload_length = usize::from(header.payload_length);
    if payload_length > after_header.len() && !decoded.is_snapped() {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Ipv6, AnomalyKind::LengthMismatch));
    }

    // Walk the extension chain to find the real transport protocol.
    let mut protocol = header.next_header;
    let mut cursor = after_header;
    let mut is_fragment = false;
    let mut fragment_offset = 0u16;
    let mut more_fragments = false;
    let mut identification = 0u32;
    let mut walked = 0;

    while is_ipv6_extension(protocol) {
        if walked >= MAX_IPV6_EXTENSION_HEADERS {
            decoded
                .anomalies
                .push(Anomaly::new(Layer::Ipv6, AnomalyKind::TooManyLayers));
            break;
        }
        let Some(ext_len) = ipv6_extension_len(protocol, cursor) else {
            decoded
                .anomalies
                .push(Anomaly::new(Layer::Ipv6, AnomalyKind::TruncatedHeader));
            break;
        };
        if protocol == IpNumber::IPV6_FRAGMENTATION_HEADER {
            is_fragment = true;
            // Bytes 2..4 hold the offset in the top 13 bits and the "more
            // fragments" flag in the lowest; bytes 4..8 hold the id.
            if let (Some(&hi), Some(&lo)) = (cursor.get(2), cursor.get(3)) {
                fragment_offset = (u16::from(hi) << 8 | u16::from(lo)) >> 3;
                more_fragments = lo & 1 != 0;
            }
            if let Some(bytes) = cursor.get(4..8) {
                identification = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            }
        }
        protocol = IpNumber(cursor[0]);
        cursor = &cursor[ext_len..];
        walked += 1;
    }

    let header_len = offset_of(decoded.frame, cursor).saturating_sub(start);
    decoded.network = Some(Network::Ipv6(Ipv6Info {
        source: header.source.into(),
        destination: header.destination.into(),
        protocol: protocol.0,
        hop_limit: header.hop_limit,
        payload_length: header.payload_length,
        header_len,
        is_fragment,
        fragment_offset,
        more_fragments,
        identification,
    }));

    let claimed_end = start
        .saturating_add(Ipv6Header::LEN)
        .saturating_add(payload_length);
    let end = claimed_end.min(decoded.frame.len());
    let transport_start = offset_of(decoded.frame, cursor);
    decoded.network_payload = clamp_range(transport_start, end, decoded.frame.len());

    if is_fragment && fragment_offset != 0 {
        decoded.payload = clamp_range(transport_start, end, decoded.frame.len());
        return;
    }

    decode_transport(decoded, protocol, transport_start, end);
}

fn is_ipv6_extension(protocol: IpNumber) -> bool {
    matches!(
        protocol,
        IpNumber::IPV6_HEADER_HOP_BY_HOP
            | IpNumber::IPV6_ROUTE_HEADER
            | IpNumber::IPV6_FRAGMENTATION_HEADER
            | IpNumber::IPV6_DESTINATION_OPTIONS
            | IpNumber::AUTHENTICATION_HEADER
            | IpNumber::MOBILITY_HEADER
    )
}

/// Length in bytes of the extension header at the front of `slice`, or `None`
/// if the slice is too short to hold it.
fn ipv6_extension_len(protocol: IpNumber, slice: &[u8]) -> Option<usize> {
    if slice.len() < 2 {
        return None;
    }
    let len = match protocol {
        // The fragment header is a fixed 8 bytes and has no length field.
        IpNumber::IPV6_FRAGMENTATION_HEADER => 8,
        // The authentication header counts in 4-byte units, minus 2.
        IpNumber::AUTHENTICATION_HEADER => (usize::from(slice[1]) + 2) * 4,
        // Everything else counts 8-byte units after the first.
        _ => (usize::from(slice[1]) + 1) * 8,
    };
    (slice.len() >= len).then_some(len)
}

/// Decode a transport header from a standalone buffer.
///
/// Used for a datagram that has just been reassembled from IP fragments: the
/// network layer is already known to the caller, and what is left is a
/// transport header sitting at offset zero of its own buffer.
///
/// The returned [`Decoded`] has no network layer, so `five_tuple` returns
/// `None` — the caller pairs the transport it gets back with the addresses it
/// already has.
#[must_use]
pub fn decode_transport_bytes(bytes: &[u8], protocol: u8) -> Decoded<'_> {
    let mut decoded = Decoded::new(bytes, bytes.len());
    decode_transport(&mut decoded, IpNumber(protocol), 0, bytes.len());
    decoded
}

/// Decode the transport header living at `start`, with the IP packet ending at
/// `end`.
fn decode_transport(decoded: &mut Decoded<'_>, protocol: IpNumber, start: usize, end: usize) {
    let frame_len = decoded.frame.len();
    let available = decoded.frame.get(start..end.min(frame_len)).unwrap_or(&[]);

    match protocol {
        IpNumber::TCP => decode_tcp(decoded, available, start, end),
        IpNumber::UDP => decode_udp(decoded, available, start, end),
        IpNumber::ICMP | IpNumber::IPV6_ICMP => {
            decode_icmp(
                decoded,
                available,
                start,
                end,
                protocol == IpNumber::IPV6_ICMP,
            );
        }
        other => {
            decoded.transport = Some(Transport::Other { protocol: other.0 });
            decoded.payload = clamp_range(start, end, frame_len);
        }
    }
}

fn decode_tcp(decoded: &mut Decoded<'_>, slice: &[u8], start: usize, end: usize) {
    const MIN_TCP_HEADER: usize = 20;

    if slice.len() < MIN_TCP_HEADER {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Tcp, AnomalyKind::TruncatedHeader));
        return;
    }

    // Data offset is the top nibble of byte 12, in 4-byte words.
    let data_offset = usize::from(slice[12] >> 4);
    if data_offset < 5 {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Tcp, AnomalyKind::ImpossibleLength));
        return;
    }
    let header_len = data_offset * 4;
    if slice.len() < header_len {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Tcp, AnomalyKind::TruncatedHeader));
        return;
    }

    let Ok((header, _)) = TcpHeader::from_slice(slice) else {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Tcp, AnomalyKind::TruncatedHeader));
        return;
    };

    decoded.transport = Some(Transport::Tcp(TcpInfo {
        source_port: header.source_port,
        destination_port: header.destination_port,
        sequence_number: header.sequence_number,
        acknowledgment_number: header.acknowledgment_number,
        window_size: header.window_size,
        flags: TcpFlags {
            fin: header.fin,
            syn: header.syn,
            rst: header.rst,
            psh: header.psh,
            ack: header.ack,
            urg: header.urg,
            ece: header.ece,
            cwr: header.cwr,
        },
        header_len,
    }));
    decoded.payload = clamp_range(start + header_len, end, decoded.frame.len());
}

fn decode_udp(decoded: &mut Decoded<'_>, slice: &[u8], start: usize, end: usize) {
    const UDP_HEADER_LEN: usize = 8;

    if slice.len() < UDP_HEADER_LEN {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Udp, AnomalyKind::TruncatedHeader));
        return;
    }

    let Ok((header, _)) = UdpHeader::from_slice(slice) else {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Udp, AnomalyKind::TruncatedHeader));
        return;
    };

    let claimed = usize::from(header.length);
    if claimed < UDP_HEADER_LEN {
        // A UDP length below its own header size is impossible; a classic way
        // to make two stacks compute different payload lengths.
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Udp, AnomalyKind::ImpossibleLength));
    } else if claimed > slice.len() && !decoded.is_snapped() {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Udp, AnomalyKind::LengthMismatch));
    }

    decoded.transport = Some(Transport::Udp(UdpInfo {
        source_port: header.source_port,
        destination_port: header.destination_port,
        length: header.length,
    }));

    // Trust the smaller of what UDP claims and what the IP layer allows.
    let udp_end = start.saturating_add(claimed.max(UDP_HEADER_LEN));
    decoded.payload = clamp_range(
        start + UDP_HEADER_LEN,
        udp_end.min(end),
        decoded.frame.len(),
    );
}

fn decode_icmp(decoded: &mut Decoded<'_>, slice: &[u8], start: usize, end: usize, is_v6: bool) {
    if slice.len() < ICMP_HEADER_LEN {
        decoded
            .anomalies
            .push(Anomaly::new(Layer::Icmp, AnomalyKind::TruncatedHeader));
        // Type and code are the first two bytes; report them if they are there
        // at all, because a truncated ICMP message is still worth attributing.
        if slice.len() >= 2 {
            decoded.transport = Some(Transport::Icmp(IcmpInfo {
                icmp_type: slice[0],
                code: slice[1],
                is_v6,
            }));
        }
        return;
    }

    decoded.transport = Some(Transport::Icmp(IcmpInfo {
        icmp_type: slice[0],
        code: slice[1],
        is_v6,
    }));
    decoded.payload = clamp_range(start + ICMP_HEADER_LEN, end, decoded.frame.len());
}

/// Build a byte range that is always in bounds and never inverted.
fn clamp_range(start: usize, end: usize, frame_len: usize) -> Range<usize> {
    let start = start.min(frame_len);
    let end = end.min(frame_len).max(start);
    start..end
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings)]
mod tests;
