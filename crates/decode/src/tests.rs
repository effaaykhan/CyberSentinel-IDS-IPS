//! Decoder tests.
//!
//! Frames are built byte by byte rather than with a packet-construction library,
//! because half of what is under test is what happens when a header field lies
//! about a length. A builder that produces only well-formed packets could not
//! express the interesting cases.

use super::*;

// ---------------------------------------------------------------------------
// wire-format builders
// ---------------------------------------------------------------------------

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ETHERTYPE_ARP: u16 = 0x0806;

fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // destination MAC
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // source MAC
    ];
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn vlan_tag(vlan_id: u16, inner_ether_type: u16) -> Vec<u8> {
    let mut tag = Vec::with_capacity(4);
    tag.extend_from_slice(&vlan_id.to_be_bytes());
    tag.extend_from_slice(&inner_ether_type.to_be_bytes());
    tag
}

fn ones_complement_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A well-formed IPv4 header, with knobs for each way it can be made wrong.
#[derive(Debug, Clone)]
struct Ipv4Builder {
    protocol: u8,
    source: [u8; 4],
    destination: [u8; 4],
    /// Override `total_len`; otherwise 20 + payload length.
    total_len: Option<u16>,
    /// Override the IHL nibble; otherwise 5.
    ihl: Option<u8>,
    /// Override the version nibble; otherwise 4.
    version: Option<u8>,
    fragment_offset: u16,
    more_fragments: bool,
    /// Corrupt the header checksum.
    break_checksum: bool,
}

impl Default for Ipv4Builder {
    fn default() -> Self {
        Self {
            protocol: 6,
            source: [192, 0, 2, 1],
            destination: [198, 51, 100, 7],
            total_len: None,
            ihl: None,
            version: None,
            fragment_offset: 0,
            more_fragments: false,
            break_checksum: false,
        }
    }
}

impl Ipv4Builder {
    fn build(&self, payload: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        let version = self.version.unwrap_or(4);
        let ihl = self.ihl.unwrap_or(5);
        header[0] = (version << 4) | (ihl & 0x0f);
        let total_len = self
            .total_len
            .unwrap_or_else(|| u16::try_from(20 + payload.len()).unwrap());
        header[2..4].copy_from_slice(&total_len.to_be_bytes());
        header[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        let flags_and_offset =
            (u16::from(self.more_fragments) << 13) | (self.fragment_offset & 0x1fff);
        header[6..8].copy_from_slice(&flags_and_offset.to_be_bytes());
        header[8] = 64;
        header[9] = self.protocol;
        header[12..16].copy_from_slice(&self.source);
        header[16..20].copy_from_slice(&self.destination);

        let checksum = ones_complement_checksum(&header);
        let checksum = if self.break_checksum {
            checksum.wrapping_add(1)
        } else {
            checksum
        };
        header[10..12].copy_from_slice(&checksum.to_be_bytes());

        header.extend_from_slice(payload);
        header
    }
}

/// A TCP header, with knobs for its data offset.
#[derive(Debug, Clone)]
struct TcpBuilder {
    source_port: u16,
    destination_port: u16,
    flags: u8,
    data_offset: Option<u8>,
}

impl Default for TcpBuilder {
    fn default() -> Self {
        Self {
            source_port: 51_000,
            destination_port: 80,
            flags: 0b0001_0010, // SYN|ACK
            data_offset: None,
        }
    }
}

impl TcpBuilder {
    fn build(&self, payload: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        header[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        header[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        header[4..8].copy_from_slice(&1u32.to_be_bytes());
        header[8..12].copy_from_slice(&2u32.to_be_bytes());
        header[12] = self.data_offset.unwrap_or(5) << 4;
        header[13] = self.flags;
        header[14..16].copy_from_slice(&64_240u16.to_be_bytes());
        header.extend_from_slice(payload);
        header
    }
}

fn udp(source_port: u16, destination_port: u16, length: Option<u16>, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 8];
    header[0..2].copy_from_slice(&source_port.to_be_bytes());
    header[2..4].copy_from_slice(&destination_port.to_be_bytes());
    let length = length.unwrap_or_else(|| u16::try_from(8 + payload.len()).unwrap());
    header[4..6].copy_from_slice(&length.to_be_bytes());
    header.extend_from_slice(payload);
    header
}

fn icmp(icmp_type: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![icmp_type, code, 0, 0, 0, 1, 0, 1];
    header.extend_from_slice(payload);
    header
}

fn ipv6(next_header: u8, payload_length: Option<u16>, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0u8; 40];
    header[0] = 0x60;
    let payload_length = payload_length.unwrap_or_else(|| u16::try_from(payload.len()).unwrap());
    header[4..6].copy_from_slice(&payload_length.to_be_bytes());
    header[6] = next_header;
    header[7] = 64;
    // 2001:db8::1 -> 2001:db8::2
    header[8..10].copy_from_slice(&[0x20, 0x01]);
    header[10..12].copy_from_slice(&[0x0d, 0xb8]);
    header[23] = 1;
    header[24..26].copy_from_slice(&[0x20, 0x01]);
    header[26..28].copy_from_slice(&[0x0d, 0xb8]);
    header[39] = 2;
    header.extend_from_slice(payload);
    header
}

/// A full, well-formed TCP-over-IPv4 frame carrying `payload`.
fn tcp_frame(payload: &[u8]) -> Vec<u8> {
    let tcp = TcpBuilder::default().build(payload);
    let ip = Ipv4Builder::default().build(&tcp);
    ethernet(ETHERTYPE_IPV4, &ip)
}

/// Decode a frame that was captured in full.
fn decode_whole(frame: &[u8]) -> Decoded<'_> {
    decode(frame, frame.len())
}

// ---------------------------------------------------------------------------
// well-formed packets
// ---------------------------------------------------------------------------

#[test]
fn decodes_tcp_over_ipv4() {
    let frame = tcp_frame(b"GET / HTTP/1.1\r\n");
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    let tuple = decoded.five_tuple().expect("a 5-tuple");
    assert_eq!(tuple.src_ip.to_string(), "192.0.2.1");
    assert_eq!(tuple.dest_ip.to_string(), "198.51.100.7");
    assert_eq!(tuple.src_port, Some(51_000));
    assert_eq!(tuple.dest_port, Some(80));
    assert_eq!(tuple.proto, Protocol::Tcp);

    let Some(Transport::Tcp(tcp)) = decoded.transport else {
        panic!("expected TCP, got {:?}", decoded.transport);
    };
    assert!(tcp.flags.syn && tcp.flags.ack);
    assert_eq!(tcp.flags.to_short_string(), "SA");
    assert_eq!(tcp.header_len, 20);

    assert_eq!(decoded.payload_bytes(), b"GET / HTTP/1.1\r\n");
}

#[test]
fn the_payload_is_a_range_into_the_original_frame() {
    let frame = tcp_frame(b"payload-bytes");
    let decoded = decode_whole(&frame);

    // 14 ethernet + 20 IPv4 + 20 TCP
    assert_eq!(decoded.payload, 54..54 + 13);
    assert_eq!(&frame[decoded.payload.clone()], b"payload-bytes");
    assert_eq!(decoded.payload_len(), 13);
}

#[test]
fn decodes_udp_over_ipv4() {
    let udp = udp(53_000, 53, None, b"\x00\x01query");
    let ip = Ipv4Builder {
        protocol: 17,
        ..Ipv4Builder::default()
    }
    .build(&udp);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    let tuple = decoded.five_tuple().unwrap();
    assert_eq!(tuple.proto, Protocol::Udp);
    assert_eq!(tuple.dest_port, Some(53));
    assert_eq!(decoded.payload_bytes(), b"\x00\x01query");
}

#[test]
fn decodes_icmp_and_reports_no_ports() {
    let icmp = icmp(8, 0, b"ping-payload");
    let ip = Ipv4Builder {
        protocol: 1,
        ..Ipv4Builder::default()
    }
    .build(&icmp);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    let Some(Transport::Icmp(info)) = decoded.transport else {
        panic!("expected ICMP, got {:?}", decoded.transport);
    };
    assert_eq!((info.icmp_type, info.code, info.is_v6), (8, 0, false));

    let tuple = decoded.five_tuple().unwrap();
    assert_eq!(tuple.proto, Protocol::Icmp);
    assert_eq!(tuple.src_port, None);
    assert_eq!(tuple.dest_port, None);
    assert_eq!(decoded.payload_bytes(), b"ping-payload");
}

#[test]
fn decodes_tcp_over_ipv6() {
    let tcp = TcpBuilder::default().build(b"v6-payload");
    let ip = ipv6(6, None, &tcp);
    let frame = ethernet(ETHERTYPE_IPV6, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    let tuple = decoded.five_tuple().unwrap();
    assert_eq!(tuple.src_ip.to_string(), "2001:db8::1");
    assert_eq!(tuple.dest_ip.to_string(), "2001:db8::2");
    assert_eq!(tuple.proto, Protocol::Tcp);
    assert_eq!(decoded.payload_bytes(), b"v6-payload");
}

#[test]
fn decodes_icmpv6() {
    let message = icmp(128, 0, b"v6ping");
    let ip = ipv6(58, None, &message);
    let frame = ethernet(ETHERTYPE_IPV6, &ip);
    let decoded = decode_whole(&frame);

    let Some(Transport::Icmp(info)) = decoded.transport else {
        panic!("expected ICMPv6, got {:?}", decoded.transport);
    };
    assert!(info.is_v6);
    assert_eq!(info.icmp_type, 128);
}

#[test]
fn walks_an_ipv6_extension_header_to_the_transport() {
    let tcp = TcpBuilder::default().build(b"after-ext");
    // Hop-by-hop options: next_header = TCP, len = 0 (meaning 8 bytes).
    let mut extension = vec![6u8, 0, 0, 0, 0, 0, 0, 0];
    extension.extend_from_slice(&tcp);
    let ip = ipv6(0, None, &extension);
    let frame = ethernet(ETHERTYPE_IPV6, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    assert_eq!(decoded.five_tuple().unwrap().proto, Protocol::Tcp);
    assert_eq!(decoded.payload_bytes(), b"after-ext");
}

#[test]
fn decodes_a_vlan_tagged_frame() {
    let tcp = TcpBuilder::default().build(b"tagged");
    let ip = Ipv4Builder::default().build(&tcp);
    let mut body = vlan_tag(100, ETHERTYPE_IPV4);
    body.extend_from_slice(&ip);
    let frame = ethernet(ETHERTYPE_VLAN, &body);
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    assert_eq!(decoded.vlan_ids[0], Some(100));
    assert_eq!(decoded.vlan_ids[1], None);
    assert_eq!(decoded.payload_bytes(), b"tagged");
}

#[test]
fn decodes_a_qinq_double_tagged_frame() {
    let tcp = TcpBuilder::default().build(b"double");
    let ip = Ipv4Builder::default().build(&tcp);
    let mut body = vlan_tag(10, ETHERTYPE_VLAN);
    body.extend_from_slice(&vlan_tag(20, ETHERTYPE_IPV4));
    body.extend_from_slice(&ip);
    let frame = ethernet(ETHERTYPE_QINQ, &body);
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    assert_eq!(decoded.vlan_ids, [Some(10), Some(20)]);
    assert_eq!(decoded.payload_bytes(), b"double");
}

#[test]
fn a_non_ip_ethertype_is_not_an_anomaly() {
    // ARP is ordinary traffic. Calling it anomalous would drown the real ones.
    let frame = ethernet(ETHERTYPE_ARP, &[0u8; 28]);
    let decoded = decode_whole(&frame);

    assert!(decoded.anomalies.is_empty());
    assert!(decoded.network.is_none());
    assert!(decoded.five_tuple().is_none());
    assert_eq!(decoded.ether_type, Some(ETHERTYPE_ARP));
}

#[test]
fn ethernet_padding_below_the_minimum_frame_size_is_not_an_anomaly() {
    // A 4-byte payload leaves the frame under 60 bytes, so a real NIC pads it.
    // total_len is then smaller than the captured frame, which is normal.
    let tcp = TcpBuilder::default().build(&[]);
    let ip = Ipv4Builder::default().build(&tcp);
    let mut frame = ethernet(ETHERTYPE_IPV4, &ip);
    frame.resize(60, 0);

    let decoded = decode_whole(&frame);
    assert!(decoded.anomalies.is_empty(), "{:?}", decoded.anomalies);
    assert_eq!(decoded.payload_len(), 0, "padding must not become payload");
}

// ---------------------------------------------------------------------------
// anomalies
// ---------------------------------------------------------------------------

#[test]
fn an_empty_frame_is_reported() {
    let decoded = decode(&[], 0);
    assert!(decoded
        .anomalies
        .contains(Layer::Ethernet, AnomalyKind::EmptyFrame));
}

#[test]
fn a_truncated_ethernet_header_is_reported() {
    let decoded = decode(&[0u8; 8], 8);
    assert!(decoded
        .anomalies
        .contains(Layer::Ethernet, AnomalyKind::TruncatedHeader));
}

#[test]
fn an_unknown_ip_version_is_reported() {
    let ip = Ipv4Builder {
        version: Some(7),
        ..Ipv4Builder::default()
    }
    .build(&[0u8; 20]);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Ipv4, AnomalyKind::UnknownIpVersion));
    assert!(decoded.network.is_none());
}

#[test]
fn an_ipv4_header_length_below_the_minimum_is_reported() {
    let ip = Ipv4Builder {
        ihl: Some(3),
        ..Ipv4Builder::default()
    }
    .build(&[0u8; 20]);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Ipv4, AnomalyKind::ImpossibleLength));
}

#[test]
fn an_ipv4_total_length_shorter_than_its_own_header_is_reported() {
    let ip = Ipv4Builder {
        total_len: Some(12),
        ..Ipv4Builder::default()
    }
    .build(&TcpBuilder::default().build(b"x"));
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Ipv4, AnomalyKind::ImpossibleLength));
}

#[test]
fn an_ipv4_length_that_overruns_a_complete_frame_is_reported() {
    let ip = Ipv4Builder {
        total_len: Some(9_000),
        ..Ipv4Builder::default()
    }
    .build(&TcpBuilder::default().build(b"short"));
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(
        decoded
            .anomalies
            .contains(Layer::Ipv4, AnomalyKind::LengthMismatch),
        "{:?}",
        decoded.anomalies
    );
    // The decode still succeeds; the packet is usable and now flagged.
    assert_eq!(decoded.five_tuple().unwrap().dest_port, Some(80));
}

#[test]
fn the_same_overrun_is_not_an_anomaly_when_the_frame_was_snapped() {
    // Identical bytes, but the capture snap length clipped the frame. A short
    // capture is expected and must not be confused with a lying header.
    let ip = Ipv4Builder {
        total_len: Some(9_000),
        ..Ipv4Builder::default()
    }
    .build(&TcpBuilder::default().build(b"short"));
    let frame = ethernet(ETHERTYPE_IPV4, &ip);

    let decoded = decode(&frame, 9_014);
    assert!(decoded.is_snapped());
    assert!(
        !decoded
            .anomalies
            .contains(Layer::Ipv4, AnomalyKind::LengthMismatch),
        "snap-length truncation must not be reported as a lying header"
    );
    assert_eq!(
        decoded.payload_bytes(),
        b"short",
        "payload clips to what was captured"
    );
}

#[test]
fn a_bad_ipv4_checksum_is_reported() {
    let ip = Ipv4Builder {
        break_checksum: true,
        ..Ipv4Builder::default()
    }
    .build(&TcpBuilder::default().build(b"x"));
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Ipv4, AnomalyKind::BadIpv4Checksum));
    // A bad checksum does not stop the decode: the packet is still evidence.
    assert!(decoded.five_tuple().is_some());
}

#[test]
fn a_tcp_data_offset_below_the_minimum_is_reported() {
    let tcp = TcpBuilder {
        data_offset: Some(0),
        ..TcpBuilder::default()
    }
    .build(b"payload");
    let ip = Ipv4Builder::default().build(&tcp);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Tcp, AnomalyKind::ImpossibleLength));
    assert!(decoded.transport.is_none());
    // Layer 3 survived, so the packet is still attributable to a host.
    assert!(decoded.network.is_some());
}

#[test]
fn a_tcp_data_offset_past_the_frame_is_reported() {
    let tcp = TcpBuilder {
        data_offset: Some(15), // 60 bytes of header, but only 20 are present
        ..TcpBuilder::default()
    }
    .build(&[]);
    let ip = Ipv4Builder::default().build(&tcp);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Tcp, AnomalyKind::TruncatedHeader));
}

#[test]
fn a_truncated_tcp_header_is_reported() {
    let ip = Ipv4Builder::default().build(&[0u8; 10]);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Tcp, AnomalyKind::TruncatedHeader));
}

#[test]
fn a_udp_length_below_its_own_header_is_reported() {
    let datagram = udp(1, 2, Some(3), b"payload");
    let ip = Ipv4Builder {
        protocol: 17,
        ..Ipv4Builder::default()
    }
    .build(&datagram);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Udp, AnomalyKind::ImpossibleLength));
}

#[test]
fn a_udp_length_that_overruns_a_complete_frame_is_reported() {
    let datagram = udp(1, 2, Some(4_000), b"payload");
    let ip = Ipv4Builder {
        protocol: 17,
        ..Ipv4Builder::default()
    }
    .build(&datagram);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Udp, AnomalyKind::LengthMismatch));
    // Payload is clipped to what is really there, never to what UDP claims.
    assert!(decoded.payload.end <= frame.len());
}

#[test]
fn more_vlan_tags_than_qinq_are_reported() {
    let mut body = vlan_tag(1, ETHERTYPE_VLAN);
    body.extend_from_slice(&vlan_tag(2, ETHERTYPE_VLAN));
    body.extend_from_slice(&vlan_tag(3, ETHERTYPE_IPV4));
    body.extend_from_slice(&Ipv4Builder::default().build(&TcpBuilder::default().build(b"x")));
    let frame = ethernet(ETHERTYPE_VLAN, &body);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Vlan, AnomalyKind::TooManyLayers));
}

#[test]
fn an_overlong_ipv6_extension_chain_is_reported() {
    // Nine chained hop-by-hop headers, one past the limit.
    let mut chain = Vec::new();
    for _ in 0..9 {
        chain.extend_from_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0]);
    }
    let ip = ipv6(0, None, &chain);
    let frame = ethernet(ETHERTYPE_IPV6, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded
        .anomalies
        .contains(Layer::Ipv6, AnomalyKind::TooManyLayers));
}

// ---------------------------------------------------------------------------
// fragments
// ---------------------------------------------------------------------------

#[test]
fn a_non_initial_fragment_yields_no_transport_header() {
    // Bytes at offset 185 are payload, not a TCP header. Reading ports out of
    // them would attribute the packet to a port nobody used.
    let ip = Ipv4Builder {
        fragment_offset: 185,
        ..Ipv4Builder::default()
    }
    .build(b"continuation-bytes");
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded.network.as_ref().unwrap().is_fragment());
    assert!(decoded.transport.is_none());
    assert_eq!(decoded.payload_bytes(), b"continuation-bytes");

    let tuple = decoded.five_tuple().unwrap();
    assert_eq!(tuple.proto, Protocol::Ip);
    assert_eq!(tuple.src_port, None);
}

#[test]
fn a_first_fragment_still_yields_its_transport_header() {
    let tcp = TcpBuilder::default().build(b"first-part");
    let ip = Ipv4Builder {
        more_fragments: true,
        ..Ipv4Builder::default()
    }
    .build(&tcp);
    let frame = ethernet(ETHERTYPE_IPV4, &ip);
    let decoded = decode_whole(&frame);

    assert!(decoded.network.as_ref().unwrap().is_fragment());
    assert_eq!(decoded.five_tuple().unwrap().dest_port, Some(80));
}

#[test]
fn an_ipv6_fragment_header_is_recognised() {
    // Fragment header: next=TCP, reserved, offset 185 (<<3), identification.
    let offset_field: u16 = 185 << 3;
    let mut fragment = vec![6u8, 0];
    fragment.extend_from_slice(&offset_field.to_be_bytes());
    fragment.extend_from_slice(&1u32.to_be_bytes());
    fragment.extend_from_slice(b"continuation");

    let ip = ipv6(44, None, &fragment);
    let frame = ethernet(ETHERTYPE_IPV6, &ip);
    let decoded = decode_whole(&frame);

    let Some(Network::Ipv6(info)) = decoded.network else {
        panic!("expected IPv6, got {:?}", decoded.network);
    };
    assert!(info.is_fragment);
    assert!(
        decoded.transport.is_none(),
        "a non-initial fragment has no transport header"
    );
}

// ---------------------------------------------------------------------------
// counters
// ---------------------------------------------------------------------------

#[test]
fn counters_classify_each_frame_once() {
    let mut counters = DecodeCounters::default();

    counters.record(&decode_whole(&tcp_frame(b"a")));
    let udp_frame = ethernet(
        ETHERTYPE_IPV4,
        &Ipv4Builder {
            protocol: 17,
            ..Ipv4Builder::default()
        }
        .build(&udp(1, 2, None, b"b")),
    );
    counters.record(&decode_whole(&udp_frame));
    counters.record(&decode_whole(&ethernet(ETHERTYPE_ARP, &[0u8; 28])));
    counters.record(&decode(&[0u8; 8], 8));

    assert_eq!(counters.packets, 4);
    assert_eq!(counters.ipv4, 2);
    assert_eq!(counters.tcp, 1);
    assert_eq!(counters.udp, 1);
    assert_eq!(
        counters.non_ip, 2,
        "ARP and the truncated frame both lack an IP layer"
    );
    assert_eq!(counters.anomalous, 1);
}

// ---------------------------------------------------------------------------
// totality
// ---------------------------------------------------------------------------

/// Every prefix of a valid frame must decode without panicking. This is the
/// cheap in-tree version of what `fuzz/fuzz_targets/decoder.rs` does properly.
#[test]
fn every_truncation_of_a_valid_frame_decodes_without_panicking() {
    for frame in [
        tcp_frame(b"payload"),
        ethernet(
            ETHERTYPE_IPV6,
            &ipv6(6, None, &TcpBuilder::default().build(b"payload")),
        ),
        {
            let mut body = vlan_tag(10, ETHERTYPE_VLAN);
            body.extend_from_slice(&vlan_tag(20, ETHERTYPE_IPV4));
            body.extend_from_slice(&Ipv4Builder::default().build(&udp(1, 2, None, b"x")));
            ethernet(ETHERTYPE_VLAN, &body)
        },
    ] {
        for end in 0..=frame.len() {
            let decoded = decode(&frame[..end], frame.len());
            // Whatever it decided, the payload range must be in bounds.
            assert!(
                decoded.payload.end <= end,
                "payload range escaped the frame at {end}"
            );
            assert!(decoded.payload.start <= decoded.payload.end);
            let _ = decoded.payload_bytes();
            let _ = decoded.five_tuple();
        }
    }
}

#[test]
fn hostile_byte_patterns_decode_without_panicking() {
    let patterns: [&[u8]; 6] = [
        &[],
        &[0xff; 1],
        &[0xff; 14],
        &[0x00; 64],
        &[0xff; 1500],
        &[0x45; 128],
    ];
    for pattern in patterns {
        let _ = decode(pattern, pattern.len());
        // Also with a wildly wrong original_len, which is attacker-influenced
        // on some capture backends.
        let _ = decode(pattern, usize::MAX);
        let _ = decode(pattern, 0);
    }
}
