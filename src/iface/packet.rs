use crate::phy::DeviceCapabilities;
use crate::wire::*;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "medium-ethernet")]
pub(crate) enum EthernetPacket<'a> {
    #[cfg(feature = "proto-ipv4")]
    Arp(ArpRepr),
    Ip(Packet<'a>),
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Packet<'p> {
    #[cfg(feature = "proto-ipv4")]
    Ipv4(PacketV4<'p>),
    #[cfg(feature = "proto-ipv6")]
    Ipv6(PacketV6<'p>),
}

impl<'p> Packet<'p> {
    /// The `requires` only bites on the IPv6 side: an IPv4 packet may carry any of these
    /// payloads, an IPv6 one may not (see [`PacketV6::payload`]). `IpRepr` is indexed
    /// `0 = Ipv4`, `1 = Ipv6`.
    #[flux_rs::trusted(no, reason = "propagates PacketV6's payload invariant to new_ipv6")]
    #[flux_rs::sig(fn(IpRepr[@v], IpPayload[@p]) -> _
        requires v == 1 => (p != 0 && p != 7))]
    pub(crate) fn new(ip_repr: IpRepr, payload: IpPayload<'p>) -> Self {
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(header) => Self::new_ipv4(header, payload),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(header) => Self::new_ipv6(header, payload),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    pub(crate) fn new_ipv4(ip_repr: Ipv4Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv4(PacketV4 {
            header: ip_repr,
            payload,
        })
    }

    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::trusted(no, reason = "establishes PacketV6's payload invariant")]
    #[flux_rs::sig(fn(Ipv6Repr, IpPayload[@p]) -> _ requires p != 0 && p != 7)]
    pub(crate) fn new_ipv6(ip_repr: Ipv6Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv6(PacketV6 {
            header: ip_repr,
            #[cfg(feature = "proto-ipv6-hbh")]
            hop_by_hop: None,
            #[cfg(feature = "proto-ipv6-fragmentation")]
            fragment: None,
            #[cfg(feature = "proto-ipv6-routing")]
            routing: None,
            payload,
        })
    }

    pub(crate) fn ip_repr(&self) -> IpRepr {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => IpRepr::Ipv4(p.header),
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => IpRepr::Ipv6(p.header),
        }
    }

    pub(crate) fn payload(&self) -> &IpPayload<'p> {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => &p.payload,
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => &p.payload,
        }
    }

    pub(crate) fn emit_payload(
        &self,
        _ip_repr: &IpRepr,
        payload: &mut [u8],
        caps: &DeviceCapabilities,
    ) {
        match self.payload() {
            #[cfg(feature = "proto-ipv4")]
            IpPayload::Icmpv4(icmpv4_repr) => {
                icmpv4_repr.emit(&mut Icmpv4Packet::new_unchecked(payload), &caps.checksum)
            }
            #[cfg(all(feature = "proto-ipv4", feature = "multicast"))]
            IpPayload::Igmp(igmp_repr) => igmp_repr.emit(&mut IgmpPacket::new_unchecked(payload)),
            #[cfg(feature = "proto-ipv6")]
            IpPayload::Icmpv6(icmpv6_repr) => {
                let ipv6_repr = match _ip_repr {
                    #[cfg(feature = "proto-ipv4")]
                    IpRepr::Ipv4(_) => unreachable!(),
                    IpRepr::Ipv6(repr) => repr,
                };

                icmpv6_repr.emit(
                    &ipv6_repr.src_addr,
                    &ipv6_repr.dst_addr,
                    &mut Icmpv6Packet::new_unchecked(payload),
                    &caps.checksum,
                )
            }
            #[cfg(feature = "proto-ipv6")]
            IpPayload::HopByHopIcmpv6(hbh_repr, icmpv6_repr) => {
                let ipv6_repr = match _ip_repr {
                    #[cfg(feature = "proto-ipv4")]
                    IpRepr::Ipv4(_) => unreachable!(),
                    IpRepr::Ipv6(repr) => repr,
                };

                let ipv6_ext_hdr = Ipv6ExtHeaderRepr {
                    next_header: IpProtocol::Icmpv6,
                    length: 0,
                    data: &[],
                };
                ipv6_ext_hdr.emit(&mut Ipv6ExtHeader::new_unchecked(
                    &mut payload[..ipv6_ext_hdr.header_len()],
                ));

                let hbh_start = ipv6_ext_hdr.header_len();
                let hbh_end = hbh_start + hbh_repr.buffer_len();
                hbh_repr.emit(&mut Ipv6HopByHopHeader::new_unchecked(
                    &mut payload[hbh_start..hbh_end],
                ));

                icmpv6_repr.emit(
                    &ipv6_repr.src_addr,
                    &ipv6_repr.dst_addr,
                    &mut Icmpv6Packet::new_unchecked(&mut payload[hbh_end..]),
                    &caps.checksum,
                );
            }

            #[cfg(feature = "socket-raw")]
            IpPayload::Raw(raw_packet) => {
                let len = raw_packet.len();
                payload[..len].copy_from_slice(raw_packet)
            }
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpPayload::Udp(udp_repr, inner_payload) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &_ip_repr.src_addr(),
                &_ip_repr.dst_addr(),
                inner_payload.len(),
                |buf| buf.copy_from_slice(inner_payload),
                &caps.checksum,
            ),
            #[cfg(feature = "socket-tcp")]
            &IpPayload::Tcp(mut tcp_repr) => {
                // This is a terrible hack to make TCP performance more acceptable on systems
                // where the TCP buffers are significantly larger than network buffers,
                // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                // together with four 1500 B Ethernet receive buffers. If left untreated,
                // this would result in our peer pushing our window and sever packet loss.
                //
                // I'm really not happy about this "solution" but I don't know what else to do.
                if let Some(max_burst_size) = caps.max_burst_size {
                    let mut max_segment_size = caps.max_transmission_unit;
                    max_segment_size -= _ip_repr.header_len();
                    max_segment_size -= tcp_repr.header_len();

                    let max_window_size = max_burst_size * max_segment_size;
                    if tcp_repr.window_len as usize > max_window_size {
                        tcp_repr.window_len = max_window_size as u16;
                    }
                }

                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(payload),
                    &_ip_repr.src_addr(),
                    &_ip_repr.dst_addr(),
                    &caps.checksum,
                );
            }
            #[cfg(feature = "socket-dhcpv4")]
            IpPayload::Dhcpv4(udp_repr, dhcp_repr) => udp_repr.emit(
                &mut UdpPacket::new_unchecked(payload),
                &_ip_repr.src_addr(),
                &_ip_repr.dst_addr(),
                dhcp_repr.buffer_len(),
                |buf| dhcp_repr.emit(&mut DhcpPacket::new_unchecked(buf)).unwrap(),
                &caps.checksum,
            ),
        }
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv4")]
pub(crate) struct PacketV4<'p> {
    header: Ipv4Repr,
    payload: IpPayload<'p>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv6")]
#[flux_rs::refined_by(payload_ty: int)]
#[flux_rs::invariant(payload_ty != 0 && payload_ty != 7)]
pub(crate) struct PacketV6<'p> {
    pub(crate) header: Ipv6Repr,
    #[cfg(feature = "proto-ipv6-hbh")]
    pub(crate) hop_by_hop: Option<Ipv6HopByHopRepr<'p>>,
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fragment: Option<Ipv6FragmentRepr>,
    #[cfg(feature = "proto-ipv6-routing")]
    pub(crate) routing: Option<Ipv6RoutingRepr<'p>>,
    /// Never one of the two IPv4-only payloads, `Icmpv4` (0) or `Dhcpv4` (7). This is the
    /// fact [`IpPayload::as_sixlowpan_next_header`] rests on; it is established at the two
    /// places a `PacketV6` is built, `Packet::new_ipv6` and `Packet::new`.
    ///
    /// `HopByHopIcmpv6` (3) is deliberately NOT excluded: `mldv2_report_packet` really does
    /// build one (`iface/interface/ipv6.rs`), and with `multicast` + a `Ieee802154` medium it
    /// reaches 6LoWPAN dispatch. Adding `payload_ty != 3` here makes Flux reject that
    /// construction, which is the correct answer -- so that arm's `unreachable!()` stays.
    #[flux_rs::field(IpPayload[payload_ty])]
    pub(crate) payload: IpPayload<'p>,
}

/// Refined by which variant it is, so a signature can rule particular payloads out.
///
/// The indices are written out per variant rather than left to declaration order: every
/// variant here is `cfg`-gated, so declaration order is not stable across feature sets,
/// and a signature naming `0` has to mean `Icmpv4` in every build.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(payload_ty: int)]
pub(crate) enum IpPayload<'p> {
    #[cfg(feature = "proto-ipv4")]
    #[flux_rs::variant((Icmpv4Repr) -> IpPayload[0])]
    Icmpv4(Icmpv4Repr<'p>),
    #[cfg(all(feature = "proto-ipv4", feature = "multicast"))]
    #[flux_rs::variant((IgmpRepr) -> IpPayload[1])]
    Igmp(IgmpRepr),
    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::variant((Icmpv6Repr) -> IpPayload[2])]
    Icmpv6(Icmpv6Repr<'p>),
    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::variant((Ipv6HopByHopRepr, Icmpv6Repr) -> IpPayload[3])]
    HopByHopIcmpv6(Ipv6HopByHopRepr<'p>, Icmpv6Repr<'p>),
    #[cfg(feature = "socket-raw")]
    #[flux_rs::variant((&[u8]) -> IpPayload[4])]
    Raw(&'p [u8]),
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    #[flux_rs::variant((UdpRepr, &[u8]) -> IpPayload[5])]
    Udp(UdpRepr, &'p [u8]),
    #[cfg(feature = "socket-tcp")]
    #[flux_rs::variant((TcpRepr) -> IpPayload[6])]
    Tcp(TcpRepr<'p>),
    #[cfg(feature = "socket-dhcpv4")]
    #[flux_rs::variant((UdpRepr, DhcpRepr) -> IpPayload[7])]
    Dhcpv4(UdpRepr, DhcpRepr<'p>),
}

impl<'p> IpPayload<'p> {
    /// # Panics
    ///
    /// Panics on `HopByHopIcmpv6`, which has no 6LoWPAN next-header encoding.
    ///
    /// The two IPv4-only payloads, `Icmpv4` and `Dhcpv4`, cannot occur in a [`PacketV6`] and
    /// so cannot reach here; the `requires` states that and Flux discharges the two
    /// `assert(false)`s below. `HopByHopIcmpv6` is a different story -- see
    /// [`PacketV6::payload`] -- and keeps its `unreachable!()`.
    #[allow(unsafe_code)]
    #[cfg(feature = "proto-sixlowpan")]
    #[flux_rs::trusted(no, reason = "discharges the assert(false) licensing unreachable_unchecked")]
    #[flux_rs::sig(fn(&IpPayload[@p]) -> _ requires p != 0 && p != 7)]
    pub(crate) fn as_sixlowpan_next_header(&self) -> SixlowpanNextHeader {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Self::Icmpv4(_) => {
                // If this assert never fires, Flux has shown this branch unreachable.
                flux_rs::assert(false);
                unsafe { core::hint::unreachable_unchecked() }
            }
            #[cfg(feature = "socket-dhcpv4")]
            Self::Dhcpv4(..) => {
                // Follows the same reasoning as above.
                flux_rs::assert(false);
                unsafe { core::hint::unreachable_unchecked() }
            }
            #[cfg(feature = "proto-ipv6")]
            Self::Icmpv6(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Icmpv6),
            #[cfg(feature = "proto-ipv6")]
            Self::HopByHopIcmpv6(_, _) => unreachable!(),
            #[cfg(all(feature = "proto-ipv4", feature = "multicast"))]
            Self::Igmp(_) => unreachable!(),
            #[cfg(feature = "socket-tcp")]
            Self::Tcp(_) => SixlowpanNextHeader::Uncompressed(IpProtocol::Tcp),
            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            Self::Udp(..) => SixlowpanNextHeader::Compressed,
            #[cfg(feature = "socket-raw")]
            Self::Raw(_) => todo!(),
        }
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
pub(crate) fn icmp_reply_payload_len(len: usize, mtu: usize, header_len: usize) -> usize {
    // Send back as much of the original payload as will fit within
    // the minimum MTU required by IPv4. See RFC 1812 § 4.3.2.3 for
    // more details.
    //
    // Since the entire network layer packet must fit within the minimum
    // MTU supported, the payload must not exceed the following:
    //
    // <min mtu> - IP Header Size * 2 - ICMPv4 DstUnreachable hdr size
    len.min(mtu - header_len * 2 - 8)
}
