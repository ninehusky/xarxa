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

/// Indexed by `(ip_ty, plen, blen)`:
///
/// * `ip_ty` is `ip::Repr`'s version index, 0 for v4 and 1 for v6;
/// * `plen` is the header's `payload_len` field -- the number of octets `dispatch_ip` asks the
///   `TxToken` for, after the IP header;
/// * `blen` is a *lower bound stated exactly where it is known* on the payload repr's
///   `buffer_len()`, carried up from `IpPayload`.
///
/// `blen` is only ever used on the small side of `blen <= m`, so a variant that cannot state
/// its own length indexes `0` rather than lying; see `IpPayload`.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(ip_ty: int, plen: int, blen: int)]
#[flux_rs::invariant((ip_ty == 0 || ip_ty == 1) && 0 <= plen && blen <= plen)]
pub(crate) enum Packet<'p> {
    #[cfg(feature = "proto-ipv4")]
    #[flux_rs::variant((PacketV4[@p]) -> Packet[0, p.plen, p.blen])]
    Ipv4(PacketV4<'p>),
    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::variant((PacketV6[@p]) -> Packet[1, p.plen, p.blen])]
    Ipv6(PacketV6<'p>),
}

impl<'p> Packet<'p> {
    #[flux_rs::trusted(no, reason = "fan-in: forwards both indices to the per-version builders")]
    #[flux_rs::sig(
        fn(ip_repr: IpRepr[@ip], payload: IpPayload[@b]) -> Self[ip.ip_ty, ip.plen, b]
        requires b <= ip.plen
    )]
    pub(crate) fn new(ip_repr: IpRepr, payload: IpPayload<'p>) -> Self {
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(header) => Self::new_ipv4(header, payload),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(header) => Self::new_ipv6(header, payload),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    #[flux_rs::trusted(no, reason = "carries payload_len and the payload bound into the Packet")]
    #[flux_rs::sig(
        fn(ip_repr: Ipv4Repr[@r], payload: IpPayload[@b]) -> Self[0, r.plen, b]
        requires b <= r.plen
    )]
    pub(crate) fn new_ipv4(ip_repr: Ipv4Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv4(PacketV4 {
            header: ip_repr,
            payload,
        })
    }

    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::trusted(no, reason = "carries payload_len and the payload bound into the Packet")]
    #[flux_rs::sig(
        fn(ip_repr: Ipv6Repr[@r], payload: IpPayload[@b]) -> Self[1, r.plen, b]
        requires b <= r.plen
    )]
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

    #[flux_rs::trusted(no, reason = "carries the header's version and payload_len out")]
    #[flux_rs::sig(fn(self: &Self[@p]) -> IpRepr[p.ip_ty, p.plen])]
    pub(crate) fn ip_repr(&self) -> IpRepr {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => IpRepr::Ipv4(p.header),
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => IpRepr::Ipv6(p.header),
        }
    }

    #[flux_rs::trusted(no, reason = "carries the payload buffer-length bound out")]
    #[flux_rs::sig(fn(self: &Self[@p]) -> &IpPayload[p.blen])]
    pub(crate) fn payload(&self) -> &IpPayload<'p> {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => &p.payload,
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => &p.payload,
        }
    }

    /// Emit this packet's payload into `payload`.
    ///
    /// The contract is `blen <= m`: the payload repr will not write past the slice it is given.
    /// `blen` is `Packet`'s payload buffer-length index and `m` is the slice length. It is the
    /// bound `Icmpv6Repr::emit` asks for (`r.blen <= as_mut_reft(p.buffer)`), and the one the
    /// other payload reprs will ask for once they are refined.
    ///
    /// It is *not* a constant floor. H2's `40 <= m` is refuted by a real packet: `m` is
    /// `IpRepr::payload_len`, which is the payload repr's `buffer_len()`, and an ICMPv6
    /// `EchoRequest` over four data octets makes that 12.
    ///
    /// `emit_ip_into` discharges it from `blen + header_len <= n`, and `dispatch_ip` discharges
    /// *that* from `n == IpRepr::buffer_len() == header_len + plen` together with the
    /// `blen <= plen` invariant on `PacketV4`/`PacketV6` -- i.e. from the fact that every
    /// dispatcher sets `ip_repr.payload_len` to the payload's `buffer_len()` before dispatching.
    ///
    /// What the bound does *not* buy, per arm: the `Icmpv6` arms also owe
    /// `40 <= as_mut_reft(buffer)`, which is unsatisfiable here for exactly the reason above and
    /// has to come off `Icmpv6Repr::emit`; the two `unreachable!()` arms (`MightPanic`); the
    /// hop-by-hop header slices, where `hbh_end` is unconstrained because neither
    /// `Ipv6ExtHeaderRepr::header_len` nor `Ipv6HopByHopRepr::buffer_len` has a signature; the
    /// TCP window clamp's two `-=` underflows; and the `udp`/`dhcpv4` closures, whose bodies
    /// Flux does not check.
    #[flux_rs::trusted(no, reason = "checks the body; carries the payload buffer-length bound")]
    #[flux_rs::sig(
        fn(
            self: &Self[@p],
            _ip_repr: &IpRepr[@ip],
            payload: &mut [u8][@m],
            caps: &DeviceCapabilities,
        )
        requires p.blen <= m
    )]
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

                // Routed through `Buf` so the destination keeps its length: a bare `&mut [u8]`
                // instantiates core's blanket `AsMut for &mut T`, which carries no associated
                // refinement, and the buffer bound would then bind nothing.
                icmpv6_repr.emit(
                    &ipv6_repr.src_addr,
                    &ipv6_repr.dst_addr,
                    &mut Icmpv6Packet::new_unchecked(Buf::new(payload)),
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

                // As above: `Buf::with_offset` carries the tail's length into the refinement,
                // where `&mut payload[hbh_end..]` would lose it (flux-rs/flux#1714).
                icmpv6_repr.emit(
                    &ipv6_repr.src_addr,
                    &ipv6_repr.dst_addr,
                    &mut Icmpv6Packet::new_unchecked(Buf::with_offset(payload, hbh_end)),
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
#[flux_rs::refined_by(plen: int, blen: int)]
// `blen <= plen` is the whole point: every dispatcher sets `payload_len` to the payload repr's
// `buffer_len()` immediately before building the packet, so the IP header's payload_len is
// exactly the room the payload needs. Stating it here is what lets `dispatch_ip` discharge
// `emit_payload`'s bound from the buffer length it already asked the `TxToken` for.
#[flux_rs::invariant(0 <= plen && blen <= plen)]
pub(crate) struct PacketV4<'p> {
    #[field(Ipv4Repr[plen])]
    header: Ipv4Repr,
    #[field(IpPayload[blen])]
    payload: IpPayload<'p>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv6")]
#[flux_rs::refined_by(plen: int, blen: int)]
// See `PacketV4`.
#[flux_rs::invariant(0 <= plen && blen <= plen)]
pub(crate) struct PacketV6<'p> {
    #[field(Ipv6Repr[plen])]
    pub(crate) header: Ipv6Repr,
    #[cfg(feature = "proto-ipv6-hbh")]
    pub(crate) hop_by_hop: Option<Ipv6HopByHopRepr<'p>>,
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fragment: Option<Ipv6FragmentRepr>,
    #[cfg(feature = "proto-ipv6-routing")]
    pub(crate) routing: Option<Ipv6RoutingRepr<'p>>,
    #[field(IpPayload[blen])]
    pub(crate) payload: IpPayload<'p>,
}

/// Indexed by `blen`: a *sound lower bound* on the number of octets this payload's `emit` will
/// write, i.e. on the payload repr's `buffer_len()`.
///
/// It is a lower bound, not an equality, because only some of the payload reprs are refined:
///
/// * **exact** -- `Icmpv6` (`icmpv6::Repr` is `refined_by(blen)`), `Udp` (`UdpRepr` has no
///   payload of its own and `header_len()` is the constant `HEADER_LEN == 8`, so the length is
///   `8 + data.len()`), and `Raw` (`buffer_len()` *is* `data.len()`).
/// * **approximate, indexed `0`** -- `Icmpv4`, `Igmp`, `HopByHopIcmpv6`, `Tcp`, `Dhcpv4`. Those
///   reprs (`icmpv4::Repr`, `igmp::Repr`, `Ipv6HopByHopRepr`, `tcp::Repr`, `dhcpv4::Repr`) carry
///   no length index, so nothing better is statable here.
///
/// Indexing `0` is sound rather than a lie because `blen` is only ever consumed on the small
/// side of `blen <= m` (`Packet::emit_payload`): under-claiming weakens the precondition and
/// proves nothing about those arms. It would be unsound the moment someone writes `m <= blen`.
/// This is the same shape as `icmpv6::Repr`'s `Ndisc`/`Mld`/`Rpl` arms.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// No `0 <= blen` invariant: `icmpv6::Repr` carries none, so an abstract `Icmpv6Repr[@r]` cannot
// prove it for the arm that forwards `r.blen`. Nothing downstream needs it -- `blen` is only
// used on the small side of `blen <= plen` and `blen <= m`.
#[flux_rs::refined_by(blen: int)]
pub(crate) enum IpPayload<'p> {
    #[cfg(feature = "proto-ipv4")]
    #[flux_rs::variant((Icmpv4Repr) -> IpPayload[0])]
    Icmpv4(Icmpv4Repr<'p>),
    #[cfg(all(feature = "proto-ipv4", feature = "multicast"))]
    #[flux_rs::variant((IgmpRepr) -> IpPayload[0])]
    Igmp(IgmpRepr),
    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::variant((Icmpv6Repr[@r]) -> IpPayload[r.blen])]
    Icmpv6(Icmpv6Repr<'p>),
    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::variant((Ipv6HopByHopRepr, Icmpv6Repr) -> IpPayload[0])]
    HopByHopIcmpv6(Ipv6HopByHopRepr<'p>, Icmpv6Repr<'p>),
    #[cfg(feature = "socket-raw")]
    #[flux_rs::variant((&[u8][@k]) -> IpPayload[k])]
    Raw(&'p [u8]),
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    #[flux_rs::variant((UdpRepr, &[u8][@k]) -> IpPayload[8 + k])]
    Udp(UdpRepr, &'p [u8]),
    #[cfg(feature = "socket-tcp")]
    #[flux_rs::variant((TcpRepr) -> IpPayload[0])]
    Tcp(TcpRepr<'p>),
    #[cfg(feature = "socket-dhcpv4")]
    #[flux_rs::variant((UdpRepr, DhcpRepr) -> IpPayload[0])]
    Dhcpv4(UdpRepr, DhcpRepr<'p>),
}

impl<'p> IpPayload<'p> {
    #[cfg(feature = "proto-sixlowpan")]
    pub(crate) fn as_sixlowpan_next_header(&self) -> SixlowpanNextHeader {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Self::Icmpv4(_) => unreachable!(),
            #[cfg(feature = "socket-dhcpv4")]
            Self::Dhcpv4(..) => unreachable!(),
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
