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
// `plen` is the IP header's `payload_len`, carried on both variants. `blen` is the buffer the
// payload will fill, and uses `-1` for "not tracked", following `IpPayload`.
#[flux_rs::refined_by(ip_ty: int, plen: int, blen: int, minlen: int)]
#[flux_rs::invariant(ip_ty == 0 || ip_ty == 1)]
// A tracked payload length is a v4 one, and it equals the IP header's `payload_len`. Both halves
// come from the variants: `PacketV4` carries the equality as its own invariant, and the v6 side
// admits only an untracked payload.
#[flux_rs::invariant(blen == -1 || (ip_ty == 0 && blen == plen))]
// The payload cannot claim to need more octets than the header says it will be given. This is
// what carries the hop-by-hop floor to `dispatch_ip`, where `n == buffer_len()` relates it to
// the transmit buffer.
#[flux_rs::invariant(minlen <= plen)]
pub(crate) enum Packet<'p> {
    #[cfg(feature = "proto-ipv4")]
    #[flux_rs::variant((PacketV4[@p]) -> Packet[0, p.plen, p.blen, p.minlen])]
    Ipv4(PacketV4<'p>),
    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::variant((PacketV6[@p]) -> Packet[1, p.plen, p.blen, p.minlen])]
    Ipv6(PacketV6<'p>),
}

impl<'p> Packet<'p> {
    #[flux_rs::sig(
        fn(ip_repr: IpRepr[@ipr], payload: IpPayload[@b]) -> Packet[ipr.ip_ty, ipr.plen, b.blen, b.minlen]
        requires (ipr.ip_ty == 0 && b.blen != -1 => b.blen == ipr.plen)
            && (ipr.ip_ty == 1 => b.blen == -1)
            && b.minlen <= ipr.plen
    )]
    #[flux_rs::no_panic]
    pub(crate) fn new(ip_repr: IpRepr, payload: IpPayload<'p>) -> Self {
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(header) => Self::new_ipv4(header, payload),
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(header) => Self::new_ipv6(header, payload),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    #[flux_rs::sig(
        fn(ip_repr: Ipv4Repr[@r], payload: IpPayload[@b]) -> Packet[0, r.plen, b.blen, b.minlen]
        requires (b.blen != -1 => b.blen == r.plen) && b.minlen <= r.plen
    )]
    #[flux_rs::no_panic]
    pub(crate) fn new_ipv4(ip_repr: Ipv4Repr, payload: IpPayload<'p>) -> Self {
        Self::Ipv4(PacketV4 {
            header: ip_repr,
            payload,
        })
    }

    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::sig(
        fn(ip_repr: Ipv6Repr[@r], payload: IpPayload[@b]) -> Packet[1, r.plen, -1, b.minlen]
        requires b.blen == -1 && b.minlen <= r.plen
    )]
    #[flux_rs::no_panic]
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

    #[flux_rs::sig(fn(self: &Self[@p]) -> IpRepr[p.ip_ty, p.plen])]
    #[flux_rs::no_panic]
    pub(crate) fn ip_repr(&self) -> IpRepr {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => IpRepr::Ipv4(p.header),
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => IpRepr::Ipv6(p.header),
        }
    }

    #[flux_rs::sig(fn(self: &Self[@p]) -> &IpPayload[p.blen, p.minlen])]
    #[flux_rs::no_panic]
    pub(crate) fn payload(&self) -> &IpPayload<'p> {
        match self {
            #[cfg(feature = "proto-ipv4")]
            Packet::Ipv4(p) => &p.payload,
            #[cfg(feature = "proto-ipv6")]
            Packet::Ipv6(p) => &p.payload,
        }
    }

    /// The precondition is the whole point of this function's signature: `blen` is the exact
    /// buffer the payload fills, so `blen == m` is what makes the ICMPv4 arm's `Repr::emit`
    /// call dischargeable. Guarded by `blen != -1` because every other payload variant is
    /// indexed `-1` (see `IpPayload`), which leaves those arms owing exactly what they owed
    /// before this signature existed.
    ///
    /// `m <= 65535` is `ip::checksum::data`'s accumulator bound, surfaced rather than assumed.
    #[flux_rs::trusted(no, reason = "carries the payload buffer length into each repr's emit")]
    #[flux_rs::sig(
        fn(
            self: &Self[@p],
            _ip_repr: &IpRepr,
            payload: &mut [u8][@m],
            caps: &DeviceCapabilities,
        )
        requires (p.blen != -1 => (p.blen == m && m <= 65535)) && p.minlen <= m
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
                // Routed through `Buf` for the same reason as the Icmpv6 arm below: a bare
                // `&mut [u8]` instantiates core's blanket `AsMut for &mut T`, which carries no
                // associated refinement, and naming `as_mut_reft` at it aborts this body.
                icmpv4_repr.emit(
                    &mut Icmpv4Packet::new_unchecked(Buf::new(payload)),
                    &caps.checksum,
                )
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
            IpPayload::Udp(udp_repr, inner_payload) => {
                // `emit_slice` rather than `emit` with a copying closure: a refined bound on an
                // `impl FnOnce` parameter is not checked inside a closure body
                // (flux-rs/flux#23), so the closure's `copy_from_slice` could never be proved.
                // Routed through `Buf` for the same reason as the Icmpv4 arm above.
                let mut udp_packet = UdpPacket::new_unchecked(Buf::new(payload));
                udp_repr.emit_slice(
                    &mut udp_packet,
                    &_ip_repr.src_addr(),
                    &_ip_repr.dst_addr(),
                    inner_payload,
                    &caps.checksum,
                )
            }
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

                // Routed through `Buf` for the same reason as the Icmpv4 arm above. The bound
                // is *stated* here and not discharged: `TcpRepr` carries no refinement, so
                // `tcp_repr.buffer_len()` is not statable at this type and this variant is
                // still indexed `-1`. See the note on `IpPayload`.
                tcp_repr.emit(
                    &mut TcpPacket::new_unchecked(Buf::new(payload)),
                    &_ip_repr.src_addr(),
                    &_ip_repr.dst_addr(),
                    &caps.checksum,
                );
            }
            #[cfg(feature = "socket-dhcpv4")]
            IpPayload::Dhcpv4(udp_repr, dhcp_repr) => {
                // Routed through `Buf` so `udp::Repr::emit`'s buffer bound binds something. The
                // bound is *stated* here and not discharged: `DhcpRepr` carries no refinement,
                // so `dhcp_repr.buffer_len()` is not statable at this type and this variant is
                // still indexed `-1`. See the note on `IpPayload`.
                let mut udp_packet = UdpPacket::new_unchecked(Buf::new(payload));
                udp_repr.emit(
                    &mut udp_packet,
                    &_ip_repr.src_addr(),
                    &_ip_repr.dst_addr(),
                    dhcp_repr.buffer_len(),
                    |buf| dhcp_repr.emit(&mut DhcpPacket::new_unchecked(buf)).unwrap(),
                    &caps.checksum,
                )
            }
        }
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv4")]
#[flux_rs::refined_by(plen: int, blen: int, minlen: int)]
// The IP header's `payload_len` *is* what the payload emits, wherever the payload's length is
// tracked at all. Checked at every construction rather than assumed.
#[flux_rs::invariant(blen == -1 || blen == plen)]
#[flux_rs::invariant(minlen <= plen)]
pub(crate) struct PacketV4<'p> {
    #[flux_rs::field(Ipv4Repr[plen])]
    header: Ipv4Repr,
    #[flux_rs::field(IpPayload[blen, minlen])]
    payload: IpPayload<'p>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg(feature = "proto-ipv6")]
#[flux_rs::refined_by(plen: int, blen: int, minlen: int)]
// No payload *buffer* length is tracked on the v6 side, so an `IpPayload` whose length *is*
// tracked (today only `Icmpv4`) cannot be put in a `PacketV6`. Nothing in the crate does.
// The header's `payload_len` is carried regardless, mirroring `PacketV4`, and so is the
// `minlen` floor, which is what the hop-by-hop arm needs.
#[flux_rs::invariant(blen == -1)]
#[flux_rs::invariant(minlen <= plen)]
pub(crate) struct PacketV6<'p> {
    #[flux_rs::field(Ipv6Repr[plen])]
    pub(crate) header: Ipv6Repr,
    #[cfg(feature = "proto-ipv6-hbh")]
    pub(crate) hop_by_hop: Option<Ipv6HopByHopRepr<'p>>,
    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fragment: Option<Ipv6FragmentRepr>,
    #[cfg(feature = "proto-ipv6-routing")]
    pub(crate) routing: Option<Ipv6RoutingRepr<'p>>,
    #[flux_rs::field(IpPayload[blen, minlen])]
    pub(crate) payload: IpPayload<'p>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// `blen` is the buffer this payload will fill exactly, or `-1` where it is not tracked.
//
// `Icmpv4` and `Udp` are exact. `Udp` needs no refinement on `UdpRepr` at all: the datagram is
// the fixed 8-octet header plus the payload slice, and the slice's length is already in the
// refinement, so the variant states it directly.
//
// Every other repr here is unrefined -- its `buffer_len()` is not statable at this type -- so
// they are indexed `-1`, and `emit_payload`'s precondition guards on `blen != -1`. That leaves
// those arms owing exactly what they owed before, rather than claiming a length the code does
// not carry. `Tcp` and `Dhcpv4` now *state* their emitter's buffer bound without discharging
// it; refining `TcpRepr`, `DhcpRepr` and `IgmpRepr` by their own `buffer_len()`, and tying
// `Icmpv6Repr`'s existing `blen` index to its `buffer_len()`, is what turns each `-1` into a
// real index.
//
// `minlen` is separate and always statable: a *lower* bound on the octets the payload writes,
// `0` where nothing is known. `blen` has to be exact or absent, which is why `HopByHopIcmpv6`
// cannot use it -- `ipv6::Repr::buffer_len`'s MLD arm is deliberately approximate and the record
// lengths are a `Vec` sum. A floor is enough for that arm's obligations, which are all of the
// form `offset <= payload.len()`.
#[flux_rs::refined_by(blen: int, minlen: int)]
#[flux_rs::invariant(blen == -1 || 8 <= blen)]
#[flux_rs::invariant(0 <= minlen)]
#[flux_rs::invariant(blen != -1 => minlen <= blen)]
pub(crate) enum IpPayload<'p> {
    #[cfg(feature = "proto-ipv4")]
    #[flux_rs::variant((Icmpv4Repr[@r]) -> IpPayload[r.blen, 0])]
    Icmpv4(Icmpv4Repr<'p>),
    #[cfg(all(feature = "proto-ipv4", feature = "multicast"))]
    #[flux_rs::variant((IgmpRepr) -> IpPayload[-1, 0])]
    Igmp(IgmpRepr),
    #[cfg(feature = "proto-ipv6")]
    #[flux_rs::variant((Icmpv6Repr) -> IpPayload[-1, 0])]
    Icmpv6(Icmpv6Repr<'p>),
    #[cfg(feature = "proto-ipv6")]
    // 2 is `Ipv6ExtHeaderRepr::header_len()`, which `emit_payload` writes before the
    // hop-by-hop options. The ICMPv6 body contributes more, but not a statable amount.
    #[flux_rs::variant((Ipv6HopByHopRepr[@h], Icmpv6Repr) -> IpPayload[-1, 2 + h.blen])]
    HopByHopIcmpv6(Ipv6HopByHopRepr<'p>, Icmpv6Repr<'p>),
    #[cfg(feature = "socket-raw")]
    #[flux_rs::variant((&[u8]) -> IpPayload[-1, 0])]
    Raw(&'p [u8]),
    #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
    // 8 is `udp::HEADER_LEN`, restated as a literal because flux cannot see through the
    // `Range` const it is derived from.
    #[flux_rs::variant((UdpRepr, &[u8][@m]) -> IpPayload[8 + m, 0])]
    Udp(UdpRepr, &'p [u8]),
    #[cfg(feature = "socket-tcp")]
    #[flux_rs::variant((TcpRepr) -> IpPayload[-1, 0])]
    Tcp(TcpRepr<'p>),
    #[cfg(feature = "socket-dhcpv4")]
    #[flux_rs::variant((UdpRepr, DhcpRepr) -> IpPayload[-1, 0])]
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
