use bitflags::bitflags;

use super::{Error, Result};
use crate::time::Duration;
use crate::wire::Ipv6Address;
use crate::wire::{Maybe, MaybeAddr, RawHardwareAddress};
use crate::wire::Ref;
use crate::wire::mld::read_ipv6_addr_at;
use crate::wire::icmpv6::{Message, Packet, field};
use crate::wire::{NdiscOption, NdiscOptionRepr};
use crate::wire::{NdiscPrefixInformation, NdiscRedirectedHeader};

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct RouterFlags: u8 {
        const MANAGED = 0b10000000;
        const OTHER   = 0b01000000;
    }
}

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct NeighborFlags: u8 {
        const ROUTER    = 0b10000000;
        const SOLICITED = 0b01000000;
        const OVERRIDE  = 0b00100000;
    }
}

/// Getters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the current hop limit field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u8
        requires 5 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn current_hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CUR_HOP_LIMIT]
    }

    /// Return the Router Advertisement flags.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> RouterFlags
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn router_flags(&self) -> RouterFlags {
        let data = self.buffer.as_ref();
        RouterFlags::from_bits_truncate(data[field::ROUTER_FLAGS])
    }

    /// Return the router lifetime field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Duration
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn router_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        // field::ROUTER_LT (6..8), spelled as a literal: a `const` of struct type is opaque
        // to Flux, so the range's endpoints are unconstrained `usize`s.
        Duration::from_secs(crate::wire::read_u16_at(data, 6) as u64)
    }

    /// Return the reachable time field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Duration
        requires 12 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn reachable_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        // field::REACHABLE_TM (8..12), read as two big-endian halves: there is no
        // `read_u32_at` helper, and `NetworkEndian::read_u32` takes a sub-slice whose length
        // the caller cannot recover (flux-rs/flux#1714). Same four bytes, same value.
        let hi = crate::wire::read_u16_at(data, 8) as u32;
        let lo = crate::wire::read_u16_at(data, 10) as u32;
        Duration::from_millis(((hi << 16) | lo) as u64)
    }

    /// Return the retransmit time field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Duration
        requires 16 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn retrans_time(&self) -> Duration {
        let data = self.buffer.as_ref();
        // field::RETRANS_TM (12..16), split for the same reason as `reachable_time`.
        let hi = crate::wire::read_u16_at(data, 12) as u32;
        let lo = crate::wire::read_u16_at(data, 14) as u32;
        Duration::from_millis(((hi << 16) | lo) as u64)
    }
}

/// Common getters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the target address field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Ipv6Address
        requires 24 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn target_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        read_ipv6_addr_at(data, 8) // field::TARGET_ADDR
    }
}

/// Getters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Neighbor Solicitation flags.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> NeighborFlags
        requires 5 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn neighbor_flags(&self) -> NeighborFlags {
        let data = self.buffer.as_ref();
        NeighborFlags::from_bits_truncate(data[field::NEIGH_FLAGS])
    }
}

/// Getters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the destination address field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Ipv6Address
        requires 40 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn dest_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        read_ipv6_addr_at(data, 24) // field::DEST_ADDR
    }
}

/// Setters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the current hop limit field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u8)
        requires 5 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_current_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CUR_HOP_LIMIT] = value;
    }

    /// Set the Router Advertisement flags.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], RouterFlags)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_router_flags(&mut self, flags: RouterFlags) {
        self.buffer.as_mut()[field::ROUTER_FLAGS] = flags.bits();
    }

    /// Set the router lifetime field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], Duration)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_router_lifetime(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        // field::ROUTER_LT (6..8)
        crate::wire::write_u16_at(data, 6, value.secs() as u16);
    }

    /// Set the reachable time field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], Duration)
        requires 12 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_reachable_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        // field::REACHABLE_TM (8..12), written as the two big-endian halves it is defined to
        // produce -- there is no `write_u32_at` helper. Identical bytes.
        let v = value.total_millis() as u32;
        crate::wire::write_u16_at(data, 8, (v >> 16) as u16);
        crate::wire::write_u16_at(data, 10, v as u16);
    }

    /// Set the retransmit time field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], Duration)
        requires 16 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_retrans_time(&mut self, value: Duration) {
        let data = self.buffer.as_mut();
        // field::RETRANS_TM (12..16), split for the same reason as `set_reachable_time`.
        let v = value.total_millis() as u32;
        crate::wire::write_u16_at(data, 12, (v >> 16) as u16);
        crate::wire::write_u16_at(data, 14, v as u16);
    }
}

/// Common setters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the target address field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], Ipv6Address)
        requires 24 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_target_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        // field::TARGET_ADDR (8..24)
        crate::wire::write_octets16_at(data, 8, &value.octets());
    }
}

/// Setters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Neighbor Solicitation flags.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], NeighborFlags)
        requires 5 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_neighbor_flags(&mut self, flags: NeighborFlags) {
        self.buffer.as_mut()[field::NEIGH_FLAGS] = flags.bits();
    }
}

/// Setters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the destination address field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], Ipv6Address)
        requires 40 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_dest_addr(&mut self, value: Ipv6Address) {
        let data = self.buffer.as_mut();
        // field::DEST_ADDR (24..40)
        crate::wire::write_octets16_at(data, 24, &value.octets());
    }
}

flux_rs::defs! {
    // What an optional link-layer address option contributes: two octets of preamble plus the
    // address, rounded up, or nothing. `round8` is `ndiscoption`'s own -- a second definition
    // with the same body would be a distinct function to fixpoint, and the offsets here are
    // compared against `NdiscOptionRepr::buffer_len`, which is stated in terms of that one.
    fn nd_opt_addr(present: bool, len: int) -> int {
        if present { if 2 + len <= 8 { 8 } else { 16 } } else { 0 }
    }

    // What an optional redirected-header option contributes. 48 is eight octets of preamble
    // plus `Ipv6Repr::buffer_len()`, a constant 40, rounded up to a multiple of eight.
    //
    // The rounding is written out rather than delegated: `ndiscoption::round8` is in another
    // module, and a local helper called from here would be a nested defn call. Neither is
    // unfolded, so `8 <= blen` -- and with it every setter bound in the Redirect arm -- could
    // not be discharged through either. Checked against the original by `Repr::buffer_len`
    // proving its own index.
    fn nd_opt_redir(present: bool, dlen: int) -> int {
        if present {
            if (48 + dlen) % 8 == 0 { 48 + dlen } else { 48 + dlen + 8 - (48 + dlen) % 8 }
        } else {
            0
        }
    }
}

/// An optional redirected header that keeps its data's length.
///
/// See [`MaybeAddr`], for the same reason.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(present: bool, dlen: int)]
// `RedirectedHeader`'s own invariant bounds its data length, but that constrains the *struct*,
// not this enum's index; without restating it `dlen` is unconstrained wherever a `Repr` is
// destructured, and `Repr`'s `8 <= blen` cannot be proved. The upper half is what carries
// `blen <= 65535` the same way.
#[flux_rs::invariant(0 <= dlen && dlen <= 65424)]
pub enum MaybeRedirected<'a> {
    #[flux_rs::variant(MaybeRedirected[false, 0])]
    Absent,
    #[flux_rs::variant((NdiscRedirectedHeader[@h]) -> MaybeRedirected[true, h.dlen])]
    Present(NdiscRedirectedHeader<'a>),
}

impl<'a> MaybeRedirected<'a> {
    /// Whether a redirected header is present.
    #[flux_rs::sig(fn(&MaybeRedirected[@m]) -> bool[m.present])]
    pub const fn is_present(&self) -> bool {
        matches!(self, MaybeRedirected::Present(_))
    }

    /// As an `Option`. The refinement is lost on the way out.
    pub const fn as_option(&self) -> Option<NdiscRedirectedHeader<'a>> {
        match *self {
            MaybeRedirected::Present(h) => Some(h),
            MaybeRedirected::Absent => None,
        }
    }

    /// From an `Option`. The result's index is unknown but fixed.
    pub const fn from_option(value: Option<NdiscRedirectedHeader<'a>>) -> MaybeRedirected<'a> {
        match value {
            Some(h) => MaybeRedirected::Present(h),
            None => MaybeRedirected::Absent,
        }
    }
}

/// The octets an optional link-layer address option contributes.
#[flux_rs::sig(fn(MaybeAddr[@l]) -> usize[nd_opt_addr(l.present, l.len)])]
#[flux_rs::no_panic]
const fn opt_addr_len(lladdr: MaybeAddr) -> usize {
    match lladdr {
        MaybeAddr::Present(addr) => {
            let len = 2 + addr.len();
            if len % 8 == 0 { len } else { len + 8 - len % 8 }
        }
        MaybeAddr::Absent => 0,
    }
}

/// A high-level representation of an Neighbor Discovery packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// Indexed by the length of the *fixed* header each variant writes, which is the per-arm bound
// `Repr::emit`'s setters actually need: 8 for RouterSolicit (`field::UNUSED.end`), 16 for
// RouterAdvert (`RETRANS_TM.end`), 24 for the two Neighbor arms (`TARGET_ADDR.end`) and 40 for
// Redirect (`DEST_ADDR.end`). It is a *lower* bound on `buffer_len()`, not equal to it: the
// trailing NDISC options contribute a length that `NdiscOptionRepr` -- unrefined -- cannot state.
// That is enough for the caller: `Icmpv6Repr::emit` can now discharge this arm from its own
// `r.blen <= buffer` conjunct instead of a blanket `40 <= buffer`.
// Smallest variant is RouterSolicit at `field::UNUSED.end` == 8. Flux checks this against the
// `variant` indices below; `Icmpv6Repr`'s own `4 <= blen` invariant rests on it.
#[flux_rs::invariant(8 <= blen)]
// See `icmpv4::Repr`: an NDISC message is emitted inside an ICMPv6 packet, inside an IPv6
// packet whose length field is sixteen bits. This is what lets `Icmpv6Repr`'s own
// `blen <= 65535` hold through its `Ndisc` variant.
#[flux_rs::invariant(blen <= 65535)]
#[flux_rs::refined_by(blen: int)]
pub enum Repr<'a> {
    #[flux_rs::variant({MaybeAddr[@l]} -> Repr[8 + nd_opt_addr(l.present, l.len)])]
    RouterSolicit {
        lladdr: MaybeAddr,
    },
    #[flux_rs::variant({u8, RouterFlags, Duration, Duration, Duration,
                        MaybeAddr[@l], Maybe<u32>[@m],
                        Maybe<NdiscPrefixInformation>[@pi]}
                       -> Repr[16 + nd_opt_addr(l.present, l.len)
                               + (if m { 8 } else { 0 }) + (if pi { 32 } else { 0 })])]
    RouterAdvert {
        hop_limit: u8,
        flags: RouterFlags,
        router_lifetime: Duration,
        reachable_time: Duration,
        retrans_time: Duration,
        lladdr: MaybeAddr,
        mtu: Maybe<u32>,
        prefix_info: Maybe<NdiscPrefixInformation>,
    },
    #[flux_rs::variant({Ipv6Address, MaybeAddr[@l]}
                       -> Repr[24 + nd_opt_addr(l.present, l.len)])]
    NeighborSolicit {
        target_addr: Ipv6Address,
        lladdr: MaybeAddr,
    },
    #[flux_rs::variant({NeighborFlags, Ipv6Address, MaybeAddr[@l]}
                       -> Repr[24 + nd_opt_addr(l.present, l.len)])]
    NeighborAdvert {
        flags: NeighborFlags,
        target_addr: Ipv6Address,
        lladdr: MaybeAddr,
    },
    #[flux_rs::variant({Ipv6Address, Ipv6Address, MaybeAddr[@l], MaybeRedirected[@h]}
                       -> Repr[40 + nd_opt_addr(l.present, l.len)
                               + nd_opt_redir(h.present, h.dlen)])]
    Redirect {
        target_addr: Ipv6Address,
        dest_addr: Ipv6Address,
        lladdr: MaybeAddr,
        redirected_hdr: MaybeRedirected<'a>,
    },
}

impl<'a> Repr<'a> {
    /// Parse an NDISC packet and return a high-level representation of the
    /// packet.
    #[allow(clippy::single_match)]
    pub fn parse(packet: &Packet<Ref<'a>>) -> Result<Repr<'a>> {
        // `checked_len` rather than `check_len`: the same test, but its `Ok` arm names the
        // buffer's length, which is what `payload` opens its window against.
        packet.checked_len()?;

        let (mut src_ll_addr, mut mtu, mut prefix_info, mut target_ll_addr, mut redirected_hdr) =
            (None, None, None, None, None);

        let mut offset = 0;
        while packet.payload().len() > offset {
            let pkt = NdiscOption::new_checked_ref(Ref::new(&packet.payload()[offset..]))?;

            // If an option doesn't parse, ignore it and still parse the others.
            if let Ok(opt) = NdiscOptionRepr::parse(&pkt) {
                match opt {
                    NdiscOptionRepr::SourceLinkLayerAddr(addr) => src_ll_addr = Some(addr),
                    NdiscOptionRepr::TargetLinkLayerAddr(addr) => target_ll_addr = Some(addr),
                    NdiscOptionRepr::PrefixInformation(prefix) => prefix_info = Some(prefix),
                    NdiscOptionRepr::RedirectedHeader(redirect) => redirected_hdr = Some(redirect),
                    NdiscOptionRepr::Mtu(m) => mtu = Some(m),
                    _ => {}
                }
            }

            let len = pkt.data_len() as usize * 8;
            if len == 0 {
                return Err(Error);
            }
            offset += len;
        }

        // The option slots are accumulated above as `Option`s, which carry no refinement.
        // Converting once here is what lets the variants state their own length; the resulting
        // index is unknown but fixed, which is all `buffer_len` and `emit` need -- they read the
        // same value.
        let src_ll_addr = MaybeAddr::from_option(src_ll_addr);
        let target_ll_addr = MaybeAddr::from_option(target_ll_addr);
        let mtu = Maybe::from_option(mtu);
        let prefix_info = Maybe::from_option(prefix_info);
        let redirected_hdr = MaybeRedirected::from_option(redirected_hdr);

        match packet.msg_type() {
            Message::RouterSolicit => Ok(Repr::RouterSolicit {
                lladdr: src_ll_addr,
            }),
            Message::RouterAdvert => Ok(Repr::RouterAdvert {
                hop_limit: packet.current_hop_limit(),
                flags: packet.router_flags(),
                router_lifetime: packet.router_lifetime(),
                reachable_time: packet.reachable_time(),
                retrans_time: packet.retrans_time(),
                lladdr: src_ll_addr,
                mtu,
                prefix_info,
            }),
            Message::NeighborSolicit => Ok(Repr::NeighborSolicit {
                target_addr: packet.target_addr(),
                lladdr: src_ll_addr,
            }),
            Message::NeighborAdvert => Ok(Repr::NeighborAdvert {
                flags: packet.neighbor_flags(),
                target_addr: packet.target_addr(),
                lladdr: target_ll_addr,
            }),
            Message::Redirect => Ok(Repr::Redirect {
                target_addr: packet.target_addr(),
                dest_addr: packet.dest_addr(),
                // RFC 4861 §4.5: a Redirect carries a Target LL address (type 2).
                lladdr: target_ll_addr,
                redirected_hdr,
            }),
            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    //
    // 8, 16, 24 and 40 restate `field::UNUSED.end`, `field::RETRANS_TM.end`,
    // `field::TARGET_ADDR.end` and `field::DEST_ADDR.end`: flux cannot see through a `Range`
    // const. The option lengths are spelled out rather than routed through
    // `NdiscOptionRepr::buffer_len` so each is a function of this repr's own index.
    #[flux_rs::trusted(no, reason = "ties the `blen` index to the emitted length")]
    #[flux_rs::sig(fn(self: &Self[@r]) -> usize[r.blen])]
    #[flux_rs::no_panic]
    pub const fn buffer_len(&self) -> usize {
        match self {
            &Repr::RouterSolicit { lladdr } => 8 + opt_addr_len(lladdr),
            &Repr::RouterAdvert {
                lladdr,
                mtu,
                prefix_info,
                ..
            } => {
                let mut offset = 16 + opt_addr_len(lladdr);
                if mtu.is_present() {
                    offset += 8;
                }
                if prefix_info.is_present() {
                    offset += 32;
                }
                offset
            }
            &Repr::NeighborSolicit { lladdr, .. } | &Repr::NeighborAdvert { lladdr, .. } => {
                24 + opt_addr_len(lladdr)
            }
            &Repr::Redirect {
                lladdr,
                redirected_hdr,
                ..
            } => {
                let mut offset = 40 + opt_addr_len(lladdr);
                if let MaybeRedirected::Present(NdiscRedirectedHeader { data, .. }) = redirected_hdr
                {
                    let len = 48 + crate::flux_util::byte_len(data);
                    offset += if len % 8 == 0 { len } else { len + 8 - len % 8 };
                }
                offset
            }
        }
    }

    /// Emit this high-level representation into an ICMPv6 packet.
    ///
    /// The receiver bound is existential (`{v: ..}`) rather than indexed (`[@p]`):
    /// `set_msg_type` rewrites the `code` index, and an indexed `&mut` receiver then fails
    /// Flux's invariance check with `type invariant may not hold`.
    ///
    /// 40 octets is the widest *fixed* header any arm writes -- Redirect's `set_dest_addr`
    /// reaches `field::DEST_ADDR.end`. It is exactly the bound `Icmpv6Repr::emit` already
    /// carries, so no caller owes anything new.
    ///
    /// STILL OWED: the option emits below want 48 octets of *payload*, i.e.
    /// `icmpv6_header_len(code) + 48 <= as_mut_reft(buffer)`, and the RouterAdvert and Redirect
    /// arms additionally want `offset + 48 <= payload len`. Neither is provable here, for two
    /// reasons that both live outside this function. `Icmpv6Repr`'s `Ndisc` variant is indexed
    /// `0` rather than by `NdiscRepr::buffer_len()` (see the note above `Icmpv6Repr` in
    /// `icmpv6.rs`), so the caller carries no option size at all; and
    /// `NdiscOptionRepr::buffer_len` has no Flux signature, so `offset` is an unconstrained
    /// `usize`. Refining `NdiscOptionRepr` by its buffer length is what closes both.
    #[flux_rs::trusted(no, reason = "carries the icmpv6 buffer bound to the ndisc setters")]
    #[flux_rs::sig(
        fn(&Repr[@r], packet: &strg Packet<T>[@p])
        requires r.blen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures packet: Packet<T>{v: v.buffer == p.buffer}
    )]
    pub fn emit<T>(&self, packet: &mut Packet<T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        match *self {
            Repr::RouterSolicit { lladdr } => {
                packet.set_msg_type(Message::RouterSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                if let MaybeAddr::Present(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_buf());
                    NdiscOptionRepr::SourceLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            }

            Repr::RouterAdvert {
                hop_limit,
                flags,
                router_lifetime,
                reachable_time,
                retrans_time,
                lladdr,
                mtu,
                prefix_info,
            } => {
                packet.set_msg_type(Message::RouterAdvert);
                packet.set_msg_code(0);
                packet.set_current_hop_limit(hop_limit);
                packet.set_router_flags(flags);
                packet.set_router_lifetime(router_lifetime);
                packet.set_reachable_time(reachable_time);
                packet.set_retrans_time(retrans_time);
                let mut offset = 0;
                if let MaybeAddr::Present(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_buf());
                    let opt = NdiscOptionRepr::SourceLinkLayerAddr(lladdr);
                    opt.emit(&mut opt_pkt);
                    offset += opt.buffer_len();
                }
                if let Maybe::Just(mtu) = mtu {
                    emit_option_at(packet, offset, &NdiscOptionRepr::Mtu(mtu));
                    offset += NdiscOptionRepr::Mtu(mtu).buffer_len();
                }
                if let Maybe::Just(prefix_info) = prefix_info {
                    emit_option_at(packet, offset, &NdiscOptionRepr::PrefixInformation(prefix_info));
                }
            }

            Repr::NeighborSolicit {
                target_addr,
                lladdr,
            } => {
                packet.set_msg_type(Message::NeighborSolicit);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                if let MaybeAddr::Present(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_buf());
                    NdiscOptionRepr::SourceLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            }

            Repr::NeighborAdvert {
                flags,
                target_addr,
                lladdr,
            } => {
                packet.set_msg_type(Message::NeighborAdvert);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_neighbor_flags(flags);
                packet.set_target_addr(target_addr);
                if let MaybeAddr::Present(lladdr) = lladdr {
                    let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_buf());
                    NdiscOptionRepr::TargetLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                }
            }

            Repr::Redirect {
                target_addr,
                dest_addr,
                lladdr,
                redirected_hdr,
            } => {
                packet.set_msg_type(Message::Redirect);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_target_addr(target_addr);
                packet.set_dest_addr(dest_addr);
                let offset = match lladdr {
                    MaybeAddr::Present(lladdr) => {
                        let mut opt_pkt = NdiscOption::new_unchecked(packet.payload_buf());
                        NdiscOptionRepr::TargetLinkLayerAddr(lladdr).emit(&mut opt_pkt);
                        NdiscOptionRepr::TargetLinkLayerAddr(lladdr).buffer_len()
                    }
                    MaybeAddr::Absent => 0,
                };
                if let MaybeRedirected::Present(redirected_hdr) = redirected_hdr {
                    emit_option_at(packet, offset, &NdiscOptionRepr::RedirectedHeader(redirected_hdr));
                }
            }
        }
    }
}

/// Emit one NDISC option `offset` octets into an ICMPv6 packet's payload.
///
/// The caller owes `icmpv6_header_len(code) + offset + 48 <= as_mut_reft(buffer)`, which is
/// `NdiscOptionRepr::emit`'s own 48-octet bound translated through the payload split. It is not
/// discharged at any of the three call sites, and cannot be: `NdiscOptionRepr::buffer_len` has no
/// Flux signature, so `offset` is an unconstrained `usize`. Refining `NdiscOptionRepr` by its
/// buffer length is what closes it.
///
/// The window comes from `payload_buf` rather than `payload_mut()[offset..]`: a bare `&mut [u8]`
/// makes the option wrapper `NdiscOption<&mut [u8]>`, which instantiates core's blanket
/// `impl<T, U> AsMut<U> for &mut T`, and that impl has no associated refinement to name.
#[flux_rs::trusted(no, reason = "panic site: the option window and every option setter")]
#[flux_rs::sig(
    fn(packet: &mut Packet<T>[@p], offset: usize, opt: &NdiscOptionRepr[@o])
    requires crate::wire::icmpv6::icmpv6_header_len(p.code) + offset + o.blen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
)]
fn emit_option_at<T>(packet: &mut Packet<T>, offset: usize, opt: &NdiscOptionRepr)
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    // `advance` would reach `Buf::as_mut`'s `get_unchecked_mut(offset..)` without a runtime
    // bound -- its `n <= len` is a flux `requires` with no executable counterpart, and it is
    // not discharged at any call site here. A short buffer would become an out-of-bounds
    // write where it used to panic. The checked reslice keeps the panic and still carries the
    // length, since `Buf::new` has offset 0.
    let mut window = packet.payload_buf();
    let data = window.as_mut();
    let mut opt_pkt = NdiscOption::new_unchecked(crate::wire::Buf::new(&mut data[offset..]));
    opt.emit(&mut opt_pkt);
}

#[cfg(feature = "medium-ethernet")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::phy::ChecksumCapabilities;
    use crate::wire::EthernetAddress;
    use crate::wire::Icmpv6Repr;

    const MOCK_IP_ADDR_1: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const MOCK_IP_ADDR_2: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    static ROUTER_ADVERT_BYTES: [u8; 24] = [
        0x86, 0x00, 0xa9, 0xde, 0x40, 0x80, 0x03, 0x84, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03,
        0x84, 0x01, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
    ];
    static SOURCE_LINK_LAYER_OPT: [u8; 8] = [0x01, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn create_repr<'a>() -> Icmpv6Repr<'a> {
        Icmpv6Repr::Ndisc(Repr::RouterAdvert {
            hop_limit: 64,
            flags: RouterFlags::MANAGED,
            router_lifetime: Duration::from_secs(900),
            reachable_time: Duration::from_millis(900),
            retrans_time: Duration::from_millis(900),
            lladdr: MaybeAddr::Present(EthernetAddress::from_octets([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).into()),
            mtu: Maybe::Nothing,
            prefix_info: Maybe::Nothing,
        })
    }

    /// A short buffer must panic, not write out of bounds.
    ///
    /// `NdiscOptionRepr::buffer_len` rounds `2 + len` up to a multiple of 8 while
    /// `emit_link_layer_addr` writes only `data[2..2 + len]`, so a link-layer address shorter
    /// than 6 octets leaves a gap the preceding emit does not bounds-check. Reaching the option
    /// window through `Buf::advance` -- whose `n <= len` is a flux `requires` with no executable
    /// counterpart -- turned that into an out-of-bounds write via `as_mut`'s
    /// `get_unchecked_mut`. This pins the checked behaviour.
    #[test]
    #[should_panic]
    fn test_short_buffer_panics_rather_than_writing_out_of_bounds() {
        let repr = Icmpv6Repr::Ndisc(Repr::RouterAdvert {
            hop_limit: 64,
            flags: RouterFlags::MANAGED,
            router_lifetime: Duration::from_secs(900),
            reachable_time: Duration::from_millis(900),
            retrans_time: Duration::from_millis(900),
            lladdr: MaybeAddr::Present(RawHardwareAddress::from_bytes(&[1, 2, 3])),
            mtu: Maybe::Just(1500),
            prefix_info: Maybe::Nothing,
        });

        let mut bytes = [0u8; 21];
        let mut packet = crate::wire::Icmpv6Packet::new_unchecked(&mut bytes[..]);
        repr.emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
    }

    #[test]
    fn test_router_advert_deconstruct() {
        let packet = Packet::new_unchecked(Ref::new(&ROUTER_ADVERT_BYTES[..]));
        assert_eq!(packet.msg_type(), Message::RouterAdvert);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.current_hop_limit(), 64);
        assert_eq!(packet.router_flags(), RouterFlags::MANAGED);
        assert_eq!(packet.router_lifetime(), Duration::from_secs(900));
        assert_eq!(packet.reachable_time(), Duration::from_millis(900));
        assert_eq!(packet.retrans_time(), Duration::from_millis(900));
        assert_eq!(packet.payload(), &SOURCE_LINK_LAYER_OPT[..]);
    }

    #[test]
    fn test_router_advert_construct() {
        let mut bytes = vec![0x0; 24];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::RouterAdvert);
        packet.set_msg_code(0);
        packet.set_current_hop_limit(64);
        packet.set_router_flags(RouterFlags::MANAGED);
        packet.set_router_lifetime(Duration::from_secs(900));
        packet.set_reachable_time(Duration::from_millis(900));
        packet.set_retrans_time(Duration::from_millis(900));
        packet
            .payload_mut()
            .copy_from_slice(&SOURCE_LINK_LAYER_OPT[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&*packet.into_inner(), &ROUTER_ADVERT_BYTES[..]);
    }

    #[test]
    fn test_router_advert_repr_parse() {
        let packet = Packet::new_unchecked(&ROUTER_ADVERT_BYTES[..]);
        assert_eq!(
            Icmpv6Repr::parse(
                &MOCK_IP_ADDR_1,
                &MOCK_IP_ADDR_2,
                &packet,
                &ChecksumCapabilities::default()
            )
            .unwrap(),
            create_repr()
        );
    }

    #[test]
    fn test_router_advert_repr_emit() {
        let mut bytes = [0x2a; 24];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        create_repr().emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &ROUTER_ADVERT_BYTES[..]);
    }

    #[test]
    fn test_redirect_lladdr_roundtrip() {
        // A Redirect's link-layer address is a Target LL option (type 2);
        // emit then parse must preserve it, not drop it to None.
        let lladdr = EthernetAddress::from_octets([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).into();
        let repr = Icmpv6Repr::Ndisc(Repr::Redirect {
            target_addr: MOCK_IP_ADDR_1,
            dest_addr: MOCK_IP_ADDR_2,
            lladdr: MaybeAddr::Present(lladdr),
            redirected_hdr: MaybeRedirected::Absent,
        });

        let mut bytes = vec![0u8; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        repr.emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );

        let packet = Packet::new_unchecked(&bytes[..]);
        let parsed = Icmpv6Repr::parse(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &packet,
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(parsed, repr);
    }
}
