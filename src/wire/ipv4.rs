use core::fmt;

use super::{Error, Result};
use crate::phy::ChecksumCapabilities;
use crate::wire::ip::{checksum, pretty_print_ip_payload};

pub use super::IpProtocol as Protocol;

/// Minimum MTU required of all links supporting IPv4. See [RFC 791 § 3.1].
///
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
// RFC 791 states the following:
//
// > Every internet module must be able to forward a datagram of 68
// > octets without further fragmentation... Every internet destination
// > must be able to receive a datagram of 576 octets either in one piece
// > or in fragments to be reassembled.
//
// As a result, we can assume that every host we send packets to can
// accept a packet of the following size.
pub const MIN_MTU: usize = 576;

/// All multicast-capable nodes
pub const MULTICAST_ALL_SYSTEMS: Address = Address::new(224, 0, 0, 1);

/// All multicast-capable routers
pub const MULTICAST_ALL_ROUTERS: Address = Address::new(224, 0, 0, 2);

/// Minimum IHL length 5x32 bit words or 20 bytes
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
const MINIMUM_IHL_BYTES: u8 = 20;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Key {
    id: u16,
    src_addr: Address,
    dst_addr: Address,
    protocol: Protocol,
}

pub use core::net::Ipv4Addr as Address;

pub(crate) trait AddressExt {
    /// Query whether the address is an unicast address.
    ///
    /// `x_` prefix is to avoid a collision with the still-unstable method in `core::ip`.
    fn x_is_unicast(&self) -> bool;

    /// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
    /// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
    fn prefix_len(&self) -> Option<u8>;
}

impl AddressExt for Address {
    /// Query whether the address is an unicast address.
    fn x_is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
    }

    fn prefix_len(&self) -> Option<u8> {
        let mut ones = true;
        let mut prefix_len = 0;
        for byte in self.octets() {
            let mut mask = 0x80;
            for _ in 0..8 {
                let one = byte & mask != 0;
                if ones {
                    // Expect 1s until first 0
                    if one {
                        prefix_len += 1;
                    } else {
                        ones = false;
                    }
                } else if one {
                    // 1 where 0 was expected
                    return None;
                }
                mask >>= 1;
            }
        }
        Some(prefix_len)
    }
}

/// A specification of an IPv4 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Cidr {
    address: Address,
    prefix_len: u8,
}

impl Cidr {
    /// Create an IPv4 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 32.
    pub const fn new(address: Address, prefix_len: u8) -> Cidr {
        assert!(prefix_len <= 32);
        Cidr {
            address,
            prefix_len,
        }
    }

    /// Create an IPv4 CIDR block from the given address and network mask.
    pub fn from_netmask(addr: Address, netmask: Address) -> Result<Cidr> {
        let netmask = netmask.to_bits();
        if netmask.leading_zeros() == 0 && netmask.trailing_zeros() == netmask.count_zeros() {
            Ok(Cidr {
                address: addr,
                prefix_len: netmask.count_ones() as u8,
            })
        } else {
            Err(Error)
        }
    }

    /// Return the address of this IPv4 CIDR block.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the network mask of this IPv4 CIDR.
    pub const fn netmask(&self) -> Address {
        if self.prefix_len == 0 {
            return Address::new(0, 0, 0, 0);
        }

        let number = 0xffffffffu32 << (32 - self.prefix_len);
        Address::from_bits(number)
    }

    /// Return the broadcast address of this IPv4 CIDR.
    pub fn broadcast(&self) -> Option<Address> {
        let network = self.network();

        if network.prefix_len == 31 || network.prefix_len == 32 {
            return None;
        }

        let network_number = network.address.to_bits();
        let number = network_number | 0xffffffffu32 >> network.prefix_len;
        Some(Address::from_bits(number))
    }

    /// Return the network block of this IPv4 CIDR.
    pub const fn network(&self) -> Cidr {
        Cidr {
            address: Address::from_bits(self.address.to_bits() & self.netmask().to_bits()),
            prefix_len: self.prefix_len,
        }
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        self.address.to_bits() & self.netmask().to_bits()
            == addr.to_bits() & self.netmask().to_bits()
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the subnetwork described by the given IPv4 CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cidr {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{}/{=u8}", self.address, self.prefix_len);
    }
}

// A ghost field carries an integer in the refinement and nothing at runtime.
//
// The payload window is `header_len()..total_len()` and the checksummed header window is
// `..header_len()`. Both ends are buffer *contents* -- the low nibble of octet 0 scaled by four,
// and the big-endian `u16` at octets 2..4 -- and contents are not in the refinement, so no
// accessor bound could name them. This is the way to name them anyway. `Packet` holds one ghost
// of each kind, and because both are ZSTs they cost no space and `Packet<T>`'s layout is
// unchanged.
//
// The values are anchored by `Packet::header_len` and `Packet::total_len`, the two trusted
// getters that claim the octets equal the ghosts. Everything else is proved. See those two
// functions for the enumeration of writers that keeps the claims true.
//
// Two ghost types rather than one so that `derive(Clone)` on `Packet` can re-establish each
// field's invariant: a single type would have to carry the wider of the two bounds, and the
// derived `clone` could then not prove `hlen <= 255`.

/// The header-length ghost.
///
/// The invariant is the range of the type the field is read back as, and nothing more:
/// `header_len` in fact only ever reads back a multiple of four in `0..=60`, but that needs
/// bitvector reasoning flux does not do here, so claiming it would be assuming it. The facts the
/// windows actually need -- `20 <= hlen`, `hlen <= tlen`, `tlen <= buffer_len` -- come from
/// [`Packet::checked_len`], which tests all three.
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val && val <= 255)]
#[derive(PartialEq, Eq, Clone, Copy)]
struct GhostU8;

impl GhostU8 {
    /// A ghost constrained only by the invariant.
    #[flux_rs::trusted(yes, reason = "opaque: the ghost carries no runtime value")]
    #[flux_rs::sig(fn() -> GhostU8{v: 0 <= v && v <= 255})]
    #[flux_rs::no_panic]
    const fn unknown() -> GhostU8 {
        GhostU8
    }

    /// A ghost pinned to `val`.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the ghost value")]
    #[flux_rs::sig(fn(val: u8) -> GhostU8[val])]
    #[flux_rs::no_panic]
    const fn new(_val: u8) -> GhostU8 {
        GhostU8
    }
}

/// The total-length ghost. See [`GhostU8`].
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val && val <= 65535)]
#[derive(PartialEq, Eq, Clone, Copy)]
struct GhostU16;

impl GhostU16 {
    /// A ghost constrained only by the invariant.
    #[flux_rs::trusted(yes, reason = "opaque: the ghost carries no runtime value")]
    #[flux_rs::sig(fn() -> GhostU16{v: 0 <= v && v <= 65535})]
    #[flux_rs::no_panic]
    const fn unknown() -> GhostU16 {
        GhostU16
    }

    /// A ghost pinned to `val`.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the ghost value")]
    #[flux_rs::sig(fn(val: u16) -> GhostU16[val])]
    #[flux_rs::no_panic]
    const fn new(_val: u16) -> GhostU16 {
        GhostU16
    }
}

/// A read/write wrapper around an Internet Protocol version 4 packet buffer.
#[derive(PartialEq, Eq, Clone)]
#[flux_rs::refined_by(buffer: T, hlen: int, tlen: int)]
#[flux_rs::invariant(0 <= hlen && hlen <= 255 && 0 <= tlen && tlen <= 65535)]
pub struct Packet<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
    #[flux_rs::field(GhostU8[hlen])]
    ghlen: GhostU8,
    #[flux_rs::field(GhostU16[tlen])]
    gtlen: GhostU16,
}

// Written out rather than derived so the ghosts stay out of the output: a derive would print
// `Packet { buffer: .., ghlen: GhostU8, gtlen: GhostU16 }`, and a ghost is not supposed to be
// observable. Both impls reproduce the derived form for the one field that existed before.
impl<T: AsRef<[u8]> + fmt::Debug> fmt::Debug for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Packet")
            .field("buffer", &self.buffer)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<T: AsRef<[u8]> + defmt::Format> defmt::Format for Packet<T> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "Packet {{ buffer: {} }}", self.buffer)
    }
}

/// Read the four octets of an address at `at`.
///
/// `data[at..at + 4].try_into().unwrap()` in source; flux does not model
/// `TryInto<[u8; 4]> for &[u8]`, so the equal-length `copy_from_slice` stands in for it. Both
/// panic on a length mismatch and `at + 4 <= n` rules both out, so the check is gated, not
/// removed.
#[flux_rs::trusted(no, reason = "panic site: copies four octets out of the buffer")]
#[flux_rs::sig(fn(&[u8][@n], at: usize) -> Address requires at + 4 <= n)]
#[flux_rs::no_panic]
fn read_ipv4_at(data: &[u8], at: usize) -> Address {
    let mut octets = [0; 4];
    octets.copy_from_slice(crate::wire::sub(data, at, 4));
    Address::from_octets(octets)
}

mod field {
    use crate::wire::field::*;

    pub const VER_IHL: usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH: Field = 2..4;
    pub const IDENT: Field = 4..6;
    pub const FLG_OFF: Field = 6..8;
    pub const TTL: usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}

pub const HEADER_LEN: usize = field::DST_ADDR.end;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with IPv4 packet structure.
    ///
    /// The ghosts start unconstrained: this reads nothing, so it learns nothing. They are pinned
    /// to the header octets the first time [`header_len`](Self::header_len) or
    /// [`total_len`](Self::total_len) is called.
    #[flux_rs::trusted(no, reason = "carries the buffer length into the Packet index")]
    #[flux_rs::sig(fn (T[@buflen]) -> Packet<T>{v : v.buffer == buflen})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet {
            buffer,
            ghlen: GhostU8::unknown(),
            gtlen: GhostU16::unknown(),
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[flux_rs::trusted(no, reason = "carries the buffer length through the Result")]
    #[flux_rs::sig(fn (T[@buflen]) -> Result<Packet<T>{v : v.buffer == buflen}>)]
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        match packet.check_len() {
            Ok(()) => Ok(packet),
            Err(e) => Err(e),
        }
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    /// Returns `Err(Error)` if the header length is greater
    /// than total length.
    /// Returns `Err(Error)` if the header length is less than minimum allowed IHL
    ///
    /// The result of this check is invalidated by calling [set_header_len]
    /// and [set_total_len].
    ///
    /// [set_header_len]: #method.set_header_len
    /// [set_total_len]: #method.set_total_len
    #[flux_rs::no_panic]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf]) -> Result<()>
    )]
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    pub fn check_len(&self) -> Result<()> {
        match self.checked_len() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// [`check_len`](Self::check_len), returning the buffer length it validated.
    ///
    /// The whole of `check_len`; the public method just discards the length. It exists because
    /// `Result<()>`'s `Ok` payload is `()` and so carries no refinement, which leaves a caller
    /// with nothing to show for a successful check. Returning the length instead lets the `Ok`
    /// arm say something, and what it says is exactly the four facts the windows below want: the
    /// buffer's length is what it is, the header length field is at least the minimum IHL, the
    /// payload window does not run backwards, and the total length field is not a lie about the
    /// buffer.
    ///
    /// Every one of those tests was already here, in this order, with the same `if len < ..`
    /// comparisons. They are stated in the bound only because the ghosts make `header_len` and
    /// `total_len` nameable.
    #[allow(clippy::if_same_then_else)]
    #[flux_rs::no_panic]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(buf.buffer) &&
                               20 <= buf.hlen && buf.hlen <= buf.tlen && buf.tlen <= v}>
    )]
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    fn checked_len(&self) -> Result<usize> {
        let data = self.buffer.as_ref();
        let len = data.len();
        if len < 20 { // field::DST_ADDR.end is 20, but flux doesn't know that
            Err(Error)
        } else {
            if len < self.header_len() as usize {
                Err(Error)
            } else if self.header_len() as u16 > self.total_len() {
                Err(Error)
            } else if len < self.total_len() as usize {
                Err(Error)
            } else if self.header_len() < MINIMUM_IHL_BYTES {
                Err(Error)
            } else {
                Ok(len)
            }
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the version field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> u8 requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_IHL] >> 4
    }

    /// Read the IHL nibble out of octet 0 and scale it to octets.
    ///
    /// The read half of [`header_len`](Self::header_len), split out so that it stays checked.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf]) -> u8 requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    fn header_len_field(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the header length, in octets.
    ///
    /// The anchor for the `hlen` ghost: the return type *claims* the low nibble of octet 0,
    /// scaled by four, is `hlen`. Nothing proves that -- the buffer's contents are not in the
    /// refinement -- so it is the assumption the header and payload windows rest on.
    ///
    /// What keeps it true is that every writer of that nibble preserves it or updates the ghost.
    /// [`set_header_len`](Self::set_header_len) is the only one that changes it, and it writes the
    /// ghost in the same statement; [`set_version`](Self::set_version) writes octet 0 but masks
    /// the low nibble out, and every other setter starts at octet 1 or later. `payload_mut` hands
    /// out a window starting at `hlen`, and requires `4 <= hlen` so that the window cannot reach
    /// either ghost's octets. There is no `AsMut<[u8]> for Packet<T>`, `AsRef` hands out a shared
    /// borrow, and `into_inner` consumes the packet. See `test_header_writes_preserve_ghosts`.
    ///
    /// The read itself stays checked: the trusted body is a call, and the bound is discharged
    /// inside [`header_len_field`](Self::header_len_field). All this assumes is the equality,
    /// which is the part flux cannot see.
    #[inline]
    #[flux_rs::trusted(yes, reason = "anchors the `hlen` ghost to the IHL nibble at octet 0")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf]) -> u8[buf.hlen]
        requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn header_len(&self) -> u8 {
        self.header_len_field()
    }

    /// Return the Differential Services Code Point field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> u8 requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    pub fn dscp(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] >> 2
    }

    /// Return the Explicit Congestion Notification field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> u8 requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    pub fn ecn(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] & 0x03
    }

    /// Read the total length field out of octets 2..4.
    ///
    /// The read half of [`total_len`](Self::total_len), split out so that it stays checked.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf]) -> u16 requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    fn total_len_field(&self) -> u16 {
        let data = self.buffer.as_ref();
        crate::wire::read_u16_at(data, 2) // field::LENGTH
    }

    /// Return the total length field.
    ///
    /// The anchor for the `tlen` ghost, on the same terms as
    /// [`header_len`](Self::header_len): the return type claims the `u16` at octets 2..4 is
    /// `tlen`, and [`set_total_len`](Self::set_total_len) is its only writer.
    #[inline]
    #[flux_rs::trusted(yes, reason = "anchors the `tlen` ghost to the u16 at octets 2..4")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf]) -> u16[buf.tlen]
        requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn total_len(&self) -> u16 {
        self.total_len_field()
    }

    /// Return the fragment identification field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> u16 requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        crate::wire::read_u16_at(data, 4) // field::IDENT
    }

    /// Return the "don't fragment" flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> bool requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn dont_frag(&self) -> bool {
        let data = self.buffer.as_ref();
        crate::wire::read_u16_at(data, 6) & 0x4000 != 0 // field::FLG_OFF
    }

    /// Return the "more fragments" flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> bool requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        crate::wire::read_u16_at(data, 6) & 0x2000 != 0 // field::FLG_OFF
    }

    /// Return the fragment offset, in octets.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> u16 requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        crate::wire::read_u16_at(data, 6) << 3 // field::FLG_OFF
    }

    /// Return the time to live field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> u8 requires 9 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TTL]
    }

    /// Return the next_header (protocol) field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> Protocol requires 10 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn next_header(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::PROTOCOL])
    }

    /// Return the header checksum field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> u16 requires 12 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        crate::wire::read_u16_at(data, 10) // field::CHECKSUM
    }

    /// Return the source address field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> Address requires 16 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        read_ipv4_at(data, 12) // field::SRC_ADDR
    }

    /// Return the destination address field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &Packet<T>[@buf]) -> Address requires 20 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        read_ipv4_at(data, 16) // field::DST_ADDR
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    //
    // `&data[..header_len]` in source; `prefix` is the same borrow with its length stated, which
    // is what lets `checksum::data`'s own `n <= 65535` bound land. That bound is discharged by
    // the `Ghost` invariant: `hlen` is read back as a `u8`.
    #[flux_rs::trusted(no, reason = "panic site: checksums the header window")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf]) -> bool
        requires
            1 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer) &&
            buf.hlen <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::data(crate::wire::prefix(data, self.header_len() as usize)) == !0
    }

    /// Returns the key for identifying the packet.
    #[flux_rs::trusted(no, reason = "reads five header fields at fixed offsets")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@buf]) -> Key
        requires 20 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn get_key(&self) -> Key {
        Key {
            id: self.ident(),
            src_addr: self.src_addr(),
            dst_addr: self.dst_addr(),
            protocol: self.next_header(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    //
    // Writes octet 0, which holds the `hlen` ghost's nibble -- but `value << 4` has a zero low
    // nibble for every `value`, so the IHL nibble is preserved and the ghost survives. That is
    // why this can keep `&mut` (index-preserving) rather than needing `set_header_len`'s `&strg`.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            0 < <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Set the header length, in octets.
    ///
    /// Writes the ghost as well as the octet. This is the whole of what keeps
    /// [`header_len`](Self::header_len)'s claim true, so the two must not drift apart: `&strg`
    /// rather than `&mut` because `&mut` pins the index, and the index is exactly what this
    /// changes.
    ///
    /// The ghost is set to `(value / 4) * 4`, not to `value`. The field is a four-bit count of
    /// 32-bit words, so this stores `value / 4` and reads back a multiple of four; a `value` that
    /// is not one comes back truncated. Requiring `value % 4 == 0` instead would state a contract
    /// the function does not have.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Packet<T>[@buf], value: u8)
        requires
            0 < <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
        ensures self: Packet<T>[buf.buffer, (value / 4) * 4, buf.tlen]
    )]
    #[flux_rs::no_panic]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
        self.ghlen = GhostU8::new((value / 4) * 4);
    }

    /// Set the Differential Services Code Point field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            1 < <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            1 < <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    ///
    /// Writes the `tlen` ghost as well as the octets, on the same terms as
    /// [`set_header_len`](Self::set_header_len). This field round-trips, so the `ensures` names
    /// `value` itself.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Packet<T>[@buf], value: u16)
        requires
            4 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
        ensures self: Packet<T>[buf.buffer, buf.hlen, value]
    )]
    #[flux_rs::no_panic]
    pub fn set_total_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 2, value);
        self.gtlen = GhostU16::new(value);
    }

    /// Set the fragment identification field.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            6 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 4, value)
    }

    /// Clear the entire flags field.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf])
        requires
            8 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = crate::wire::read_u16_at(data, 6);
        let raw = raw & !0xe000;
        crate::wire::write_u16_at(data, 6, raw);
    }

    /// Set the "don't fragment" flag.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            8 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_dont_frag(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = crate::wire::read_u16_at(data, 6);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        crate::wire::write_u16_at(data, 6, raw);
    }

    /// Set the "more fragments" flag.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            8 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = crate::wire::read_u16_at(data, 6);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        crate::wire::write_u16_at(data, 6, raw);
    }

    /// Set the fragment offset, in octets.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            8 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let raw = crate::wire::read_u16_at(data, 6);
        let raw = (raw & 0xe000) | (value >> 3);
        crate::wire::write_u16_at(data, 6, raw);
    }

    /// Set the time to live field.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic occurs here")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], value: u8)
        requires
            9 < <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::TTL] = value
    }

    /// Set the next header (protocol) field.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            9 < <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            12 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 10, value)
    }

    /// Set the source address field.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            16 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        crate::wire::write_octets4_at(data, 12, &value.octets())
    }

    /// Set the destination address field.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], _)
        requires
            20 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        crate::wire::write_octets4_at(data, 16, &value.octets())
    }

    /// Compute and fill in the header checksum, over a header of exactly `header_len` octets.
    ///
    /// Unlike [`fill_checksum`](Self::fill_checksum) this does not read the IHL nibble back out
    /// of the buffer, so its safety is a property of the arguments rather than of the buffer's
    /// contents -- which is what makes it provable. Callers that have just *written* the header
    /// length know it; use this rather than `fill_checksum` on a path that must verify.
    #[flux_rs::trusted(no, reason = "checksum over a caller-supplied header length")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf], header_len: usize)
        requires
            12 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer) &&
            header_len <= 60 &&
            header_len <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn fill_checksum_with_header_len(&mut self, header_len: usize) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(crate::wire::prefix(data, header_len))
        };
        self.set_checksum(checksum)
    }

    /// Compute and fill in the header checksum.
    //
    // This used to be `trusted(yes)` on the ground that the window `..header_len()` is bounded
    // by the IHL nibble read out of the buffer, which flux could not relate to the buffer's
    // length. The `hlen` ghost relates them, so the body is checked now and the assumption is
    // gone: `buf.hlen <= as_ref_reft` is stated instead, where a caller's checker can see it.
    //
    // That bound is an *exposed obligation* -- this is `pub`, and its one remaining live in-crate
    // caller, `socket/raw.rs:412`, sits inside a `dequeue_with` closure that flux does not check,
    // so nothing discharges it there. `fill_checksum_with_header_len` takes the length the caller
    // just wrote and needs no ghost at all; every in-crate caller on a path that must verify has
    // already moved to it.
    #[flux_rs::trusted(no, reason = "panic site: checksums the header window")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf])
        requires
            20 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer) &&
            20 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer) &&
            buf.hlen <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(crate::wire::prefix(data, self.header_len() as usize))
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the payload.
    //
    // `4 <= hlen` is not a bounds conjunct -- `hlen <= tlen <= as_mut_reft` is what puts the
    // window in bounds. It is a *ghost-preservation* conjunct: the caller can write anything
    // through the returned slice, and the window starts at `hlen`, so a window starting before
    // octet 4 would reach the IHL nibble at octet 0 or the total length at octets 2..4 and make
    // `header_len`/`total_len`'s claims false while this `&mut` keeps the index pinned. Four is
    // the minimum that rules that out; `checked_len` in fact gives 20. A necessity control does
    // not fire on it for that reason -- see the PR body.
    #[inline]
    #[flux_rs::trusted(no, reason = "panic site: the payload window is header_len..total_len")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@buf]) -> &mut [u8]
        requires
            4 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer) &&
            4 <= buf.hlen &&
            buf.hlen <= buf.tlen &&
            buf.tlen <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer)
    )]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

#[flux_rs::assoc(
    fn as_ref_reft(source: Self) -> int {
        <T as AsRef<[u8]>>::as_ref_reft(source.buffer)
    }
)]
impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    #[flux_rs::no_panic]
    #[flux_rs::sig(
        fn(self: &Self[@source])
            -> &[u8][Self::as_ref_reft(source)]
    )]
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an Internet Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    pub src_addr: Address,
    pub dst_addr: Address,
    pub next_header: Protocol,
    pub payload_len: usize,
    pub hop_limit: u8,
}

impl Repr {
    /// Parse an Internet Protocol version 4 packet and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(
        packet: &Packet<&T>,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr> {
        packet.check_len()?;
        // Version 4 is expected.
        if packet.version() != 4 {
            return Err(Error);
        }
        // Valid checksum is expected.
        if checksum_caps.ipv4.rx() && !packet.verify_checksum() {
            return Err(Error);
        }

        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        // We do not support fragmentation.
        if packet.more_frags() || packet.frag_offset() != 0 {
            return Err(Error);
        }

        let payload_len = packet.total_len() as usize - packet.header_len() as usize;

        // All DSCP values are acceptable, since they are of no concern to receiving endpoint.
        // All ECN values are acceptable, since ECN requires opt-in from both endpoints.
        // All TTL values are acceptable, since we do not perform routing.
        Ok(Repr {
            src_addr: packet.src_addr(),
            dst_addr: packet.dst_addr(),
            next_header: packet.next_header(),
            payload_len,
            hop_limit: packet.hop_limit(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    // `field::DST_ADDR.end` is 20, but flux can't see through the `Range` const, so the
    // literal is restated in the signature (same workaround as `check_len`).
    #[flux_rs::trusted(no, reason = "20 is the constant the whole ipv4 proof rests on")]
    #[flux_rs::sig(fn(self: &Self) -> usize[20])]
    #[flux_rs::no_panic]
    pub const fn buffer_len(&self) -> usize {
        // We never emit any options.
        // Literal rather than `field::DST_ADDR.end`: flux cannot see through the `Range`
        // const (same reason as `check_len`).
        20
    }

    /// Emit a high-level representation into an Internet Protocol version 4 packet.
    // The buffer bound is written as an existential rather than as `[@buf] requires ..` because
    // `set_header_len` and `set_total_len` are `&strg`: they change the packet's index, and a
    // `&mut Packet<T>[@buf]` pins it, so the write-back does not fold. An existential `&mut` is
    // invariant in the *property*, not in the index, and both setters preserve the property --
    // neither touches the buffer, only the ghosts.
    #[flux_rs::trusted(no, reason = "calls packet.set_hop_limit")]
    #[flux_rs::sig(
        fn(
            self: &Self,
            packet: &mut Packet<T>{buf:
                20 <= <T as AsMut<[u8]>>::as_mut_reft(buf.buffer) &&
                20 <= <T as AsRef<[u8]>>::as_ref_reft(buf.buffer)},
            checksum_caps: &ChecksumCapabilities
        )
    )]
    #[flux_rs::no_panic]
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        packet: &mut Packet<T>,
        checksum_caps: &ChecksumCapabilities,
    ) {
        packet.set_version(4);
        packet.set_header_len(field::DST_ADDR.end as u8);
        packet.set_dscp(0);
        packet.set_ecn(0);
        let total_len = packet.header_len() as u16 + self.payload_len as u16;
        packet.set_total_len(total_len);
        packet.set_ident(0);
        packet.clear_flags();
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_hop_limit(self.hop_limit);
        packet.set_next_header(self.next_header);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);

        if checksum_caps.ipv4.tx() {
            packet.fill_checksum_with_header_len(20);
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self, &ChecksumCapabilities::ignored()) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "IPv4 ({err})")?;
                write!(
                    f,
                    " src={} dst={} proto={} hop_limit={}",
                    self.src_addr(),
                    self.dst_addr(),
                    self.next_header(),
                    self.hop_limit()
                )?;
                if self.version() != 4 {
                    write!(f, " ver={}", self.version())?;
                }
                if self.header_len() != 20 {
                    write!(f, " hlen={}", self.header_len())?;
                }
                if self.dscp() != 0 {
                    write!(f, " dscp={}", self.dscp())?;
                }
                if self.ecn() != 0 {
                    write!(f, " ecn={}", self.ecn())?;
                }
                write!(f, " tlen={}", self.total_len())?;
                if self.dont_frag() {
                    write!(f, " df")?;
                }
                if self.more_frags() {
                    write!(f, " mf")?;
                }
                if self.frag_offset() != 0 {
                    write!(f, " off={}", self.frag_offset())?;
                }
                if self.more_frags() || self.frag_offset() != 0 {
                    write!(f, " id={}", self.ident())?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv4 src={} dst={} proto={}",
            self.src_addr, self.dst_addr, self.next_header
        )
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    #[flux_rs::trusted(yes, reason = "ICE flux infer.rs:896: `incompatible types` on a place still blocked (`†`) by a mutable borrow at the join. See ICE-INBOX.md.")]
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        use crate::wire::ip::checksum::format_checksum;

        let checksum_caps = ChecksumCapabilities::ignored();

        let (ip_repr, payload) = match Packet::new_checked(buffer) {
            Err(err) => return write!(f, "{indent}({err})"),
            Ok(ip_packet) => match Repr::parse(&ip_packet, &checksum_caps) {
                Err(_) => return Ok(()),
                Ok(ip_repr) => {
                    if ip_packet.more_frags() || ip_packet.frag_offset() != 0 {
                        write!(
                            f,
                            "{}IPv4 Fragment more_frags={} offset={}",
                            indent,
                            ip_packet.more_frags(),
                            ip_packet.frag_offset()
                        )?;
                        return Ok(());
                    } else {
                        write!(f, "{indent}{ip_repr}")?;
                        format_checksum(f, ip_packet.verify_checksum(), false)?;
                        (ip_repr, ip_packet.payload())
                    }
                }
            },
        };

        pretty_print_ip_payload(f, indent, ip_repr, payload)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_1: Address = Address::new(192, 168, 1, 1);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_2: Address = Address::new(192, 168, 1, 2);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_3: Address = Address::new(192, 168, 1, 3);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_4: Address = Address::new(192, 168, 1, 4);
    #[allow(unused)]
    pub(crate) const MOCK_UNSPECIFIED: Address = Address::UNSPECIFIED;

    static PACKET_BYTES: [u8; 30] = [
        0x45, 0x00, 0x00, 0x1e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xd5, 0x6e, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    static PAYLOAD_BYTES: [u8; 10] = [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

    #[test]
    fn ghost_fields_are_not_observable() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let s = format!("{packet:?}");
        assert!(!s.contains("Ghost"), "ghost leaked into Debug: {s}");
        assert!(s.starts_with("Packet { buffer: "), "Debug shape changed: {s}");
    }

    #[test]
    fn test_header_writes_preserve_ghosts() {
        // `header_len` and `total_len` claim the IHL nibble at octet 0 and the u16 at octets
        // 2..4 equal the ghosts. That is only kept true because `set_header_len` and
        // `set_total_len` are the sole writers of those two fields, and every other setter
        // either leaves them alone or -- `set_version` -- masks the IHL nibble out. This is
        // that enumeration, tested.
        let mut bytes = vec![0; 30];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(20);
        packet.set_total_len(30);

        macro_rules! check {
            ($($call:expr => $name:expr),* $(,)?) => {$(
                $call;
                assert_eq!(packet.header_len(), 20, concat!($name, ": header_len"));
                assert_eq!(packet.total_len(), 30, concat!($name, ": total_len"));
            )*};
        }
        check!(
            packet.set_version(4) => "set_version(4)",
            packet.set_version(6) => "set_version(6)",
            packet.set_version(15) => "set_version(15)",
            packet.set_dscp(0x3f) => "set_dscp",
            packet.set_ecn(0x3) => "set_ecn",
            packet.set_ident(0xffff) => "set_ident",
            packet.clear_flags() => "clear_flags",
            packet.set_dont_frag(true) => "set_dont_frag",
            packet.set_more_frags(true) => "set_more_frags",
            packet.set_frag_offset(0xfff8) => "set_frag_offset",
            packet.set_hop_limit(0xff) => "set_hop_limit",
            packet.set_next_header(Protocol::Tcp) => "set_next_header",
            packet.set_checksum(0xffff) => "set_checksum",
            packet.set_src_addr(MOCK_IP_ADDR_1) => "set_src_addr",
            packet.set_dst_addr(MOCK_IP_ADDR_2) => "set_dst_addr",
            packet.fill_checksum() => "fill_checksum",
            packet.fill_checksum_with_header_len(20) => "fill_checksum_with_header_len",
        );

        // The payload window starts at `header_len`, and `payload_mut` requires `4 <= hlen` so
        // that a caller writing through it cannot reach either ghost's octets.
        for b in packet.payload_mut() {
            *b = 0xff;
        }
        assert_eq!(packet.header_len(), 20, "payload_mut: header_len");
        assert_eq!(packet.total_len(), 30, "payload_mut: total_len");
    }

    #[test]
    fn test_set_header_len_truncates() {
        // The field is a four-bit word count, so `set_header_len` stores `value / 4`. The ghost
        // is written to match what reads back, which is why its `ensures` says `(value / 4) * 4`
        // and not `value`.
        let mut bytes = vec![0; 30];
        let mut packet = Packet::new_unchecked(&mut bytes);
        for value in 0u8..=60 {
            packet.set_header_len(value);
            assert_eq!(packet.header_len(), (value / 4) * 4, "set_header_len({value})");
        }
    }

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.dscp(), 0);
        assert_eq!(packet.ecn(), 0);
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.ident(), 0x102);
        assert!(packet.more_frags());
        assert!(packet.dont_frag());
        assert_eq!(packet.frag_offset(), 0x203 * 8);
        assert_eq!(packet.hop_limit(), 0x1a);
        assert_eq!(packet.next_header(), Protocol::Icmp);
        assert_eq!(packet.checksum(), 0xd56e);
        assert_eq!(packet.src_addr(), Address::new(0x11, 0x12, 0x13, 0x14));
        assert_eq!(packet.dst_addr(), Address::new(0x21, 0x22, 0x23, 0x24));
        assert!(packet.verify_checksum());
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 30];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.clear_flags();
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(30);
        packet.set_ident(0x102);
        packet.set_more_frags(true);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0x203 * 8);
        packet.set_hop_limit(0x1a);
        packet.set_next_header(Protocol::Icmp);
        packet.set_src_addr(Address::new(0x11, 0x12, 0x13, 0x14));
        packet.set_dst_addr(Address::new(0x21, 0x22, 0x23, 0x24));
        packet.fill_checksum();
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(
            Packet::new_unchecked(&bytes).payload().len(),
            PAYLOAD_BYTES.len()
        );
        assert_eq!(
            Packet::new_unchecked(&mut bytes).payload_mut().len(),
            PAYLOAD_BYTES.len()
        );
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        Packet::new_unchecked(&mut bytes).set_total_len(128);

        assert_eq!(Packet::new_checked(&bytes).unwrap_err(), Error);
    }

    static REPR_PACKET_BYTES: [u8; 24] = [
        0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0xd2, 0x79, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0xff,
    ];

    static REPR_PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    const fn packet_repr() -> Repr {
        Repr {
            src_addr: Address::new(0x11, 0x12, 0x13, 0x14),
            dst_addr: Address::new(0x21, 0x22, 0x23, 0x24),
            next_header: Protocol::Icmp,
            payload_len: 4,
            hop_limit: 64,
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_parse_bad_version() {
        let mut bytes = vec![0; 24];
        bytes.copy_from_slice(&REPR_PACKET_BYTES[..]);
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(6);
        packet.fill_checksum();
        let packet = Packet::new_unchecked(&*packet.into_inner());
        assert_eq!(
            Repr::parse(&packet, &ChecksumCapabilities::default()),
            Err(Error)
        );
    }

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = vec![0; 40];
        bytes[0] = 0x09;
        assert_eq!(Packet::new_checked(&mut bytes), Err(Error));
    }

    #[test]
    fn test_parse_small_ihl() {
        let mut bytes = vec![0; 24];
        bytes.copy_from_slice(&REPR_PACKET_BYTES[..]);
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(16);

        assert_eq!(Packet::new_checked(&mut bytes), Err(Error));
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet, &ChecksumCapabilities::default());
        packet.payload_mut().copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(&*packet.into_inner(), &REPR_PACKET_BYTES[..]);
    }

    #[test]
    fn test_unspecified() {
        assert!(Address::UNSPECIFIED.is_unspecified());
        assert!(!Address::UNSPECIFIED.is_broadcast());
        assert!(!Address::UNSPECIFIED.is_multicast());
        assert!(!Address::UNSPECIFIED.is_link_local());
        assert!(!Address::UNSPECIFIED.is_loopback());
    }

    #[test]
    fn test_broadcast() {
        assert!(!Address::BROADCAST.is_unspecified());
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_multicast());
        assert!(!Address::BROADCAST.is_link_local());
        assert!(!Address::BROADCAST.is_loopback());
    }

    #[test]
    fn test_cidr() {
        let cidr = Cidr::new(Address::new(192, 168, 1, 10), 24);

        let inside_subnet = [
            [192, 168, 1, 0],
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [192, 168, 1, 10],
            [192, 168, 1, 127],
            [192, 168, 1, 255],
        ];

        let outside_subnet = [
            [192, 168, 0, 0],
            [127, 0, 0, 1],
            [192, 168, 2, 0],
            [192, 168, 0, 255],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ];

        let subnets = [
            ([192, 168, 1, 0], 32),
            ([192, 168, 1, 255], 24),
            ([192, 168, 1, 10], 30),
        ];

        let not_subnets = [
            ([192, 168, 1, 10], 23),
            ([127, 0, 0, 1], 8),
            ([192, 168, 1, 0], 0),
            ([192, 168, 0, 255], 32),
        ];

        for addr in inside_subnet.iter().map(|a| Address::from_octets(*a)) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.iter().map(|a| Address::from_octets(*a)) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets
            .iter()
            .map(|&(a, p)| Cidr::new(Address::new(a[0], a[1], a[2], a[3]), p))
        {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets
            .iter()
            .map(|&(a, p)| Cidr::new(Address::new(a[0], a[1], a[2], a[3]), p))
        {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(cidr.address(), 0);
        assert!(cidr_without_prefix.contains_addr(&Address::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_cidr_from_netmask() {
        assert!(Cidr::from_netmask(Address::new(0, 0, 0, 0), Address::new(1, 0, 2, 0)).is_err());
        assert!(Cidr::from_netmask(Address::new(0, 0, 0, 0), Address::new(0, 0, 0, 0)).is_err());
        assert_eq!(
            Cidr::from_netmask(Address::new(0, 0, 0, 1), Address::new(255, 255, 255, 0)).unwrap(),
            Cidr::new(Address::new(0, 0, 0, 1), 24)
        );
        assert_eq!(
            Cidr::from_netmask(Address::new(192, 168, 0, 1), Address::new(255, 255, 0, 0)).unwrap(),
            Cidr::new(Address::new(192, 168, 0, 1), 16)
        );
        assert_eq!(
            Cidr::from_netmask(Address::new(172, 16, 0, 1), Address::new(255, 240, 0, 0)).unwrap(),
            Cidr::new(Address::new(172, 16, 0, 1), 12)
        );
        assert_eq!(
            Cidr::from_netmask(
                Address::new(255, 255, 255, 1),
                Address::new(255, 255, 255, 0)
            )
            .unwrap(),
            Cidr::new(Address::new(255, 255, 255, 1), 24)
        );
        assert_eq!(
            Cidr::from_netmask(
                Address::new(255, 255, 255, 255),
                Address::new(255, 255, 255, 255)
            )
            .unwrap(),
            Cidr::new(Address::new(255, 255, 255, 255), 32)
        );
    }

    #[test]
    fn test_cidr_netmask() {
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 0).netmask(),
            Address::new(0, 0, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 1), 24).netmask(),
            Address::new(255, 255, 255, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 32).netmask(),
            Address::new(255, 255, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(127, 0, 0, 0), 8).netmask(),
            Address::new(255, 0, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 0, 0), 16).netmask(),
            Address::new(255, 255, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 16).netmask(),
            Address::new(255, 255, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 17).netmask(),
            Address::new(255, 255, 128, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(172, 16, 0, 0), 12).netmask(),
            Address::new(255, 240, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 1), 24).netmask(),
            Address::new(255, 255, 255, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 255), 32).netmask(),
            Address::new(255, 255, 255, 255)
        );
    }

    #[test]
    fn test_cidr_broadcast() {
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 0).broadcast().unwrap(),
            Address::new(255, 255, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 1), 24).broadcast().unwrap(),
            Address::new(0, 0, 0, 255)
        );
        assert_eq!(Cidr::new(Address::new(0, 0, 0, 0), 32).broadcast(), None);
        assert_eq!(
            Cidr::new(Address::new(127, 0, 0, 0), 8)
                .broadcast()
                .unwrap(),
            Address::new(127, 255, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 0, 0), 16)
                .broadcast()
                .unwrap(),
            Address::new(192, 168, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 16)
                .broadcast()
                .unwrap(),
            Address::new(192, 168, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 17)
                .broadcast()
                .unwrap(),
            Address::new(192, 168, 127, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(172, 16, 0, 1), 12)
                .broadcast()
                .unwrap(),
            Address::new(172, 31, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 1), 24)
                .broadcast()
                .unwrap(),
            Address::new(255, 255, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 254), 31).broadcast(),
            None
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 255), 32).broadcast(),
            None
        );
    }

    #[test]
    fn test_cidr_network() {
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 0).network(),
            Cidr::new(Address::new(0, 0, 0, 0), 0)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 1), 24).network(),
            Cidr::new(Address::new(0, 0, 0, 0), 24)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 32).network(),
            Cidr::new(Address::new(0, 0, 0, 0), 32)
        );
        assert_eq!(
            Cidr::new(Address::new(127, 0, 0, 0), 8).network(),
            Cidr::new(Address::new(127, 0, 0, 0), 8)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 0, 0), 16).network(),
            Cidr::new(Address::new(192, 168, 0, 0), 16)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 16).network(),
            Cidr::new(Address::new(192, 168, 0, 0), 16)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 17).network(),
            Cidr::new(Address::new(192, 168, 0, 0), 17)
        );
        assert_eq!(
            Cidr::new(Address::new(172, 16, 0, 1), 12).network(),
            Cidr::new(Address::new(172, 16, 0, 0), 12)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 1), 24).network(),
            Cidr::new(Address::new(255, 255, 255, 0), 24)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 255), 32).network(),
            Cidr::new(Address::new(255, 255, 255, 255), 32)
        );
    }
}
