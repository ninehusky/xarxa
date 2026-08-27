use super::{Error, Result};
use core::fmt;

use crate::wire::Ipv6Address as Address;
use crate::wire::{Ref, sub, write_octets16_at};

enum_with_unknown! {
    #[refined]
    /// IPv6 Extension Routing Header Routing Type
    pub enum Type(u8) {
        /// Source Route (DEPRECATED)
        ///
        /// See <https://tools.ietf.org/html/rfc5095> for details.
        Type0 = 0,
        /// Nimrod (DEPRECATED 2009-05-06)
        Nimrod = 1,
        /// Type 2 Routing Header for Mobile IPv6
        ///
        /// See <https://tools.ietf.org/html/rfc6275#section-6.4> for details.
        Type2 = 2,
        /// RPL Source Routing Header
        ///
        /// See <https://tools.ietf.org/html/rfc6554> for details.
        Rpl = 3,
        /// RFC3692-style Experiment 1
        ///
        /// See <https://tools.ietf.org/html/rfc4727> for details.
        Experiment1 = 253,
        /// RFC3692-style Experiment 2
        ///
        /// See <https://tools.ietf.org/html/rfc4727> for details.
        Experiment2 = 254,
        /// Reserved for future use
        Reserved = 252
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Type::Type0 => write!(f, "Type0"),
            Type::Nimrod => write!(f, "Nimrod"),
            Type::Type2 => write!(f, "Type2"),
            Type::Rpl => write!(f, "Rpl"),
            Type::Experiment1 => write!(f, "Experiment1"),
            Type::Experiment2 => write!(f, "Experiment2"),
            Type::Reserved => write!(f, "Reserved"),
            Type::Unknown(id) => write!(f, "{id}"),
        }
    }
}

/// A ghost carrying the routing-type octet.
///
/// The bound `check_len` establishes is conditioned on the routing type -- 22 octets for Type2,
/// 6 for Rpl -- and that is a property of the buffer's *contents*, so it cannot be a projection
/// of anything already in the refinement. Same device as `ipv4`'s `hlen`/`tlen` ghosts, and it
/// is what lets `checked_len` hand the per-type bound to `Repr::parse_ref`.
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val && val <= 255)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Ghost;

impl Ghost {
    /// A ghost whose value is unconstrained.
    #[flux_rs::trusted(yes, reason = "opaque: the ghost carries no runtime value")]
    #[flux_rs::sig(fn() -> Ghost{v: 0 <= v && v <= 255})]
    #[flux_rs::no_panic]
    const fn unknown() -> Ghost {
        Ghost
    }

    /// A ghost pinned to `val`.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the ghost value")]
    #[flux_rs::sig(fn(val: u8) -> Ghost[val])]
    #[flux_rs::no_panic]
    const fn from_u8(_val: u8) -> Ghost {
        Ghost
    }
}

/// A read/write wrapper around an IPv6 Routing Header buffer.
//
// Written out rather than derived for `Debug` so the ghost stays out of the output.
#[derive(PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(buffer: T, rtype: int)]
pub struct Header<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
    #[flux_rs::field(Ghost[rtype])]
    grtype: Ghost,
}

impl<T: AsRef<[u8]> + fmt::Debug> fmt::Debug for Header<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("buffer", &self.buffer)
            .finish()
    }
}

// Format of the Routing Header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// .                                                               .
// .                       type-specific data                      .
// .                                                               .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
// See https://tools.ietf.org/html/rfc8200#section-4.4 for details.
//
// **NOTE**: The fields start counting after the header length field.
mod field {
    #![allow(non_snake_case)]
    // The accessors write their offsets as literals -- flux cannot see through these consts --
    // so several are now named only by `check_len` and by the comment beside each literal.
    #![allow(unused)]

    use crate::wire::field::*;

    // Minimum size of the header.
    pub const MIN_HEADER_SIZE: usize = 2;

    // 8-bit identifier of a particular Routing header variant.
    pub const TYPE: usize = 0;
    // 8-bit unsigned integer. The number of route segments remaining.
    pub const SEG_LEFT: usize = 1;

    // The Type 2 Routing Header has the following format:
    //
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  Next Header  | Hdr Ext Len=2 | Routing Type=2|Segments Left=1|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                            Reserved                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // +                                                               +
    // |                                                               |
    // +                         Home Address                          +
    // |                                                               |
    // +                                                               +
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // 16-byte field containing the home address of the destination mobile node.
    pub const HOME_ADDRESS: Field = 6..22;

    // The RPL Source Routing Header has the following format:
    //
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  Next Header  |  Hdr Ext Len  | Routing Type  | Segments Left |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | CmprI | CmprE |  Pad  |               Reserved                |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // .                                                               .
    // .                        Addresses[1..n]                        .
    // .                                                               .
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // 8-bit field containing the CmprI and CmprE values.
    pub const CMPR: usize = 2;
    // 8-bit field containing the Pad value.
    pub const PAD: usize = 3;
    // Variable length field containing addresses
    pub const ADDRESSES: usize = 6;
}

/// Read the sixteen-octet IPv6 address at `at`.
///
/// The equal-length `copy_from_slice` stands in for `try_into().unwrap()`, which flux cannot
/// prove -- it does not model `TryInto<[u8; 16]> for &[u8]`. Both panic on a length mismatch
/// and `at + 16 <= n` rules both out, so the check is gated rather than removed.
#[flux_rs::trusted(no, reason = "panic site: copy_from_slice equal-length")]
#[flux_rs::sig(fn(&[u8][@n], at: usize) -> Address requires at + 16 <= n)]
#[flux_rs::no_panic]
fn read_ipv6_at(data: &[u8], at: usize) -> Address {
    let mut octets = [0; 16];
    octets.copy_from_slice(sub(data, at, 16));
    Address::from_octets(octets)
}

/// Core getter methods relevant to any routing type.
impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Routing Header structure.
    pub const fn new_unchecked(buffer: T) -> Header<T> {
        Header {
            buffer,
            grtype: Ghost::unknown(),
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// [`check_len`](Self::check_len), carrying its proof out through the `Ok` arm.
    ///
    /// The two per-type bounds are conditioned on `rtype`, which the ghost anchors: 22 octets
    /// for Type2 (code 2, `field::HOME_ADDRESS.end`) and 6 for Rpl (code 3, `field::ADDRESSES`).
    /// `Repr::parse_ref` matches on the same `routing_type()`, so each arm gets the bound its
    /// accessors need.
    #[flux_rs::trusted(no, reason = "carries the buffer length through the Result")]
    #[flux_rs::sig(
        fn(&Header<T>[@h])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(h.buffer) && 2 <= v
                            && (h.rtype == 2 => 22 <= v)
                            && (h.rtype == 3 => 6 <= v)}>
    )]
    fn checked_len(&self) -> Result<usize> {
        // The test `check_len` used to run, moved here so its `Ok` arm can name what it proved.
        // 2, 22 and 6 restate `field::MIN_HEADER_SIZE`, `field::HOME_ADDRESS.end` and
        // `field::ADDRESSES`: flux cannot see through those consts.
        let len = self.buffer.as_ref().len();
        if len < 2 {
            return Err(Error);
        }
        // The length test sits *inside* each arm rather than in a match guard: a guard that
        // fails falls through to `_`, and the arm's `rtype` fact goes with it, so the
        // postcondition's `h.rtype == 3 => 6 <= v` could not be proved.
        match self.routing_type() {
            Type::Type2 => {
                if len < 22 {
                    return Err(Error);
                }
            }
            Type::Rpl => {
                if len < 6 {
                    return Err(Error);
                }
            }
            // Spelled out rather than `_ => ()`: a catch-all does not give flux the negative
            // facts, so `h.rtype != 2` was not available on this path and the postcondition's
            // two implications could not be discharged. Same trap as `TcpOption::emit`.
            Type::Type0
            | Type::Nimrod
            | Type::Reserved
            | Type::Experiment1
            | Type::Experiment2
            | Type::Unknown(_) => (),
        }
        Ok(len)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        self.checked_len()?;
        Ok(())
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the routing type field.
    // Literal offsets rather than the `field::` consts: flux cannot see through them, so the
    // bound has to be written out. Same throughout this file.
    /// The anchor for the `rtype` ghost: the return type *claims* the octet at offset 0 is
    /// `rtype`. Nothing proves that -- the buffer's contents are not in the refinement -- so it
    /// is the assumption `checked_len`'s per-type bound rests on. What keeps it true is that
    /// `set_routing_type` is the only writer of that octet and updates the ghost in the same
    /// step. The read itself stays checked: the bound below is discharged at every call site.
    #[flux_rs::trusted(yes, reason = "anchors the `rtype` ghost to the octet at offset 0")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h]) -> Type[h.rtype]
        requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn routing_type(&self) -> Type {
        let data = self.buffer.as_ref();
        Type::from(data[0]) // field::TYPE
    }

    /// Return the segments left field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h]) -> u8
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn segments_left(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[1] // field::SEG_LEFT
    }
}

/// Getter methods for the Type 2 Routing Header routing type.
impl<T: AsRef<[u8]>> Header<T> {
    /// Return the IPv6 Home Address
    ///
    /// # Panics
    /// This function may panic if this header is not the Type2 Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h]) -> Address
        requires 22 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn home_address(&self) -> Address {
        let data = self.buffer.as_ref();
        read_ipv6_at(data, 6) // field::HOME_ADDRESS
    }
}

/// Getter methods for the RPL Source Routing Header routing type.
impl<T: AsRef<[u8]>> Header<T> {
    /// Return the number of prefix octets elided from addresses[1..n-1].
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h]) -> u8
        requires 3 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn cmpr_i(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[2] >> 4 // field::CMPR
    }

    /// Return the number of prefix octets elided from the last address (`addresses[n]`).
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h]) -> u8
        requires 3 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn cmpr_e(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[2] & 0xf // field::CMPR
    }

    /// Return the number of octets used for padding after `addresses[n]`.
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h]) -> u8
        requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn pad(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[3] >> 4 // field::PAD
    }

    /// Return the address vector in bytes
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: opens the address window at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h]) -> &[u8]
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn addresses(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[6..] // field::ADDRESSES
    }
}

/// Core setter methods relevant to any routing type.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the routing type.
    ///
    /// `&strg` rather than `&mut`: an indexed `&mut` pins every field of the index, `rtype`
    /// included, so no setter that moves the ghost can be called through it. This is a
    /// flux-only change -- the Rust signature is still `&mut Header<T>`.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Header<T>[@h], value: Type[@c])
        requires 1 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
        ensures self: Header<T>[h.buffer, c]
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_routing_type(&mut self, value: Type) {
        let data = self.buffer.as_mut();
        data[0] = value.into(); // field::TYPE
        // `u8::from` rather than `value.into()`: the macro specs `From<Type> for u8` as
        // code-preserving, but `Into`'s blanket impl carries no spec, so the code is lost.
        self.grtype = Ghost::from_u8(u8::from(value));
    }

    /// Set the segments left field.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: u8)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_segments_left(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[1] = value; // field::SEG_LEFT
    }

    /// Initialize reserved fields to 0.
    ///
    /// # Panics
    /// This function may panic if the routing type is not set.
    //
    // This reads through `AsRef` and writes through `AsMut`, and flux relates the two lengths
    // nowhere, so both are stated.
    //
    // The `_` arm handles routing types this function has no layout for. `rtype` is the ghost
    // anchored to the octet at offset 0, so the type *is* nameable: `2` is `Type::Type2` and
    // `3` is `Type::Rpl`, the two arms below. `Repr::emit` calls `set_routing_type` immediately
    // before each `clear_reserved`, which is what discharges this.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::no_panic_if(h.rtype == 2 || h.rtype == 3)]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h])
        requires
            (h.rtype == 2 || h.rtype == 3)
            && 1 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
            && 6 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[inline]
    pub fn clear_reserved(&mut self) {
        let routing_type = self.routing_type();
        let data = self.buffer.as_mut();

        // `if`/`else` rather than a `match`: flux does not carry the negation of the earlier
        // arms into a match's catch-all, so the final arm reads as reachable however tightly
        // `rtype` is constrained. Spelled this way the guards are ordinary path conditions.
        if routing_type == Type::Type2 {
            data[2] = 0;
            data[3] = 0;
            data[4] = 0;
            data[5] = 0;
        } else if routing_type == Type::Rpl {
            // Retain the higher order 4 bits of the padding field
            data[3] &= 0xF0; // field::PAD
            data[4] = 0;
            data[5] = 0;
        } else {
            panic!("Unrecognized routing type when clearing reserved fields.")
        }
    }
}

/// Setter methods for the RPL Source Routing Header routing type.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the Ipv6 Home Address
    ///
    /// # Panics
    /// This function may panic if this header is not the Type 2 Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: Address)
        requires 22 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_home_address(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        write_octets16_at(data, 6, &value.octets()); // field::HOME_ADDRESS
    }
}

/// Setter methods for the RPL Source Routing Header routing type.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the number of prefix octets elided from addresses[1..n-1].
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: u8)
        requires 3 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_cmpr_i(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        // field::CMPR
        let raw = (value << 4) | (data[2] & 0xF);
        data[2] = raw;
    }

    /// Set the number of prefix octets elided from the last address (`addresses[n]`).
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: u8)
        requires 3 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_cmpr_e(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        // field::CMPR
        let raw = (value & 0xF) | (data[2] & 0xF0);
        data[2] = raw;
    }

    /// Set the number of octets used for padding after `addresses[n]`.
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: u8)
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_pad(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[3] = value << 4; // field::PAD
    }

    /// Set address data
    ///
    /// # Panics
    /// This function may panic if this header is not the RPL Source Routing Header routing type.
    //
    // `copy_from_slice` panics unless `value.len()` is exactly `len - 6`. That is a real
    // precondition of this function, now stated: `copy_suffix_at` derives the window's length
    // rather than taking it as an argument, which `copy_window_at` cannot do.
    #[flux_rs::trusted(no, reason = "panic site: writes the address window at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: &[u8][@m])
        requires 6 + m == <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn set_addresses(&mut self, value: &[u8]) {
        let data = self.buffer.as_mut();
        crate::wire::copy_suffix_at(data, 6, value); // field::ADDRESSES
    }
}

impl fmt::Display for Header<Ref<'_>> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse_ref(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "IPv6 Routing ({err})")?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of an IPv6 Routing Header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
// Indexed by the number of octets `emit` writes, which is `buffer_len()`. `Type2` is the
// two-octet routing-type/segments-left preamble, four reserved octets and a 16-octet address;
// `Rpl` is the same six-octet preamble followed by the address vector. The index is what lets
// `emit` state a bound the `Rpl` arm can actually meet -- a blanket `22 <=` would be the
// `Type2` width charged to every caller.
#[flux_rs::refined_by(blen: int)]
#[flux_rs::invariant(6 <= blen)]
pub enum Repr<'a> {
    #[flux_rs::variant({u8, Address} -> Repr[22])]
    Type2 {
        /// Number of route segments remaining.
        segments_left: u8,
        /// The home address of the destination mobile node.
        home_address: Address,
    },
    #[flux_rs::variant({u8, u8, u8, u8, &[u8][@m]} -> Repr[6 + m])]
    Rpl {
        /// Number of route segments remaining.
        segments_left: u8,
        /// Number of prefix octets from each segment, except the last segment, that are elided.
        cmpr_i: u8,
        /// Number of prefix octets from the last segment that are elided.
        cmpr_e: u8,
        /// Number of octets that are used for padding after `address[n]` at the end of the
        /// RPL Source Route Header.
        pad: u8,
        /// Vector of addresses, numbered 1 to `n`.
        addresses: &'a [u8],
    },
}

impl<'a> Repr<'a> {
    /// Parse an IPv6 Routing Header and return a high-level representation.
    ///
    /// There is no generic `parse` over `&T`: a reference in type-parameter position has the
    /// unit sort, so nothing about the buffer's extent is statable there and none of the reads
    /// below would be provable -- the body was not being refinement-checked at all. Callers
    /// build a [`Ref`] instead.
    pub fn parse_ref(header: &'a Header<Ref<'a>>) -> Result<Repr<'a>> {
        header.checked_len()?;
        match header.routing_type() {
            Type::Type2 => Ok(Repr::Type2 {
                segments_left: header.segments_left(),
                home_address: header.home_address(),
            }),
            Type::Rpl => Ok(Repr::Rpl {
                segments_left: header.segments_left(),
                cmpr_i: header.cmpr_i(),
                cmpr_e: header.cmpr_e(),
                pad: header.pad(),
                addresses: header.addresses(),
            }),

            _ => Err(Error),
        }
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        match self {
            // Routing Type + Segments Left + Reserved + Home Address
            Repr::Type2 { home_address, .. } => 2 + 4 + home_address.octets().len(),
            Repr::Rpl { addresses, .. } => 2 + 4 + addresses.len(),
        }
    }

    /// Emit a high-level representation into an IPv6 Routing Header.
    // The buffer parameter is `Header<T>` with `T: Sized`, not `Header<&mut T>` with `T: ?Sized`.
    // The old shape instantiated core's blanket `impl<T, U> AsMut<U> for &mut T`, which carries no
    // associated refinement, so naming `as_mut_reft` for the setters below raised `associated
    // refinement 'as_mut_reft' is missing from implementation` -- a spec error, which aborts the
    // whole body. The `Sized` form lets a caller pass `wire::Buf`, whose `AsMut` impl is local and
    // refined; `&mut [u8]` still satisfies the bounds, so this is strictly more permissive.
    //
    // `r.blen` is `buffer_len()`. `clear_reserved` reads the routing type back through `AsRef`,
    // which flux relates to the `AsMut` length nowhere, so both are named.
    //
    // `header` is `&strg`, not `&mut Header<T>[@h]`: an indexed `&mut` pins every field of the
    // index, `rtype` included, so `set_routing_type` cannot be called through it. A `&strg`
    // place carries the new index out instead. Flux-only; the Rust signature is unchanged.
    #[flux_rs::sig(
        fn(self: &Self[@r], header: &strg Header<T>[@h])
        // Equality on the mutable side: `set_addresses` writes `buffer[6..]` from a slice of
        // exactly `blen - 6`, and `copy_from_slice` panics on any other length.
        requires r.blen == <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
              && r.blen <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
        ensures header: Header<T>{v: v.buffer == h.buffer}
    )]
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        match *self {
            Repr::Type2 {
                segments_left,
                home_address,
            } => {
                header.set_routing_type(Type::Type2);
                header.set_segments_left(segments_left);
                header.clear_reserved();
                header.set_home_address(home_address);
            }
            Repr::Rpl {
                segments_left,
                cmpr_i,
                cmpr_e,
                pad,
                addresses,
            } => {
                header.set_routing_type(Type::Rpl);
                header.set_segments_left(segments_left);
                header.set_cmpr_i(cmpr_i);
                header.set_cmpr_e(cmpr_e);
                header.set_pad(pad);
                header.clear_reserved();
                header.set_addresses(addresses);
            }
        }
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Repr::Type2 {
                segments_left,
                home_address,
            } => {
                write!(
                    f,
                    "IPv6 Routing type={} seg_left={} home_address={}",
                    Type::Type2,
                    segments_left,
                    home_address
                )
            }
            Repr::Rpl {
                segments_left,
                cmpr_i,
                cmpr_e,
                pad,
                ..
            } => {
                write!(
                    f,
                    "IPv6 Routing type={} seg_left={} cmpr_i={} cmpr_e={} pad={}",
                    Type::Rpl,
                    segments_left,
                    cmpr_i,
                    cmpr_e,
                    pad
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Type 2 Routing Header
    static BYTES_TYPE2: [u8; 22] = [
        0x2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x1,
    ];

    // A representation of a Type 2 Routing header
    static REPR_TYPE2: Repr = Repr::Type2 {
        segments_left: 1,
        home_address: Address::LOCALHOST,
    };

    // A Source Routing Header with full IPv6 addresses in bytes
    static BYTES_SRH_FULL: [u8; 38] = [
        0x3, 0x2, 0x0, 0x0, 0x0, 0x0, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x2, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x3, 0x1,
    ];

    // A representation of a Source Routing Header with full IPv6 addresses
    static REPR_SRH_FULL: Repr = Repr::Rpl {
        segments_left: 2,
        cmpr_i: 0,
        cmpr_e: 0,
        pad: 0,
        addresses: &[
            0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xfd,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x1,
        ],
    };

    // A Source Routing Header with elided IPv6 addresses in bytes
    static BYTES_SRH_ELIDED: [u8; 14] = [
        0x3, 0x2, 0xfe, 0x50, 0x0, 0x0, 0x2, 0x3, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    // A representation of a Source Routing Header with elided IPv6 addresses
    static REPR_SRH_ELIDED: Repr = Repr::Rpl {
        segments_left: 2,
        cmpr_i: 15,
        cmpr_e: 14,
        pad: 5,
        addresses: &[0x2, 0x3, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0],
    };

    #[test]
    fn test_check_len() {
        // less than min header size
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_TYPE2[..3]).check_len()
        );
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_SRH_FULL[..3]).check_len()
        );
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_SRH_ELIDED[..3]).check_len()
        );
        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_TYPE2[..]).check_len());
        assert_eq!(
            Ok(()),
            Header::new_unchecked(&BYTES_SRH_FULL[..]).check_len()
        );
        assert_eq!(
            Ok(()),
            Header::new_unchecked(&BYTES_SRH_ELIDED[..]).check_len()
        );
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_TYPE2[..]);
        assert_eq!(header.routing_type(), Type::Type2);
        assert_eq!(header.segments_left(), 1);
        assert_eq!(header.home_address(), Address::LOCALHOST);

        let header = Header::new_unchecked(&BYTES_SRH_FULL[..]);
        assert_eq!(header.routing_type(), Type::Rpl);
        assert_eq!(header.segments_left(), 2);
        assert_eq!(header.addresses(), &BYTES_SRH_FULL[6..]);

        let header = Header::new_unchecked(&BYTES_SRH_ELIDED[..]);
        assert_eq!(header.routing_type(), Type::Rpl);
        assert_eq!(header.segments_left(), 2);
        assert_eq!(header.addresses(), &BYTES_SRH_ELIDED[6..]);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_checked(Ref::new(&BYTES_TYPE2[..])).unwrap();
        let repr = Repr::parse_ref(&header).unwrap();
        assert_eq!(repr, REPR_TYPE2);

        let header = Header::new_checked(Ref::new(&BYTES_SRH_FULL[..])).unwrap();
        let repr = Repr::parse_ref(&header).unwrap();
        assert_eq!(repr, REPR_SRH_FULL);

        let header = Header::new_checked(Ref::new(&BYTES_SRH_ELIDED[..])).unwrap();
        let repr = Repr::parse_ref(&header).unwrap();
        assert_eq!(repr, REPR_SRH_ELIDED);
    }

    #[test]
    fn test_repr_emit() {
        let mut bytes = [0xFFu8; 22];
        let mut header = Header::new_unchecked(&mut bytes[..]);
        REPR_TYPE2.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_TYPE2[..]);

        let mut bytes = [0xFFu8; 38];
        let mut header = Header::new_unchecked(&mut bytes[..]);
        REPR_SRH_FULL.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_SRH_FULL[..]);

        let mut bytes = [0xFFu8; 14];
        let mut header = Header::new_unchecked(&mut bytes[..]);
        REPR_SRH_ELIDED.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_SRH_ELIDED[..]);
    }

    #[test]
    fn test_buffer_len() {
        assert_eq!(REPR_TYPE2.buffer_len(), 22);
        assert_eq!(REPR_SRH_FULL.buffer_len(), 38);
        assert_eq!(REPR_SRH_ELIDED.buffer_len(), 14);
    }
}
