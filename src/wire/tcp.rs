use byteorder::{ByteOrder, NetworkEndian};
use core::{cmp, fmt, ops};

use super::{Error, Result};
use crate::phy::ChecksumCapabilities;
use crate::wire::ip::checksum;
use crate::wire::{IpAddress, IpProtocol};
use crate::wire::{
    Buf, Maybe, Ref, read_i32_at, read_u16_at, sub, write_i32_at, write_u16_at, write_u32_at,
};

flux_rs::defs! {
    // The octets `SackRanges` contributes to the options field, less the two kind/length
    // octets, as a function of which of the three slots are occupied. Eight octets per
    // occupied slot: a pair of 32-bit edges. Kept in lockstep with `SackRanges::block_len`
    // and with `Repr::header_len`'s destructured sum, which is the same value.
    fn sack_len(a: bool, b: bool, c: bool) -> int {
        (if a { 8 } else { 0 }) + (if b { 8 } else { 0 }) + (if c { 8 } else { 0 })
    }

    // The octets the options field occupies, before the round up to a multiple of four.
    // Kept in lockstep with `header_len_of`, which is the only place it is computed.
    //
    // The sACK term is `+ 2` for the kind and length octets, and is present whenever any slot
    // is -- which is what `Repr::header_len` tests, and it is weaker than what `Repr::emit`
    // tests, so the space is always at least what is written.
    fn opt_len(mss: bool, ws: bool, sp: bool, ts: bool, a: bool, b: bool, c: bool) -> int {
        (if mss { 4 } else { 0 })
            + (if ws { 3 } else { 0 })
            + (if sp { 2 } else { 0 })
            + (if ts { 10 } else { 0 })
            + (if a || b || c { sack_len(a, b, c) + 2 } else { 0 })
    }

    // A 32-bit two's-complement wrap, as `wrapping_add`/`wrapping_sub` compute it. Correct for
    // any `x` that overshoots by at most one period -- which covers the difference of two
    // `i32`s, and the sum of an `i32` with a `usize` the caller has already bounded by
    // `i32::MAX`. Written as a conditional rather than with `%` so fixpoint sees linear
    // arithmetic. Same device as flux-core's `wrap_once`.
    fn wrap32(x: int) -> int {
        if x > 2147483647 {
            x - 4294967296
        } else if x < -2147483648 {
            x + 4294967296
        } else {
            x
        }
    }

    // The header length the options imply: the fixed 20 octets plus the options, rounded up to
    // a multiple of four. Written out rather than as `20 + opt_len(..)` because a `defn` does
    // not unfold inside another `defn`; `header_len_of`'s signature is what keeps the two in
    // lockstep, and the shape below is the body's, so the round up matches statement for
    // statement.
    fn hdr_len(mss: bool, ws: bool, sp: bool, ts: bool, a: bool, b: bool, c: bool) -> int {
        if (20
            + (if mss { 4 } else { 0 })
            + (if ws { 3 } else { 0 })
            + (if sp { 2 } else { 0 })
            + (if ts { 10 } else { 0 })
            + (if a || b || c {
                (if a { 8 } else { 0 }) + (if b { 8 } else { 0 }) + (if c { 8 } else { 0 }) + 2
            } else {
                0
            })) % 4 == 0 { (20
            + (if mss { 4 } else { 0 })
            + (if ws { 3 } else { 0 })
            + (if sp { 2 } else { 0 })
            + (if ts { 10 } else { 0 })
            + (if a || b || c {
                (if a { 8 } else { 0 }) + (if b { 8 } else { 0 }) + (if c { 8 } else { 0 }) + 2
            } else {
                0
            })) } else { (20
            + (if mss { 4 } else { 0 })
            + (if ws { 3 } else { 0 })
            + (if sp { 2 } else { 0 })
            + (if ts { 10 } else { 0 })
            + (if a || b || c {
                (if a { 8 } else { 0 }) + (if b { 8 } else { 0 }) + (if c { 8 } else { 0 }) + 2
            } else {
                0
            })) + 4 - (20
            + (if mss { 4 } else { 0 })
            + (if ws { 3 } else { 0 })
            + (if sp { 2 } else { 0 })
            + (if ts { 10 } else { 0 })
            + (if a || b || c {
                (if a { 8 } else { 0 }) + (if b { 8 } else { 0 }) + (if c { 8 } else { 0 }) + 2
            } else {
                0
            })) % 4 }
    }
}

/// A TCP sequence number.
///
/// A sequence number is a monotonically advancing integer modulo 2<sup>32</sup>.
/// Sequence numbers do not have a discontiguity when compared pairwise across a signed overflow.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[flux_rs::refined_by(v: int)]
pub struct SeqNumber(#[flux_rs::field(i32[v])] pub i32);

impl SeqNumber {
    #[flux_rs::sig(
        fn(SeqNumber[@a], SeqNumber[@b])
            -> SeqNumber[if wrap32(a.v - b.v) > 0 { a.v } else { b.v }]
    )]
    #[flux_rs::no_panic]
    pub fn max(self, rhs: Self) -> Self {
        if self > rhs { self } else { rhs }
    }

    #[flux_rs::sig(
        fn(SeqNumber[@a], SeqNumber[@b])
            -> SeqNumber[if wrap32(a.v - b.v) < 0 { a.v } else { b.v }]
    )]
    #[flux_rs::no_panic]
    pub fn min(self, rhs: Self) -> Self {
        if self < rhs { self } else { rhs }
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 as u32)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SeqNumber {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{}", self.0 as u32);
    }
}

impl ops::Add<usize> for SeqNumber {
    type Output = SeqNumber;

    // No signature, though one is *writable*: with `flux_util::usize_to_i32` discharging the
    // cast from the guard below, `-> SeqNumber[wrap32(a.v + n)]` is provable in principle. It
    // is left off because fixpoint does not terminate on it -- a full check ran past 30 minutes
    // against a ~7 minute norm and was killed. The `wrap32` case split multiplied across this
    // body's callers is the suspect. Retry when the sequence-number work needs it, and bisect
    // the blowup rather than assuming the whole body is at fault.
    fn add(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to add to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_add(rhs as i32))
    }
}

impl ops::Sub<usize> for SeqNumber {
    type Output = SeqNumber;

    // No signature, for the same reason as `Add<usize>` above.
    fn sub(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to subtract to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_sub(rhs as i32))
    }
}

impl ops::AddAssign<usize> for SeqNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

impl ops::Sub for SeqNumber {
    type Output = usize;

    // The underflow panic stays, and is the reason the result is nameable at all: past it, the
    // wrapped difference is known non-negative, so it is the distance between the two numbers.
    #[flux_rs::sig(fn(SeqNumber[@a], SeqNumber[@b]) -> usize[wrap32(a.v - b.v)])]
    fn sub(self, rhs: SeqNumber) -> usize {
        let result = self.0.wrapping_sub(rhs.0);
        if result < 0 {
            panic!("attempt to subtract sequence numbers with underflow")
        }
        result as usize
    }
}

/// The order is **modular, and therefore not transitive**: with `a = 0`, `b = 2^30` and
/// `c = 2^31` one has `a < b`, `b < c` and `c < a`. It is the standard TCP comparison and it is
/// correct exactly while every pair under comparison is within 2^31 of the other, which is what
/// a well-formed window guarantees.
///
/// The four provided methods are overridden rather than left to `partial_cmp` so each can carry
/// a signature. `partial_cmp` itself cannot: it returns `Option<Ordering>`, and neither
/// `core::Option` nor `Ordering` can be refined here. The bodies compute what `partial_cmp`
/// computes, so nothing about the comparison changes -- this is where the fact becomes visible,
/// not where it becomes true.
impl cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<cmp::Ordering> {
        self.0.wrapping_sub(other.0).partial_cmp(&0)
    }

    #[flux_rs::sig(fn(&SeqNumber[@a], &SeqNumber[@b]) -> bool[wrap32(a.v - b.v) < 0])]
    #[flux_rs::no_panic]
    fn lt(&self, other: &SeqNumber) -> bool {
        self.0.wrapping_sub(other.0) < 0
    }

    #[flux_rs::sig(fn(&SeqNumber[@a], &SeqNumber[@b]) -> bool[wrap32(a.v - b.v) <= 0])]
    #[flux_rs::no_panic]
    fn le(&self, other: &SeqNumber) -> bool {
        self.0.wrapping_sub(other.0) <= 0
    }

    #[flux_rs::sig(fn(&SeqNumber[@a], &SeqNumber[@b]) -> bool[wrap32(a.v - b.v) > 0])]
    #[flux_rs::no_panic]
    fn gt(&self, other: &SeqNumber) -> bool {
        self.0.wrapping_sub(other.0) > 0
    }

    #[flux_rs::sig(fn(&SeqNumber[@a], &SeqNumber[@b]) -> bool[wrap32(a.v - b.v) >= 0])]
    #[flux_rs::no_panic]
    fn ge(&self, other: &SeqNumber) -> bool {
        self.0.wrapping_sub(other.0) >= 0
    }
}

/// A ghost field: carries an integer in the refinement and nothing at runtime.
///
/// TCP's options window is `20..header_len` and its payload is `header_len..`, and `header_len`
/// is computed from the buffer's *contents* -- the top nibble of the u16 at offset 12. Contents
/// are not in the refinement, so no accessor's bound can mention it. This is the way to name it
/// anyway. `Packet` holds one of these, and because the struct is a ZST it costs no space and
/// `Packet<T>`'s layout is unchanged.
///
/// The value is anchored by [`Packet::header_len`], the trusted getter that claims the nibble
/// equals the ghost. Everything else is proved.
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val && val <= 255)]
#[derive(PartialEq, Eq, Clone, Copy)]
struct Ghost;

impl Ghost {
    /// A ghost whose value is unconstrained.
    ///
    /// The bound is the `u8` range and nothing more. `header_len` in fact only ever reads back a
    /// multiple of four in `0..=60`, but flux does not interpret `>>` well enough to prove it --
    /// `(raw >> 12) * 4 <= 60` does not discharge -- so claiming it here would be assuming it.
    /// The facts the windows actually need, `20 <= hlen` and `hlen <= buffer_len`, come from
    /// [`Packet::checked_len`], which tests them.
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
    const fn new(_val: u8) -> Ghost {
        Ghost
    }
}

/// A read/write wrapper around a Transmission Control Protocol packet buffer.
#[derive(PartialEq, Eq, Clone)]
#[flux_rs::refined_by(buffer: T, hlen: int)]
#[flux_rs::invariant(0 <= hlen && hlen <= 255)]
pub struct Packet<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
    #[flux_rs::field(Ghost[hlen])]
    ghlen: Ghost,
}

// Written out rather than derived so the ghost stays out of the output: a derive would print
// `Packet { buffer: .., ghlen: Ghost }`, and the ghost is not supposed to be observable. Both
// impls reproduce the derived form for the one field that existed before.
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

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const SEQ_NUM: Field = 4..8;
    pub const ACK_NUM: Field = 8..12;
    pub const FLAGS: Field = 12..14;
    pub const WIN_SIZE: Field = 14..16;
    pub const CHECKSUM: Field = 16..18;
    pub const URGENT: Field = 18..20;

    pub const fn OPTIONS(length: u8) -> Field {
        URGENT.end..(length as usize)
    }

    pub const FLG_FIN: u16 = 0x001;
    pub const FLG_SYN: u16 = 0x002;
    pub const FLG_RST: u16 = 0x004;
    pub const FLG_PSH: u16 = 0x008;
    pub const FLG_ACK: u16 = 0x010;
    pub const FLG_URG: u16 = 0x020;
    pub const FLG_ECE: u16 = 0x040;
    pub const FLG_CWR: u16 = 0x080;
    pub const FLG_NS: u16 = 0x100;

    pub const OPT_END: u8 = 0x00;
    pub const OPT_NOP: u8 = 0x01;
    pub const OPT_MSS: u8 = 0x02;
    pub const OPT_WS: u8 = 0x03;
    pub const OPT_SACKPERM: u8 = 0x04;
    pub const OPT_SACKRNG: u8 = 0x05;
    pub const OPT_TSTAMP: u8 = 0x08;
}

pub const HEADER_LEN: usize = field::URGENT.end;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with TCP packet structure.
    ///
    /// The ghost starts unconstrained: this reads nothing, so it learns nothing. It is pinned to
    /// the header length field the first time [`header_len`](Self::header_len) is called.
    #[flux_rs::sig(fn(T[@b]) -> Packet<T>{p: p.buffer == b})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet {
            buffer,
            ghlen: Ghost::unknown(),
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    ///
    /// Deliberately left unrefined. `checked_len` proves `20 <= hlen <= buffer_len`, and carrying
    /// that out through the `Ok` payload is
    /// [`new_checked_ref`](Packet::new_checked_ref)'s job; stating it here instead costs an
    /// error at every `T` for which `as_ref_reft` is unstatable, `pretty_print`'s
    /// `&dyn AsRef<[u8]>` among them.
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    /// Returns `Err(Error)` if the header length field has a value smaller
    /// than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(fn(self: &Packet<T>[@p]) -> Result<()>)]
    #[flux_rs::no_panic]
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
    /// arm say something, and what it says is exactly the three facts the windows below want:
    /// the buffer's length is what it is, the header length field is not a lie about the buffer,
    /// and the options window `20..header_len` does not run backwards.
    ///
    /// All three tests were already here. The third is stated in the bound only because the
    /// ghost makes `header_len` nameable.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@p])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && 20 <= p.hlen && p.hlen <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();
        if len < 20 {
            // field::URGENT.end
            Err(Error)
        } else {
            let header_len = self.header_len() as usize;
            if len < header_len || header_len < 20 {
                // field::URGENT.end
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

    /// Return the source port field.
    // Literal offsets rather than `field::SRC_PORT`: flux cannot see through the `Field`
    // (`Range`) const, so the bound has to be written out. Same throughout this impl.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn src_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 0) // field::SRC_PORT
    }

    /// Return the destination port field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 2) // field::DST_PORT
    }

    /// Return the sequence number field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> SeqNumber requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn seq_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(read_i32_at(data, 4)) // field::SEQ_NUM
    }

    /// Return the acknowledgement number field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> SeqNumber requires 12 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn ack_number(&self) -> SeqNumber {
        let data = self.buffer.as_ref();
        SeqNumber(read_i32_at(data, 8)) // field::ACK_NUM
    }

    /// The u16 at offset 12, with its bound proved and no claim about its value.
    ///
    /// The nine flag getters and [`header_len_field`](Self::header_len_field) all read this one
    /// field; routing them through here states the bound once.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    fn flags_field(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 12) // field::FLAGS
    }

    /// Return the FIN flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn fin(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_FIN != 0
    }

    /// Return the SYN flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn syn(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_SYN != 0
    }

    /// Return the RST flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn rst(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_RST != 0
    }

    /// Return the PSH flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn psh(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_PSH != 0
    }

    /// Return the ACK flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn ack(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_ACK != 0
    }

    /// Return the URG flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn urg(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_URG != 0
    }

    /// Return the ECE flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn ece(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_ECE != 0
    }

    /// Return the CWR flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn cwr(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_CWR != 0
    }

    /// Return the NS flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn ns(&self) -> bool {
        let raw = self.flags_field();
        raw & field::FLG_NS != 0
    }

    /// The header length in octets, with its read proved and no claim about its value.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u8 requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    fn header_len_field(&self) -> u8 {
        let raw = self.flags_field();
        ((raw >> 12) * 4) as u8
    }

    /// Return the header length, in octets.
    ///
    /// The anchor for the ghost field: the return type *claims* the top nibble of the u16 at
    /// offset 12, scaled by four, is `hlen`. Nothing proves that -- the buffer's contents are not
    /// in the refinement -- so it is the assumption the options and payload windows rest on.
    ///
    /// What keeps it true is that every writer of those two octets preserves the nibble.
    /// [`set_header_len`](Self::set_header_len) is the only one that changes it, and it updates
    /// the ghost in the same step; the ten flag writers all mask the low twelve bits only. See
    /// `test_flag_writes_preserve_header_len`.
    ///
    /// The read itself stays checked: the trusted body is a call, and the bound is discharged
    /// inside [`header_len_field`](Self::header_len_field). All this assumes is the equality,
    /// which is the part flux cannot see.
    #[flux_rs::trusted(yes, reason = "anchors the `hlen` ghost to the nibble at offset 12")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u8[p.hlen] requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn header_len(&self) -> u8 {
        self.header_len_field()
    }

    /// Return the window size field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 16 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn window_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 14) // field::WIN_SIZE
    }

    /// Return the checksum field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 18 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 16) // field::CHECKSUM
    }

    /// Return the urgent pointer field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 20 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn urgent_at(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 18) // field::URGENT
    }

    /// Return the length of the segment, in terms of sequence space.
    //
    // `p.hlen <= as_ref_reft` is what keeps the subtraction below from running backwards; it is
    // the second half of what `checked_len` returns. The crate is `check_overflow = "lazy"`, so
    // flux does not exercise it yet -- under `"strict"` it discharges one of this body's
    // obligations, and dropping it takes the body from 2 errors to 3.
    #[flux_rs::trusted(no, reason = "panic site: subtracts the header length from the buffer")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> usize requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && p.hlen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    pub fn segment_len(&self) -> usize {
        let data = self.buffer.as_ref();
        let mut length = data.len() - self.header_len() as usize;
        if self.syn() {
            length += 1
        }
        if self.fin() {
            length += 1
        }
        length
    }

    /// Returns whether the selective acknowledgement SYN flag is set or not.
    #[flux_rs::trusted(no, reason = "panic site: reslices the window named by the header length")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> Result<bool> requires 20 <= p.hlen && p.hlen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    pub fn selective_ack_permitted(&self) -> Result<bool> {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        let mut options = sub(data, 20, header_len - 20); // field::OPTIONS(header_len)
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            if option == TcpOption::SackPermitted {
                return Ok(true);
            }
            options = next_options;
        }
        Ok(false)
    }

    /// Return the selective acknowledgement ranges, if any. If there are none in the packet, an
    /// array of ``None`` values will be returned.
    ///
    #[flux_rs::trusted(no, reason = "panic site: reslices the window named by the header length")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> Result<SackRanges> requires 20 <= p.hlen && p.hlen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    pub fn selective_ack_ranges(&self) -> Result<SackRanges> {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_ref();
        let mut options = sub(data, 20, header_len - 20); // field::OPTIONS(header_len)
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            if let TcpOption::SackRange(slice) = option {
                return Ok(slice);
            }
            options = next_options;
        }
        Ok(SackRanges::none())
    }

    /// Validate the partial checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    //
    // No `no_panic`: the family-mismatch panic documented above lives in
    // `checksum::pseudo_header` and is a *value* obligation on the two addresses, a different
    // axis from the length work here. The `requires` covers only the header read.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p], &IpAddress, &IpAddress) -> bool requires 18 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    pub fn verify_partial_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();

        checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp, data.len() as u32)
            == self.checksum()
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    //
    // See `verify_partial_checksum` for why there is no `no_panic`. The `<= 65535` half is
    // `checksum::data`'s own bound: this hands it the whole buffer, so the bound lands on the
    // buffer rather than on a window of it.
    #[flux_rs::trusted(no, reason = "panic site: checksums the whole buffer")]
    #[flux_rs::sig(fn(&Packet<T>[@p], &IpAddress, &IpAddress) -> bool requires <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535)]
    pub fn verify_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp, data.len() as u32),
            checksum::data(data),
        ]) == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the source port field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 0, value) // field::SRC_PORT
    }

    /// Set the destination port field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 2, value) // field::DST_PORT
    }

    /// Set the sequence number field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_seq_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        write_i32_at(data, 4, value.0) // field::SEQ_NUM
    }

    /// Set the acknowledgement number field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 12 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_ack_number(&mut self, value: SeqNumber) {
        let data = self.buffer.as_mut();
        write_i32_at(data, 8, value.0) // field::ACK_NUM
    }

    /// Clear the entire flags field.
    //
    // Masks the low twelve bits only, so the header-length nibble -- and with it
    // [`header_len`](Self::header_len)'s claim about the ghost -- survives. `&mut` rather than
    // `&strg` says the same thing in the refinement: `self` comes back at the index it went in
    // with, ghost included.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p]) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = raw & !0x0fff;
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the FIN flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_fin(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_FIN
        } else {
            raw & !field::FLG_FIN
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the SYN flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_syn(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_SYN
        } else {
            raw & !field::FLG_SYN
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the RST flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_rst(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_RST
        } else {
            raw & !field::FLG_RST
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the PSH flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_psh(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_PSH
        } else {
            raw & !field::FLG_PSH
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the ACK flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_ack(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_ACK
        } else {
            raw & !field::FLG_ACK
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the URG flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_urg(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_URG
        } else {
            raw & !field::FLG_URG
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the ECE flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_ece(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_ECE
        } else {
            raw & !field::FLG_ECE
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the CWR flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_cwr(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_CWR
        } else {
            raw & !field::FLG_CWR
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the NS flag.
    //
    // Touches one of the low nine bits only; see `clear_flags` on why the ghost survives.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_ns(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = if value {
            raw | field::FLG_NS
        } else {
            raw & !field::FLG_NS
        };
        write_u16_at(data, 12, raw) // field::FLAGS
    }

    /// Set the header length, in octets.
    ///
    /// Writes the ghost as well as the octets. This is the whole of what keeps
    /// [`header_len`](Self::header_len)'s claim true, so the two must not drift apart: `&strg`
    /// rather than `&mut` because a `&mut T{v: ..}` weakening does not compose through a call
    /// chain, and `Repr::emit` needs the new value to survive into `options_mut` after it.
    ///
    /// The ghost is set to `(value / 4) * 4`, not to `value`. The field is a four-bit count of
    /// 32-bit words, so this stores `value / 4` and reads back a multiple of four; a `value` that
    /// is not one comes back truncated, which `test_impossible_len` relies on. Requiring
    /// `value % 4 == 0` instead would state a contract the function does not have.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Packet<T>[@p], value: u8)
        requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures self: Packet<T>[p.buffer, (value / 4) * 4]
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        let raw = read_u16_at(data, 12); // field::FLAGS
        let raw = (raw & !0xf000) | ((value as u16) / 4) << 12;
        write_u16_at(data, 12, raw); // field::FLAGS
        self.ghlen = Ghost::new((value / 4) * 4);
    }

    /// Set the window size field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 16 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_window_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 14, value) // field::WIN_SIZE
    }

    /// Set the checksum field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 18 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 16, value) // field::CHECKSUM
    }

    /// Set the urgent pointer field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], _) requires 20 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_urgent_at(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 18, value) // field::URGENT
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    //
    // See `Packet::verify_partial_checksum` for why there is no `no_panic`, and
    // `Packet::verify_checksum` for where the `<= 65535` comes from.
    #[flux_rs::trusted(no, reason = "panic site: checksums the whole buffer")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], &IpAddress, &IpAddress)
        requires 18 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer) && <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
    )]
    pub fn fill_checksum(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp, data.len() as u32),
                checksum::data(data),
            ])
        };
        self.set_checksum(checksum)
    }

    /// Return a pointer to the options.
    //
    // Indexed directly rather than through a `wire::buf` helper. The window is written
    // `20..header_len` rather than `field::OPTIONS(header_len)` only because flux cannot see
    // through a `const fn` returning a `Range`; spelled out, both ends are in the `requires` and
    // flux proves the slice itself. A trusted helper here would buy nothing -- a returned `&mut`
    // loses its length index either way (flux-rs/flux#1714) -- and would swap a proved bound for
    // an assumed one.
    #[flux_rs::trusted(no, reason = "panic site: reslices the window named by the header length")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p]) -> &mut [u8]
        requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && 20 <= p.hlen && p.hlen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[20..header_len] // field::OPTIONS(header_len)
    }

    /// Return the options window, carrying its length in the refinement.
    ///
    /// [`options_mut`](Self::options_mut) cannot: a returned `&mut` loses its length index
    /// (flux-rs/flux#1714), so the window arrives as an unindexed slice and nothing written into
    /// it can be shown to fit. `Buf` is how the rest of the crate carries a length across that
    /// boundary; the length claimed here is the one `options_mut` slices to, and the bound that
    /// makes that slicing legal is the `requires` below, discharged at the call site.
    #[flux_rs::trusted(yes, reason = "returned &mut loses its length; see flux-rs/flux#1714")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p]) -> Buf[p.hlen - 20]
        requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && 20 <= p.hlen && p.hlen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn options_buf(&mut self) -> Buf<'_> {
        Buf::new(self.options_mut())
    }

    /// Return a mutable pointer to the payload data.
    //
    // See `options_mut` on why this indexes directly.
    #[flux_rs::trusted(no, reason = "panic site: reslices past the header length")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p]) -> &mut [u8]
        requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && p.hlen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[header_len..]
    }

    /// Return the payload window, carrying its length in the refinement.
    ///
    /// Same relation to [`payload_mut`](Self::payload_mut) as
    /// [`options_buf`](Self::options_buf) has to `options_mut`, and for the same reason: a
    /// returned `&mut` loses its length index (flux-rs/flux#1714), so the payload copy in
    /// [`Repr::emit`] cannot be shown to fit the window it is copied into.
    #[flux_rs::trusted(yes, reason = "returned &mut loses its length; see flux-rs/flux#1714")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p]) -> Buf[<T as AsMut<[u8]>>::as_mut_reft(p.buffer) - p.hlen]
        requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && p.hlen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload_buf(&mut self) -> Buf<'_> {
        Buf::new(self.payload_mut())
    }
}

#[flux_rs::assoc(
    fn as_ref_reft(source: Self) -> int {
        <T as AsRef<[u8]>>::as_ref_reft(source.buffer)
    }
)]
impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    #[flux_rs::no_panic]
    #[flux_rs::sig(fn(self: &Self[@source]) -> &[u8][Self::as_ref_reft(source)])]
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// One SACK block: the pair of 32-bit edges, or its absence.
///
/// `Option<(u32, u32)>` in all but name. It exists because a refinement cannot be attached to
/// `core::Option` from outside: `Option` already has flux's default field-less sort, and an
/// `extern_spec` giving it `refined_by(is_some: bool)` leaves two encodings of the same type
/// alive at once, which crashes fixpoint's sort elaboration. See `ICE-INBOX.md`, 2026-08-20.
/// A crate-local enum has no default to conflict with. Same shape as [`HardwareAddress`], which
/// is refined by a bool and has always verified.
///
/// [`HardwareAddress`]: crate::wire::HardwareAddress
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(present: bool)]
pub enum SackBlock {
    #[flux_rs::variant(SackBlock[false])]
    Absent,
    #[flux_rs::variant((u32, u32) -> SackBlock[true])]
    Present(u32, u32),
}

impl SackBlock {
    /// Whether this block is advertised.
    #[flux_rs::sig(fn(&SackBlock[@b]) -> bool[b])]
    pub const fn is_present(&self) -> bool {
        matches!(self, SackBlock::Present(..))
    }

    /// The block as an `Option`.
    ///
    /// The refinement is lost on the way out -- `Option` is unrefined here, which is the whole
    /// reason this type exists -- so this is for callers who only want the value.
    pub const fn as_option(&self) -> Option<(u32, u32)> {
        match *self {
            SackBlock::Present(left, right) => Some((left, right)),
            SackBlock::Absent => None,
        }
    }

    /// The block from an `Option`.
    ///
    /// The result's `present` is unknown to flux, for the same reason as [`as_option`]. That is
    /// enough for every bound in this module: `Repr::header_len` sizes the options window from
    /// the same three bools that `TcpOption::SackRange`'s length is a function of, so they
    /// cancel whatever they are.
    ///
    /// [`as_option`]: Self::as_option
    pub const fn from_option(value: Option<(u32, u32)>) -> SackBlock {
        match value {
            Some((left, right)) => SackBlock::Present(left, right),
            None => SackBlock::Absent,
        }
    }
}

/// The SACK blocks a segment advertises: up to three, each a pair of 32-bit edges.
///
/// Three named fields rather than `[SackBlock; 3]` because `[T; N]` has the unit sort, so the
/// number of occupied slots is not statable at the array type -- and that count is exactly what
/// `TcpOption::SackRange`'s length is a function of. As three fields the count is in the
/// refinement and `sack_len` can name it.
///
/// The slots are filled from `first`: a later slot occupied while an earlier one is empty is
/// not produced by either `Repr::parse` or the socket, but it is representable, and both
/// `block_len` and `emit` handle it by compacting, as the old `filter()` did.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(a: bool, b: bool, c: bool)]
pub struct SackRanges {
    #[flux_rs::field(SackBlock[a])]
    pub first: SackBlock,
    #[flux_rs::field(SackBlock[b])]
    pub second: SackBlock,
    #[flux_rs::field(SackBlock[c])]
    pub third: SackBlock,
}

impl SackRanges {
    /// No blocks advertised.
    #[flux_rs::sig(fn() -> SackRanges[false, false, false])]
    pub const fn none() -> SackRanges {
        SackRanges {
            first: SackBlock::Absent,
            second: SackBlock::Absent,
            third: SackBlock::Absent,
        }
    }

    /// Whether any block is advertised.
    #[flux_rs::sig(fn(&SackRanges[@s]) -> bool[s.a || s.b || s.c])]
    pub const fn any(&self) -> bool {
        self.first.is_present() || self.second.is_present() || self.third.is_present()
    }

    /// The octets the blocks occupy, less the two kind/length octets.
    #[flux_rs::sig(fn(&SackRanges[@s]) -> usize[sack_len(s.a, s.b, s.c)])]
    pub const fn block_len(&self) -> usize {
        (if self.first.is_present() { 8 } else { 0 })
            + (if self.second.is_present() { 8 } else { 0 })
            + (if self.third.is_present() { 8 } else { 0 })
    }
}

/// A representation of a single TCP option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(blen: int)]
pub enum TcpOption<'a> {
    #[flux_rs::variant(TcpOption[1])]
    EndOfList,
    #[flux_rs::variant(TcpOption[1])]
    NoOperation,
    #[flux_rs::variant((u16) -> TcpOption[4])]
    MaxSegmentSize(u16),
    #[flux_rs::variant((u8) -> TcpOption[3])]
    WindowScale(u8),
    #[flux_rs::variant(TcpOption[2])]
    SackPermitted,
    #[flux_rs::variant((SackRanges[@s]) -> TcpOption[2 + sack_len(s.a, s.b, s.c)])]
    SackRange(SackRanges),
    #[flux_rs::variant({u32, u32} -> TcpOption[10])]
    TimeStamp { tsval: u32, tsecr: u32 },
    #[flux_rs::variant({u8, &[u8][@n]} -> TcpOption[2 + n])]
    Unknown { kind: u8, data: &'a [u8] },
}

/// One SACK block: the pair of 32-bit edges at `at`, or `None` when the option does not reach
/// that far.
///
/// `at + 8 <= data.len()` rather than `at < data.len()`, which is what the caller's loop used
/// to test: `data.len()` is the option length less two, which the caller has already made a
/// multiple of eight, and `at` is one too, so the two conditions coincide -- and this one is
/// the bound the two reads need.
///
/// RFC 2018: Each contiguous block of data queued at the data receiver is defined in the SACK
/// option by two 32-bit unsigned integers in network byte order[...]
#[flux_rs::sig(fn(&[u8][@n], at: usize) -> SackBlock requires at <= 16)]
fn sack_block(data: &[u8], at: usize) -> SackBlock {
    if at + 8 <= data.len() {
        SackBlock::Present(
            NetworkEndian::read_u32(&data[at..at + 4]),
            NetworkEndian::read_u32(&data[at + 4..at + 8]),
        )
    } else {
        SackBlock::Absent
    }
}

impl<'a> TcpOption<'a> {
    /// The three `ok_or` tests are spelled out as length comparisons: `first` and `get` return
    /// an `Option` whose `Some` says nothing about the slice inside it, so the length the check
    /// established did not survive. Each test below rejects exactly the buffers its `Option`
    /// counterpart did -- `get(2..length)` is `None` when `length < 2` or when it runs past the
    /// buffer -- and what it leaves behind is `data`'s length, which is what every read in the
    /// inner match needs.
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], TcpOption<'a>)> {
        let (length, option);
        if buffer.is_empty() {
            return Err(Error);
        }
        match buffer[0] {
            field::OPT_END => {
                length = 1;
                option = TcpOption::EndOfList;
            }
            field::OPT_NOP => {
                length = 1;
                option = TcpOption::NoOperation;
            }
            kind => {
                if buffer.len() < 2 {
                    return Err(Error);
                }
                length = buffer[1] as usize;
                if length < 2 || buffer.len() < length {
                    return Err(Error);
                }
                let data = &buffer[2..length];
                match (kind, length) {
                    (field::OPT_END, _) | (field::OPT_NOP, _) => unreachable!(),
                    (field::OPT_MSS, 4) => {
                        option = TcpOption::MaxSegmentSize(NetworkEndian::read_u16(data))
                    }
                    (field::OPT_MSS, _) => return Err(Error),
                    (field::OPT_WS, 3) => option = TcpOption::WindowScale(data[0]),
                    (field::OPT_WS, _) => return Err(Error),
                    (field::OPT_SACKPERM, 2) => option = TcpOption::SackPermitted,
                    (field::OPT_SACKPERM, _) => return Err(Error),
                    (field::OPT_SACKRNG, n) => {
                        if n < 10 || (n - 2) % 8 != 0 {
                            return Err(Error);
                        }
                        if n > 26 {
                            // It's possible for a remote to send 4 SACK blocks, but extremely rare.
                            // Better to "lose" that 4th block and save the extra RAM and CPU
                            // cycles in the vastly more common case.
                            //
                            // RFC 2018: SACK option that specifies n blocks will have a length of
                            // 8*n+2 bytes, so the 40 bytes available for TCP options can specify a
                            // maximum of 4 blocks.  It is expected that SACK will often be used in
                            // conjunction with the Timestamp option used for RTTM [...] thus a
                            // maximum of 3 SACK blocks will be allowed in this case.
                            net_debug!("sACK with >3 blocks, truncating to 3");
                        }
                        let sack_ranges: SackRanges;

                        // RFC 2018: Each contiguous block of data queued at the data receiver is
                        // defined in the SACK option by two 32-bit unsigned integers in network
                        // byte order[...]
                        // Three literal offsets rather than `iter_mut().enumerate()`:
                        // `enumerate` hands out an unbounded `usize`, and with `i` unbounded
                        // `i * 8 + 4` is a possible overflow -- enough to lose `left <= mid`
                        // before any bound on `data` is considered.
                        sack_ranges = SackRanges {
                            first: sack_block(data, 0),
                            second: sack_block(data, 8),
                            third: sack_block(data, 16),
                        };
                        option = TcpOption::SackRange(sack_ranges);
                    }
                    (field::OPT_TSTAMP, 10) => {
                        let tsval = NetworkEndian::read_u32(&data[0..4]);
                        let tsecr = NetworkEndian::read_u32(&data[4..8]);
                        option = TcpOption::TimeStamp { tsval, tsecr };
                    }
                    (_, _) => option = TcpOption::Unknown { kind, data },
                }
            }
        }
        Ok((&buffer[length..], option))
    }

    #[flux_rs::sig(fn(&Self[@o]) -> usize[o.blen])]
    pub fn buffer_len(&self) -> usize {
        match *self {
            TcpOption::EndOfList => 1,
            TcpOption::NoOperation => 1,
            TcpOption::MaxSegmentSize(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 2,
            TcpOption::SackRange(s) => s.block_len() + 2,
            TcpOption::TimeStamp { tsval: _, tsecr: _ } => 10,
            TcpOption::Unknown { data, .. } => 2 + crate::flux_util::byte_len(data),
        }
    }

    #[flux_rs::sig(fn(&Self[@o], buffer: &mut [u8][@n]) -> &mut [u8][n - o.blen]
                   requires o.blen <= n)]
    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let length;
        match *self {
            TcpOption::EndOfList => {
                length = 1;
                // There may be padding space which also should be initialized.
                for p in buffer.iter_mut() {
                    *p = field::OPT_END;
                }
            }
            TcpOption::NoOperation => {
                length = 1;
                buffer[0] = field::OPT_NOP;
            }
            TcpOption::MaxSegmentSize(_)
            | TcpOption::WindowScale(_)
            | TcpOption::SackPermitted
            | TcpOption::SackRange(_)
            | TcpOption::TimeStamp { .. }
            | TcpOption::Unknown { .. } => {
                length = self.buffer_len();
                buffer[1] = length as u8;
                match self {
                    &TcpOption::EndOfList | &TcpOption::NoOperation => unreachable!(),
                    &TcpOption::MaxSegmentSize(value) => {
                        buffer[0] = field::OPT_MSS;
                        NetworkEndian::write_u16(&mut buffer[2..], value)
                    }
                    &TcpOption::WindowScale(value) => {
                        buffer[0] = field::OPT_WS;
                        buffer[2] = value;
                    }
                    &TcpOption::SackPermitted => {
                        buffer[0] = field::OPT_SACKPERM;
                    }
                    &TcpOption::SackRange(ranges) => {
                        buffer[0] = field::OPT_SACKRNG;
                        // Three explicit writes with a running offset rather than
                        // `filter().enumerate()`: `enumerate` hands out an unbounded `usize`,
                        // so `i * 8 + 2` is unbounded and neither write under it is in bounds.
                        // `pos` advances only on an occupied slot, which is the compaction
                        // `filter` performed.
                        let mut pos = 2;
                        if let SackBlock::Present(left, right) = ranges.first {
                            write_u32_at(buffer, pos, left);
                            write_u32_at(buffer, pos + 4, right);
                            pos += 8;
                        }
                        if let SackBlock::Present(left, right) = ranges.second {
                            write_u32_at(buffer, pos, left);
                            write_u32_at(buffer, pos + 4, right);
                            pos += 8;
                        }
                        if let SackBlock::Present(left, right) = ranges.third {
                            write_u32_at(buffer, pos, left);
                            write_u32_at(buffer, pos + 4, right);
                        }
                    }
                    &TcpOption::TimeStamp { tsval, tsecr } => {
                        buffer[0] = field::OPT_TSTAMP;
                        NetworkEndian::write_u32(&mut buffer[2..], tsval);
                        NetworkEndian::write_u32(&mut buffer[6..], tsecr);
                    }
                    &TcpOption::Unknown {
                        kind,
                        data: provided,
                    } => {
                        buffer[0] = kind;
                        buffer[2..].copy_from_slice(provided)
                    }
                }
            }
        }
        &mut buffer[length..]
    }
}

/// The possible control flags of a Transmission Control Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Control {
    None,
    Psh,
    Syn,
    Fin,
    Rst,
}

#[allow(clippy::len_without_is_empty)]
impl Control {
    /// Return the length of a control flag, in terms of sequence space.
    pub const fn len(self) -> usize {
        match self {
            Control::Syn | Control::Fin => 1,
            _ => 0,
        }
    }

    /// Turn the PSH flag into no flag, and keep the rest as-is.
    pub const fn quash_psh(self) -> Control {
        match self {
            Control::Psh => Control::None,
            _ => self,
        }
    }
}

/// A high-level representation of a Transmission Control Protocol packet.
//
// Indexed by the payload's length, and nothing else. That is enough to give `buffer_len` a
// ceiling as well as its floor, which is what `IpRepr::new` and `set_payload_len` need against
// `Ipv4Repr`/`Ipv6Repr`'s `plen <= 65535`. There is no invariant, so the index is derived at
// every construction site rather than owed -- the 492 struct literals across the crate are
// untouched.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[flux_rs::refined_by(plen: int, mss: bool, ws: bool, sp: bool, ts: bool, a: bool, b: bool, c: bool)]
pub struct Repr<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub control: Control,
    pub seq_number: SeqNumber,
    pub ack_number: Option<SeqNumber>,
    pub window_len: u16,
    #[flux_rs::field(Maybe<u8>[ws])]
    pub window_scale: Maybe<u8>,
    #[flux_rs::field(Maybe<u16>[mss])]
    pub max_seg_size: Maybe<u16>,
    #[flux_rs::field(bool[sp])]
    pub sack_permitted: bool,
    #[flux_rs::field(SackRanges[a, b, c])]
    pub sack_ranges: SackRanges,
    #[flux_rs::field(Maybe<TcpTimestampRepr>[ts])]
    pub timestamp: Maybe<TcpTimestampRepr>,
    #[flux_rs::field(&[u8][plen])]
    pub payload: &'a [u8],
}

pub type TcpTimestampGenerator = fn() -> u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcpTimestampRepr {
    pub tsval: u32,
    pub tsecr: u32,
}

impl TcpTimestampRepr {
    pub fn new(tsval: u32, tsecr: u32) -> Self {
        Self { tsval, tsecr }
    }

    pub fn generate_reply(&self, generator: Option<TcpTimestampGenerator>) -> Option<Self> {
        Self::generate_reply_with_tsval(generator, self.tsval)
    }

    pub fn generate_reply_with_tsval(
        generator: Option<TcpTimestampGenerator>,
        tsval: u32,
    ) -> Option<Self> {
        Some(Self::new(generator?(), tsval))
    }
}

/// The header length implied by a set of options, in octets.
///
/// The floor is what matters and it is stated over the *arguments*, not over a `Repr`: a caller
/// that has read the option fields into locals gets back a length it can compare against what it
/// is about to write. [`Repr::emit`] is that caller, and it is why this is not a method -- read
/// twice, the fields would give two unrelated values.
///
/// `(v / 4) * 4` rather than `v` because that is what `Packet::set_header_len` stores: the field
/// is a four-bit count of 32-bit words. The round up below makes the two coincide, and stating
/// it this way means nothing downstream has to know that.
#[flux_rs::trusted(no, reason = "relates the header length to the options it accounts for")]
#[flux_rs::sig(
    fn(mss: &Maybe<u16>[@m], ws: &Maybe<u8>[@w], sp: bool[@s], ts: &Maybe<TcpTimestampRepr>[@t],
       ranges: &SackRanges[@r])
        -> usize{v: v == hdr_len(m, w, s, t, r.a, r.b, r.c) && 20 <= v && v <= 68}
)]
#[flux_rs::no_panic]
fn header_len_of(
    mss: &Maybe<u16>,
    ws: &Maybe<u8>,
    sack_permitted: bool,
    ts: &Maybe<TcpTimestampRepr>,
    ranges: &SackRanges,
) -> usize {
    let mut length = 20; // field::URGENT.end
    if mss.is_present() {
        length += 4
    }
    if ws.is_present() {
        length += 3
    }
    if sack_permitted {
        length += 2;
    }
    if ts.is_present() {
        length += 10;
    }
    let sack_range_len: usize = ranges.block_len();
    if sack_range_len > 0 {
        length += sack_range_len + 2;
    }
    // `length % 4 != 0` rather than `!length.is_multiple_of(4)`: that method carries no
    // flux spec, so `no_panic` reports it as a possible panic. Same test.
    if length % 4 != 0 {
        length += 4 - length % 4;
    }
    length
}

impl<'a> Repr<'a> {
    /// Parse a Transmission Control Protocol packet and return a high-level representation.
    ///
    /// A reference in type-parameter position has the unit sort, so no bound on `T`'s buffer is
    /// statable here and neither window below would be provable. The body therefore lives on
    /// [`parse_ref`](Self::parse_ref), over a buffer whose length is nameable; this re-wraps the
    /// same bytes and forwards, which repeats no work the old body did not do.
    pub fn parse<T>(
        packet: &Packet<&'a T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Repr::parse_ref(
            &Packet::new_unchecked(Ref::new(packet.buffer.as_ref())),
            src_addr,
            dst_addr,
            checksum_caps,
        )
    }

    /// [`parse`](Self::parse) over a [`Ref`], where the buffer's length is in the refinement.
    ///
    /// `checked_len` rather than `check_len`: the same test, but its `Ok` arm names the three
    /// facts the accessors below need -- the buffer's length, that the header-length field is
    /// not a lie about it, and that the options window does not run backwards -- and over `Ref`
    /// they are statable.
    pub fn parse_ref(
        packet: &Packet<Ref<'a>>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr<'a>> {
        packet.checked_len()?;

        // Source and destination ports must be present.
        if packet.src_port() == 0 {
            return Err(Error);
        }
        if packet.dst_port() == 0 {
            return Err(Error);
        }
        // Valid checksum is expected.
        if checksum_caps.tcp.rx() && !packet.verify_checksum(src_addr, dst_addr) {
            return Err(Error);
        }

        let control = match (packet.syn(), packet.fin(), packet.rst(), packet.psh()) {
            (false, false, false, false) => Control::None,
            (false, false, false, true) => Control::Psh,
            (true, false, false, _) => Control::Syn,
            (false, true, false, _) => Control::Fin,
            (false, false, true, _) => Control::Rst,
            _ => return Err(Error),
        };
        let ack_number = match packet.ack() {
            true => Some(packet.ack_number()),
            false => None,
        };
        // The PSH flag is ignored.
        // The URG flag and the urgent field is ignored. This behavior is standards-compliant,
        // however, most deployed systems (e.g. Linux) are *not* standards-compliant, and would
        // cut the byte at the urgent pointer from the stream.

        let mut max_seg_size = Maybe::Nothing;
        let mut window_scale = Maybe::Nothing;
        let mut options = packet.options();
        let mut sack_permitted = false;
        let mut sack_ranges = SackRanges::none();
        let mut timestamp = Maybe::Nothing;
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) => max_seg_size = Maybe::Just(value),
                TcpOption::WindowScale(value) => {
                    // RFC 1323: Thus, the shift count must be limited to 14 (which allows windows
                    // of 2**30 = 1 Gigabyte). If a Window Scale option is received with a shift.cnt
                    // value exceeding 14, the TCP should log the error but use 14 instead of the
                    // specified value.
                    window_scale = if value > 14 {
                        net_debug!(
                            "{}:{}:{}:{}: parsed window scaling factor >14, setting to 14",
                            src_addr,
                            packet.src_port(),
                            dst_addr,
                            packet.dst_port()
                        );
                        Maybe::Just(14)
                    } else {
                        Maybe::Just(value)
                    };
                }
                TcpOption::SackPermitted => sack_permitted = true,
                TcpOption::SackRange(slice) => sack_ranges = slice,
                TcpOption::TimeStamp { tsval, tsecr } => {
                    timestamp = Maybe::Just(TcpTimestampRepr::new(tsval, tsecr));
                }
                _ => (),
            }
            options = next_options;
        }

        Ok(Repr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            control: control,
            seq_number: packet.seq_number(),
            ack_number: ack_number,
            window_len: packet.window_len(),
            window_scale: window_scale,
            max_seg_size: max_seg_size,
            sack_permitted: sack_permitted,
            sack_ranges: sack_ranges,
            timestamp: timestamp,
            payload: packet.payload(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// This should be used for buffer space calculations.
    /// The TCP header length is a multiple of 4.
    ///
    /// A range, not the exact value: whether an option is present is a fact about the `Option`
    /// fields, which are not in this type's refinement. [`header_len_of`] states the exact
    /// relation for a caller that has already taken those fields apart, which is what
    /// [`emit`](Self::emit) does.
    ///
    /// 20 is `field::URGENT.end`, restated as a literal because flux cannot see through the
    /// `Range` const it comes from; it is what the fixed part of the header costs. 68 is the
    /// other end: `4 + 3 + 2 + 10` of single options, `8 * 3 + 2` of sACK, and the round up to a
    /// multiple of four. The ceiling is what keeps the sum in `buffer_len` from reading as a
    /// wrapping one, and what bounds the `as u8` cast in `emit`.
    #[flux_rs::trusted(no, reason = "bounds the emitted header length")]
    #[flux_rs::sig(fn(&Self[@r]) -> usize{v: v == hdr_len(r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c) && 20 <= v && v <= 68})]
    #[flux_rs::no_panic]
    pub fn header_len(&self) -> usize {
        header_len_of(
            &self.max_seg_size,
            &self.window_scale,
            self.sack_permitted,
            &self.timestamp,
            &self.sack_ranges,
        )
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    ///
    /// The same floor as [`header_len`](Self::header_len), carried through the payload: this is
    /// what `IpPayload::Tcp`'s `minlen` rests on, and through it `Repr::emit`'s `20 <=` bound on
    /// the buffer it is handed.
    ///
    /// `byte_len` rather than `.len()` so the sum carries the `isize::MAX` ceiling; without it
    /// `check_overflow = "lazy"` models the addition as wrapping and the floor is lost.
    #[flux_rs::trusted(no, reason = "the emitted packet length, exactly")]
    #[flux_rs::sig(fn(&Self[@r]) -> usize{v: v == hdr_len(r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c) + r.plen && 20 <= v})]
    pub fn buffer_len(&self) -> usize {
        self.header_len() + crate::flux_util::byte_len(self.payload)
    }

    /// Emit a high-level representation into a Transmission Control Protocol packet.
    //
    // `Packet<T>` with `T: Sized`, not `Packet<&mut T>` with `T: ?Sized`. The old shape
    // instantiated core's blanket `impl<T, U> AsMut<U> for &mut T`, which carries no associated
    // refinement, so `associated refinement 'as_mut_reft' is missing` aborted refinement
    // checking of this whole body: 22 obligations below were silently unchecked, and this
    // file's reported site count was a floor, not a count. `&mut T` still satisfies the bounds,
    // so every existing caller resolves. Same move as `icmpv4::Repr::emit`.
    //
    // 20 is `field::URGENT.end`, the fixed part of the header, restated as a literal because
    // flux cannot see through a `Range` const. It discharges every fixed-offset setter below.
    // The window obligations -- `options_mut`, `payload_mut` and the payload copy -- are *not*
    // discharged: they need `self.header_len()` and `self.payload.len()`, and `TcpRepr` carries
    // no refinement, so neither is statable at this type. They are left owing, not hidden.
    //
    // `packet` is `&strg`, not `&mut Packet<T>[@p]`. An indexed `&mut` pins every field of the
    // index, `hlen` included, so no setter that moves the ghost can be called through it --
    // `set_header_len` failed with `type invariant may not hold (when place is folded)`, and it
    // failed the same way for a literal argument, so it was never about the value. A `&strg`
    // place carries the new index out instead. This is a flux-only change: the Rust signature
    // is still `&mut Packet<T>`. Same move as `ipv4::Repr::emit`.
    #[flux_rs::trusted(no, reason = "panic site: the header setters and the payload copy")]
    #[flux_rs::sig(
        fn(&Self[@r], packet: &strg Packet<T>[@p], &IpAddress, &IpAddress, &ChecksumCapabilities)
        requires hdr_len(r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c) + r.plen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
              && hdr_len(r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c) + r.plen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
        ensures packet: Packet<T>{q: q.buffer == p.buffer}
    )]
    pub fn emit<T>(
        &self,
        packet: &mut Packet<T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        checksum_caps: &ChecksumCapabilities,
    ) where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_ack_number(self.ack_number.unwrap_or(SeqNumber(0)));
        packet.set_window_len(self.window_len);
        // Each option-bearing field is read once, here, into a value flux can name. Reading
        // `self.max_seg_size` again below would give a second, unrelated value: the length
        // computed from the first would then say nothing about the branch taken by the second,
        // and every option write would be unbounded. `header_len_of` and the block below share
        // these five locals for exactly that reason.
        let mss = self.max_seg_size;
        let ws = self.window_scale;
        let ts = self.timestamp;
        let sack_permitted = self.sack_permitted;
        let sack_ranges = self.sack_ranges;
        let header_len = header_len_of(&mss, &ws, sack_permitted, &ts, &sack_ranges);
        packet.set_header_len(header_len as u8);
        packet.clear_flags();
        match self.control {
            Control::None => (),
            Control::Psh => packet.set_psh(true),
            Control::Syn => packet.set_syn(true),
            Control::Fin => packet.set_fin(true),
            Control::Rst => packet.set_rst(true),
        }
        packet.set_ack(self.ack_number.is_some());
        {
            let mut window = packet.options_buf();
            let mut options: &mut [u8] = window.as_mut();
            if let Maybe::Just(value) = mss {
                let tmp = options;
                options = TcpOption::MaxSegmentSize(value).emit(tmp);
            }
            if let Maybe::Just(value) = ws {
                let tmp = options;
                options = TcpOption::WindowScale(value).emit(tmp);
            }
            if sack_permitted {
                let tmp = options;
                options = TcpOption::SackPermitted.emit(tmp);
            } else if self.ack_number.is_some() && sack_ranges.any() {
                let tmp = options;
                options = TcpOption::SackRange(sack_ranges).emit(tmp);
            }
            if let Maybe::Just(timestamp) = ts {
                let tmp = options;
                options = TcpOption::TimeStamp {
                    tsval: timestamp.tsval,
                    tsecr: timestamp.tsecr,
                }
                .emit(tmp);
            }

            if !options.is_empty() {
                TcpOption::EndOfList.emit(options);
            }
        }
        packet.set_urgent_at(0);
        let mut window = packet.payload_buf();
        window.as_mut()[..self.payload.len()].copy_from_slice(self.payload);

        if checksum_caps.tcp.tx() {
            packet.fill_checksum(src_addr, dst_addr)
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }

    /// Return the length of the segment, in terms of sequence space.
    pub const fn segment_len(&self) -> usize {
        self.payload.len() + self.control.len()
    }

    /// Return whether the segment has no flags set (except PSH) and no data.
    pub const fn is_empty(&self) -> bool {
        match self.control {
            _ if !self.payload.is_empty() => false,
            Control::Syn | Control::Fin | Control::Rst => false,
            Control::None | Control::Psh => true,
        }
    }
}

// The buffer arrives with no length index, and `Ref` is where it acquires one; the body is on
// the `Packet<Ref>` impl below.
/// A [`Repr`] paired with the number of octets it emits.
///
/// [`Repr::buffer_len`] is bounded but not exact: the option octets turn on three
/// `Option::is_some` reads and on how many of the three sACK slots are filled, and neither is
/// reachable through the container's refinement. Every field of `Repr` is `pub`, so a ghost
/// accumulator would go stale on the first `repr.max_seg_size = ...` -- which `Socket::dispatch`
/// does. Measuring once, at the point the representation is moved in, makes the total statable
/// with nothing trusted: `blen` is the value [`Repr::buffer_len`] returned for this `repr`, and
/// `repr` is private, so nothing can change it behind the number.
///
/// Same device as `dhcpv4::SizedRepr`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
// 20 is `Repr::buffer_len`'s floor, the fixed part of the TCP header.
#[flux_rs::refined_by(blen: int, plen: int, mss: bool, ws: bool, sp: bool, ts: bool,
                      a: bool, b: bool, c: bool)]
#[flux_rs::invariant(20 <= blen)]
#[flux_rs::invariant(blen == hdr_len(mss, ws, sp, ts, a, b, c) + plen)]
pub(crate) struct SizedRepr<'a> {
    #[flux_rs::field(Repr[plen, mss, ws, sp, ts, a, b, c])]
    repr: Repr<'a>,
    #[flux_rs::field(usize[blen])]
    blen: usize,
}

impl<'a> SizedRepr<'a> {
    /// Measure `repr` and keep the two together.
    ///
    /// The result's `blen` is carried out against the repr's payload length, which is what lets
    /// a caller holding a short payload -- `Socket::reply` builds one with `payload: &[]` --
    /// discharge `IpRepr::new`'s and `set_payload_len`'s `plen <= 65535`.
    #[flux_rs::sig(
        fn(Repr[@r]) -> SizedRepr[hdr_len(r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c) + r.plen,
                                  r.plen, r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c]
    )]
    pub(crate) fn new(repr: Repr<'a>) -> Self {
        let blen = repr.buffer_len();
        Self { repr, blen }
    }

    /// The length of the packet [`Self::emit`] writes.
    #[flux_rs::sig(fn(self: &Self[@r]) -> usize[r.blen])]
    #[flux_rs::no_panic]
    pub(crate) fn buffer_len(&self) -> usize {
        self.blen
    }

    /// The header length, as [`Repr::header_len`] reports it.
    #[flux_rs::sig(fn(&Self[@r]) -> usize{v: v == hdr_len(r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c) && 20 <= v && v <= 68})]
    pub(crate) fn header_len(&self) -> usize {
        self.repr.header_len()
    }

    /// The advertised window.
    #[flux_rs::no_panic]
    pub(crate) fn window_len(&self) -> u16 {
        self.repr.window_len
    }

    /// Set the advertised window.
    ///
    /// `&strg` so the caller keeps `blen`, as for the three setters below. None of these four
    /// fields is part of what [`Repr::buffer_len`] counts, and each postcondition is proved
    /// rather than stated -- the body writes `repr` and leaves the measured length alone.
    #[flux_rs::sig(fn(self: &strg SizedRepr[@r], u16) ensures self: SizedRepr[r.blen, r.plen, r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c])]
    #[flux_rs::no_panic]
    pub(crate) fn set_window_len(&mut self, value: u16) {
        self.repr.window_len = value;
    }

    /// Set the control flag.
    #[flux_rs::sig(fn(self: &strg SizedRepr[@r], Control) ensures self: SizedRepr[r.blen, r.plen, r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c])]
    #[flux_rs::no_panic]
    pub(crate) fn set_control(&mut self, value: Control) {
        self.repr.control = value;
    }

    /// Set the sequence number.
    #[flux_rs::sig(fn(self: &strg SizedRepr[@r], SeqNumber) ensures self: SizedRepr[r.blen, r.plen, r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c])]
    #[flux_rs::no_panic]
    pub(crate) fn set_seq_number(&mut self, value: SeqNumber) {
        self.repr.seq_number = value;
    }

    /// Set the acknowledgement number.
    ///
    /// The sACK option is the one whose presence turns on `ack_number`, and
    /// [`Repr::header_len`] counts it either way, so this does not move the length.
    #[flux_rs::sig(
        fn(self: &strg SizedRepr[@r], Option<SeqNumber>) ensures self: SizedRepr[r.blen, r.plen, r.mss, r.ws, r.sp, r.ts, r.a, r.b, r.c]
    )]
    #[flux_rs::no_panic]
    pub(crate) fn set_ack_number(&mut self, value: Option<SeqNumber>) {
        self.repr.ack_number = value;
    }

    /// The representation that was measured.
    ///
    /// The payload length comes back out with it: `ack_reply` unwraps, sets the sACK slots and
    /// re-measures, and without this the re-measured `buffer_len` would have no ceiling again.
    #[flux_rs::sig(fn(SizedRepr[@s]) -> Repr[s.plen, s.mss, s.ws, s.sp, s.ts, s.a, s.b, s.c])]
    pub(crate) fn into_repr(self) -> Repr<'a> {
        self.repr
    }

    /// Emit the representation into `packet`, exactly as [`Repr::emit`] would.
    #[flux_rs::sig(
        fn(&Self[@s], packet: &strg Packet<T>[@p], &IpAddress, &IpAddress, &ChecksumCapabilities)
        requires s.blen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
              && s.blen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
        ensures packet: Packet<T>{q: q.buffer == p.buffer}
    )]
    pub(crate) fn emit<T>(
        &self,
        packet: &mut Packet<T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        checksum_caps: &ChecksumCapabilities,
    ) where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        self.repr.emit(packet, src_addr, dst_addr, checksum_caps)
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&Packet::new_unchecked(Ref::new(self.buffer.as_ref())), f)
    }
}

// A trait impl's signature is fixed, so this cannot carry the accessors' `requires`. The check
// is taken inside the body instead: `checked_len`'s `Ok` arm proves every bound the header
// reads and the two windows want, and the arm that fails it reads no header at all, which is
// what makes a truncated segment safe to print.
impl fmt::Display for Packet<Ref<'_>> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Cannot use Repr::parse because we don't have the IP addresses.
        if let Err(err) = self.checked_len() {
            return write!(f, "TCP ({err})");
        }
        write!(f, "TCP src={} dst={}", self.src_port(), self.dst_port())?;
        if self.syn() {
            write!(f, " syn")?
        }
        if self.fin() {
            write!(f, " fin")?
        }
        if self.rst() {
            write!(f, " rst")?
        }
        if self.psh() {
            write!(f, " psh")?
        }
        if self.ece() {
            write!(f, " ece")?
        }
        if self.cwr() {
            write!(f, " cwr")?
        }
        if self.ns() {
            write!(f, " ns")?
        }
        write!(f, " seq={}", self.seq_number())?;
        if self.ack() {
            write!(f, " ack={}", self.ack_number())?;
        }
        write!(f, " win={}", self.window_len())?;
        if self.urg() {
            write!(f, " urg={}", self.urgent_at())?;
        }
        write!(f, " len={}", self.payload().len())?;

        let mut options = self.options();
        while !options.is_empty() {
            let (next_options, option) = match TcpOption::parse(options) {
                Ok(res) => res,
                Err(err) => return write!(f, " ({err})"),
            };
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) => write!(f, " mss={value}")?,
                TcpOption::WindowScale(value) => write!(f, " ws={value}")?,
                TcpOption::SackPermitted => write!(f, " sACK")?,
                TcpOption::SackRange(slice) => write!(f, " sACKr{slice:?}")?, // debug print conveniently includes the []s
                TcpOption::TimeStamp { tsval, tsecr } => {
                    write!(f, " tsval {tsval:08x} tsecr {tsecr:08x}")?
                }
                TcpOption::Unknown { kind, .. } => write!(f, " opt({kind})")?,
            }
            options = next_options;
        }
        Ok(())
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TCP src={} dst={}", self.src_port, self.dst_port)?;
        match self.control {
            Control::Syn => write!(f, " syn")?,
            Control::Fin => write!(f, " fin")?,
            Control::Rst => write!(f, " rst")?,
            Control::Psh => write!(f, " psh")?,
            Control::None => (),
        }
        write!(f, " seq={}", self.seq_number)?;
        if let Some(ack_number) = self.ack_number {
            write!(f, " ack={ack_number}")?;
        }
        write!(f, " win={}", self.window_len)?;
        write!(f, " len={}", self.payload.len())?;
        if let Maybe::Just(max_seg_size) = self.max_seg_size {
            write!(f, " mss={max_seg_size}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Repr<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "TCP src={} dst={}", self.src_port, self.dst_port);
        match self.control {
            Control::Syn => defmt::write!(fmt, " syn"),
            Control::Fin => defmt::write!(fmt, " fin"),
            Control::Rst => defmt::write!(fmt, " rst"),
            Control::Psh => defmt::write!(fmt, " psh"),
            Control::None => (),
        }
        defmt::write!(fmt, " seq={}", self.seq_number);
        if let Some(ack_number) = self.ack_number {
            defmt::write!(fmt, " ack={}", ack_number);
        }
        defmt::write!(fmt, " win={}", self.window_len);
        defmt::write!(fmt, " len={}", self.payload.len());
        if let Maybe::Just(max_seg_size) = self.max_seg_size {
            defmt::write!(fmt, " mss={}", max_seg_size);
        }
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        // `Ref::new` off the `dyn`'s own `as_ref`: the trait signature is fixed, so the buffer
        // arrives with no length index, and `Ref` is where it acquires one.
        match Packet::new_checked_ref(Ref::new(buffer.as_ref())) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(packet) => write!(f, "{indent}{packet}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::Ipv4Address;

    #[cfg(feature = "proto-ipv4")]
    const SRC_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    #[cfg(feature = "proto-ipv4")]
    const DST_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    #[cfg(feature = "proto-ipv4")]
    static PACKET_BYTES: [u8; 28] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x60, 0x35, 0x01,
        0x23, 0x01, 0xb6, 0x02, 0x01, 0x03, 0x03, 0x0c, 0x01, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[cfg(feature = "proto-ipv4")]
    static OPTION_BYTES: [u8; 4] = [0x03, 0x03, 0x0c, 0x01];

    #[cfg(feature = "proto-ipv4")]
    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn ghost_field_is_not_observable() {
        let bytes = [0u8; 24];
        let packet = Packet::new_unchecked(&bytes[..]);
        let s = format!("{packet:?}");
        assert!(!s.contains("Ghost"), "ghost leaked into Debug: {s}");
        assert!(s.starts_with("Packet { buffer: "), "Debug shape changed: {s}");
    }

    #[test]
    fn test_flag_writes_preserve_header_len() {
        // `header_len`'s claim about the ghost is only kept true because every other writer of
        // the u16 at offset 12 leaves the top nibble alone. This is that claim, tested.
        let mut bytes = vec![0; 24];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(24);

        packet.clear_flags();
        assert_eq!(packet.header_len(), 24, "clear_flags");

        macro_rules! check {
            ($($setter:ident),*) => {$(
                packet.$setter(true);
                assert_eq!(packet.header_len(), 24, concat!(stringify!($setter), "(true)"));
                packet.$setter(false);
                assert_eq!(packet.header_len(), 24, concat!(stringify!($setter), "(false)"));
            )*};
        }
        check!(set_fin, set_syn, set_rst, set_psh, set_ack, set_urg, set_ece, set_cwr, set_ns);
    }

    #[test]
    fn test_set_header_len_truncates() {
        // The field is a four-bit word count, so `set_header_len` stores `value / 4`. The ghost
        // is written to match what reads back, which is why its `ensures` says `(value / 4) * 4`
        // and not `value`.
        let mut bytes = vec![0; 24];
        let mut packet = Packet::new_unchecked(&mut bytes);
        for value in 0u8..=60 {
            packet.set_header_len(value);
            assert_eq!(packet.header_len(), (value / 4) * 4, "set_header_len({value})");
        }
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(Ref::new(&PACKET_BYTES[..]));
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 80);
        assert_eq!(packet.seq_number(), SeqNumber(0x01234567));
        assert_eq!(packet.ack_number(), SeqNumber(0x89abcdefu32 as i32));
        assert_eq!(packet.header_len(), 24);
        assert!(packet.fin());
        assert!(!packet.syn());
        assert!(packet.rst());
        assert!(!packet.psh());
        assert!(packet.ack());
        assert!(packet.urg());
        assert_eq!(packet.window_len(), 0x0123);
        assert_eq!(packet.urgent_at(), 0x0201);
        assert_eq!(packet.checksum(), 0x01b6);
        assert_eq!(packet.options(), &OPTION_BYTES[..]);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_construct() {
        let mut bytes = vec![0xa5; PACKET_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(48896);
        packet.set_dst_port(80);
        packet.set_seq_number(SeqNumber(0x01234567));
        packet.set_ack_number(SeqNumber(0x89abcdefu32 as i32));
        packet.set_header_len(24);
        packet.clear_flags();
        packet.set_fin(true);
        packet.set_syn(false);
        packet.set_rst(true);
        packet.set_psh(false);
        packet.set_ack(true);
        packet.set_urg(true);
        packet.set_window_len(0x0123);
        packet.set_urgent_at(0x0201);
        packet.set_checksum(0xEEEE);
        packet.options_mut().copy_from_slice(&OPTION_BYTES[..]);
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_truncated() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..23]);
        assert_eq!(packet.check_len(), Err(Error));
    }

    #[test]
    fn test_impossible_len() {
        let mut bytes = vec![0; 20];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(10);
        assert_eq!(packet.check_len(), Err(Error));
    }

    #[cfg(feature = "proto-ipv4")]
    static SYN_PACKET_BYTES: [u8; 24] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x01,
        0x23, 0x7a, 0x8d, 0x00, 0x00, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[cfg(feature = "proto-ipv4")]
    fn packet_repr() -> Repr<'static> {
        Repr {
            src_port: 48896,
            dst_port: 80,
            seq_number: SeqNumber(0x01234567),
            ack_number: None,
            window_len: 0x0123,
            window_scale: Maybe::Nothing,
            control: Control::Syn,
            max_seg_size: Maybe::Nothing,
            sack_permitted: false,
            sack_ranges: SackRanges::none(),
            timestamp: Maybe::Nothing,
            payload: &PAYLOAD_BYTES,
        }
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_parse() {
        let packet = Packet::new_unchecked(&SYN_PACKET_BYTES[..]);
        let repr = Repr::parse(
            &packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(
            &mut packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &SYN_PACKET_BYTES[..]);
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_header_len_multiple_of_4() {
        let mut repr = packet_repr();
        repr.window_scale = Maybe::Just(0); // This TCP Option needs 3 bytes.
        assert_eq!(repr.header_len() % 4, 0); // Should e.g. be 28 instead of 27.
    }

    macro_rules! assert_option_parses {
        ($opt:expr, $data:expr) => {{
            assert_eq!(TcpOption::parse($data), Ok((&[][..], $opt)));
            let buffer = &mut [0; 40][..$opt.buffer_len()];
            assert_eq!($opt.emit(buffer), &mut []);
            assert_eq!(&*buffer, $data);
        }};
    }

    #[test]
    fn test_tcp_options() {
        assert_option_parses!(TcpOption::EndOfList, &[0x00]);
        assert_option_parses!(TcpOption::NoOperation, &[0x01]);
        assert_option_parses!(TcpOption::MaxSegmentSize(1500), &[0x02, 0x04, 0x05, 0xdc]);
        assert_option_parses!(TcpOption::WindowScale(12), &[0x03, 0x03, 0x0c]);
        assert_option_parses!(TcpOption::SackPermitted, &[0x4, 0x02]);
        assert_option_parses!(
            TcpOption::SackRange(SackRanges {
                first: SackBlock::Present(500, 1500),
                second: SackBlock::Absent,
                third: SackBlock::Absent,
            }),
            &[0x05, 0x0a, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x05, 0xdc]
        );
        assert_option_parses!(
            TcpOption::SackRange(SackRanges {
                first: SackBlock::Present(875, 1225),
                second: SackBlock::Present(1500, 2500),
                third: SackBlock::Absent,
            }),
            &[
                0x05, 0x12, 0x00, 0x00, 0x03, 0x6b, 0x00, 0x00, 0x04, 0xc9, 0x00, 0x00, 0x05, 0xdc,
                0x00, 0x00, 0x09, 0xc4
            ]
        );
        assert_option_parses!(
            TcpOption::SackRange(SackRanges {
                first: SackBlock::Present(875000, 1225000),
                second: SackBlock::Present(1500000, 2500000),
                third: SackBlock::Present(876543210, 876654320),
            }),
            &[
                0x05, 0x1a, 0x00, 0x0d, 0x59, 0xf8, 0x00, 0x12, 0xb1, 0x28, 0x00, 0x16, 0xe3, 0x60,
                0x00, 0x26, 0x25, 0xa0, 0x34, 0x3e, 0xfc, 0xea, 0x34, 0x40, 0xae, 0xf0
            ]
        );
        assert_option_parses!(
            TcpOption::TimeStamp {
                tsval: 5000000,
                tsecr: 7000000
            },
            &[
                0x08, // data length
                0x0a, // type
                0x00, 0x4c, 0x4b, 0x40, //tsval
                0x00, 0x6a, 0xcf, 0xc0 //tsecr
            ]
        );
        assert_option_parses!(
            TcpOption::Unknown {
                kind: 12,
                data: &[1, 2, 3][..]
            },
            &[0x0c, 0x05, 0x01, 0x02, 0x03]
        )
    }

    #[test]
    fn test_malformed_tcp_options() {
        assert_eq!(TcpOption::parse(&[]), Err(Error));
        assert_eq!(TcpOption::parse(&[0xc]), Err(Error));
        assert_eq!(TcpOption::parse(&[0xc, 0x05, 0x01, 0x02]), Err(Error));
        assert_eq!(TcpOption::parse(&[0xc, 0x01]), Err(Error));
        assert_eq!(TcpOption::parse(&[0x2, 0x02]), Err(Error));
        assert_eq!(TcpOption::parse(&[0x3, 0x02]), Err(Error));
    }
}

impl<'a> Packet<Ref<'a>> {
    /// [`new_checked`](Self::new_checked) over a [`Ref`], carrying its proof out.
    ///
    /// The generic `new_checked` cannot say this: at a reference or `dyn` self type the
    /// `as_ref_reft` in the postcondition is unstatable. Over `Ref` the buffer's length is
    /// `b.len`, and the three facts `checked_len` already proves are exactly what
    /// [`options`](Self::options), [`payload`](Self::payload) and [`Repr::parse_ref`] require.
    #[flux_rs::trusted(no, reason = "carries `checked_len`'s proof out through the `Ok` arm")]
    #[flux_rs::sig(
        fn(Ref[@b]) -> Result<Packet<Ref>{p: p.buffer == b && 20 <= p.hlen && p.hlen <= b.len}>
    )]
    pub fn new_checked_ref(buffer: Ref<'a>) -> Result<Packet<Ref<'a>>> {
        let packet = Packet::new_unchecked(buffer);
        packet.checked_len()?;
        Ok(packet)
    }

    /// Return a pointer to the options.
    ///
    /// The `Packet<&'a T>` twin of this cannot be proved: a reference in type-parameter position
    /// has the unit sort, so neither end of the window is statable there -- not even with the
    /// ghost, because `hlen <= buffer_len` names a length the self type does not have. Over
    /// `Ref<'a>` the buffer's length is `p.buffer.len`, the far end is the ghost, and the
    /// options' length survives into the caller's index.
    #[flux_rs::trusted(no, reason = "panic site: opens the window named by the header-length field")]
    #[flux_rs::sig(
        fn(&Packet<Ref>[@p]) -> &[u8][p.hlen - 20]
        requires 20 <= p.hlen && p.hlen <= p.buffer.len
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        // 20 is `field::URGENT.end`, the start of `field::OPTIONS`; flux cannot see through a
        // `Range` const.
        self.buffer.window(20, self.header_len() as usize)
    }

    /// Return a pointer to the payload.
    ///
    /// See [`options`](Self::options) for why the `Packet<&'a T>` twin cannot be proved.
    #[flux_rs::trusted(no, reason = "panic site: opens the window past the header")]
    #[flux_rs::sig(
        fn(&Packet<Ref>[@p]) -> &[u8][p.buffer.len - p.hlen]
        requires 14 <= p.buffer.len && p.hlen <= p.buffer.len
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let len = self.buffer.as_ref().len();
        self.buffer.window(self.header_len() as usize, len)
    }
}
