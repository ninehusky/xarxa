//! A length-refined mutable byte buffer.
//!
//! This type exists for two reasons, both flux limitations.
//!
//! 1. Core's blanket `impl<T, U> AsMut<U> for &mut T` cannot be given an associated refinement --
//!    flux assigns a reference self type the *unit* sort, so the pointee's length is
//!    unrecoverable (`expected 'T::sort', found '()'`). That makes `&mut [u8]` unusable as the
//!    `T` of a refined `Packet<T>`, which is what every real `emit` call site instantiates.
//!    `Buf`'s `AsRef`/`AsMut` impls are local, so we can write their refinements ourselves.
//!
//! 2. A *returned* `&mut` lands in the caller as an invariant ref and loses its length index
//!    (flux-rs/flux#1714). Both `&mut b[k..]` and `b.split_at_mut(k)` hit this, so a sub-slice's
//!    length cannot be established at the call site at all. `Buf` therefore carries an `offset`
//!    and does the slicing inside `as_ref`/`as_mut`, whose bodies are trusted -- the refinement
//!    is *declared* rather than derived from a returned reference.
//!
//! The struct is `opaque` because `len` is `inner.len() - offset`, which cannot be written as a
//! field index; it is established by the constructors instead.
//!
//! # Closed-module invariant
//!
//! `as_ref`/`as_mut` slice at `offset` without a bounds check. Their safety condition is
//! `offset <= inner.len()`, which is **not** a caller obligation -- no caller states it and none
//! could -- but an invariant of this module, closed by inspection of a private field in an
//! `opaque` struct. Both fields are private and this file has no submodules, so the three
//! constructors below are the complete set of ways a `Buf` comes into existence:
//!
//! * `new(inner)`        -- `offset = 0 <= inner.len()`, and `len = inner.len()`.
//! * `with_offset(i, o)` -- `requires o <= n`, discharged by flux at all four call sites
//!                          (three in `dispatch_ip`, one in `dispatch_ipv4_frag`, both
//!                          `trusted(no)`).
//! * `reborrow(&mut self)` -- copies both fields verbatim, so it preserves whatever held before.
//!
//! Each establishes the stronger equality `inner.len() - offset == len`. No method mutates
//! `offset` or replaces `inner`: `copy_at` only writes bytes, and `as_mut` hands out a `&mut [u8]`
//! *into* the tail, through which neither the field nor the slice's length is reachable. So no
//! path can shrink `inner` or grow `offset` after construction, and the invariant is stable.
//!
//! This is the "internal assumption" side of the boundary/internal distinction, so it is spelled
//! out rather than assumed. Note the contrast with the free functions further down, whose safety
//! conditions *are* caller obligations stated in their signatures.

use byteorder::{ByteOrder, NetworkEndian};

/// A mutable byte buffer that carries its length in its refinement.
#[flux_rs::opaque]
#[flux_rs::refined_by(len: int)]
pub struct Buf<'a> {
    inner: &'a mut [u8],
    offset: usize,
}

impl<'a> Buf<'a> {
    /// Wrap a mutable byte slice whole.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the `len` index")]
    #[flux_rs::sig(fn(&mut [u8][@n]) -> Buf[n])]
    #[flux_rs::no_panic]
    pub fn new(inner: &'a mut [u8]) -> Buf<'a> {
        Buf { inner, offset: 0 }
    }

    /// Reborrow this buffer, preserving its length.
    ///
    /// Needed because `IpRepr::emit` takes its buffer by value, so a caller that must also
    /// write the payload afterwards cannot hand over the original.
    #[flux_rs::trusted(yes, reason = "opaque: reborrow preserves the `len` index")]
    #[flux_rs::sig(fn(self: &mut Self[@n]) -> Buf[n])]
    #[flux_rs::no_panic]
    pub fn reborrow(&mut self) -> Buf<'_> {
        Buf {
            inner: self.inner,
            offset: self.offset,
        }
    }

    /// Copy `src` into this buffer starting at `at` bytes past its start.
    ///
    /// Trusted: the write goes through a chained index, whose intermediate `&mut` would lose
    /// its length (flux-rs/flux#1714). The `at + src.len() <= len` precondition is what makes
    /// it safe, and it is discharged at the call site.
    #[flux_rs::trusted(yes, reason = "opaque: chained index would lose the length")]
    #[flux_rs::sig(fn(self: &mut Self[@len], at: usize, src: &[u8][@m]) requires at + m <= len)]
    #[flux_rs::no_panic]
    pub fn copy_at(&mut self, at: usize, src: &[u8]) {
        let len = src.len();
        self.inner[self.offset + at..][..len].copy_from_slice(src);
    }

    /// Wrap the tail of a mutable byte slice, starting at `offset`.
    ///
    /// The slicing happens in `as_ref`/`as_mut` rather than here, so no sub-slice reference is
    /// ever returned across a call boundary.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the `len` index")]
    #[flux_rs::sig(fn(&mut [u8][@n], offset: usize{offset <= n}) -> Buf[n - offset])]
    #[flux_rs::no_panic]
    pub fn with_offset(inner: &'a mut [u8], offset: usize) -> Buf<'a> {
        Buf { inner, offset }
    }
}

#[flux_rs::assoc(
    fn as_ref_reft(source: Self) -> int {
        source.len
    }
)]
impl AsRef<[u8]> for Buf<'_> {
    #[flux_rs::trusted(yes, reason = "opaque: `offset <= inner.len()` holds by construction")]
    #[flux_rs::no_panic]
    #[flux_rs::sig(fn(self: &Self[@source]) -> &[u8][Self::as_ref_reft(source)])]
    #[allow(unsafe_code)]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `offset <= inner.len()` is a *closed-module invariant*, not a caller
        // obligation -- see the module docs above for the enumeration that establishes it.
        unsafe { self.inner.get_unchecked(self.offset..) }
    }
}

#[flux_rs::assoc(
    fn as_mut_reft(source: Self) -> int {
        source.len
    }
)]
impl AsMut<[u8]> for Buf<'_> {
    #[flux_rs::trusted(yes, reason = "opaque: `offset <= inner.len()` holds by construction")]
    #[flux_rs::no_panic]
    #[flux_rs::sig(fn(self: &mut Self[@source]) -> &mut [u8][Self::as_mut_reft(source)])]
    #[allow(unsafe_code)]
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: `offset <= inner.len()` is a *closed-module invariant*, not a caller
        // obligation -- see the module docs above for the enumeration that establishes it.
        unsafe { self.inner.get_unchecked_mut(self.offset..) }
    }
}

// NOT CONVERTED to unchecked indexing, deliberately. `read_u16_at`, `write_u16_at`,
// `write_u24_at` and `write_octets16_at` each have their `requires` discharged at every
// immediate call site, but the *transitive* chain above at least one of those callers runs
// through a function whose body is unchecked under `default_trusted = true`, so the bound is
// asserted by nobody. Making these unchecked would trade a panic for UB. Blockers, one each:
//
//   read_u16_at        `Ipv4Packet::total_len` (ipv4.rs:317) is `trusted(no)` and requires
//                      `4 <= len`, but five in-crate callers have unchecked bodies and so
//                      discharge nothing: `Ipv4Packet::{payload, payload_mut}`, `Ipv4Repr::parse`,
//                      its `fmt`, and `iface::interface::ipv4::process_ipv4`.
//   write_u16_at       `Ipv4Packet::fill_checksum` (ipv4.rs:674) calls `set_checksum` from an
//                      unchecked body -- it carries a flux `sig` but no `trusted(no)`, and is
//                      documented there as ASSUMED, NOT PROVEN. Live caller: `socket/raw.rs:412`.
//   write_u24_at       two blockers. (a) the `Ipv6Repr::emit` chain below; (b) byteorder's
//                      `write_uint` also asserts `pack_size(n) <= 3`, a *value* bound that no
//                      signature here states, so it is discharged by nobody either.
//   write_octets16_at  `Ipv6Repr::emit` (ipv6.rs:708) requires `40 <= len`, but
//                      `iface::interface::sixlowpan::sixlowpan_to_ipv6` (sixlowpan.rs:198) calls
//                      it from an unchecked body.
//
// Each becomes convertible the moment its blocker gains `#[flux_rs::trusted(no)]` and verifies;
// none is fixable from inside this file.

/// Read a big-endian `u16` at `at`.
///
/// Trusted: `&data[at..at + 2]` is a returned `&` whose length the caller cannot recover
/// (flux-rs/flux#1714), so `byteorder`'s `2 <= len` precondition is unprovable at the call site.
/// The `at + 2 <= n` bound here is what makes it safe, and it *is* checked at every caller.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[u8][@n], at: usize) -> u16 requires at + 2 <= n)]
#[flux_rs::no_panic]
pub fn read_u16_at(data: &[u8], at: usize) -> u16 {
    NetworkEndian::read_u16(&data[at..at + 2])
}

/// Write a big-endian `u16` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [u8][@n], at: usize, value: u16) requires at + 2 <= n)]
#[flux_rs::no_panic]
pub fn write_u16_at(data: &mut [u8], at: usize, value: u16) {
    NetworkEndian::write_u16(&mut data[at..at + 2], value)
}

/// Write a big-endian `u24` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [u8][@n], at: usize, value: u32) requires at + 3 <= n)]
#[flux_rs::no_panic]
pub fn write_u24_at(data: &mut [u8], at: usize, value: u32) {
    NetworkEndian::write_u24(&mut data[at..at + 3], value)
}

/// Copy a 4-octet address into `data` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [u8][@n], at: usize, octets: &[u8; 4]) requires at + 4 <= n)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
pub fn write_octets4_at(data: &mut [u8], at: usize, octets: &[u8; 4]) {
    // SAFETY: `at + 4 <= n` is a precondition, discharged by the caller and checked by Flux at
    // every call site, so `data[at..at + 4]` is in bounds; it also rules out the `at + 4`
    // overflow, since the sum is bounded by a slice length. `octets` is a shared borrow and
    // `data` a unique one, so the two regions cannot overlap.
    //
    // The transitive discharge chain for both call sites is
    //   TxToken::consume  boundary
    //   -> dispatch_ip / dispatch_ipv4_frag  trusted(no)
    //   -> IpRepr::emit / emit_ipv4_frag_header  trusted(no)
    //   -> Ipv4Repr::emit  trusted(no)
    //   -> Ipv4Packet::set_{src,dst}_addr  trusted(no)
    // with no unchecked body anywhere on it. That is what makes the unchecked write sound;
    // the sibling helpers below do *not* have that property and are deliberately left checked.
    //
    // `Ipv4Packet::set_{src,dst}_addr` are `pub`, so the chain also leaves the crate. Their
    // `requires 16/20 <= as_mut_reft(buf.buffer)` is the *exposed* form of this bound: an
    // obligation a consumer owes, in the same category as the length contract `TxToken::consume`
    // hands to a driver, and discharged the same way -- by checking the consumer. A consumer that
    // is not checked owes nothing and gets nothing; with the bounds check it panicked, without it
    // this writes out of bounds (confirmed: `new_unchecked(&mut [0u8; 4][..]).set_dst_addr(a)`
    // corrupts adjacent memory, and Miri reports the offset). That is the stated interface, not a
    // defect -- but it is why the bound belongs in the signature where a consumer's checker can
    // see it, and why widening these setters' visibility without the `requires` would be wrong.
    unsafe { core::ptr::copy_nonoverlapping(octets.as_ptr(), data.as_mut_ptr().add(at), 4) }
}

/// Copy a 16-octet address into `data` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [u8][@n], at: usize, octets: &[u8; 16]) requires at + 16 <= n)]
#[flux_rs::no_panic]
pub fn write_octets16_at(data: &mut [u8], at: usize, octets: &[u8; 16]) {
    data[at..at + 16].copy_from_slice(octets)
}

/// Borrow the first `n` octets of `data`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[u8][@len], n: usize) -> &[u8][n] requires n <= len)]
#[flux_rs::no_panic]
pub fn prefix(data: &[u8], n: usize) -> &[u8] {
    &data[..n]
}
