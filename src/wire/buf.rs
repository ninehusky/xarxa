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
    fn as_ref(&self) -> &[u8] {
        &self.inner[self.offset..]
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
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner[self.offset..]
    }
}

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
pub fn write_octets4_at(data: &mut [u8], at: usize, octets: &[u8; 4]) {
    data[at..at + 4].copy_from_slice(octets)
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
