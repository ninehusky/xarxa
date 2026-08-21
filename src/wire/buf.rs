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
//! * `new(inner)` -- `offset = 0 <= inner.len()`, and `len = inner.len()`.
//! * `with_offset(i, o)` -- `requires o <= n`, and that bound is **discharged at every call
//!   site** the crate has: the three in `dispatch_ip`, which is `trusted(no)` and carries a
//!   local `check_overflow = "strict"` for exactly this reason; `iface/packet.rs`'s
//!   hop-by-hop arm, via the `minlen` floor `IpPayload` carries; `wire/icmpv6.rs`'s
//!   `payload_buf`; and `wire/mld.rs`'s record loop, whose offsets are written in closed form
//!   so they relate to `Repr`'s `8 + 20 * k` index. A further site in `dispatch_ipv4_frag` is
//!   `cfg`'d out of the firmware config and will hit the identical
//!   `tx_len = ip_len + eth_len` wall when it is not.
//! * `reborrow(&mut self)` -- copies both fields verbatim, so it preserves whatever held before.
//!
//! Each establishes the stronger equality `inner.len() - offset == len`. Exactly one method
//! mutates `offset` and none replaces `inner`: `copy_at` only writes bytes, and `as_mut` hands
//! out a `&mut [u8]` *into* the tail, through which neither the field nor the slice's length is
//! reachable, so no path can shrink `inner`. `advance(n)` does grow `offset`, and preserves the
//! invariant: its `n <= len` precondition, checked at every call site, gives
//! `n <= inner.len() - offset`, hence `offset + n <= inner.len()`. It also preserves the
//! equality, since it decreases `len` by exactly what it adds to `offset`. So the invariant is
//! stable across every operation.
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

    /// Advance past `n` octets, which the caller has finished with.
    ///
    /// Trusted for the same reason as the constructors: `offset` is private to an `opaque`
    /// struct, so the update cannot be expressed as a field index. `n <= len` is what keeps
    /// `offset <= inner.len()` -- see the closed-module invariant in the module docs.
    #[flux_rs::trusted(yes, reason = "opaque: `offset + n <= inner.len()` follows from `n <= len`")]
    #[flux_rs::sig(fn(self: &mut Self[@len], n: usize{n <= len}) ensures self: Buf[len - n])]
    #[flux_rs::no_panic]
    pub fn advance(&mut self, n: usize) {
        self.offset += n;
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
// through a function whose body is unchecked under `default_trusted = true`, or through a
// bound flux cannot state at all. The bound is then asserted by nobody, and making these
// unchecked would trade a panic for UB.
//
// The blocker list below was re-measured against the *firmware* feature set
// (`medium-ethernet,socket-udp,socket-tcp,socket-dhcpv4,proto-ipv4,proto-ipv6`), which is what
// the nRF52840 `usb_ethernet` binary actually contains. The previously named sixlowpan blocker
// is compiled out there, but two other unchecked callers take its place, so nothing was freed.
//
//   write_octets16_at  `Ipv6Repr::emit` (ipv6.rs:708) requires `40 <= len`. Under the firmware
//   write_u24_at       config its unchecked callers are `Icmpv6Repr::emit`'s inner
//   write_u16_at       `emit_contained_packet` (icmpv6.rs:811) and `NdiscOption Repr::emit`
//                      (ndiscoption.rs:573) -- both hand it a `payload_mut()` of unbounded
//                      length. Verified by control: strengthening `Ipv6Repr::emit`'s `requires`
//                      with an absurd conjunct produced exactly one new error, at
//                      `IpRepr::emit` (ip.rs:892), and none at either of those two, i.e. they
//                      carry nothing. `write_u16_at` reaches the same chain through
//                      `Ipv6Packet::set_payload_len`.
//   write_u24_at       additionally: byteorder's `write_uint` asserts `pack_size(n) <= 3`, a
//                      *value* bound. Adding `value < 16777216` here was tried; flux cannot
//                      discharge it at `Ipv6Packet::set_flow_label` (ipv6.rs:549), whose `raw`
//                      is `((data[1] & 0xf0) as u32) << 16 | (value & 0x0fffff)` -- true, but it
//                      needs bitvector reasoning flux does not do here.
//   write_u16_at       additionally, on the v4 side: `Ipv4Packet::fill_checksum` (ipv4.rs:674)
//                      calls `set_checksum` from a body that cannot be proved at all (see the
//                      note on that function), and `socket/raw.rs:412` calls it from inside a
//                      `dequeue_with` closure, which flux does not check either.
//   read_u16_at        NOT an annotation gap -- a flux limitation. `Ipv4Packet::total_len`
//                      (ipv4.rs:317) requires `4 <= as_ref_reft(buf.buffer)`, but three of its
//                      callers -- `Packet::payload`, `Ipv4Repr::parse` and the `Display` impl --
//                      are all over `Packet<&T>` with `T: ?Sized`. Giving each `trusted(no)`
//                      was tried: the bodies are checked and every one fails with
//                      `associated refinement 'as_ref_reft' is missing from implementation`,
//                      because core's blanket `AsRef for &T` has no associated refinement (the
//                      same unit-sort problem this module's header describes). Writing the
//                      `requires` explicitly fails earlier still, with
//                      `mismatched sorts: expected 'T::sort', found '()'`. `Display::fmt` could
//                      not carry it in any case -- a trait impl's signature is fixed, so no
//                      consumer owes it anything. `Packet::payload_mut` is separately
//                      unprovable: its `header_len()..total_len()` range is a property of
//                      buffer *contents*.
//
// The first three become convertible only once the icmpv6/ndiscoption emit bodies are checked
// (they belong to another agent's file) *and* the v4-side items above are resolved.
// `read_u16_at` is not convertible until flux can refine a reference self type.

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

/// Read a big-endian `i32` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[u8][@n], at: usize) -> i32 requires at + 4 <= n)]
#[flux_rs::no_panic]
pub fn read_i32_at(data: &[u8], at: usize) -> i32 {
    NetworkEndian::read_i32(&data[at..at + 4])
}

/// Write a big-endian `i32` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [u8][@n], at: usize, value: i32) requires at + 4 <= n)]
#[flux_rs::no_panic]
pub fn write_i32_at(data: &mut [u8], at: usize, value: i32) {
    NetworkEndian::write_i32(&mut data[at..at + 4], value)
}

/// Read a big-endian `u32` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[u8][@n], at: usize) -> u32 requires at + 4 <= n)]
#[flux_rs::no_panic]
pub fn read_u32_at(data: &[u8], at: usize) -> u32 {
    NetworkEndian::read_u32(&data[at..at + 4])
}

/// Write a big-endian `u32` at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [u8][@n], at: usize, value: u32) requires at + 4 <= n)]
#[flux_rs::no_panic]
pub fn write_u32_at(data: &mut [u8], at: usize, value: u32) {
    NetworkEndian::write_u32(&mut data[at..at + 4], value)
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

/// Borrow `n` octets of `data` starting at `at`. See [`read_u16_at`] for why this is trusted.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[u8][@len], at: usize, n: usize) -> &[u8][n] requires at + n <= len)]
#[flux_rs::no_panic]
pub fn sub(data: &[u8], at: usize, n: usize) -> &[u8] {
    &data[at..at + n]
}

/// Borrow the tail of `data` from `at`.
///
/// Unlike [`prefix`] and [`sub`] the result is deliberately left *un*indexed, and this function
/// is therefore checked rather than trusted. `dhcpv4::Packet::options` walks a cursor down by
/// reassigning it to successive tails; a slot whose type carries a fixed length index cannot be
/// reassigned to a shorter one ("assignment might be unsafe"), least of all a closure upvar,
/// whose type is fixed at capture. That walk re-derives every bound it needs from `len()` within
/// a single step, so the exact residual length is not wanted here -- only the guarantee that
/// `at` is a legal split point.
#[flux_rs::sig(fn(&[u8][@len], at: usize) -> &[u8] requires at <= len)]
#[flux_rs::no_panic]
pub fn tail(data: &[u8], at: usize) -> &[u8] {
    &data[at..]
}

/// Copy `src` into the `len`-octet window of `data` at `at`. See [`read_u16_at`] for why the
/// bound is trusted.
///
/// `copy_from_slice`'s own length assert is deliberately retained -- writing the window as
/// `data[at..at + len]` rather than `data[at..at + src.len()]` is what keeps it comparing two
/// different quantities. `src: &[u8][len]` is stated *alongside* that check, not instead of it,
/// so a checked caller proves the assert cannot fire while an unchecked one still gets the
/// panic rather than a silently shorter or longer write. Hence no `no_panic` here.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [u8][@n], at: usize, len: usize, src: &[u8][len]) requires at + len <= n)]
pub fn copy_window_at(data: &mut [u8], at: usize, len: usize, src: &[u8]) {
    data[at..at + len].copy_from_slice(src)
}

/// A shared byte-slice window whose length lives in the refinement.
///
/// The read-side twin of [`Buf`]. Its only job is to be a **non-reference** type: a reference in
/// type-parameter position gets the unit sort, so `Packet<&'a [u8]>` cannot state a bound on its
/// buffer, while `Packet<Ref<'a>>` can. Unlike `Buf` this carries no offset, so the field is
/// refined directly and nothing here is trusted or unsafe.
#[flux_rs::refined_by(len: int)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ref<'a> {
    #[flux_rs::field(&[u8][len])]
    inner: &'a [u8],
}

impl<'a> Ref<'a> {
    #[flux_rs::sig(fn(&[u8][@n]) -> Ref[n])]
    #[flux_rs::no_panic]
    pub fn new(inner: &'a [u8]) -> Ref<'a> {
        Ref { inner }
    }

    /// The window `start..end`, with the buffer's lifetime rather than `&self`'s.
    ///
    /// This is the whole point of the type: a shared reference keeps its index across a return
    /// (flux-rs/flux#1714 is about `&mut`), so the window's length survives to the caller.
    #[flux_rs::sig(
        fn(Ref[@r], start: usize, end: usize{start <= end && end <= r.len}) -> &[u8][end - start]
    )]
    #[flux_rs::no_panic]
    pub fn window(self, start: usize, end: usize) -> &'a [u8] {
        &self.inner[start..end]
    }
}

#[flux_rs::assoc(
    fn as_ref_reft(source: Self) -> int {
        source.len
    }
)]
impl AsRef<[u8]> for Ref<'_> {
    #[flux_rs::sig(fn(self: &Self[@source]) -> &[u8][Self::as_ref_reft(source)])]
    #[flux_rs::no_panic]
    fn as_ref(&self) -> &[u8] {
        self.inner
    }
}
