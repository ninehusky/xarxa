//! `managed::ManagedSlice` length.
//!
//! The load-bearing claim is on `Deref`: dereferencing preserves the length. The `Vec` and
//! `ManagedSlice` refinements exist to give that length something to name.

use flux_rs::*;

/// `Vec`'s sort is opaque here, so `ManagedSlice::Owned` has no length to name without this.
#[cfg(feature = "alloc")]
#[extern_spec]
#[refined_by(len: int)]
#[invariant(0 <= len && len <= 9223372036854775807)]
struct Vec<T, A: core::alloc::Allocator = alloc::alloc::Global>;

#[cfg(feature = "alloc")]
#[extern_spec(managed)]
#[refined_by(len: int)]
// The ceiling is a language guarantee about the backing allocation, not an index: no
// slice or `Vec` exceeds `isize::MAX` bytes, so its length does not either. Without it a sum
// over a length is modelled as wrapping.
//
// OPEN, AND KNOWN TO BE FALSE FOR ONE CASE. The guarantee is about *bytes*, so it does not hold
// for a zero-sized `T`: `[(); usize::MAX]` is a legal array and coerces to a slice of that
// length. `flux_util::byte_len` dodges this by restricting itself to `[u8]`; an extern spec
// cannot, because it must match the item's own generics, and flux has no way to say "`T` is not
// zero-sized".
//
// Nothing in the crate reaches it -- the only generic `ManagedSlice` holder is `RingBuffer`, and
// xarxa instantiates it at `u8` and `PacketMetadata<H>`. But `RingBuffer` is `pub` and generic,
// so a downstream `RingBuffer<'_, ()>` would sit on a false axiom, and a false axiom proves
// anything. A post-monomorphization `const` assert does not close it: it fires on `cargo build`
// of a *reachable* instantiation and not at all under `cargo check`. A sealed `NonZst` bound on
// `T` would, at the cost of a breaking change to a public generic type.
#[invariant(len >= 0 && len <= 9223372036854775807)]
enum ManagedSlice<'a, T> {
    #[variant(({&mut [T][@n] | n <= 9223372036854775807}) -> ManagedSlice<T>[n])]
    Borrowed(&'a mut [T]),
    #[variant((alloc::vec::Vec<T>[@n]) -> ManagedSlice<T>[n])]
    Owned(alloc::vec::Vec<T>),
}

/// No-`alloc` configuration: `Borrowed` is the only variant that exists.
#[cfg(not(feature = "alloc"))]
#[extern_spec(managed)]
#[refined_by(len: int)]
// The ceiling is a language guarantee about the backing allocation, not an index: no
// slice or `Vec` exceeds `isize::MAX` bytes, so its length does not either. Without it a sum
// over a length is modelled as wrapping.
//
// OPEN, AND KNOWN TO BE FALSE FOR ONE CASE. The guarantee is about *bytes*, so it does not hold
// for a zero-sized `T`: `[(); usize::MAX]` is a legal array and coerces to a slice of that
// length. `flux_util::byte_len` dodges this by restricting itself to `[u8]`; an extern spec
// cannot, because it must match the item's own generics, and flux has no way to say "`T` is not
// zero-sized".
//
// Nothing in the crate reaches it -- the only generic `ManagedSlice` holder is `RingBuffer`, and
// xarxa instantiates it at `u8` and `PacketMetadata<H>`. But `RingBuffer` is `pub` and generic,
// so a downstream `RingBuffer<'_, ()>` would sit on a false axiom, and a false axiom proves
// anything. A post-monomorphization `const` assert does not close it: it fires on `cargo build`
// of a *reachable* instantiation and not at all under `cargo check`. A sealed `NonZst` bound on
// `T` would, at the cost of a breaking change to a public generic type.
//
// The block is written twice because the ceiling is the target's `isize::MAX` and `variant` is
// not a standalone attribute -- it exists only inside `extern_spec`'s expansion, so it cannot
// be `cfg_attr`'d. On 32-bit the ceiling is `i32::MAX`, which is the bound `SeqNumber`'s
// arithmetic needs; the host test build is 64-bit and keeps the wider one.
#[cfg(not(target_pointer_width = "32"))]
#[invariant(len >= 0 && len <= 9223372036854775807)]
enum ManagedSlice<'a, T> {
    #[variant(({&mut [T][@n] | n <= 9223372036854775807}) -> ManagedSlice<T>[n])]
    Borrowed(&'a mut [T]),
}

#[cfg(all(not(feature = "alloc"), target_pointer_width = "32"))]
#[extern_spec(managed)]
#[refined_by(len: int)]
#[invariant(len >= 0 && len <= 2147483647)]
enum ManagedSlice<'a, T> {
    #[variant(({&mut [T][@n] | n <= 2147483647}) -> ManagedSlice<T>[n])]
    Borrowed(&'a mut [T]),
}

#[extern_spec(managed)]
#[assoc(fn as_deref(v: Self, target: int) -> bool { v.len == target })]
impl<'a, T> core::ops::Deref for ManagedSlice<'a, T> {
    #[no_panic]
    #[sig(fn(self: &Self[@v]) -> &<ManagedSlice<T> as core::ops::Deref>::Target[v])]
    fn deref(&'a self) -> &'a <ManagedSlice<'a, T> as core::ops::Deref>::Target;
}

#[extern_spec(managed)]
impl<'a, T> core::ops::DerefMut for ManagedSlice<'a, T> {
    #[no_panic]
    #[sig(fn(self: &strg ManagedSlice<T>[@v]) -> &mut <ManagedSlice<T> as core::ops::Deref>::Target[v] ensures self: ManagedSlice<T>[v])]
    fn deref_mut(&'a mut self) -> &'a mut <ManagedSlice<'a, T> as core::ops::Deref>::Target;
}
