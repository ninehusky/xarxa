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
#[invariant(len >= 0 && len <= 9223372036854775807)]
enum ManagedSlice<'a, T> {
    #[variant(({&mut [T][@n] | n <= 9223372036854775807}) -> ManagedSlice<T>[n])]
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
