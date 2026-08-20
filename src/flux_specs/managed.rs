//! `managed::ManagedSlice` length.
//!
//! The load-bearing claim is on `Deref`: dereferencing preserves the length. The `Vec` and
//! `ManagedSlice` refinements exist to give that length something to name.

use flux_rs::*;

/// `Vec`'s sort is opaque here, so `ManagedSlice::Owned` has no length to name without this.
#[cfg(feature = "alloc")]
#[extern_spec]
#[refined_by(len: int)]
#[invariant(0 <= len)]
struct Vec<T, A: core::alloc::Allocator = alloc::alloc::Global>;

#[cfg(feature = "alloc")]
#[extern_spec(managed)]
#[refined_by(len: int)]
#[invariant(len >= 0)]
enum ManagedSlice<'a, T> {
    #[variant((&mut [T][@n]) -> ManagedSlice<T>[n])]
    Borrowed(&'a mut [T]),
    #[variant((alloc::vec::Vec<T>[@n]) -> ManagedSlice<T>[n])]
    Owned(alloc::vec::Vec<T>),
}

/// No-`alloc` configuration: `Borrowed` is the only variant that exists.
#[cfg(not(feature = "alloc"))]
#[extern_spec(managed)]
#[refined_by(len: int)]
#[invariant(len >= 0)]
enum ManagedSlice<'a, T> {
    #[variant((&mut [T][@n]) -> ManagedSlice<T>[n])]
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
