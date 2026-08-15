//! `managed::ManagedSlice` length, and the `alloc::vec::Vec` refinement it needs.
//!
//! Third-party, not `core`, and entirely xarxa's claim. The `Deref`/`DerefMut` *trait*
//! specs these impls hang off are flux-core copies and live in [`super::flux_core`].

use flux_rs::*;

// `Vec`'s sort is opaque here, so `ManagedSlice`'s `Owned(Vec<T>)` variant has no length to
// name. Refine it ourselves; `opaque` because its fields are private.
#[extern_spec]
#[refined_by(len: int)]
#[invariant(0 <= len)]
struct Vec<T, A: core::alloc::Allocator = alloc::alloc::Global>;

#[extern_spec(managed)]
#[refined_by(len: int)]
#[invariant(len >= 0)]
enum ManagedSlice<'a, T> {
    #[variant((&mut [T][@n]) -> ManagedSlice<T>[n])]
    Borrowed(&'a mut [T]),
    // Present because the `alloc` feature is on in this build; the extern spec must list
    // every variant of the real definition or flux rejects it outright.
    #[variant((alloc::vec::Vec<T>[@n]) -> ManagedSlice<T>[n])]
    Owned(alloc::vec::Vec<T>),
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
    #[sig(fn(self: &mut Self[@v]) -> &mut <ManagedSlice<T> as core::ops::Deref>::Target[v])]
    fn deref_mut(&'a mut self) -> &'a mut <ManagedSlice<'a, T> as core::ops::Deref>::Target;
}
