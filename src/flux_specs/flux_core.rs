//! Specs copied verbatim out of flux-core. **Trust boundary: read this file as a
//! transcription check, not as a set of claims.**
//!
//! xarxa cannot depend on flux-core directly -- `cargo-flux` never passes `-L <sysroot>`,
//! so flux_core's own dependency on `flux_attrs` fails to resolve and the crate cannot be
//! injected. The items the wire code needs are therefore mirrored here.
//!
//! Every item below is byte-identical to its flux-core original, doc comments included:
//!
//! | item | flux-core source |
//! | --- | --- |
//! | `Range`, `RangeTo`, `RangeFrom` | `lib/flux-core/src/ops/range.rs` |
//! | `Index` | `lib/flux-core/src/ops/index.rs` |
//! | `Deref`, `DerefMut` | `lib/flux-core/src/ops/deref.rs` |
//! | `SliceIndex` + its four impls, `Index`/`IndexMut` for `[T]` | `lib/flux-core/src/slice/index.rs` |
//! | `<[T]>::len` | `lib/flux-core/src/slice/mod.rs` |
//!
//! Pinned at flux-core `696b795f31`. To re-check the copy, diff each item against that
//! commit; the only permitted deviation is the import (`flux_rs::*` here, `flux_attrs::*`
//! there -- xarxa depends on flux-rs, which re-exports the same macros).
//!
//! Only the items xarxa actually uses are mirrored. **Nothing xarxa asserts on its own
//! behalf belongs in this file** -- that goes in a sibling module, where it gets reviewed
//! as a claim. Delete this file once flux-core can be a dependency.
//!
//! # Soundness of `SliceIndex`-based annotations
//!
//! Carried over from flux-core's own note: several annotations rely on [`SliceIndex`]
//! being a sealed trait. It requires `private_slice_index::Sealed`, which has no public
//! path outside of `core`, so its set of implementations is fixed and exhaustive. The
//! sealed implementations were inspected to ensure these specs are sound.

#[allow(unused_imports)]
use core::ops;

use flux_rs::*;

// --- ops/range.rs ----------------------------------------------------------------------

#[extern_spec(core::ops)]
#[refined_by(start: Idx, end: Idx)]
struct Range<Idx> {
    #[field(Idx[start])]
    start: Idx,
    #[field(Idx[end])]
    end: Idx,
}

#[extern_spec(core::ops)]
#[refined_by(end: Idx)]
struct RangeTo<Idx> {
    #[field(Idx[end])]
    end: Idx,
}

#[extern_spec(core::ops)]
#[refined_by(start: Idx)]
struct RangeFrom<Idx> {
    #[field(Idx[start])]
    start: Idx,
}

// --- ops/index.rs ----------------------------------------------------------------------

#[extern_spec(core::ops)]
trait Index<Idx> {
    #![assoc(fn in_bounds(v: Self, idx: Idx) -> bool { true })]
    #![assoc(fn output_pred(v: Self, idx: Idx, out: Self::Output) -> bool { true })]

    #[sig(fn(self: &Self[@v], index: Idx { <Self as Index<Idx>>::in_bounds(v, index) }) -> &Self::Output{out: <Self as Index<Idx>>::output_pred(v, index, out)})]
    fn index(&self, index: Idx) -> &Self::Output;
}

// --- ops/deref.rs ----------------------------------------------------------------------

#[extern_spec(core::ops)]
#[assoc(fn as_deref(v: Self, target: Self::Target) -> bool { true })]
trait Deref {
    #[sig(fn(self: &Self[@v]) -> &Self::Target{target: Self::as_deref(v, target)})]
    fn deref(&self) -> &Self::Target;
}

#[extern_spec(core::ops)]
trait DerefMut: Deref {
    #[sig(fn(self: &mut Self[@v]) -> &mut Self::Target{target: Self::as_deref(v, target)})]
    fn deref_mut(&mut self) -> &mut Self::Target;
}

// --- slice/index.rs --------------------------------------------------------------------

////////////////////////////////////////////////////////////////////////////////////////////////
/// Extern Specs for `ops::Index` which delegate to SliceIndex::index //////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

#[extern_spec(core::slice)]
impl<T, I: SliceIndex<[T]>> ops::Index<I> for [T] {
    #![assoc(
        fn in_bounds(len: int, idx: I) -> bool {
            <I as SliceIndex<[T]>>::in_bounds(idx, len)
        }
        fn output_pred(len: int, idx: I, out: <I as SliceIndex<[T]>>::Output) -> bool {
            <I as SliceIndex<[T]>>::output_pred(idx, len, out)
        }
    )]
    /// Delegates to `SliceIndex::index`, documented as panicking iff out of
    /// bounds, so `#[no_panic]` is sound under the `in_bounds` precondition.
    /// Core impl: https://github.com/rust-lang/rust/blob/c6a955468b025dbe3d1de3e8f3e30496d1fb7f40/library/core/src/slice/index.rs#L15
    #[no_panic]
    #[sig(fn(&Self[@len], {I[@idx] | <Self as ops::Index<I>>::in_bounds(len, idx)}) -> &I::Output{out: <I as SliceIndex<[T]>>::output_pred(idx, len, out)})]
    fn index(&self, index: I) -> &I::Output;
}

/// Extern Specs for `ops::IndexMut` which delegate to SliceIndex::index

#[extern_spec(core::slice)]
impl<T, I: SliceIndex<[T]>> ops::IndexMut<I> for [T] {
    /// See `index`. Core impl: https://github.com/rust-lang/rust/blob/c6a955468b025dbe3d1de3e8f3e30496d1fb7f40/library/core/src/slice/index.rs#L26
    #[no_panic]
    #[sig(fn(&mut Self[@len], {I[@idx] | <Self as ops::Index<I>>::in_bounds(len, idx)}) -> &mut I::Output{out: <I as SliceIndex<[T]>>::output_pred(idx, len, out)})]
    fn index_mut(&mut self, index: I) -> &mut I::Output;
}

////////////////////////////////////////////////////////////////////////////////////////////////
/// Extern Specs for SliceIndex::index /////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(idx: Self, v: T) -> bool)]
#[flux::assoc(fn output_pred(idx: Self, v: T, out: Self::Output) -> bool { true })]
trait SliceIndex<T> {}

#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(idx: int, len: int) -> bool { idx < len })]
impl<T> SliceIndex<[T]> for usize {}

#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { r.start <= r.end && r.end <= len })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == r.end - r.start })]
impl<T> SliceIndex<[T]> for ops::Range<usize> {}

#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { r.end <= len })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == r.end })]
impl<T> SliceIndex<[T]> for ops::RangeTo<usize> {}

#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { r.start <= len })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == len - r.start })]
impl<T> SliceIndex<[T]> for ops::RangeFrom<usize> {}

// --- slice/mod.rs ----------------------------------------------------------------------
//
// `<[T]>::len` is a flux-core copy but does NOT live here. Flux permits only one extern
// spec per impl (`E0999: multiple extern specs for core::slice::<impl [T]>::T`), and
// xarxa also refines `copy_from_slice` on that same inherent impl, so the two must share
// a single block. It sits in `super::slice` with its provenance marked inline.
//
// The split errs toward the reviewed file rather than the trusted one: an item outside
// this file is over-reviewed at worst, whereas an item wrongly inside it is under-reviewed.
