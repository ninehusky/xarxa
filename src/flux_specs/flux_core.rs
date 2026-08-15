//! Spec source copied verbatim from flux-core `696b795f31`, which xarxa cannot depend on
//! (`cargo-flux` never passes `-L <sysroot>`, so flux_core's own `flux_attrs` dependency
//! fails to resolve). `extern_spec` registers with flux wherever it appears, so pasting
//! the source in is all that is needed -- these are live, not reference material.
//!
//! Review this file by diffing it, not by reading it. Every item is byte-identical to its
//! original in `lib/flux-core/src/{ops/range.rs, ops/index.rs, ops/deref.rs,
//! slice/index.rs}`; the only permitted deviation is `flux_rs::*` for `flux_attrs::*`.
//! Anything xarxa claims on its own behalf belongs in a sibling module, not here.
//!
//! flux-core's own soundness note, carried over: the `SliceIndex` annotations rely on it
//! being a sealed trait, so its set of impls is fixed and exhaustive.

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

// `<[T]>::len` is also a flux-core copy, but flux allows only one extern spec per impl and
// xarxa refines `copy_from_slice` on the same one. Both are in `super::slice`.
