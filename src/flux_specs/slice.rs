//! `core::slice` specs xarxa states on its own behalf.
//!
//! flux-core's `slice/index.rs` copies live in [`super::flux_core`]; only what xarxa adds
//! beyond them is here -- with one exception, `<[T]>::len`, explained on its block below.

#[allow(unused_imports)]
use core::ops;

use flux_rs::*;

/// The two items below must share one block: Flux permits only one extern spec per impl
/// (`E0999: multiple extern specs for core::slice::<impl [T]>::T`), and they are inherent
/// methods on the same `[T]`. Their provenance differs, so it is marked per item.
#[extern_spec(core::slice)]
impl<T> [T] {
    // VERBATIM from flux-core `lib/flux-core/src/slice/mod.rs` @ 696b795f31. Belongs to
    // `super::flux_core` by rights and is here only because of the one-spec-per-impl rule
    // above; review it as a transcription, not as a claim.
    #[no_panic]
    #[spec(fn(&Self[@n]) -> usize[n])]
    fn len(&self) -> usize;

    // xarxa's own. Not in flux-core. Panics iff the lengths differ; equal lengths are
    // encoded in the signature, so `#[no_panic]` is sound.
    #[no_panic]
    #[spec(fn(self: &mut Self[@n], src: &[T][n]))]
    fn copy_from_slice(&mut self, src: &[T])
    where
        T: Copy;
}

// Not in flux-core; `&data[..]` needs it. A full range is always in bounds and yields the whole
// slice.
//
// Sound for the same sealed-trait reason as flux-core's four `SliceIndex` impls: `RangeFull`
// is one of the fixed set of sealed implementors, and `[T]`'s impl of it cannot panic.
#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { true })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == len })]
impl<T> SliceIndex<[T]> for ops::RangeFull {}
