//! `core::slice` specs xarxa states on its own behalf, plus `len` -- see below.

#[allow(unused_imports)]
use core::ops;

use core::slice::ChunksExact;

use flux_rs::*;

/// Flux allows one extern spec per impl, so the flux-core copy and xarxa's own share this
/// block; provenance is marked per item.
#[extern_spec(core::slice)]
impl<T> [T] {
    /// Verbatim from flux-core `slice/mod.rs` @ 696b795f31. Review as a transcription.
    #[no_panic]
    #[spec(fn(&Self[@n]) -> usize[n])]
    fn len(&self) -> usize;

    /// Verbatim from flux-core `slice/mod.rs` @ 696b795f31. Review as a transcription.
    #[no_panic]
    #[spec(fn(&Self[@n]) -> bool[n == 0])]
    fn is_empty(&self) -> bool;

    /// xarxa's own. Panics iff the lengths differ, which the signature rules out.
    /// <https://doc.rust-lang.org/1.89.0/src/core/slice/mod.rs.html#3805>
    #[no_panic]
    #[spec(fn(self: &mut Self[@n], src: &[T][n]))]
    fn copy_from_slice(&mut self, src: &[T])
    where
        T: Copy;

    /// Panics on a zero chunk size and only then; the remainder is split off arithmetically.
    /// <https://doc.rust-lang.org/1.89.0/src/core/slice/mod.rs.html#1204>
    #[flux_rs::no_panic_if(chunk_size > 0)]
    #[spec(fn(&[T], chunk_size: usize) -> ChunksExact<T>)]
    fn chunks_exact(&self, chunk_size: usize) -> ChunksExact<T>;
}

/// xarxa's own; `&data[..]` needs it. Sound for the same sealed-trait reason as flux-core's
/// four `SliceIndex` impls.
#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { true })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == len })]
impl<T> SliceIndex<[T]> for ops::RangeFull {}
