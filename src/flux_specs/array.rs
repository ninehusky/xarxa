//! `core::array` specs, copied verbatim from flux-core `696b795f31`.
//!
//! Review this file by diffing it against `lib/flux-core/src/array/mod.rs`, not by reading
//! it; the only permitted deviation is `flux_rs::*` for `flux_attrs::*`.
//!
//! An array is not a slice: `[T; N]` has the unit sort, so `[T; N]: Index<I>` falls back to
//! the `Index` trait's default `in_bounds`/`output_pred` (both `true`) and an indexed range
//! comes back with no length. These delegate to the slice impl with `N` in place of the
//! length, which is what makes `&a[0..3]` a `&[T][3]`.

#[allow(unused_imports)]
use core::ops::Index;
#[allow(unused_imports)]
use core::ops::IndexMut;

use flux_rs::*;

#[extern_spec(core::array)]
impl<T, I, const N: usize> Index<I> for [T; N]
where
    [T]: Index<I>,
{
    #![assoc(
        fn in_bounds(len: (), idx: I) -> bool {
            <[T] as Index<I>>::in_bounds(N, idx)
        }

        fn output_pred(len: (), idx: I, out: <[T] as Index<I>>::Output) -> bool {
            <[T] as Index<I>>::output_pred(N, idx, out)
        }
    )]

    #[sig(fn(&Self, {I[@idx] | <[T] as Index<I>>::in_bounds(N, idx)}) -> &<[T; N] as Index<I>>::Output{out: <[T] as Index<I>>::output_pred(N, idx, out)})]
    fn index(&self, index: I) -> &<[T; N] as Index<I>>::Output;
}

#[extern_spec(core::array)]
impl<T, I, const N: usize> IndexMut<I> for [T; N]
where
    [T]: IndexMut<I>,
{
    #[sig(fn(&mut Self, {I[@idx] | <[T] as Index<I>>::in_bounds(N, idx)}) -> &mut <[T; N] as Index<I>>::Output{out: <[T] as Index<I>>::output_pred(N, idx, out)})]
    fn index_mut(&mut self, index: I) -> &mut <[T; N] as Index<I>>::Output;
}
