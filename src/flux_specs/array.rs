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

/// xarxa's own, not a flux-core copy. These are the way to get an array's length into the
/// refinement: an implicit array-to-slice coercion gets a fresh, unconstrained length every
/// time it happens, so a bound measured through one coercion says nothing about a slice
/// obtained through another. `as_slice`/`as_mut_slice` name `N`, so a measurement and a use
/// agree. Both are a pointer cast, hence `no_panic`.
/// <https://doc.rust-lang.org/1.89.0/src/core/array/mod.rs.html#640>
#[extern_spec(core::array)]
impl<T, const N: usize> [T; N] {
    #[no_panic]
    #[spec(fn(&Self) -> &[T][N])]
    fn as_slice(&self) -> &[T];

    #[no_panic]
    #[spec(fn(&mut Self) -> &mut [T][N])]
    fn as_mut_slice(&mut self) -> &mut [T];
}
