// Referenced only from `extern_spec` bodies, which are stripped in non-flux builds.
#[allow(unused_imports)]
use byteorder::{BigEndian, ByteOrder};
#[allow(unused_imports)]
use core::ops;

use flux_rs::*;

#[extern_spec(core::convert)]
#[assoc(fn as_ref_reft(source: Self) -> T)]
trait AsRef<T: ?Sized> {
    #[no_panic]
    #[spec(
        fn(self: &Self[@source])
            -> &T[Self::as_ref_reft(source)]
    )]
    fn as_ref(&self) -> &T;
}

#[extern_spec(core::convert)]
#[assoc(fn as_mut_reft(source: Self) -> T)]
trait AsMut<T: ?Sized> {
    #[no_panic]
    #[spec(
        fn(self: &mut Self[@source])
            -> &mut T[Self::as_mut_reft(source)]
    )]
    fn as_mut(&mut self) -> &mut T;
}

#[extern_spec(core::slice)]
impl<T> [T] {
    #[no_panic]
    #[spec(fn(self: &Self[@n]) -> usize[n])]
    fn len(&self) -> usize;

    // Panics iff the lengths differ; equal lengths are encoded in the signature.
    #[no_panic]
    #[spec(fn(self: &mut Self[@n], src: &[T][n]))]
    fn copy_from_slice(&mut self, src: &[T])
    where
        T: Copy;
}

// ---------------------------------------------------------------------------------------------
// Copied from flux-core (`lib/flux-core/src/ops/{range,index}.rs` and `src/slice/index.rs` at
// 292bdd21). flux-core is not a dependency of xarxa, so `&buf[a..b]` otherwise has an unknown
// length and every `Index`/`IndexMut` call reads as possibly-panicking. Only the items the wire
// code needs are mirrored here; drop this block once flux-core is a dependency.
// ---------------------------------------------------------------------------------------------

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

#[extern_spec(core::ops)]
trait Index<Idx> {
    #![assoc(fn in_bounds(v: Self, idx: Idx) -> bool { true })]
    #![assoc(fn output_pred(v: Self, idx: Idx, out: Self::Output) -> bool { true })]

    #[spec(fn(self: &Self[@v], index: Idx { <Self as Index<Idx>>::in_bounds(v, index) }) -> &Self::Output{out: <Self as Index<Idx>>::output_pred(v, index, out)})]
    fn index(&self, index: Idx) -> &Self::Output;
}

// `SliceIndex` is sealed, so its set of impls is fixed and the refinements below are exhaustive.
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

// Not in flux-core; `&data[..]` needs it. A full range is always in bounds and yields the whole
// slice.
#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { true })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == len })]
impl<T> SliceIndex<[T]> for ops::RangeFull {}

// Both delegate to `SliceIndex`, documented as panicking iff out of bounds, so `#[no_panic]` is
// sound under the `in_bounds` precondition.
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
    #[no_panic]
    #[spec(fn(&Self[@len], {I[@idx] | <Self as ops::Index<I>>::in_bounds(len, idx)}) -> &I::Output{out: <I as SliceIndex<[T]>>::output_pred(idx, len, out)})]
    fn index(&self, index: I) -> &I::Output;
}

#[extern_spec(core::slice)]
impl<T, I: SliceIndex<[T]>> ops::IndexMut<I> for [T] {
    #[no_panic]
    #[spec(fn(&mut Self[@len], {I[@idx] | <Self as ops::Index<I>>::in_bounds(len, idx)}) -> &mut I::Output{out: <I as SliceIndex<[T]>>::output_pred(idx, len, out)})]
    fn index_mut(&mut self, index: I) -> &mut I::Output;
}

// Not in flux-core. Without it `min(a, b)` is unconstrained, so the `..length` slices in
// `udp::Socket::{recv,peek}_slice` cannot be shown in bounds.
#[extern_spec(core::cmp)]
#[no_panic]
#[spec(fn(v1: T[@a], v2: T[@b]) -> T[if a < b { a } else { b }])]
fn min<T: Ord>(v1: T, v2: T) -> T;

// `byteorder` is compiled without flux, so its bodies are invisible (`NoMIRAvailable`) and every
// call reads as possibly-panicking. These read/write exactly 2 bytes and panic only if the slice
// is shorter, which the length bound rules out.
#[extern_spec(byteorder)]
impl ByteOrder for BigEndian {
    #[no_panic]
    #[spec(fn(buf: &[u8]{v: 2 <= v}) -> u16)]
    fn read_u16(buf: &[u8]) -> u16;

    #[no_panic]
    #[spec(fn(buf: &mut [u8]{v: 2 <= v}, n: u16))]
    fn write_u16(buf: &mut [u8], n: u16);
}

// A slice is its own `AsMut<[u8]>` target, so the refinement (its length) passes through
// unchanged. Needed so `T = &mut [u8]` call sites can discharge `as_mut_reft` obligations.
#[extern_spec(core::convert)]
#[assoc(fn as_mut_reft(source: int) -> int { source })]
impl<T> AsMut<[T]> for [T] {}

// BLOCKED on a flux bug. Retested against flux 650d309447 (2026-08-03): the elaboration error
// (`expected 'T::sort', found '()'` on `source`) is gone, but the underlying defect is not --
// a reference self type still gets the **unit sort**, and the failure has merely moved to a
// fixpoint ICE. Enabling the impl below makes `mld::Repr::emit` crash with
//
//     fixpoint crash: elaborate solver failed on: true => 25 <= c0 (fld0$1 a0)
//     The sort Tuple0 is not numeric ... Cannot unify int with Tuple0
//
// i.e. `as_mut_reft(&mut T)` is typed `Tuple0` where the buffer length obligation wants an int.
// The ICE aborts rustc, so any error count from such a run is meaningless.
//
// Until reference types forward their pointee's sort, `&mut [u8]` cannot be the `T` of a refined
// `AsMut<[u8]>` signature -- which is what every real `emit` call site is. This is what stops
// `mld`/`ndisc` `Repr::emit` from discharging `clear_reserved`'s buffer precondition.
//
// #[extern_spec(core::convert)]
// impl<T: PointeeSized, U: PointeeSized> AsMut<U> for &mut T where T: AsMut<U> {
//     #![reft(fn as_mut_reft(source: Self) -> U { <T as AsMut<U>>::as_mut_reft(source) })]
// }

// `Vec`'s sort is opaque here, so `ManagedSlice`'s `Owned(Vec<T>)` variant has no length to
// name. Refine it ourselves; `opaque` because its fields are private.
#[extern_spec]
#[refined_by(len: int)]
#[invariant(0 <= len)]
struct Vec<T, A: core::alloc::Allocator = alloc::alloc::Global>;

// ---------------------------------------------------------------------------
// `managed::ManagedSlice` length.
// ---------------------------------------------------------------------------

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

