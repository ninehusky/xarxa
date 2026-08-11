#[allow(unused_imports)]
use byteorder::{BigEndian, ByteOrder};
use flux_rs::*;

// ---------------------------------------------------------------------------
// byteorder specs.
//
// `byteorder` is a third-party crate with no MIR available to Flux, so every
// `NetworkEndian::{read,write}_*` is reported `MightPanic(NoMIRAvailable)` and
// nothing on our side can discharge it. `BigEndian`'s bodies are all
// `buf[..N]`, so the sole panic condition is `buf.len() < N`; the `requires`
// below states exactly that and `#[no_panic]` records that it is the only one.
// `NetworkEndian` is a type alias for `BigEndian`, so these cover both spellings.
// ---------------------------------------------------------------------------

#[extern_spec(byteorder)]
impl ByteOrder for BigEndian {
    #[no_panic]
    #[sig(fn(&[u8][@n]) -> u16 requires n >= 2)]
    fn read_u16(buf: &[u8]) -> u16;

    #[no_panic]
    #[sig(fn(&[u8][@n]) -> u32 requires n >= 4)]
    fn read_u32(buf: &[u8]) -> u32;

    #[no_panic]
    #[sig(fn(&mut [u8][@n], u16) requires n >= 2)]
    fn write_u16(buf: &mut [u8], n: u16);

    #[no_panic]
    #[sig(fn(&mut [u8][@n], u32) requires n >= 4)]
    fn write_u32(buf: &mut [u8], n: u32);
}

// `idx` is the length (more precisely, the refinement index) of the borrowed
// view. Impls that carry one define it; everything else falls back to the
// uninterpreted `opaque_idx`, which says nothing but keeps the function total.
// A total function is what lets a *foreign* impl -- notably the `&T`/`&mut T`
// auto-deref blankets, whose generic parameter list contains an elided lifetime
// that an `extern_spec` cannot name -- be used without a definition of its own.
flux_rs::defs! {
    fn opaque_idx<A, B>(s: A) -> B;
}

#[extern_spec(core::convert)]
#[assoc(fn idx(s: Self) -> T { opaque_idx(s) })]
trait AsRef<T> {
    #[no_panic]
    #[sig(fn(&Self[@s]) -> &T[<Self as AsRef<T>>::idx(s)])]
    fn as_ref(&self) -> &T;
}

#[extern_spec(core::convert)]
#[assoc(fn idx(s: Self) -> T { opaque_idx(s) })]
trait AsMut<T> {
    #[no_panic]
    #[sig(fn(&mut Self[@s]) -> &mut T[<Self as AsMut<T>>::idx(s)])]
    fn as_mut(&mut self) -> &mut T;
}

// The core impls that ground `AsRef::idx` / `AsMut::idx` at the concrete buffer
// types `wire` instantiates its packet wrappers with (`&[u8]`, `&mut [u8]`,
// `[u8; N]`, ...). Without these the associated refinement stays uninterpreted
// and no length obligation can be discharged at a concrete call site.
#[extern_spec(core::convert)]
impl<T> AsRef<[T]> for [T] {
    #![assoc(fn idx(s: int) -> int { s })]
    #[no_panic]
    #[sig(fn(&[T][@n]) -> &[T][n])]
    fn as_ref(&self) -> &[T];
}

#[extern_spec(core::convert)]
impl<T> AsMut<[T]> for [T] {
    #![assoc(fn idx(s: int) -> int { s })]
    #[no_panic]
    #[sig(fn(&mut [T][@n]) -> &mut [T][n])]
    fn as_mut(&mut self) -> &mut [T];
}

// `Result`'s `is_ok` index, copied from flux-core's `result.rs`. A `check_len`
// whose doc says "ensure that no accessor method will panic if called" can then
// say exactly that in its return type -- `Ok` implies the buffer is at least a
// header long -- instead of pushing a precondition onto every one of its callers.
#[extern_spec]
#[refined_by(is_ok: bool)]
enum Result<T, E> {
    #[variant((T) -> Result<T, E>[true])]
    Ok(T),
    #[variant((E) -> Result<T, E>[false])]
    Err(E),
}

#[extern_spec(core::convert)]
#[assoc(fn from_val(s: T, into: Self) -> bool { true })]
trait From<T> {
    #[sig(fn(T[@s]) -> Self{v: <Self as From<T>>::from_val(s, v)})]
    fn from(value: T) -> Self;
}

#[extern_spec(core::convert)]
impl<T, U: From<T>> Into<U> for T {
    #[sig(fn(T[@s]) -> U{v: <U as From<T>>::from_val(s, v)})]
    fn into(self) -> U;
}

// ---------------------------------------------------------------------------
// Slice indexing specs.
//
// Copied from flux/lib/flux-core/src/{ops/index.rs, ops/range.rs,
// slice/index.rs} rather than loading flux-core wholesale: `cargo-flux` cannot
// inject it (it never passes `-L <sysroot>`, so flux_core's own dependency on
// flux_attrs fails to resolve), and we only want the specs that discharge real
// panic obligations.
//
// Without these, every `data[i]` / `data[a..b]` is reported
// `MightPanic(Transitive)` and no annotation on our side can discharge it.
// With them it becomes an ordinary `in_bounds` refinement obligation.
//
// All three blocks are required. Dropping `ops::Index` gives "associated
// refinement is not a member of trait"; dropping `ops::Range` gives "no field
// `start` on sort".
// ---------------------------------------------------------------------------

#[extern_spec(core::ops)]
trait Index<Idx> {
    #![assoc(fn in_bounds(v: Self, idx: Idx) -> bool { true })]
    #![assoc(fn output_pred(v: Self, idx: Idx, out: Self::Output) -> bool { true })]

    #[sig(fn(self: &Self[@v], index: Idx { <Self as Index<Idx>>::in_bounds(v, index) }) -> &Self::Output{out: <Self as Index<Idx>>::output_pred(v, index, out)})]
    fn index(&self, index: Idx) -> &Self::Output;
}

#[extern_spec(core::ops)]
trait IndexMut<Idx>
where
    Self: Index<Idx>,
{
    #[sig(fn(self: &mut Self[@v], index: Idx { <Self as Index<Idx>>::in_bounds(v, index) }) -> &mut Self::Output{out: <Self as Index<Idx>>::output_pred(v, index, out)})]
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output;
}

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
impl<T> SliceIndex<[T]> for core::ops::Range<usize> {}

#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { r.end <= len })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == r.end })]
impl<T> SliceIndex<[T]> for core::ops::RangeTo<usize> {}

#[extern_spec(core::slice)]
#[flux::assoc(fn in_bounds(r: Self, len: int) -> bool { r.start <= len })]
#[flux::assoc(fn output_pred(r: Self, len: int, out: int) -> bool { out == len - r.start })]
impl<T> SliceIndex<[T]> for core::ops::RangeFrom<usize> {}

#[extern_spec(core::slice)]
impl<T, I: SliceIndex<[T]>> core::ops::Index<I> for [T] {
    #![assoc(
        fn in_bounds(len: int, idx: I) -> bool { <I as SliceIndex<[T]>>::in_bounds(idx, len) }
        fn output_pred(len: int, idx: I, out: <I as SliceIndex<[T]>>::Output) -> bool {
            <I as SliceIndex<[T]>>::output_pred(idx, len, out)
        }
    )]
    #[no_panic]
    #[sig(fn(&Self[@len], {I[@idx] | <Self as core::ops::Index<I>>::in_bounds(len, idx)}) -> &I::Output{out: <I as SliceIndex<[T]>>::output_pred(idx, len, out)})]
    fn index(&self, index: I) -> &I::Output;
}

#[extern_spec(core::slice)]
impl<T, I: SliceIndex<[T]>> core::ops::IndexMut<I> for [T] {
    #[no_panic]
    #[sig(fn(&mut Self[@len], {I[@idx] | <Self as core::ops::Index<I>>::in_bounds(len, idx)}) -> &mut I::Output{out: <I as SliceIndex<[T]>>::output_pred(idx, len, out)})]
    fn index_mut(&mut self, index: I) -> &mut I::Output;
}

// Array indexing, copied from flux-core's `array/mod.rs`. Needed because
// `RawHardwareAddress` stores its octets in a `[u8; MAX_HARDWARE_ADDRESS_LEN]`;
// without this every `arr[..n]` is `MightPanic(NoMIRAvailable)`. `#[no_panic]`
// is ours: the delegation to `[T]`'s `in_bounds` is the whole panic condition.
#[extern_spec(core::array)]
impl<T, I, const N: usize> core::ops::Index<I> for [T; N]
where
    [T]: core::ops::Index<I>,
{
    #![assoc(
        fn in_bounds(len: (), idx: I) -> bool {
            <[T] as core::ops::Index<I>>::in_bounds(N, idx)
        }

        fn output_pred(len: (), idx: I, out: <[T] as core::ops::Index<I>>::Output) -> bool {
            <[T] as core::ops::Index<I>>::output_pred(N, idx, out)
        }
    )]
    #[no_panic]
    #[sig(fn(&Self, {I[@idx] | <[T] as core::ops::Index<I>>::in_bounds(N, idx)}) -> &<[T; N] as core::ops::Index<I>>::Output{out: <[T] as core::ops::Index<I>>::output_pred(N, idx, out)})]
    fn index(&self, index: I) -> &<[T; N] as core::ops::Index<I>>::Output;
}

#[extern_spec(core::array)]
impl<T, I, const N: usize> core::ops::IndexMut<I> for [T; N]
where
    [T]: core::ops::IndexMut<I>,
{
    #[no_panic]
    #[sig(fn(&mut Self, {I[@idx] | <[T] as core::ops::Index<I>>::in_bounds(N, idx)}) -> &mut <[T; N] as core::ops::Index<I>>::Output{out: <[T] as core::ops::Index<I>>::output_pred(N, idx, out)})]
    fn index_mut(&mut self, index: I) -> &mut <[T; N] as core::ops::Index<I>>::Output;
}

// `[T]::len` / `[T]::is_empty`, copied from flux-core's `slice/mod.rs`.
#[extern_spec(core::slice)]
impl<T> [T] {
    #[no_panic]
    #[sig(fn(&Self[@n]) -> usize[n])]
    fn len(&self) -> usize;

    #[no_panic]
    #[sig(fn(&Self[@n]) -> bool[n == 0])]
    fn is_empty(&self) -> bool;

    // Not in flux-core; written here. `copy_from_slice` panics exactly when the
    // two lengths differ, so `n == m` is the whole of its panic precondition.
    #[no_panic]
    #[sig(fn(&mut Self[@n], &[T][@m]) requires n == m)]
    fn copy_from_slice(&mut self, src: &[T])
    where
        T: Copy;
}
