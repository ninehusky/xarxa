use flux_rs::*;

#[extern_spec(core::convert)]
trait AsRef<T> {
    #[no_panic]
    fn as_ref(&self) -> &T;
}

#[extern_spec(core::convert)]
trait AsMut<T> {
    #[no_panic]
    fn as_mut(&mut self) -> &mut T;
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
trait IndexMut<Idx> where Self: Index<Idx> {
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

// ---------------------------------------------------------------------------
// `managed::ManagedSlice`, refined by its length.
//
// ADDED FOR src/iface/socket_set.rs. `SocketSet` keeps its slots in a
// `ManagedSlice`, so `self.sockets[i]` is a `Deref` to `[T]` followed by the
// slice `Index` above. Without a length on the `ManagedSlice` the slice coming
// out of `deref` has an unknown length and `i < len` cannot be stated, and
// `deref`/`deref_mut` are additionally reported `MightPanic(NoMIRAvailable)`
// because `managed` is not compiled by Flux. Their bodies (managed 0.8.0,
// src/slice.rs) are a single `match` returning a reference; the `#[no_panic]`
// below asserts that and nothing more.
//
// Three Flux quirks are load-bearing in how this is written:
//   * `#[variant(...)]` rejects lifetime arguments, hence `&mut [T]` and
//     `ManagedSlice<T>` rather than the `'a`-carrying spellings.
//   * the method signature has to be restated on the impl, not left to the
//     trait: with no method entry the impl's associated refinement is never
//     consulted. But extern_spec rewrites `&self` into a named parameter, and
//     rustc then cannot elide the output lifetime of a `Self` type that has a
//     lifetime parameter (E0106), so the receiver is written `&'a self`.
//   * inside the impl, `Self::Target` does not resolve and
//     `<Self as core::ops::Deref>::Target` ICEs the driver
//     ("unexpected DefKind in AliasTy: Impl { of_trait: true }"), so the
//     associated type is spelled out through the concrete self type.
// ---------------------------------------------------------------------------

// KNOWN GAP: this covers `managed`'s no-`alloc` shape only. With `alloc` on,
// `ManagedSlice` also has `Owned(Vec<T>)`, and Flux rejects an extern_spec
// enum that does not list every variant -- so `cargo flux check --features
// alloc` reports one extra error here. Giving `Owned` a length needs a length
// for `Vec`, whose extern_spec cannot be written without the unstable
// `allocator_api` feature (`Vec`'s real generics are `<T, A: Allocator =
// Global>`). The firmware these panic sites are measured in does not enable
// `alloc`.
#[extern_spec(managed)]
#[refined_by(len: int)]
enum ManagedSlice<'a, T> {
    #[variant((&mut [T][@n]) -> ManagedSlice<T>[n])]
    Borrowed(&'a mut [T]),
}

#[extern_spec(core::ops)]
trait Deref {
    #![assoc(fn as_deref(v: Self, target: Self::Target) -> bool { true })]

    #[sig(fn(self: &Self[@v]) -> &Self::Target{target: <Self as Deref>::as_deref(v, target)})]
    fn deref(&self) -> &Self::Target;
}

#[extern_spec(core::ops)]
trait DerefMut: Deref {
    #[sig(fn(self: &mut Self[@v]) -> &mut Self::Target{target: <Self as Deref>::as_deref(v, target)})]
    fn deref_mut(&mut self) -> &mut Self::Target;
}

#[extern_spec(managed)]
impl<'a, T> core::ops::Deref for ManagedSlice<'a, T> {
    #[no_panic]
    #[sig(fn(self: &Self[@v]) -> &<ManagedSlice<T> as core::ops::Deref>::Target{target: target == v})]
    fn deref(&'a self) -> &'a <ManagedSlice<'a, T> as core::ops::Deref>::Target;
}

#[extern_spec(managed)]
impl<'a, T> core::ops::DerefMut for ManagedSlice<'a, T> {
    #[no_panic]
    #[sig(fn(self: &mut Self[@v]) -> &mut <ManagedSlice<T> as core::ops::Deref>::Target{target: target == v})]
    fn deref_mut(&'a mut self) -> &'a mut <ManagedSlice<'a, T> as core::ops::Deref>::Target;
}
