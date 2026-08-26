//! `core::slice`/`core::iter` specs xarxa states on its own behalf.

use core::{
    array::IntoIter as ArrayIntoIter,
    iter::{Enumerate, Filter, FilterMap, Map, Step, Zip},
    ops::Range,
    slice::{ChunksExact, Iter, IterMut},
};

use flux_rs::*;

// `Iter::next` is a pointer bump against an end pointer and a `None` at the fence: no
// branch that can fail, no allocation, no user code. Flux reaches it as
// `MightPanic(Transitive)`, so every `for x in slice` in the crate owes a proof no caller
// can construct.
//
// This is a claim about the *iterator*, not about the loop body -- a `for` whose body can
// panic still reports, at the body's own call sites.
#[extern_spec(core::slice)]
#[assoc(fn next_no_panic() -> bool { true })]
impl<'a, T> Iterator for Iter<'a, T> {
    #[no_panic]
    fn next(&mut self) -> Option<&'a T>;

    // `slice::Iter` specialises these rather than inheriting the trait's defaults, so the
    // trait-level specs above do not reach them.
    #[flux_rs::no_panic_if(P::no_panic())]
    #[spec(fn(&mut Self, p: P) -> Option<<Self as Iterator>::Item>)]
    fn find<P>(&mut self, predicate: P) -> Option<&'a T>
    where
        Self: Sized,
        P: FnMut(&&'a T) -> bool;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(&mut Self, f: F) -> bool)]
    fn any<F>(&mut self, f: F) -> bool
    where
        Self: Sized,
        F: FnMut(&'a T) -> bool;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(&mut Self, f: F) -> Option<B>)]
    fn find_map<B, F>(&mut self, f: F) -> Option<B>
    where
        Self: Sized,
        F: FnMut(&'a T) -> Option<B>;

    // No closure: `count` on a slice iterator is a length read.
    #[no_panic]
    #[spec(fn(Self) -> usize)]
    fn count(self) -> usize
    where
        Self: Sized;
}

// Same argument, mutable side.
#[extern_spec(core::slice)]
#[assoc(fn next_no_panic() -> bool { true })]
impl<'a, T> Iterator for IterMut<'a, T> {
    #[no_panic]
    fn next(&mut self) -> Option<&'a mut T>;
}

// Deliberately NOT specified here: `array::equality::eq`, `PartialEq::ne`,
// `Iterator::{find, any, find_map, map}`. Each delegates to caller-supplied code -- an
// element's `eq`, or a closure -- so a blanket `no_panic` would be a false axiom rather
// than a missing one. They want `no_panic_if(..)` over the callee's own condition.

// The closure-taking `Iterator` methods cannot panic on their own account: they drive the
// iterator and call the caller's closure. `no_panic_if` forwards that to the closure rather
// than assuming it. No refinement -- these say nothing about the value, only about panicking.
#[extern_spec(core::iter)]
#[assoc(fn next_no_panic() -> bool)]
trait Iterator {
    // Whether advancing an iterator can panic is a property of the concrete iterator, not
    // of the trait: a slice bump cannot, an adapter can exactly when the thing it wraps or
    // the closure it holds can. `next_no_panic` is that question; each impl answers it.
    #[flux_rs::no_panic_if(<Self as Iterator>::next_no_panic())]
    #[spec(fn(&mut Self) -> Option<Self::Item>)]
    fn next(&mut self) -> Option<Self::Item>;

    #[flux_rs::no_panic_if(P::no_panic())]
    #[spec(fn(&mut Self, p: P) -> Option<Self::Item>)]
    fn find<P>(&mut self, predicate: P) -> Option<Self::Item>
    where
        Self: Sized,
        P: FnMut(&Self::Item) -> bool;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Self, f: F) -> Map<Self, F>)]
    fn map<B, F>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> B;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(&mut Self, f: F) -> bool)]
    fn any<F>(&mut self, f: F) -> bool
    where
        Self: Sized,
        F: FnMut(Self::Item) -> bool;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(&mut Self, f: F) -> bool)]
    fn all<F>(&mut self, f: F) -> bool
    where
        Self: Sized,
        F: FnMut(Self::Item) -> bool;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(&mut Self, f: F) -> Option<B>)]
    fn find_map<B, F>(&mut self, f: F) -> Option<B>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> Option<B>;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Self, f: F) -> FilterMap<Self, F>)]
    fn filter_map<B, F>(self, f: F) -> FilterMap<Self, F>
    where
        Self: Sized,
        F: FnMut(Self::Item) -> Option<B>;

    #[flux_rs::no_panic_if(P::no_panic())]
    #[spec(fn(&mut Self, p: P) -> Option<usize>)]
    fn position<P>(&mut self, predicate: P) -> Option<usize>
    where
        Self: Sized,
        P: FnMut(Self::Item) -> bool;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Self, f: F))]
    fn for_each<F>(self, f: F)
    where
        Self: Sized,
        F: FnMut(Self::Item);

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Self, f: F) -> Option<Self::Item>)]
    fn min_by_key<B: Ord, F>(self, f: F) -> Option<Self::Item>
    where
        Self: Sized,
        F: FnMut(&Self::Item) -> B;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Self, f: F) -> Option<Self::Item>)]
    fn max_by_key<B: Ord, F>(self, f: F) -> Option<Self::Item>
    where
        Self: Sized,
        F: FnMut(&Self::Item) -> B;

    // `zip` only builds the adapter; it drives neither iterator and calls no user code.
    // Whether the resulting `Zip` panics is a question about `Zip::next`, not about this.
    // <https://doc.rust-lang.org/1.89.0/src/core/iter/traits/iterator.rs.html#618>
    #[no_panic]
    #[spec(fn(Self, other: U) -> Zip<Self, <U as IntoIterator>::IntoIter>)]
    fn zip<U>(self, other: U) -> Zip<Self, <U as IntoIterator>::IntoIter>
    where
        Self: Sized,
        U: IntoIterator;
}

// Adapters: each cannot panic on its own account, so its condition is exactly the condition
// of what it wraps -- the inner iterator, and where it holds one, the closure. Both the assoc
// and the method need the condition: a resolved `next` call consults the method's own spec.

// <https://doc.rust-lang.org/1.89.0/src/core/iter/adapters/enumerate.rs.html#57>
#[extern_spec(core::iter)]
#[assoc(fn next_no_panic() -> bool { <I as Iterator>::next_no_panic() })]
impl<I: Iterator> Iterator for Enumerate<I> {
    #[flux_rs::no_panic_if(<I as Iterator>::next_no_panic())]
    #[spec(fn(&mut Self) -> Option<(usize, <I as Iterator>::Item)>)]
    fn next(&mut self) -> Option<(usize, <I as Iterator>::Item)>;
}

// <https://doc.rust-lang.org/1.89.0/src/core/iter/adapters/map.rs.html#123>
#[extern_spec(core::iter)]
#[assoc(fn next_no_panic() -> bool { <I as Iterator>::next_no_panic() && F::no_panic() })]
impl<B, I: Iterator, F: FnMut(<I as Iterator>::Item) -> B> Iterator for Map<I, F> {
    #[flux_rs::no_panic_if(<I as Iterator>::next_no_panic() && F::no_panic())]
    #[spec(fn(&mut Self) -> Option<B>)]
    fn next(&mut self) -> Option<B>;
}

// <https://doc.rust-lang.org/1.89.0/src/core/iter/adapters/filter_map.rs.html#60>
#[extern_spec(core::iter)]
#[assoc(fn next_no_panic() -> bool { <I as Iterator>::next_no_panic() && F::no_panic() })]
impl<B, I: Iterator, F: FnMut(<I as Iterator>::Item) -> Option<B>> Iterator for FilterMap<I, F> {
    #[flux_rs::no_panic_if(<I as Iterator>::next_no_panic() && F::no_panic())]
    #[spec(fn(&mut Self) -> Option<B>)]
    fn next(&mut self) -> Option<B>;
}

// `Range<A>` steps by `Step`, which is sealed in core over the integer and char types --
// none of which can fail to advance. <https://doc.rust-lang.org/1.89.0/src/core/iter/range.rs.html#758>
#[extern_spec(core::iter)]
#[assoc(fn next_no_panic() -> bool { true })]
impl<A: Step> Iterator for Range<A> {
    #[no_panic]
    #[spec(fn(&mut Self) -> Option<A>)]
    fn next(&mut self) -> Option<A>;
}

// A pointer bump between two indices, same as `slice::Iter`.
// <https://doc.rust-lang.org/1.89.0/src/core/array/iter.rs.html#292>
#[extern_spec(core::array)]
#[assoc(fn next_no_panic() -> bool { true })]
impl<T, const N: usize> Iterator for ArrayIntoIter<T, N> {
    #[no_panic]
    #[spec(fn(&mut Self) -> Option<<ArrayIntoIter<T, N> as Iterator>::Item>)]
    fn next(&mut self) -> Option<<ArrayIntoIter<T, N> as Iterator>::Item>;
}

// <https://doc.rust-lang.org/1.89.0/src/core/iter/adapters/filter.rs.html#94>
#[extern_spec(core::iter)]
#[assoc(fn next_no_panic() -> bool { <I as Iterator>::next_no_panic() && P::no_panic() })]
impl<I: Iterator, P: FnMut(&<I as Iterator>::Item) -> bool> Iterator for Filter<I, P> {
    #[flux_rs::no_panic_if(<I as Iterator>::next_no_panic() && P::no_panic())]
    #[spec(fn(&mut Self) -> Option<<I as Iterator>::Item>)]
    fn next(&mut self) -> Option<<I as Iterator>::Item>;

    // `count` drives the iterator and the predicate and adds; it calls nothing else.
    #[flux_rs::no_panic_if(<I as Iterator>::next_no_panic() && P::no_panic())]
    #[spec(fn(Self) -> usize)]
    fn count(self) -> usize;
}

// `&mut I` forwards every method to `I`.
// <https://doc.rust-lang.org/1.89.0/src/core/iter/traits/iterator.rs.html#4179>
#[extern_spec(core::iter)]
#[assoc(fn next_no_panic() -> bool { <I as Iterator>::next_no_panic() })]
impl<I: Iterator + ?Sized> Iterator for &mut I {
    #[flux_rs::no_panic_if(<I as Iterator>::next_no_panic())]
    #[spec(fn(&mut Self) -> Option<<I as Iterator>::Item>)]
    fn next(&mut self) -> Option<<I as Iterator>::Item>;
}

// A pointer bump over fixed-size windows; the remainder is split off up front.
// <https://doc.rust-lang.org/1.89.0/src/core/slice/iter.rs.html#1782>
#[extern_spec(core::slice)]
#[assoc(fn next_no_panic() -> bool { true })]
impl<'a, T> Iterator for ChunksExact<'a, T> {
    #[no_panic]
    #[spec(fn(&mut Self) -> Option<&[T]>)]
    fn next(&mut self) -> Option<&'a [T]>;
}
