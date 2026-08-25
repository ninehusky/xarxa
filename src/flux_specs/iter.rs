//! `core::slice`/`core::iter` specs xarxa states on its own behalf.

use core::{
    iter::{FilterMap, Map},
    slice::{Iter, IterMut},
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
trait Iterator {
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
}
