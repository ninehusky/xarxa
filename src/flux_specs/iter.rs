//! `core::slice`/`core::iter` specs xarxa states on its own behalf.

use core::slice::{Iter, IterMut};

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
