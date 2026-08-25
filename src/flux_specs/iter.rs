//! `core::slice`/`core::iter` specs xarxa states on its own behalf.

use core::slice::Iter;

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
