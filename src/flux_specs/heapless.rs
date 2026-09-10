//! `heapless` specs xarxa states on its own behalf.
//!
//! heapless is compiled without flux, so every one of its functions is body-less as far as
//! the call-graph inference is concerned and defaults to `MightPanic(NoMIRAvailable)`.
//! Nothing here refines a *value*; each item claims only that reaching it cannot panic.

use heapless::{
    vec::{OwnedVecStorage, VecInner, VecStorage},
    LenType,
};

use flux_rs::*;

// `deref` is `as_slice()`: a length read and a pointer cast over already-initialised
// storage. Reached by every `&vec[..]`, every `.iter()`, every method call that autoderefs
// to the slice, which is why this one item is the largest single heapless entry.
#[extern_spec(heapless::vec)]
impl<T, LenT: LenType, S: VecStorage<T> + ?Sized> core::ops::Deref for VecInner<T, LenT, S> {
    #[no_panic]
    fn deref(&self) -> &<VecInner<T, LenT, S> as core::ops::Deref>::Target;
}

// `new` is a `const fn` that zeroes a length and leaves the buffer uninitialised. It lives
// on the owned-storage impl, `push` on the generic one, so the two need separate blocks.
#[extern_spec(heapless::vec)]
impl<T, LenT: LenType, const N: usize> VecInner<T, LenT, OwnedVecStorage<T, N>> {
    #[no_panic]
    const fn new() -> VecInner<T, LenT, OwnedVecStorage<T, N>>;
}

// `push` tests `len < capacity` and hands the item **back** as `Err(item)` when full: the
// overflow path is a return, not a panic.
#[extern_spec(heapless::vec)]
impl<T, LenT: LenType, S: VecStorage<T> + ?Sized> VecInner<T, LenT, S> {
    #[no_panic]
    fn push(&mut self, item: T) -> Result<(), T>;
}
