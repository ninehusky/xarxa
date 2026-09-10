//! `heapless` specs xarxa states on its own behalf.
//!
//! heapless is compiled without flux, so every one of its functions is body-less as far as
//! the call-graph inference is concerned and defaults to `MightPanic(NoMIRAvailable)`.
//! Nothing here refines a *value*; each item claims only that reaching it cannot panic.

use heapless::{
    linear_map::{Iter as LinearMapIter, LinearMapInner, LinearMapStorage, OwnedStorage},
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

// heapless 0.9.3, `src/linear_map.rs`. Three of the six `LinearMap` methods xarxa calls are
// panic-free on their own account; the other three are not specified here and the reason is
// per-method, not blanket:
//
//   | method     | line | body                                              | claim        |
//   | ---        | ---  | ---                                               | ---          |
//   | `new`      | 130  | `Self { buffer: Vec::new() }`, `const`            | `no_panic`   |
//   | `clear`    | 179  | `self.buffer.clear()` -- a truncate to 0           | `no_panic`   |
//   | `iter`     | 355  | wraps `self.buffer.as_slice().iter()`              | `no_panic`   |
//   | `get`      | 215  | `.find(|&(k, _)| k.borrow() == key)`               | calls `Q::eq` |
//   | `get_mut`  | 241  | same, over `iter_mut`                              | calls `Q::eq` |
//   | `remove`   | 424  | same, then `swap_remove`                           | calls `Q::eq` |
//   | `insert`   | 290  | `.find(|&(k, _)| *k == key)`, then `push`          | calls `K::eq` |
//
// The last four reach caller-supplied `PartialEq`, so `no_panic` on them would be a false
// axiom rather than a missing one. They want `no_panic_if` over the key's own condition,
// which needs an associated refinement on `PartialEq` that this tree does not have.
#[extern_spec(heapless::linear_map)]
impl<K, V, const N: usize> LinearMapInner<K, V, OwnedStorage<K, V, N>> {
    #[no_panic]
    const fn new() -> LinearMapInner<K, V, OwnedStorage<K, V, N>>;
}

#[extern_spec(heapless::linear_map)]
impl<K: Eq, V, S: LinearMapStorage<K, V> + ?Sized> LinearMapInner<K, V, S> {
    #[no_panic]
    fn clear(&mut self);

    #[no_panic]
    fn iter(&self) -> LinearMapIter<K, V>;
}

// Not specified from heapless 0.9.3 `src/vec/mod.rs`, and why:
//
//   * `remove` (line 1091) opens with an explicit `panic!("removal index (is {index}) should
//     be < len (is {len})")`. A real obligation; it wants `no_panic_if(index < len)`, which
//     is unstatable until `VecInner` carries its length as a refinement.
//   * `Clone for VecInner` (line 1800) clones each element, so its condition is `T`'s.
//   * `AsRef<[T]> for VecInner` (line 1782) is `self`, and cannot panic -- but xarxa's
//     `AsRef` trait spec carries `as_ref_reft`, the target's length index, and an unrefined
//     `VecInner` has no length to answer it with. Supplying any constant there would be a
//     false claim about the slice, so the row stays instead.
