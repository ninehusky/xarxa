//! `core::convert` specs xarxa states on its own behalf.
//!
//! flux-core's `convert/mod.rs` refines `TryFrom`/`TryInto` only; the `AsRef`/`AsMut`
//! associated refinements below are xarxa's, and carry the buffer-length index through a
//! conversion. They are what lets `Packet<T>`'s `refined_by(buffer: T)` survive a
//! `.as_ref()`.

use flux_rs::*;

/// `as_ref_reft` is deliberately left abstract: each implementor states how its own
/// refinement maps through the conversion. An implementor that supplies no definition
/// gets no usable fact, rather than a vacuously true one.
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

/// See [`AsRef`].
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
