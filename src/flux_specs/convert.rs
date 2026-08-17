//! `core::convert` specs xarxa states on its own behalf.
//!
//! These carry a buffer-length index through a conversion, which is what lets
//! `Packet<T>`'s `refined_by(buffer: T)` survive a `.as_ref()`.

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

/// A slice is its own `AsMut<[u8]>` target, so its length passes through unchanged.
#[extern_spec(core::convert)]
#[assoc(fn as_mut_reft(source: int) -> int { source })]
impl<T> AsMut<[T]> for [T] {}
