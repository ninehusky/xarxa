//! `no_panic` forwarding for `From`.
//!
//! `?` lowers to `Result::from_residual`, whose body is `Err(From::from(e))`, and `.into()`
//! is `U::from(self)`. Neither can panic on its own account -- the question is always
//! whether the conversion panics. `from_no_panic` is that question as an associated
//! refinement, and each impl answers it.

use flux_rs::*;

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool)]
trait From<T> {
    #[flux_rs::no_panic_if(<Self as From<T>>::from_no_panic())]
    #[spec(fn(T) -> Self)]
    fn from(value: T) -> Self;
}

// `.into()` is `U::from(self)`, so it panics exactly when the conversion does. The trait
// carries its own assoc so a generic `T: Into<U>` bound has something to name; the blanket
// impl answers it by forwarding to `from_no_panic`.
#[extern_spec(core::convert)]
#[assoc(fn into_no_panic() -> bool)]
trait Into<T> {
    #[flux_rs::no_panic_if(<Self as Into<T>>::into_no_panic())]
    #[spec(fn(Self) -> T)]
    fn into(self) -> T;
}

#[extern_spec(core::convert)]
#[assoc(fn into_no_panic() -> bool { <U as From<T>>::from_no_panic() })]
impl<T, U> Into<U> for T where U: From<T> {
    #[flux_rs::no_panic_if(<U as From<T>>::from_no_panic())]
    #[spec(fn(T) -> U)]
    fn into(self) -> U;
}


// Core's own widening conversions. Declaring the assoc on `From` obliges every impl to
// answer, including core's, which cannot be annotated in tree. Each of these is a lossless
// zero-extend: no branch, no failure mode.
#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u8> for u16 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u8> for u32 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u8> for u64 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u8> for usize {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u16> for u32 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u16> for u64 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u16> for usize {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u32> for u64 {}


#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<i8> for i64 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<i16> for i64 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<i32> for i64 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u8> for i64 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u16> for i64 {}

#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<u32> for i64 {}

// The reflexive `impl<T> From<T> for T` is `fn from(t: T) -> T { t }` -- an identity move.
// It is what every same-error-type `?` in the crate goes through.
#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl<T> From<T> for T {}

// `<[T; N]>::try_from(&[T])` compares the slice's length against `N` and returns `Err` if
// they differ; there is no panicking path in it. Stating the result's `is_ok` in terms of
// the length is what lets `try_into().unwrap()` discharge at a site where the length is
// already known from a guard.
// <https://doc.rust-lang.org/1.89.0/src/core/array/mod.rs.html#264>
#[extern_spec(core::array)]
impl<'a, T: Copy + 'a, const N: usize> TryFrom<&'a [T]> for [T; N] {
    #[no_panic]
    #[spec(fn(slice: &[T][@n]) -> Result<[T; N], core::array::TryFromSliceError>[n == N])]
    fn try_from(slice: &'a [T]) -> Result<[T; N], core::array::TryFromSliceError>;
}
