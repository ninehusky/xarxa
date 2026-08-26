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

// The blanket `impl<T, U: From<T>> Into<U> for T` is `U::from(self)`, so `.into()` panics
// exactly when the conversion does.


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


// The reflexive `impl<T> From<T> for T` is `fn from(t: T) -> T { t }` -- an identity move.
// It is what every same-error-type `?` in the crate goes through.
#[extern_spec(core::convert)]
#[assoc(fn from_no_panic() -> bool { true })]
impl<T> From<T> for T {}
