//! `core::result` specs xarxa states on its own behalf.
//!
//! `Result` is **not** refined here, for the same reason `Option` is not: an `extern_spec`
//! carrying `refined_by(is_ok: bool)` is not something this tree can rely on. So `unwrap` and
//! `expect` are absent -- those genuinely panic and are ledgered, not specified.
//!
//! What is here is only the forwarding: a combinator panics exactly when the closure it was
//! handed does.

use flux_rs::*;

#[extern_spec(core::result)]
impl<T, E> Result<T, E> {
    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Result<T, E>, f: F) -> Result<U, E>)]
    fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Result<U, E>;

    // core names these the other way round: `F` is the new error type, `O` the closure.
    #[flux_rs::no_panic_if(O::no_panic())]
    #[spec(fn(Result<T, E>, op: O) -> Result<T, F>)]
    fn map_err<F, O: FnOnce(E) -> F>(self, op: O) -> Result<T, F>;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Result<T, E>, f: F) -> Result<U, E>)]
    fn and_then<U, F: FnOnce(T) -> Result<U, E>>(self, f: F) -> Result<U, E>;
}

// `FromResidual` is unstable, so both the import and the spec are gated: `cfg(flux)` is only
// ever set by `cargo flux`, and a stable build must not see either.
#[cfg(flux)]
mod residual {
    use core::ops::FromResidual;

    use flux_rs::*;

    // `?` on a `Result` lowers to this. Its body is `Err(From::from(e))`, so it panics exactly
    // when the error conversion does -- which is what the `From` assoc answers.
    #[extern_spec(core::result)]
    impl<T, E, F: From<E>> FromResidual<Result<core::convert::Infallible, E>> for Result<T, F> {
        #[flux_rs::no_panic_if(<F as From<E>>::from_no_panic())]
        #[spec(fn(Result<core::convert::Infallible, E>) -> Result<T, F>)]
        fn from_residual(residual: Result<core::convert::Infallible, E>) -> Result<T, F>;
    }
}
