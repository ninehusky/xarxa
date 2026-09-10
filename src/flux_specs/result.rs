//! `core::result` specs xarxa states on its own behalf.
//!
//! `Result` is refined by `is_ok`, which is what lets `unwrap` and `expect` state the
//! condition under which they do not panic instead of being ledgered as unconditional panic
//! sites. (`Option` is a different matter: an `extern_spec` refining it ICEs fixpoint.)
//!
//! The rest is forwarding: a combinator panics exactly when the closure it was handed does.

use flux_rs::*;

#[extern_spec(core::result)]
#[refined_by(is_ok: bool)]
enum Result<T, E> {
    #[variant((T) -> Result<T, E>[true])]
    Ok(T),
    #[variant((E) -> Result<T, E>[false])]
    Err(E),
}

#[extern_spec(core::result)]
impl<T, E> Result<T, E> {
    /// Panics iff the result is `Err`, which the index now states.
    /// <https://doc.rust-lang.org/1.89.0/src/core/result.rs.html#1097>
    #[flux_rs::no_panic_if(r)]
    #[spec(fn(Result<T, E>[@r]) -> T)]
    fn unwrap(self) -> T
    where
        E: core::fmt::Debug;

    /// <https://doc.rust-lang.org/1.89.0/src/core/result.rs.html#1054>
    #[flux_rs::no_panic_if(r)]
    #[spec(fn(Result<T, E>[@r], msg: &str) -> T)]
    fn expect(self, msg: &str) -> T
    where
        E: core::fmt::Debug;

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
