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
