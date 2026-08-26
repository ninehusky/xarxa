//! `core::option` specs xarxa states on its own behalf.
//!
//! `Option` itself is **not** refined here: an `extern_spec` carrying
//! `refined_by(is_some: bool)` ICEs fixpoint in this tree. So nothing below says anything
//! about whether the option is `Some` -- which is why `unwrap` and `expect` are absent.
//! Those genuinely can panic and are ledgered, not specified.

use flux_rs::*;

// `map` cannot panic on its own account: it matches, and on `Some` it calls `f`. Whether that
// panics is `f`'s business, and `no_panic_if(F::no_panic())` forwards the obligation to the
// closure rather than assuming it away. Transcribed from flux-core's `option.rs`; the `spec`
// is required because `no_panic_if` needs a signature on the same item, and it deliberately
// states nothing about the value.
//
// This discharges call sites that pass a **closure**. A site passing a *fn item* --
// `.map(EthernetPacket::Ip)`, a tuple-struct constructor -- still reports, because
// `F::no_panic()` does not resolve for fn items. Writing `.map(|x| EthernetPacket::Ip(x))`
// is the honest workaround at those sites.
#[extern_spec(core::option)]
impl<T> Option<T> {
    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Option<T>, F) -> Option<U>)]
    fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Option<U>;

    #[flux_rs::no_panic_if(F::no_panic())]
    #[spec(fn(Option<T>, f: F) -> T)]
    fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T;
}
