//! `core::ops::RangeInclusive` specs xarxa states on its own behalf.

#[allow(unused_imports)]
use core::ops;

use flux_rs::*;

/// `RangeInclusive::new` stores its two endpoints and an `exhausted` flag; there is no
/// fallible step in it, so it cannot panic. Without this, flux reports every `a..=b` literal
/// as `MightPanic(NotInCallGraph)` -- the constructor is `const` and never reached by the
/// call-graph walk.
/// <https://doc.rust-lang.org/1.89.0/src/core/ops/range.rs.html#398>
#[extern_spec(core::ops)]
impl<Idx> RangeInclusive<Idx> {
    #[no_panic]
    #[spec(fn(start: Idx, end: Idx) -> RangeInclusive<Idx>)]
    const fn new(start: Idx, end: Idx) -> RangeInclusive<Idx>;
}
