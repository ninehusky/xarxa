//! `core::cmp` specs xarxa states on its own behalf.

use flux_rs::*;

// Not in flux-core. Without it `min(a, b)` is unconstrained, so the `..length` slices in
// `udp::Socket::{recv,peek}_slice` cannot be shown in bounds.
#[extern_spec(core::cmp)]
#[no_panic]
#[spec(fn(v1: T[@a], v2: T[@b]) -> T[if a < b { a } else { b }])]
fn min<T: Ord>(v1: T, v2: T) -> T;
