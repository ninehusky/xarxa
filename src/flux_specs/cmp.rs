//! `core::cmp` specs xarxa states on its own behalf.

use flux_rs::*;

// Not in flux-core. Without it `min(a, b)` is unconstrained, so the `..length` slices in
// `udp::Socket::{recv,peek}_slice` cannot be shown in bounds.
#[extern_spec(core::cmp)]
#[no_panic]
#[spec(fn(v1: T[@a], v2: T[@b]) -> T[if a < b { a } else { b }])]
fn min<T: Ord>(v1: T, v2: T) -> T;

// The free `max`, not `Ord::max`: the method is a *default* trait method, not defined in
// `impl Ord for usize`, so an extern spec on the impl is rejected. Same shape as `PartialEq`'s
// default `ne`. Call sites that need the bound use `cmp::max(a, b)`.
#[extern_spec(core::cmp)]
#[no_panic]
#[spec(fn(v1: T[@a], v2: T[@b]) -> T[if a > b { a } else { b }])]
fn max<T: Ord>(v1: T, v2: T) -> T;

// `clamp` asserts `min <= max` and then compares; that assert is its only failure mode.
// <https://doc.rust-lang.org/1.89.0/src/core/cmp.rs.html#1216>
#[extern_spec(core::cmp)]
impl Ord for u32 {
    #[flux_rs::no_panic_if(min <= max)]
    #[spec(fn(u32, min: u32, max: u32) -> u32)]
    fn clamp(self, min: u32, max: u32) -> u32;
}
