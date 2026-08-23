//! `core::num` specs xarxa states on its own behalf.

use flux_rs::*;

// flux-core has this one, written as `clamp(num - rhs, 0, usize::MAX)` against a `clamp` defn
// declared in its own `#![flux::defs]` block. Copied that way it would be useless here: a defn
// does not unfold across a module, so every call site would see an opaque `clamp(..)` term
// rather than the value. Spelled out inline instead, which is the same function.
//
// `Socket::dispatch` needs it. `effective_mss` is
// `local_mss.min(remote_mss).saturating_sub(options_len)`, and without a spec the result is
// unconstrained -- which loses the payload-length ceiling `IpRepr::set_payload_len` requires.
#[extern_spec(core::num)]
impl usize {
    #[no_panic]
    #[spec(fn(num: usize, rhs: usize) -> usize[if num > rhs { num - rhs } else { 0 }])]
    fn saturating_sub(self, rhs: usize) -> usize;
}

// flux-core has these too, written against its `wrap_once` defn. Same reason as above for
// spelling the wrap out inline: a defn does not unfold across a module, so the `wrap_once(..)`
// term would be opaque at every use site. `wire::tcp`'s `wrap32` is the same function at
// `i32`'s bounds, and is where sequence-number arithmetic reads it.
//
// The condition on `wrap_once` carries over: it is correct only when the result overshoots by
// at most one period, which holds for `wrapping_add`/`wrapping_sub` on two in-range operands.
#[extern_spec(core::num)]
impl i32 {
    #[no_panic]
    #[spec(fn(num: i32, rhs: i32) -> i32[if num - rhs > 2147483647 { num - rhs - 4294967296 }
                                         else if num - rhs < -2147483648 { num - rhs + 4294967296 }
                                         else { num - rhs }])]
    fn wrapping_sub(self, rhs: i32) -> i32;

    #[no_panic]
    #[spec(fn(num: i32, rhs: i32) -> i32[if num + rhs > 2147483647 { num + rhs - 4294967296 }
                                         else if num + rhs < -2147483648 { num + rhs + 4294967296 }
                                         else { num + rhs }])]
    fn wrapping_add(self, rhs: i32) -> i32;
}
