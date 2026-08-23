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
