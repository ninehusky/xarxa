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

    // A `clz` instruction: total on every input, zero included.
    // <https://doc.rust-lang.org/1.89.0/src/core/num/uint_macros.rs.html#297>
    #[no_panic]
    fn leading_zeros(self) -> u32;

    // Divides, so it panics on a zero divisor and only then.
    // <https://doc.rust-lang.org/1.89.0/src/core/num/uint_macros.rs.html#3106>
    #[flux_rs::no_panic_if(rhs > 0)]
    #[spec(fn(num: usize, rhs: usize) -> usize)]
    fn div_ceil(self, rhs: usize) -> usize;
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

// Bit-counting and byte-order intrinsics. Each lowers to a single machine instruction or a
// byte shuffle: no branch, no failure mode. Flux reaches them as `MightPanic(Transitive)`
// and so charges every caller for a proof that cannot be written. `no_panic` with no `spec`
// leaves the *value* havoced, which is what the callers already assume.
#[extern_spec(core::num)]
impl u16 {
    #[no_panic]
    const fn to_be_bytes(self) -> [u8; 2];
    #[no_panic]
    const fn from_be_bytes(bytes: [u8; 2]) -> u16;
}

#[extern_spec(core::num)]
impl u32 {
    // A u32 has 32 bits, so a population count cannot exceed 32. Stating it is what lets
    // `Ipv4Cidr::from_netmask` establish the `prefix_len <= 32` invariant.
    #[no_panic]
    #[spec(fn(u32) -> u32{v: v <= 32})]
    const fn count_ones(self) -> u32;
    #[no_panic]
    const fn count_zeros(self) -> u32;
    #[no_panic]
    const fn leading_zeros(self) -> u32;
    #[no_panic]
    const fn trailing_zeros(self) -> u32;
    #[no_panic]
    const fn to_be_bytes(self) -> [u8; 4];
    #[no_panic]
    const fn from_be_bytes(bytes: [u8; 4]) -> u32;

    // Divides, so it panics on a zero divisor and only then.
    // <https://doc.rust-lang.org/1.89.0/src/core/num/uint_macros.rs.html#3106>
    #[flux_rs::no_panic_if(rhs > 0)]
    #[spec(fn(num: u32, rhs: u32) -> u32)]
    fn div_ceil(self, rhs: u32) -> u32;
}

#[extern_spec(core::num)]
impl u8 {
    // A `clz` instruction: total on every input, zero included.
    #[no_panic]
    const fn leading_zeros(self) -> u32;

    // Saturates rather than overflowing; that is the whole point of it.
    // <https://doc.rust-lang.org/1.89.0/src/core/num/uint_macros.rs.html#2432>
    #[no_panic]
    const fn saturating_add(self, rhs: u8) -> u8;
}
