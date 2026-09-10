//! `core::net` specs xarxa states on its own behalf.
//!
//! `Ipv6Addr` is refined by the one predicate the wire code asserts on:
//! [`Ipv6Addr::is_multicast`]. The struct is opaque -- the refinement is a ghost flag, not a
//! projection of the octets -- so nothing here relates a *concrete* address to the flag.
//! What it buys is that the property becomes *statable*: a `requires a.is_multicast` on a
//! setter is an obligation a caller can carry, instead of one a `trusted(yes)` erases.

use flux_rs::*;

/// `is_multicast` is `self.segments()[0] & 0xff00 == 0xff00` in core, over the private
/// octets; Flux has no MIR for it, so without a refinement the result is havoced.
#[extern_spec(core::net)]
#[refined_by(is_multicast: bool, is_unicast: bool)]
struct Ipv6Addr;

/// The same device as `Ipv6Addr`'s flags: a ghost bit, not a projection of the octets. It
/// makes "this address is unicast" statable as a precondition instead of a runtime assert.
#[extern_spec(core::net)]
#[refined_by(is_unicast: bool)]
struct Ipv4Addr;

#[extern_spec(core::net)]
impl Ipv6Addr {
    // Packs eight segments into the octet array. No branch, no failure mode.
    // <https://doc.rust-lang.org/1.89.0/src/core/net/ip_addr.rs.html#1740>
    #[no_panic]
    #[spec(fn(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Ipv6Addr)]
    const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Ipv6Addr;

    #[no_panic]
    #[spec(fn(&Ipv6Addr[@a]) -> bool[a.is_multicast])]
    const fn is_multicast(&self) -> bool;

    #[no_panic]
    const fn is_unspecified(&self) -> bool;
    #[no_panic]
    const fn is_loopback(&self) -> bool;
    #[no_panic]
    const fn is_unique_local(&self) -> bool;
}

// Pure bit operations over the private octets: a shuffle, a mask, a comparison. None has a
// branch that can fail, but flux's inference reaches them through `MightPanic(Transitive)`
// and so owes every caller a proof it cannot construct. `no_panic` alone -- no `spec` -- is
// the whole claim: these say nothing about the *value*, only that reaching one cannot panic.
#[extern_spec(core::net)]
impl Ipv4Addr {
    #[no_panic]
    const fn to_bits(self) -> u32;
    #[no_panic]
    const fn from_bits(bits: u32) -> Ipv4Addr;
    #[no_panic]
    const fn is_unspecified(&self) -> bool;
    #[no_panic]
    const fn is_broadcast(&self) -> bool;
}

// The octet array *is* the representation; `from` moves it in.
// <https://doc.rust-lang.org/1.89.0/src/core/net/ip_addr.rs.html#2216>
#[extern_spec(core::net)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<[u8; 16]> for Ipv6Addr {
    #[no_panic]
    #[spec(fn(octets: [u8; 16]) -> Ipv6Addr)]
    fn from(octets: [u8; 16]) -> Ipv6Addr;
}

// The eight segments are written into the octet array big-endian; no branch.
// <https://doc.rust-lang.org/1.89.0/src/core/net/ip_addr.rs.html#2228>
#[extern_spec(core::net)]
#[assoc(fn from_no_panic() -> bool { true })]
impl From<[u16; 8]> for Ipv6Addr {
    #[no_panic]
    #[spec(fn(segments: [u16; 8]) -> Ipv6Addr)]
    fn from(segments: [u16; 8]) -> Ipv6Addr;
}

// Comparing two fixed-size octet arrays.
// <https://doc.rust-lang.org/1.89.0/src/core/net/ip_addr.rs.html#1372>
#[extern_spec(core::net)]
impl PartialEq for Ipv4Addr {
    #[no_panic]
    #[spec(fn(&Ipv4Addr, &Ipv4Addr) -> bool)]
    fn eq(&self, other: &Ipv4Addr) -> bool;
}

#[extern_spec(core::net)]
impl PartialEq for Ipv6Addr {
    #[no_panic]
    #[spec(fn(&Ipv6Addr, &Ipv6Addr) -> bool)]
    fn eq(&self, other: &Ipv6Addr) -> bool;
}
