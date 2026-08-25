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
#[refined_by(is_multicast: bool)]
struct Ipv6Addr;

#[extern_spec(core::net)]
impl Ipv6Addr {
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
