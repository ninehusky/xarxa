//! `core::intrinsics` specs xarxa states on its own behalf.

use flux_rs::*;

// `#[derive(PartialEq)]` on a fieldless enum expands to a direct call to this intrinsic --
// not to the `core::mem::discriminant` wrapper -- so the spec has to name the intrinsic.
//
// An intrinsic has no MIR, so flux's call-graph inference defaults it to `MightPanic`. That
// is absence of evidence, not evidence: reading a discriminant is a load with no branch, no
// allocation and no failure mode. Every `#[derive(PartialEq, Eq, Hash)]` in the crate owes
// this call, so without the spec each derive is an unprovable obligation.
#[extern_spec(core::intrinsics)]
#[no_panic]
fn discriminant_value<T>(v: &T) -> <T as core::marker::DiscriminantKind>::Discriminant;
