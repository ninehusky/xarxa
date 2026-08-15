//! Flux extern specs for xarxa.
//!
//! Partitioned the way flux-core partitions its own: one module per upstream module whose
//! items are refined. The cut that matters for review is not by module though -- it is
//! [`flux_core`] versus everything else.
//!
//! | module | what it holds | how to review it |
//! | --- | --- | --- |
//! | [`flux_core`] | verbatim copies of specs that already ship in flux-core | check the transcription |
//! | [`convert`] | `AsRef`/`AsMut` associated refinements | check the claim |
//! | [`slice`] | `copy_from_slice`, `SliceIndex for RangeFull` | check the claim |
//! | [`cmp`] | `min` | check the claim |
//! | [`byteorder`] | `BigEndian::{read_u16, write_u16}` | check the claim |
//! | [`managed`] | `Vec`, `ManagedSlice` and its `Deref`/`DerefMut` impls | check the claim |
//!
//! Nothing outside `flux_core` is a copy of anything; each item is a claim xarxa makes on
//! its own behalf, and none of it is proven -- these are extern specs, so every one is an
//! assumption discharged by reading the upstream body. Keep it that way: if an item comes
//! from flux-core, it belongs in [`flux_core`] so the copy stays diffable.

mod byteorder;
mod cmp;
mod convert;
mod flux_core;
mod managed;
mod slice;
