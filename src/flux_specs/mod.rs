//! Flux extern specs for xarxa.
//!
//! Partitioned the way flux-core partitions its own: one module per upstream module whose
//! items are refined. The cut that matters for review is not by module though -- it is
//! [`flux_core`] versus everything else.
//!
//! | module | what it holds | how to review it |
//! | --- | --- | --- |
//! | [`flux_core`] | verbatim copies of specs that already ship in flux-core | check the transcription |
//! | [`array`] | verbatim copies of flux-core's `[T; N]` `Index`/`IndexMut` | check the transcription |
//! | [`convert`] | `AsRef`/`AsMut` associated refinements | check the claim |
//! | [`slice`] | `copy_from_slice`, `SliceIndex for RangeFull` | check the claim |
//! | [`cmp`] | `min` | check the claim |
//! | [`byteorder`] | `BigEndian::{read_u16, write_u16}` | check the claim |
//! | [`managed`] | `Vec`, `ManagedSlice` and its `Deref`/`DerefMut` impls | check the claim |
//! | [`net`] | `Ipv6Addr::is_multicast` | check the claim |

mod array;
mod byteorder;
mod cmp;
mod convert;
mod flux_core;
mod managed;
mod net;
mod slice;
