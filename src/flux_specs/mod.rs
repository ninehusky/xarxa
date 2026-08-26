//! Flux extern specs for xarxa.
//!
//! Partitioned the way flux-core partitions its own: one module per upstream module whose
//! items are refined. The cut that matters for review is not by module though -- it is
//! [`flux_core`] versus everything else.
//!
//! | module | what it holds | how to review it |
//! | --- | --- | --- |
//! | [`flux_core`] | verbatim copies of specs that already ship in flux-core | check the transcription |
//! | [`array`] | flux-core's `[T; N]` `Index`/`IndexMut`, plus `as_slice`/`as_mut_slice` | check both |
//! | [`convert`] | `AsRef`/`AsMut` associated refinements | check the claim |
//! | [`str`] | `from_utf8` | check the claim |
//! | [`slice`] | `copy_from_slice`, `SliceIndex for RangeFull` | check the claim |
//! | [`cmp`] | `min` | check the claim |
//! | [`heapless`] | `Vec::{new, push}`, `Deref` | check the claim |
//! | [`intrinsics`] | `discriminant_value` | check the claim |
//! | [`iter`] | `slice::Iter::next` | check the claim |
//! | [`byteorder`] | `BigEndian::{read_u16, write_u16}` | check the claim |
//! | [`managed`] | `Vec`, `ManagedSlice` and its `Deref`/`DerefMut` impls | check the claim |
//! | [`net`] | `Ipv6Addr::is_multicast` | check the claim |
//! | [`num`] | `usize::saturating_sub` | check the claim |
//! | [`option`] | `Option::map`, forwarding to the closure | check the claim |
//! | [`range`] | `RangeInclusive::new` | check the claim |

mod array;
mod byteorder;
mod cmp;
mod convert;
mod convert_nopanic;
mod flux_core;
mod heapless;
mod intrinsics;
mod iter;
mod managed;
mod net;
mod num;
mod option;
mod range;
mod result;
mod slice;
mod str;
