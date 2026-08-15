//! Trusted slice primitives shared by the `wire` and `storage` layers.
//!
//! Each one exists for the same reason: a `&mut` sub-slice is a *returned* reference, and flux
//! drops its length index on the way back to the caller (flux-rs/flux#1714). That makes
//! `copy_from_slice`'s equal-length precondition unprovable at the call site even when the
//! lengths are obviously equal. Wrapping the slicing in a trusted function whose signature
//! states the bound moves the obligation to the caller, where it *is* checked.

/// Copy the first `count` elements of `src` into the start of `dst`.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [T][@n], src: &[T][@m], count: usize) requires count <= n && count <= m)]
#[flux_rs::no_panic]
pub fn copy_prefix<T: Copy>(dst: &mut [T], src: &[T], count: usize) {
    dst[..count].copy_from_slice(&src[..count]);
}

/// Borrow the first `n` elements of `data`.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[T][@len], n: usize) -> &[T][n] requires n <= len)]
#[flux_rs::no_panic]
pub fn prefix<T>(data: &[T], n: usize) -> &[T] {
    &data[..n]
}

/// Borrow everything from `at` onwards.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[T][@len], at: usize) -> &[T][len - at] requires at <= len)]
#[flux_rs::no_panic]
pub fn suffix<T>(data: &[T], at: usize) -> &[T] {
    &data[at..]
}

/// Borrow `len` elements of `data` starting at `at`.
///
/// Needed where the slice is reached through a `Deref` (e.g. `ManagedSlice`): the `Range`
/// index's `output_pred` does not survive the auto-deref, so the result's length is unknown
/// even when the in-bounds fact is available.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [T][@n], at: usize, len: usize) -> &mut [T][len] requires at + len <= n)]
#[flux_rs::no_panic]
pub fn sub_mut<T>(data: &mut [T], at: usize, len: usize) -> &mut [T] {
    &mut data[at..at + len]
}

/// Shared counterpart of [`sub_mut`].
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[T][@n], at: usize, len: usize) -> &[T][len] requires at + len <= n)]
#[flux_rs::no_panic]
pub fn sub<T>(data: &[T], at: usize, len: usize) -> &[T] {
    &data[at..at + len]
}

/// Mutable counterpart of [`suffix`].
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [T][@len], at: usize) -> &mut [T][len - at] requires at <= len)]
#[flux_rs::no_panic]
pub fn suffix_mut<T>(data: &mut [T], at: usize) -> &mut [T] {
    &mut data[at..]
}
