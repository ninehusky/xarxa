//! Trusted slice primitives shared by the `wire` and `storage` layers.
//!
//! Each one exists for the same reason: a `&mut` sub-slice is a *returned* reference, and flux
//! drops its length index on the way back to the caller (flux-rs/flux#1714). That makes
//! `copy_from_slice`'s equal-length precondition unprovable at the call site even when the
//! lengths are obviously equal. Wrapping the slicing in a trusted function whose signature
//! states the bound moves the obligation to the caller, where it *is* checked.
//!
//! The bodies use the unchecked slice primitives. That is the point of the `requires` clauses:
//! each one is the exact safety condition of the `get_unchecked*` / `copy_nonoverlapping` it
//! guards, discharged by the caller and checked by flux at every call site, rather than by a
//! branch at run time. These are *boundary* obligations -- a caller owes them -- so a caller
//! that cannot prove one gets an error rather than silence.

/// Copy the first `count` elements of `src` into the start of `dst`.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [T][@n], src: &[T][@m], count: usize) requires count <= n && count <= m)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
pub fn copy_prefix<T: Copy>(dst: &mut [T], src: &[T], count: usize) {
    // SAFETY: `count <= n` and `count <= m` are preconditions, discharged by the caller and
    // checked by Flux at every call site, so both ranges are in bounds. `dst` is a unique
    // borrow and `src` a shared one, so the two regions cannot overlap. `T: Copy` rules out
    // a drop obligation on the overwritten elements.
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), count) }
}

/// Borrow the first `n` elements of `data`.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[T][@len], n: usize) -> &[T][n] requires n <= len)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
pub fn prefix<T>(data: &[T], n: usize) -> &[T] {
    // SAFETY: `n <= len` is a precondition, discharged by the caller.
    unsafe { data.get_unchecked(..n) }
}

/// Borrow everything from `at` onwards.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[T][@len], at: usize) -> &[T][len - at] requires at <= len)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
pub fn suffix<T>(data: &[T], at: usize) -> &[T] {
    // SAFETY: `at <= len` is a precondition, discharged by the caller.
    unsafe { data.get_unchecked(at..) }
}

/// Borrow `len` elements of `data` starting at `at`.
///
/// Needed where the slice is reached through a `Deref` (e.g. `ManagedSlice`): the `Range`
/// index's `output_pred` does not survive the auto-deref, so the result's length is unknown
/// even when the in-bounds fact is available.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [T][@n], at: usize, len: usize) -> &mut [T][len] requires at + len <= n)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
pub fn sub_mut<T>(data: &mut [T], at: usize, len: usize) -> &mut [T] {
    // SAFETY: `at + len <= n` is a precondition, discharged by the caller, so `at <= at + len`
    // is a valid range within bounds. It also rules out the `at + len` overflow, since the sum
    // is bounded by a slice length.
    unsafe { data.get_unchecked_mut(at..at + len) }
}

/// Shared counterpart of [`sub_mut`].
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[T][@n], at: usize, len: usize) -> &[T][len] requires at + len <= n)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
pub fn sub<T>(data: &[T], at: usize, len: usize) -> &[T] {
    // SAFETY: see `sub_mut`.
    unsafe { data.get_unchecked(at..at + len) }
}

/// Mutable counterpart of [`suffix`].
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&mut [T][@len], at: usize) -> &mut [T][len - at] requires at <= len)]
#[flux_rs::no_panic]
#[allow(unsafe_code)]
pub fn suffix_mut<T>(data: &mut [T], at: usize) -> &mut [T] {
    // SAFETY: `at <= len` is a precondition, discharged by the caller.
    unsafe { data.get_unchecked_mut(at..) }
}
