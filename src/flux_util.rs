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

/// `data.len()`, carrying Rust's guarantee that a `[u8]` is at most `isize::MAX` bytes long.
///
/// Needed wherever a length is *added* under `check_overflow = "strict"`. Flux gives a slice
/// length index no upper bound, so `8 + data.len()` reads as a possible overflow; under the
/// crate's default `lazy` the same expression is modelled as wrapping and cannot be equated
/// with the refinement-level `8 + m` either. This is the one fact that closes both, and it is a
/// language guarantee flux cannot see, not an index: no single allocation may exceed
/// `isize::MAX` bytes, and for `[u8]` the length *is* the size.
///
/// Restricted to `[u8]` on purpose -- the bound is false for a slice of zero-sized elements.
#[flux_rs::trusted(yes, reason = "core guarantees an allocation is at most isize::MAX bytes")]
#[cfg_attr(not(target_pointer_width = "32"),
    flux_rs::sig(fn(&[u8][@n]) -> usize{v: v == n && n <= 9223372036854775807}))]
#[cfg_attr(target_pointer_width = "32",
    flux_rs::sig(fn(&[u8][@n]) -> usize{v: v == n && n <= 2147483647}))]
#[flux_rs::no_panic]
pub const fn byte_len(data: &[u8]) -> usize {
    data.len()
}

/// The index of the first zero octet, or `data.len()` if there is none.
///
/// `Iterator::position` states that its index is below the slice's length, but it hands that
/// back inside an `Option`, and `Option`'s payload carries no refinement here -- xarxa cannot
/// register a spec for it, see `wire::tcp::SackBlock`. The bound is lost at the `?`, and the
/// truncation that follows keeps a bounds check it does not need.
///
/// Returning `n` for "not found" is the same information `None` carried: the caller tests it the
/// way it tested `None`, and gets a length it can slice with.
#[flux_rs::sig(fn(&[u8][@n]) -> usize{v: v <= n})]
#[flux_rs::no_panic]
pub fn first_nul(data: &[u8]) -> usize {
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0 {
            return i;
        }
        i += 1;
    }
    i
}

/// `n as i32`, for an `n` the caller has already shown fits.
///
/// Flux does not model a `usize -> i32` cast, so `n as i32` reads as an unconstrained `i32` and
/// nothing downstream of it can be named. `n <= i32::MAX` is exactly the condition under which
/// the cast is the identity on the value, so it is the caller's obligation, not a claim made
/// here -- the same shape as [`byte_len`] above, which states a language guarantee flux cannot
/// derive.
///
/// This retires no panic. `SeqNumber`'s `Add`/`Sub` still test `rhs` and still panic on the same
/// inputs; the test is what discharges the bound below, and removing it would leave this
/// undischarged rather than silently widen anything.
#[flux_rs::trusted(yes, reason = "flux does not model a usize -> i32 cast")]
#[flux_rs::sig(fn(n: usize{n <= 2147483647}) -> i32[n])]
#[flux_rs::no_panic]
pub const fn usize_to_i32(n: usize) -> i32 {
    n as i32
}

/// `a == b` for byte slices, open-coded.
///
/// `[T] == [U; N]` goes through a generic `T: PartialEq<U>`, so flux reaches it as
/// `MightPanic(Transitive)` and every comparison of two byte arrays owes a proof no caller can
/// construct. Comparing bytes cannot fail; restricting to `[u8]` is what makes that statable,
/// the same device as [`byte_len`]. The body is exactly what `PartialEq for [T]` does: compare
/// the lengths, then the elements.
#[flux_rs::no_panic]
#[flux_rs::sig(fn(&[u8][@n], &[u8][@m]) -> bool)]
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
