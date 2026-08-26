//! `core::str` specs xarxa states on its own behalf.

use flux_rs::*;

/// UTF-8 validation walks the bytes and returns `Err` on a bad sequence; it has no failure
/// mode that panics. Without this, every `str::from_utf8` in the DHCP option parser owes a
/// proof no caller can construct.
/// <https://doc.rust-lang.org/1.89.0/src/core/str/converts.rs.html#89>
#[extern_spec(core::str)]
#[no_panic]
fn from_utf8(v: &[u8]) -> Result<&str, core::str::Utf8Error>;
