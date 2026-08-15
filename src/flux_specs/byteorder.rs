//! `byteorder` specs. Third-party crate, not `core`, and entirely xarxa's claim.
//!
//! `byteorder` is compiled without flux, so its bodies are invisible (`NoMIRAvailable`) and
//! every call reads as possibly-panicking. `BigEndian`'s `read_u16`/`write_u16` bodies are
//! `buf[..2]`, so `2 <= buf.len()` is the whole of the panic precondition.
//!
//! `NetworkEndian` is a type alias for `BigEndian`, so these cover both spellings.
//!
//! Only the two widths xarxa calls are specified. `read_u32`, `write_u32`, and the rest of
//! the `ByteOrder` trait remain `NoMIRAvailable` -- unspecified, not assumed.

// Referenced only from `extern_spec` bodies, which are stripped in non-flux builds.
#[allow(unused_imports)]
use ::byteorder::{BigEndian, ByteOrder};

use flux_rs::*;

#[extern_spec(byteorder)]
impl ByteOrder for BigEndian {
    #[no_panic]
    #[spec(fn(buf: &[u8]{v: 2 <= v}) -> u16)]
    fn read_u16(buf: &[u8]) -> u16;

    #[no_panic]
    #[spec(fn(buf: &mut [u8]{v: 2 <= v}, n: u16))]
    fn write_u16(buf: &mut [u8], n: u16);
}
