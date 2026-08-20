//! `byteorder` specs.
//!
//! byteorder is compiled without flux, so its bodies are `NoMIRAvailable` and every call
//! reads as possibly-panicking. Each body below is a `buf[..N]` reslice, so `N <= len` is
//! the whole precondition.
//!
//! `NetworkEndian` is an alias for `BigEndian`; these cover both spellings. Only the widths
//! xarxa calls are specified -- the rest of the trait stays unspecified.

// Referenced only from `extern_spec` bodies, which are stripped in non-flux builds.
#[allow(unused_imports)]
use ::byteorder::{BigEndian, ByteOrder};

use flux_rs::*;

#[extern_spec(byteorder)]
impl ByteOrder for BigEndian {
    /// byteorder 1.5.0 `src/lib.rs:1940`: `u16::from_be_bytes(buf[..2].try_into().unwrap())`
    /// <https://docs.rs/byteorder/1.5.0/src/byteorder/lib.rs.html#1940>
    #[no_panic]
    #[spec(fn(buf: &[u8]{v: 2 <= v}) -> u16)]
    fn read_u16(buf: &[u8]) -> u16;

    /// byteorder 1.5.0 `src/lib.rs:1978`: `buf[..2].copy_from_slice(&n.to_be_bytes())`
    /// <https://docs.rs/byteorder/1.5.0/src/byteorder/lib.rs.html#1978>
    #[no_panic]
    #[spec(fn(buf: &mut [u8]{v: 2 <= v}, n: u16))]
    fn write_u16(buf: &mut [u8], n: u16);

    /// byteorder 1.5.0 `src/lib.rs:1945`: `u32::from_be_bytes(buf[..4].try_into().unwrap())`
    /// <https://docs.rs/byteorder/1.5.0/src/byteorder/lib.rs.html#1945>
    #[no_panic]
    #[spec(fn(buf: &[u8]{v: 4 <= v}) -> u32)]
    fn read_u32(buf: &[u8]) -> u32;

    /// byteorder 1.5.0 `src/lib.rs:1983`: `buf[..4].copy_from_slice(&n.to_be_bytes())`
    /// <https://docs.rs/byteorder/1.5.0/src/byteorder/lib.rs.html#1983>
    #[no_panic]
    #[spec(fn(buf: &mut [u8]{v: 4 <= v}, n: u32))]
    fn write_u32(buf: &mut [u8], n: u32);
}
