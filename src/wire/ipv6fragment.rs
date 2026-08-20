use super::{Error, Result};
use core::fmt;

use crate::wire::{read_u16_at, read_u32_at, write_u16_at, write_u32_at};

/// A read/write wrapper around an IPv6 Fragment Header.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(buffer: T)]
pub struct Header<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
}

// Format of the Fragment Header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Identification                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc8200#section-4.5 for details.
//
// **NOTE**: The fields start counting after the header length field.
mod field {
    use crate::wire::field::*;

    // 16-bit field containing the fragment offset, reserved and more fragments values.
    pub const FR_OF_M: Field = 0..2;
    // 32-bit field identifying the fragmented packet
    pub const IDENT: Field = 2..6;
    /// 1 bit flag indicating if there are more fragments coming.
    pub const M: usize = 1;
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Fragment Header structure.
    pub const fn new_unchecked(buffer: T) -> Header<T> {
        Header { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(fn(self: &Header<T>[@h]) -> Result<()>)]
    #[flux_rs::no_panic]
    pub fn check_len(&self) -> Result<()> {
        match self.checked_len() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// [`check_len`](Self::check_len), returning the buffer length it validated.
    ///
    /// The whole of `check_len`; the public method just discards the length. `Result<()>`'s `Ok`
    /// payload carries no refinement, so a successful check leaves a caller with nothing to show
    /// for it. Returning the length lets the `Ok` arm say the two things the accessors below
    /// want: what the buffer's length is, and that it reaches the end of the header.
    ///
    /// Every field of this header is at a fixed offset and the header is fixed-size, so this
    /// single test is the whole precondition of the file -- there is no window whose extent
    /// depends on buffer *contents*, and hence no ghost field as in `arp`, `udp` and `tcp`.
    ///
    /// Nothing consumes the length yet: `Repr::parse` below instantiates `T` at a reference
    /// type, which flux gives the unit sort, so it cannot name `as_ref_reft` at all.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(h.buffer) && 6 <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < 6 {
            // field::IDENT.end
            Err(Error)
        } else {
            Ok(len)
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the fragment offset field.
    // Literal offsets rather than `field::FR_OF_M`: flux cannot see through the `Field` (`Range`)
    // const, so the bound has to be written out. Same throughout this file.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Header<T>[@h]) -> u16
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 0) >> 3 // field::FR_OF_M
    }

    /// Return more fragment flag field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Header<T>[@h]) -> bool
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[1] & 0x1) == 1 // field::M
    }

    /// Return the fragment identification value field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Header<T>[@h]) -> u32
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn ident(&self) -> u32 {
        let data = self.buffer.as_ref();
        read_u32_at(data, 2) // field::IDENT
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set reserved fields.
    ///
    /// Set 8-bit reserved field after the next header field.
    /// Set 2-bit reserved field between fragment offset and more fragments.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h])
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        // Retain the higher order 5 bits and lower order 1 bit
        data[1] &= 0xf9; // field::M
    }

    /// Set the fragment offset field.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: u16)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        // Retain the lower order 3 bits
        let raw = ((value & 0x1fff) << 3) | ((data[1] & 0x7) as u16); // field::M
        write_u16_at(data, 0, raw); // field::FR_OF_M
    }

    /// Set the more fragments flag field.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: bool)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        // Retain the high order 7 bits
        let raw = (data[1] & 0xfe) | (value as u8 & 0x1); // field::M
        data[1] = raw;
    }

    /// Set the fragmentation identification field.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: u32)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_ident(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        write_u32_at(data, 2, value); // field::IDENT
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "IPv6 Fragment ({err})")?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of an IPv6 Fragment header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    /// The offset of the data following this header, relative to the start of the Fragmentable
    /// Part of the original packet.
    pub frag_offset: u16,
    /// When there are more fragments following this header
    pub more_frags: bool,
    /// The identification for every packet that is fragmented.
    pub ident: u32,
}

impl Repr {
    /// Parse an IPv6 Fragment Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&T>) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        header.check_len()?;
        Ok(Repr {
            frag_offset: header.frag_offset(),
            more_frags: header.more_frags(),
            ident: header.ident(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        field::IDENT.end
    }

    /// Emit a high-level representation into an IPv6 Fragment Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        header.clear_reserved();
        header.set_frag_offset(self.frag_offset);
        header.set_more_frags(self.more_frags);
        header.set_ident(self.ident);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv6 Fragment offset={} more={} ident={}",
            self.frag_offset, self.more_frags, self.ident
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Fragment Header with more fragments remaining
    static BYTES_HEADER_MORE_FRAG: [u8; 6] = [0x0, 0x1, 0x0, 0x0, 0x30, 0x39];

    // A Fragment Header with no more fragments remaining
    static BYTES_HEADER_LAST_FRAG: [u8; 6] = [0xa, 0x0, 0x0, 0x1, 0x9, 0x32];

    #[test]
    fn test_check_len() {
        // less than 6 bytes
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_HEADER_MORE_FRAG[..5]).check_len()
        );
        // valid
        assert_eq!(
            Ok(()),
            Header::new_unchecked(&BYTES_HEADER_MORE_FRAG).check_len()
        );
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        assert_eq!(header.frag_offset(), 0);
        assert!(header.more_frags());
        assert_eq!(header.ident(), 12345);

        let header = Header::new_unchecked(&BYTES_HEADER_LAST_FRAG);
        assert_eq!(header.frag_offset(), 320);
        assert!(!header.more_frags());
        assert_eq!(header.ident(), 67890);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                frag_offset: 0,
                more_frags: true,
                ident: 12345
            }
        );

        let header = Header::new_unchecked(&BYTES_HEADER_LAST_FRAG);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                frag_offset: 320,
                more_frags: false,
                ident: 67890
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            frag_offset: 0,
            more_frags: true,
            ident: 12345,
        };
        let mut bytes = [0u8; 6];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_HEADER_MORE_FRAG[0..6]);

        let repr = Repr {
            frag_offset: 320,
            more_frags: false,
            ident: 67890,
        };
        let mut bytes = [0u8; 6];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_HEADER_LAST_FRAG[0..6]);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_HEADER_MORE_FRAG.len());
    }
}
