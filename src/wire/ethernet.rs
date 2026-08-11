use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{Error, Result};

enum_with_unknown! {
    /// Ethernet protocol type.
    pub enum EtherType(u16) {
        Ipv4 = 0x0800,
        Arp  = 0x0806,
        Ipv6 = 0x86DD
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EtherType::Ipv4 => write!(f, "IPv4"),
            EtherType::Ipv6 => write!(f, "IPv6"),
            EtherType::Arp => write!(f, "ARP"),
            EtherType::Unknown(id) => write!(f, "0x{id:04x}"),
        }
    }
}

/// A six-octet Ethernet II address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[repr(C)]
#[flux_rs::refined_by(o0: int)]
pub struct Address {
    #[flux_rs::field(u8[o0])]
    o0: u8,
    rest: [u8; 5],
}

// `as_bytes` below reinterprets an `Address` as six contiguous octets. These make the
// premise of that `unsafe` a compile error rather than silent UB if the layout ever
// drifts — e.g. if a field is added, reordered, or `#[repr(C)]` is dropped.
const _: () = assert!(core::mem::size_of::<Address>() == 6);
const _: () = assert!(core::mem::align_of::<Address>() == 1);

impl Address {
    /// The broadcast address.
    pub const BROADCAST: Address = Address::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    /// Construct an Ethernet address from six octets, in big-endian.
    ///
    /// Unlike [`from_bytes`](Self::from_bytes) this preserves the value of the first
    /// octet in the refinement, so an address built from literals here is the only
    /// kind that can be statically known to be unicast.
    #[flux_rs::sig(fn(u8[@a0], u8, u8, u8, u8, u8) -> Address[a0])]
    pub const fn new(a0: u8, a1: u8, a2: u8, a3: u8, a4: u8, a5: u8) -> Address {
        Address {
            o0: a0,
            rest: [a1, a2, a3, a4, a5],
        }
    }

    /// Construct an Ethernet address from an array of octets, in big-endian.
    #[flux_rs::sig(fn([u8; 6]) -> Address)]
    pub const fn from_octets(octets: [u8; 6]) -> Address {
        Address::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        )
    }

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// The refinement is left unconstrained: an address that came off the wire is not
    /// provably unicast, which is the correct conclusion.
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    #[flux_rs::trusted(no, reason = "proves the six-octet copy_from_slice cannot panic")]
    #[flux_rs::sig(fn(&[u8][6]) -> Address)]
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        Address::from_octets(bytes)
    }

    /// Return an Ethernet address as an array of octets, in big-endian.
    #[flux_rs::sig(fn(&Address) -> [u8; 6])]
    pub const fn octets(&self) -> [u8; 6] {
        [
            self.o0,
            self.rest[0],
            self.rest[1],
            self.rest[2],
            self.rest[3],
            self.rest[4],
        ]
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    //
    // Borrowing the octets out of the split representation is the one place the
    // layout costs us something: it needs a pointer cast, so the function is
    // `trusted`. Note that this is a *layout* axiom, not a claim about the unicast
    // refinement — the chain that licenses the panic removal stays trusted-free.
    // The `[u8][6]` result keeps the length available to callers that would
    // otherwise lose it (e.g. `copy_from_slice` into a six-byte field).
    #[allow(unsafe_code)]
    #[flux_rs::trusted]
    #[flux_rs::sig(fn(&Address) -> &[u8][6])]
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY: `Address` is `#[repr(C)]` and every field is `u8` or an array of
        // `u8`, so it has alignment 1, contains no padding, and is exactly six
        // contiguous initialised bytes laid out in declaration order.
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(self).cast::<u8>(), 6) }
    }

    /// Query whether the address is an unicast address.
    //
    #[flux_rs::trusted(no, reason = "backs HardwareAddress[true]")]
    #[flux_rs::sig(fn(&Address[@o0]) -> bool[o0 % 2 == 0])]
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// Query whether this address is the broadcast address.
    #[flux_rs::trusted(no, reason = "backs HardwareAddress[true]")]
    #[flux_rs::sig(fn(&Address[@o0]) -> bool{b: b => o0 == 255})]
    pub const fn is_broadcast(&self) -> bool {
        matches!(
            self,
            Address {
                o0: 0xff,
                rest: [0xff, 0xff, 0xff, 0xff, 0xff]
            }
        )
    }

    /// Query whether the "multicast" bit in the OUI is set.
    #[flux_rs::trusted(no, reason = "backs HardwareAddress[true]")]
    #[flux_rs::sig(fn(&Address[@o0]) -> bool[o0 % 2 == 1])]
    pub const fn is_multicast(&self) -> bool {
        self.o0 % 2 == 1
    }

    /// Query whether the "locally administered" bit in the OUI is set.
    pub const fn is_local(&self) -> bool {
        self.o0 & 0x02 != 0
    }

    /// Convert the address to an Extended Unique Identifier (EUI-64)
    pub fn as_eui_64(&self) -> Option<[u8; 8]> {
        let octets = self.octets();
        let mut bytes = [0; 8];
        bytes[0..3].copy_from_slice(&octets[0..3]);
        bytes[3] = 0xFF;
        bytes[4] = 0xFE;
        bytes[5..8].copy_from_slice(&octets[3..6]);
        bytes[0] ^= 1 << 1;
        Some(bytes)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.octets();
        write!(
            f,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, fmt: defmt::Formatter) {
        let bytes = self.octets();
        defmt::write!(
            fmt,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5]
        )
    }
}

/// A read/write wrapper around an Ethernet II frame buffer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(buf: T)]
pub struct Frame<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buf])]
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    #[flux_rs::constant(core::ops::Range { start: 0, end: 6 })]
    pub const DESTINATION: Field = 0..6;
    #[flux_rs::constant(core::ops::Range { start: 6, end: 12 })]
    pub const SOURCE: Field = 6..12;
    #[flux_rs::constant(core::ops::Range { start: 12, end: 14 })]
    pub const ETHERTYPE: Field = 12..14;
    #[flux_rs::constant(core::ops::RangeFrom { start: 14 })]
    pub const PAYLOAD: Rest = 14..;
}

/// The Ethernet header length
pub const HEADER_LEN: usize = field::PAYLOAD.start;

impl<T: AsRef<[u8]>> Frame<T> {
    /// Imbue a raw octet buffer with Ethernet frame structure.
    pub const fn new_unchecked(buffer: T) -> Frame<T> {
        Frame { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    //
    // The doc comment above is the whole specification, and the return type now
    // states it: `Ok` implies the buffer is at least a header long, which is
    // exactly the precondition every accessor below requires. A caller that
    // matches on the `Ok` arm discharges those preconditions locally instead of
    // propagating a `requires` of its own -- see `Repr::parse`.
    #[flux_rs::trusted(no, reason = "establishes the accessor precondition in the return type")]
    #[flux_rs::sig(fn(&Frame<T>[@buf]) -> Result<()>{ok: ok => <T as AsRef<[u8]>>::idx(buf) >= HEADER_LEN})]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < HEADER_LEN { Err(Error) } else { Ok(()) }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the length of a frame header.
    pub const fn header_len() -> usize {
        HEADER_LEN
    }

    /// Return the length of a buffer required to hold a packet with the payload
    /// of a given length.
    pub const fn buffer_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    /// Return the destination address field.
    #[inline]
    #[flux_rs::trusted(no, reason = "proves the destination address read is in bounds")]
    #[flux_rs::sig(fn(&Frame<T>[@buf]) -> Address
        requires <T as AsRef<[u8]>>::idx(buf) >= field::DESTINATION.end)]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DESTINATION])
    }

    /// Return the source address field.
    #[inline]
    #[flux_rs::trusted(no, reason = "proves the source address read is in bounds")]
    #[flux_rs::sig(fn(&Frame<T>[@buf]) -> Address
        requires <T as AsRef<[u8]>>::idx(buf) >= field::SOURCE.end)]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SOURCE])
    }

    /// Return the EtherType field, without checking for 802.1Q.
    #[inline]
    #[flux_rs::trusted(no, reason = "proves the ethertype read is in bounds")]
    #[flux_rs::sig(fn(&Frame<T>[@buf]) -> EtherType
        requires <T as AsRef<[u8]>>::idx(buf) >= field::ETHERTYPE.end)]
    pub fn ethertype(&self) -> EtherType {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::ETHERTYPE]);
        EtherType::from(raw)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Frame<&'a T> {
    /// Return a pointer to the payload, without checking for 802.1Q.
    #[inline]
    // NOT PROVEN. `Frame<&'a T>` instantiates the struct parameter with `&T` for a
    // `?Sized` generic `T`, and Flux gives that the UNIT sort: `buf.buf` is `()`, so
    // the frame index carries no length and there is nothing a `requires` here can
    // say. (Measured: `requires false` verifies, so the precondition does reach the
    // body; `requires <&T as AsRef<[u8]>>::idx(buf) >= 14` does not discharge it,
    // because the blanket `AsRef for &T` impl has no spec and falls back to the
    // uninterpreted `opaque_idx`.) This line compiles to no panic site in the
    // firmware, so it is not one of the file's 7; the obligation stays with
    // `default_trusted`.
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    /// Set the destination address field.
    #[inline]
    #[flux_rs::trusted(no, reason = "proves the destination address write is in bounds")]
    #[flux_rs::sig(fn(&mut Frame<T>[@buf], Address)
        requires <T as AsMut<[u8]>>::idx(buf) >= field::DESTINATION.end)]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DESTINATION].copy_from_slice(value.as_bytes())
    }

    /// Set the source address field.
    #[inline]
    #[flux_rs::trusted(no, reason = "proves the source address write is in bounds")]
    #[flux_rs::sig(fn(&mut Frame<T>[@buf], Address)
        requires <T as AsMut<[u8]>>::idx(buf) >= field::SOURCE.end)]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SOURCE].copy_from_slice(value.as_bytes())
    }

    /// Set the EtherType field.
    #[inline]
    #[flux_rs::trusted(no, reason = "proves the ethertype write is in bounds")]
    #[flux_rs::sig(fn(&mut Frame<T>[@buf], EtherType)
        requires <T as AsMut<[u8]>>::idx(buf) >= field::ETHERTYPE.end)]
    pub fn set_ethertype(&mut self, value: EtherType) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ETHERTYPE], value.into())
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    #[flux_rs::trusted(no, reason = "proves the payload slice is in bounds")]
    #[flux_rs::sig(fn(&mut Frame<T>[@buf]) -> &mut [u8]
        requires <T as AsMut<[u8]>>::idx(buf) >= field::PAYLOAD.start)]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::PAYLOAD]
    }
}

#[flux_rs::assoc(fn idx(s: Self) -> int { <T as AsRef<[u8]>>::idx(s.buf) })]
impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    #[flux_rs::trusted(no, reason = "carries the buffer length through the AsRef impl")]
    #[flux_rs::sig(fn(&Frame<T>[@s]) -> &[u8][<T as AsRef<[u8]>>::idx(s.buf)])]
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EthernetII src={} dst={} type={}",
            self.src_addr(),
            self.dst_addr(),
            self.ethertype()
        )
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Frame<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        let frame = match Frame::new_checked(buffer) {
            Err(err) => return write!(f, "{indent}({err})"),
            Ok(frame) => frame,
        };
        write!(f, "{indent}{frame}")?;

        match frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EtherType::Arp => {
                indent.increase(f)?;
                super::ArpPacket::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            #[cfg(feature = "proto-ipv4")]
            EtherType::Ipv4 => {
                indent.increase(f)?;
                super::Ipv4Packet::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            #[cfg(feature = "proto-ipv6")]
            EtherType::Ipv6 => {
                indent.increase(f)?;
                super::Ipv6Packet::<&[u8]>::pretty_print(&frame.payload(), f, indent)
            }
            _ => Ok(()),
        }
    }
}

/// A high-level representation of an Internet Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    pub src_addr: Address,
    pub dst_addr: Address,
    pub ethertype: EtherType,
}

impl Repr {
    /// Parse an Ethernet II frame and return a high-level representation.
    //
    // THE CONE TERMINATES HERE, and the `match` is why. `check_len`'s return type
    // says `Ok` implies the buffer is at least `HEADER_LEN` long, which is exactly
    // what the three accessors below require -- but `?` discards that evidence
    // (measured: with `frame.check_len()?;` all three accessor calls report "a
    // precondition cannot be proved"). Matching on the result keeps it, so `parse`
    // discharges the obligation locally and needs no `requires` of its own.
    //
    // `Err(e) => return Err(e)` is exactly what `?` compiles to here: xarxa has one
    // error type (`wire::Result<T> = Result<T, Error>`), so `?`'s `From::from` is
    // the identity. Runtime behaviour is unchanged.
    #[flux_rs::trusted(no, reason = "the accessor preconditions are established by check_len")]
    pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &Frame<&T>) -> Result<Repr> {
        match frame.check_len() {
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        Ok(Repr {
            src_addr: frame.src_addr(),
            dst_addr: frame.dst_addr(),
            ethertype: frame.ethertype(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    #[flux_rs::trusted(no, reason = "pins the constant so emit's assert is provable")]
    #[flux_rs::sig(fn(&Repr) -> usize[HEADER_LEN])]
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into an Ethernet II frame.
    //
    // Both bounds are needed and they are genuinely different facts: the `assert!`
    // reads the buffer through `AsRef` and the three setters write it through
    // `AsMut`, and `AsRef::idx` and `AsMut::idx` are unrelated associated
    // refinements. With the `AsRef` half stated the `assert!` is proven dead, so
    // this function has no residual panic obligation of its own -- it propagates
    // one, to its callers.
    #[flux_rs::trusted(no, reason = "proves the assert dead and the three setter bounds")]
    #[flux_rs::sig(fn(&Repr, &mut Frame<T>[@buf])
        requires <T as AsMut<[u8]>>::idx(buf) >= HEADER_LEN
              && <T as AsRef<[u8]>>::idx(buf) >= HEADER_LEN)]
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Frame<T>) {
        assert!(frame.buffer.as_ref().len() >= self.buffer_len());
        frame.set_src_addr(self.src_addr);
        frame.set_dst_addr(self.dst_addr);
        frame.set_ethertype(self.ethertype);
    }
}

#[cfg(test)]
mod test {
    // Tests that are valid with any combination of
    // "proto-*" features.
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
        assert!(Address::BROADCAST.is_multicast());
        assert!(Address::BROADCAST.is_local());
    }
}

#[cfg(test)]
#[cfg(feature = "proto-ipv4")]
mod test_ipv4 {
    // Tests that are valid only with "proto-ipv4"
    use super::*;

    static FRAME_BYTES: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x08, 0x00, 0xaa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff,
    ];

    static PAYLOAD_BYTES: [u8; 50] = [
        0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_deconstruct() {
        let frame = Frame::new_unchecked(&FRAME_BYTES[..]);
        assert_eq!(
            frame.dst_addr(),
            Address::from_octets([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            frame.src_addr(),
            Address::from_octets([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
        assert_eq!(frame.ethertype(), EtherType::Ipv4);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 64];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address::from_octets([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address::from_octets([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv4);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&frame.into_inner()[..], &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
#[cfg(feature = "proto-ipv6")]
mod test_ipv6 {
    // Tests that are valid only with "proto-ipv6"
    use super::*;

    static FRAME_BYTES: [u8; 54] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x86, 0xdd, 0x60,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    static PAYLOAD_BYTES: [u8; 40] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_deconstruct() {
        let frame = Frame::new_unchecked(&FRAME_BYTES[..]);
        assert_eq!(
            frame.dst_addr(),
            Address::from_octets([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            frame.src_addr(),
            Address::from_octets([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
        assert_eq!(frame.ethertype(), EtherType::Ipv6);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 54];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address::from_octets([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address::from_octets([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv6);
        assert_eq!(PAYLOAD_BYTES.len(), frame.payload_mut().len());
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&frame.into_inner()[..], &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
mod layout_test {
    use super::*;
    #[test]
    fn address_is_still_six_bytes() {
        assert_eq!(core::mem::size_of::<Address>(), 6);
        assert_eq!(core::mem::align_of::<Address>(), 1);
        let a = Address::new(0x12, 0x22, 0x33, 0x44, 0x55, 0x66);
        assert_eq!(a.as_bytes(), &[0x12, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(a.octets(), [0x12, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(
            Address::from_bytes(&[0x12, 0x22, 0x33, 0x44, 0x55, 0x66]),
            a
        );
        assert!(Address::BROADCAST.is_broadcast());
        assert!(Address::BROADCAST.is_multicast());
        assert!(!Address::BROADCAST.is_unicast());
        // Even first octet -> unicast; odd -> multicast. Only octet 0 matters.
        assert!(a.is_unicast() && !a.is_multicast());
        let m = Address::new(0x13, 0x22, 0x33, 0x44, 0x55, 0x66);
        assert!(m.is_multicast() && !m.is_unicast());
    }
}
