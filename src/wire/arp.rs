use core::fmt;

use super::{Error, Ref, Result};
use super::{EthernetAddress, Ipv4Address};
use super::{copy_window_at, read_u16_at, sub, write_u16_at};

pub use super::EthernetProtocol as Protocol;

enum_with_unknown! {
    /// ARP hardware type.
    pub enum Hardware(u16) {
        Ethernet = 1
    }
}

enum_with_unknown! {
    /// ARP operation type.
    pub enum Operation(u16) {
        Request = 1,
        Reply = 2
    }
}

/// A ghost field: carries an integer in the refinement and nothing at runtime.
///
/// ARP's field offsets are functions of `hardware_len` and `protocol_len`, which live in the
/// buffer's *contents* -- and contents are not in the refinement, so no accessor's bound can
/// mention them. This is the way to name them anyway. `Packet` holds two of these, and because
/// the struct is a ZST it costs no space and `Packet<T>`'s layout is unchanged.
///
/// The values are anchored by [`Packet::hardware_len`] and [`Packet::protocol_len`], the two
/// trusted getters that assert the header byte equals the ghost. Everything else is proved.
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val && val <= 255)]
#[derive(PartialEq, Eq, Clone, Copy)]
struct Ghost;

impl Ghost {
    /// A ghost whose value is unconstrained.
    #[flux_rs::trusted(yes, reason = "opaque: the ghost carries no runtime value")]
    #[flux_rs::sig(fn() -> Ghost{v: 0 <= v && v <= 255})]
    #[flux_rs::no_panic]
    const fn unknown() -> Ghost {
        Ghost
    }

    /// A ghost pinned to `val`.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the ghost value")]
    #[flux_rs::sig(fn(val: u8) -> Ghost[val])]
    #[flux_rs::no_panic]
    const fn new(_val: u8) -> Ghost {
        Ghost
    }
}

/// A read/write wrapper around an Address Resolution Protocol packet buffer.
#[derive(PartialEq, Eq, Clone)]
#[flux_rs::refined_by(buffer: T, hlen: int, plen: int)]
#[flux_rs::invariant(0 <= hlen && hlen <= 255 && 0 <= plen && plen <= 255)]
pub struct Packet<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
    #[flux_rs::field(Ghost[hlen])]
    hlen: Ghost,
    #[flux_rs::field(Ghost[plen])]
    plen: Ghost,
}

// Written out rather than derived so the ghosts stay out of the output: a derive would print
// `Packet { buffer: .., hlen: Ghost, plen: Ghost }`, and the ghosts are not supposed to be
// observable. These reproduce the derived form for the one field that existed before.
impl<T: AsRef<[u8]> + fmt::Debug> fmt::Debug for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Packet").field("buffer", &self.buffer).finish()
    }
}

#[cfg(feature = "defmt")]
impl<T: AsRef<[u8]> + defmt::Format> defmt::Format for Packet<T> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "Packet {{ buffer: {} }}", self.buffer)
    }
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const HTYPE: Field = 0..2;
    pub const PTYPE: Field = 2..4;
    pub const HLEN: usize = 4;
    pub const PLEN: usize = 5;
    pub const OPER: Field = 6..8;

    #[inline]
    pub const fn SHA(hardware_len: u8, _protocol_len: u8) -> Field {
        let start = OPER.end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn SPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SHA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }

    #[inline]
    pub const fn THA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SPA(hardware_len, protocol_len).end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn TPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = THA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with ARP packet structure.
    ///
    /// The two ghosts start unconstrained: this reads nothing, so it learns nothing. They are
    /// pinned to the header bytes the first time `hardware_len`/`protocol_len` is called.
    #[flux_rs::sig(fn(T[@b]) -> Packet<T>{p: p.buffer == b})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet {
            buffer,
            hlen: Ghost::unknown(),
            plen: Ghost::unknown(),
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_hardware_len] or
    /// [set_protocol_len].
    ///
    /// [set_hardware_len]: #method.set_hardware_len
    /// [set_protocol_len]: #method.set_protocol_len
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(fn(self: &Packet<T>[@p]) -> Result<()>)]
    #[flux_rs::no_panic]
    pub fn check_len(&self) -> Result<()> {
        match self.checked_len() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// [`check_len`](Self::check_len), returning the buffer length it validated.
    ///
    /// The whole of `check_len`; the public method just discards the length. It exists because
    /// `Result<()>`'s `Ok` payload is `()` and so carries no refinement, which leaves a caller
    /// with nothing to show for a successful check. Returning the length instead lets the `Ok`
    /// arm say something, and what it says is the postcondition every accessor below wants.
    ///
    /// Both tests are in the bound, the second one only because the ghosts make
    /// `hardware_len`/`protocol_len` nameable. `Repr::parse` matches them against `6` and `4`,
    /// which turns this into `28 <= v` and discharges the address accessors.
    #[allow(clippy::if_same_then_else)]
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@p])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
                             && 8 + 2 * p.hlen + 2 * p.plen <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();
        if len < 8 {
            // field::OPER.end
            Err(Error)
        } else {
            // field::TPA(hardware_len, protocol_len).end, in arithmetic flux can follow.
            let hardware_len = self.hardware_len() as usize;
            let protocol_len = self.protocol_len() as usize;
            if len < 8 + 2 * hardware_len + 2 * protocol_len {
                Err(Error)
            } else {
                Ok(len)
            }
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the hardware type field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Hardware
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        let data = self.buffer.as_ref();
        let raw = read_u16_at(data, 0); // field::HTYPE
        Hardware::from(raw)
    }

    /// Return the protocol type field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Protocol
        requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn protocol_type(&self) -> Protocol {
        let data = self.buffer.as_ref();
        let raw = read_u16_at(data, 2); // field::PTYPE
        Protocol::from(raw)
    }

    /// The octet at offset 4, with its bound proved and no claim about its value.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u8
        requires 5 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    fn hardware_len_octet(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::HLEN]
    }

    /// The octet at offset 5, with its bound proved and no claim about its value.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u8
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    fn protocol_len_octet(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::PLEN]
    }

    /// Return the hardware length field.
    ///
    /// One of the two anchors for the ghost fields: the return type *claims* the octet at
    /// offset 4 is `hlen`. Nothing proves that -- the buffer's contents are not in the
    /// refinement -- so it is the assumption the address accessors' bounds rest on, and it is
    /// kept true by [`set_hardware_len`](Self::set_hardware_len), the only thing that writes
    /// this octet, which updates the ghost in the same step.
    ///
    /// The read itself stays checked: the trusted body is a call and an index expression it
    /// does not contain. All this assumes is the equality, which is the part flux cannot see.
    #[flux_rs::trusted(yes, reason = "anchors the `hlen` ghost to the octet at offset 4")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u8[p.hlen]
        requires 5 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        self.hardware_len_octet()
    }

    /// Return the protocol length field.
    ///
    /// See [`hardware_len`](Self::hardware_len); this is the same anchor for `plen`.
    #[flux_rs::trusted(yes, reason = "anchors the `plen` ghost to the octet at offset 5")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u8[p.plen]
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        self.protocol_len_octet()
    }

    /// Return the operation field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Operation
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn operation(&self) -> Operation {
        let data = self.buffer.as_ref();
        let raw = read_u16_at(data, 6); // field::OPER
        Operation::from(raw)
    }

    /// Return the source hardware address field.
    ///
    /// The four address accessors take their offsets from the ghosts rather than from
    /// `field::SHA` and friends: those are `const fn`s returning `Range<usize>`, and flux cannot
    /// see through one, so `r.start <= r.end` is unprovable however well the length is known.
    /// The original spelling is kept in a trailing comment.
    #[flux_rs::trusted(no, reason = "panic site: reads a variable-length address field")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> &[u8][p.hlen]
        requires 8 + p.hlen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn source_hardware_addr(&self) -> &[u8] {
        let hardware_len = self.hardware_len() as usize;
        let data = self.buffer.as_ref();
        sub(data, 8, hardware_len) // field::SHA
    }

    /// Return the source protocol address field.
    #[flux_rs::trusted(no, reason = "panic site: reads a variable-length address field")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> &[u8][p.plen]
        requires 8 + p.hlen + p.plen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn source_protocol_addr(&self) -> &[u8] {
        let hardware_len = self.hardware_len() as usize;
        let protocol_len = self.protocol_len() as usize;
        let data = self.buffer.as_ref();
        sub(data, 8 + hardware_len, protocol_len) // field::SPA
    }

    /// Return the target hardware address field.
    #[flux_rs::trusted(no, reason = "panic site: reads a variable-length address field")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> &[u8][p.hlen]
        requires 8 + 2 * p.hlen + p.plen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn target_hardware_addr(&self) -> &[u8] {
        let hardware_len = self.hardware_len() as usize;
        let protocol_len = self.protocol_len() as usize;
        let data = self.buffer.as_ref();
        sub(data, 8 + hardware_len + protocol_len, hardware_len) // field::THA
    }

    /// Return the target protocol address field.
    #[flux_rs::trusted(no, reason = "panic site: reads a variable-length address field")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> &[u8][p.plen]
        requires 8 + 2 * p.hlen + 2 * p.plen <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn target_protocol_addr(&self) -> &[u8] {
        let hardware_len = self.hardware_len() as usize;
        let protocol_len = self.protocol_len() as usize;
        let data = self.buffer.as_ref();
        sub(data, 8 + 2 * hardware_len + protocol_len, protocol_len) // field::TPA
    }
}

impl<'a> Packet<Ref<'a>> {
    /// [`new_checked`](Self::new_checked), returning a [`CheckedPacket`].
    ///
    /// The only producer of the invariant `Display` reads. `checked_len`'s `Ok` arm states
    /// `8 + 2*p.hlen + 2*p.plen <= as_ref_reft(p.buffer)`, and at `T = Ref` that associated
    /// refinement *is* `buffer.len` -- so the invariant discharges here and nowhere else.
    pub fn new_checked_display(buffer: Ref<'a>) -> Result<CheckedPacket<'a>> {
        let packet = Packet::new_unchecked(buffer);
        packet.checked_len()?;
        Ok(CheckedPacket(packet))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the hardware type field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], _)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 0, value.into()) // field::HTYPE
    }

    /// Set the protocol type field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], _)
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_protocol_type(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 2, value.into()) // field::PTYPE
    }

    /// Set the hardware length field.
    ///
    /// Writes the ghost as well as the octet. This is the whole of what keeps
    /// [`hardware_len`](Self::hardware_len)'s claim true, so the two must not drift apart:
    /// `&strg` rather than `&mut` because a `&mut T{v: ..}` weakening does not compose through
    /// a call chain, and `Repr::emit` needs the new value to survive into the setters after it.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Packet<T>[@p], value: u8)
        requires 5 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures self: Packet<T>[p.buffer, value, p.plen]
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_hardware_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::HLEN] = value;
        self.hlen = Ghost::new(value);
    }

    /// Set the protocol length field.
    ///
    /// See [`set_hardware_len`](Self::set_hardware_len); this is the same for `plen`.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Packet<T>[@p], value: u8)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures self: Packet<T>[p.buffer, p.hlen, value]
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_protocol_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::PLEN] = value;
        self.plen = Ghost::new(value);
    }

    /// Set the operation field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], _)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 6, value.into()) // field::OPER
    }

    /// Set the source hardware address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    ///
    /// The assert is still there; `value: &[u8][p.hlen]` states the same condition where flux
    /// can see it, so a checked caller proves it cannot fire.
    #[flux_rs::trusted(no, reason = "panic site: writes a variable-length address field")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], value: &[u8][p.hlen])
        requires 5 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 + p.hlen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    pub fn set_source_hardware_addr(&mut self, value: &[u8]) {
        let hardware_len = self.hardware_len() as usize;
        let data = self.buffer.as_mut();
        copy_window_at(data, 8, hardware_len, value) // field::SHA
    }

    /// Set the source protocol address field.
    ///
    /// See [`set_source_hardware_addr`](Self::set_source_hardware_addr) for the length
    /// precondition.
    #[flux_rs::trusted(no, reason = "panic site: writes a variable-length address field")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], value: &[u8][p.plen])
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 + p.hlen + p.plen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    pub fn set_source_protocol_addr(&mut self, value: &[u8]) {
        let hardware_len = self.hardware_len() as usize;
        let protocol_len = self.protocol_len() as usize;
        let data = self.buffer.as_mut();
        copy_window_at(data, 8 + hardware_len, protocol_len, value) // field::SPA
    }

    /// Set the target hardware address field.
    ///
    /// See [`set_source_hardware_addr`](Self::set_source_hardware_addr) for the length
    /// precondition.
    #[flux_rs::trusted(no, reason = "panic site: writes a variable-length address field")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], value: &[u8][p.hlen])
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 + 2 * p.hlen + p.plen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    pub fn set_target_hardware_addr(&mut self, value: &[u8]) {
        let hardware_len = self.hardware_len() as usize;
        let protocol_len = self.protocol_len() as usize;
        let data = self.buffer.as_mut();
        copy_window_at(data, 8 + hardware_len + protocol_len, hardware_len, value) // field::THA
    }

    /// Set the target protocol address field.
    ///
    /// See [`set_source_hardware_addr`](Self::set_source_hardware_addr) for the length
    /// precondition.
    #[flux_rs::trusted(no, reason = "panic site: writes a variable-length address field")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], value: &[u8][p.plen])
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 + 2 * p.hlen + 2 * p.plen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    pub fn set_target_protocol_addr(&mut self, value: &[u8]) {
        let hardware_len = self.hardware_len() as usize;
        let protocol_len = self.protocol_len() as usize;
        let data = self.buffer.as_mut();
        copy_window_at(data, 8 + 2 * hardware_len + protocol_len, protocol_len, value) // field::TPA
    }
}

#[flux_rs::assoc(
    fn as_ref_reft(source: Self) -> int {
        <T as AsRef<[u8]>>::as_ref_reft(source.buffer)
    }
)]
impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    #[flux_rs::no_panic]
    #[flux_rs::sig(fn(self: &Self[@source]) -> &[u8][Self::as_ref_reft(source)])]
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an Address Resolution Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Repr {
    /// An Ethernet and IPv4 Address Resolution Protocol packet.
    EthernetIpv4 {
        operation: Operation,
        source_hardware_addr: EthernetAddress,
        source_protocol_addr: Ipv4Address,
        target_hardware_addr: EthernetAddress,
        target_protocol_addr: Ipv4Address,
    },
}

// `Repr::buffer_len` returns the literal 28 so the value is visible to the refinement; this
// makes that literal a compile error if the field layout ever drifts.
const _: () = assert!(field::TPA(6, 4).end == 28);

impl Repr {
    /// Parse an Address Resolution Protocol packet and return a high-level representation,
    /// or return `Err(Error)` if the packet is not recognized.
    ///
    /// `check_len` is matched on rather than `?`-ed: `?` discards the `Result`'s refinement,
    /// so the bound it proves does not survive into this body.
    #[flux_rs::trusted(no, reason = "gates every accessor below it")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> Result<Repr>)]
    pub fn parse<T: AsRef<[u8]>>(packet: &Packet<T>) -> Result<Repr> {
        match packet.checked_len() {
            Ok(_) => {}
            Err(e) => return Err(e),
        }

        match (
            packet.hardware_type(),
            packet.protocol_type(),
            packet.hardware_len(),
            packet.protocol_len(),
        ) {
            (Hardware::Ethernet, Protocol::Ipv4, 6, 4) => {
                Ok(Repr::EthernetIpv4 {
                    operation: packet.operation(),
                    source_hardware_addr: EthernetAddress::from_bytes(
                        packet.source_hardware_addr(),
                    ),
                    source_protocol_addr: Ipv4Address::from_octets(
                        packet.source_protocol_addr().try_into().unwrap(),
                    ),
                    target_hardware_addr: EthernetAddress::from_bytes(
                        packet.target_hardware_addr(),
                    ),
                    target_protocol_addr: Ipv4Address::from_octets(
                        packet.target_protocol_addr().try_into().unwrap(),
                    ),
                })
            }
            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    // The literal is `field::TPA(6, 4).end` for the one representation there is; written out
    // because flux cannot see through the `Field` (`Range`) const, and `dispatch_ethernet`
    // sizes its tx buffer by this value. The `const` assert above makes a drift in the field
    // layout a compile error rather than a silently wrong bound.
    #[flux_rs::trusted(no, reason = "carries the emitted length to the tx-buffer sizing")]
    #[flux_rs::sig(fn(&Repr) -> usize[28])]
    #[flux_rs::no_panic]
    pub const fn buffer_len(&self) -> usize {
        match *self {
            Repr::EthernetIpv4 { .. } => 28, // field::TPA(6, 4).end
        }
    }

    /// Emit a high-level representation into an Address Resolution Protocol packet.
    ///
    /// The `requires` is `buffer_len()` for the one representation there is: the caller must
    /// hand over a buffer long enough for what this writes, which is the same contract the
    /// method already had, now stated where a checker can see it.
    #[flux_rs::trusted(no, reason = "gates every setter below it")]
    #[flux_rs::sig(
        fn(&Repr, packet: &strg Packet<T>[@p])
        requires 28 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
              && 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
        ensures packet: Packet<T>[p.buffer, 6, 4]
    )]
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        match *self {
            Repr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => {
                packet.set_hardware_type(Hardware::Ethernet);
                packet.set_protocol_type(Protocol::Ipv4);
                packet.set_hardware_len(6);
                packet.set_protocol_len(4);
                packet.set_operation(operation);
                packet.set_source_hardware_addr(source_hardware_addr.as_bytes());
                packet.set_source_protocol_addr(&source_protocol_addr.octets());
                packet.set_target_hardware_addr(target_hardware_addr.as_bytes());
                packet.set_target_protocol_addr(&target_protocol_addr.octets());
            }
        }
    }
}

/// A [`Packet`] over a [`Ref`] whose header has been validated. DEMO.
///
/// `fmt::Display::fmt`'s signature is fixed, so it cannot carry the nine accessors' `requires`.
/// [`checked_len`](Packet::checked_len) already proves every one of them, but its `Ok` arm is an
/// *existential* refinement on the returned length and that does not survive a trait boundary.
/// A type **invariant** does, because it travels with the type rather than with a value's index
/// -- so the bound lives on a type only a checked construction can produce.
///
/// No runtime check is added and no panic is replaced. The check establishing this invariant is
/// the one `pretty_print` already ran; a short buffer still takes the `Err` arm and still prints
/// `({err})`. What changes is that the nine reads on the `Ok` path are now proved rather than
/// undischarged.
///
/// The strongest of the nine bounds is `target_protocol_addr`'s, and it implies the other eight:
/// `hlen` and `plen` are non-negative, so `8 + 2*hlen + 2*plen <= len` gives `8 <= len` and every
/// intermediate offset. `Packet`'s own octet bounds are restated here because a struct invariant
/// does not reach through to the wrapper's index.
#[flux_rs::refined_by(buffer: Ref, hlen: int, plen: int)]
#[flux_rs::invariant(0 <= hlen && hlen <= 255 && 0 <= plen && plen <= 255)]
#[flux_rs::invariant(8 + 2 * hlen + 2 * plen <= buffer.len)]
pub struct CheckedPacket<'a>(
    #[flux_rs::field(Packet<Ref>[buffer, hlen, plen])] Packet<Ref<'a>>,
);

impl<'a> CheckedPacket<'a> {
    /// The packet underneath, for consumers that re-derive what they need.
    ///
    /// The invariant belongs to `CheckedPacket` and does not travel with the reference.
    #[flux_rs::sig(fn(&Self[@c]) -> &Packet<Ref>[c.buffer, c.hlen, c.plen])]
    #[flux_rs::no_panic]
    pub fn as_packet(&self) -> &Packet<Ref<'a>> {
        &self.0
    }
}

impl fmt::Display for CheckedPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(&self.0) {
            Ok(repr) => write!(f, "{repr}"),
            _ => {
                write!(f, "ARP (unrecognized)")?;
                write!(
                    f,
                    " htype={:?} ptype={:?} hlen={:?} plen={:?} op={:?}",
                    self.0.hardware_type(),
                    self.0.protocol_type(),
                    self.0.hardware_len(),
                    self.0.protocol_len(),
                    self.0.operation()
                )?;
                write!(
                    f,
                    " sha={:?} spa={:?} tha={:?} tpa={:?}",
                    self.0.source_hardware_addr(),
                    self.0.source_protocol_addr(),
                    self.0.target_hardware_addr(),
                    self.0.target_protocol_addr()
                )?;
                Ok(())
            }
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Repr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => {
                write!(
                    f,
                    "ARP type=Ethernet+IPv4 src={source_hardware_addr}/{source_protocol_addr} tgt={target_hardware_addr}/{target_protocol_addr} op={operation:?}"
                )
            }
        }
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        // `Ref::new` off the `dyn`'s own `as_ref`: the trait signature is fixed, so the buffer
        // arrives with no length index, and `Ref` is where it acquires one. This already
        // validated before formatting; switching to `new_checked_display` is the entire
        // call-site cost of the change in this file.
        match Packet::new_checked_display(Ref::new(buffer.as_ref())) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(packet) => write!(f, "{indent}{packet}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 28] = [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x21,
        0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x41, 0x42, 0x43, 0x44,
    ];

    #[test]
    fn ghost_fields_are_not_observable() {
        let bytes = [0u8; 28];
        let packet = Packet::new_unchecked(&bytes[..]);
        let s = format!("{packet:?}");
        assert!(!s.contains("Ghost"), "ghosts leaked into Debug: {s}");
        assert!(s.starts_with("Packet { buffer: "), "Debug shape changed: {s}");
    }

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.protocol_type(), Protocol::Ipv4);
        assert_eq!(packet.hardware_len(), 6);
        assert_eq!(packet.protocol_len(), 4);
        assert_eq!(packet.operation(), Operation::Request);
        assert_eq!(
            packet.source_hardware_addr(),
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]
        );
        assert_eq!(packet.source_protocol_addr(), &[0x21, 0x22, 0x23, 0x24]);
        assert_eq!(
            packet.target_hardware_addr(),
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]
        );
        assert_eq!(packet.target_protocol_addr(), &[0x41, 0x42, 0x43, 0x44]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 28];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_protocol_type(Protocol::Ipv4);
        packet.set_hardware_len(6);
        packet.set_protocol_len(4);
        packet.set_operation(Operation::Request);
        packet.set_source_hardware_addr(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        packet.set_source_protocol_addr(&[0x21, 0x22, 0x23, 0x24]);
        packet.set_target_hardware_addr(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        packet.set_target_protocol_addr(&[0x41, 0x42, 0x43, 0x44]);
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }

    fn packet_repr() -> Repr {
        Repr::EthernetIpv4 {
            operation: Operation::Request,
            source_hardware_addr: EthernetAddress::from_bytes(&[
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            ]),
            source_protocol_addr: Ipv4Address::from_octets([0x21, 0x22, 0x23, 0x24]),
            target_hardware_addr: EthernetAddress::from_bytes(&[
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
            ]),
            target_protocol_addr: Ipv4Address::from_octets([0x41, 0x42, 0x43, 0x44]),
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let mut bytes = vec![0xa5; 28];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet_repr().emit(&mut packet);
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }
}
