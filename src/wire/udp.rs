use core::fmt;

use super::{Error, Result};
use crate::phy::ChecksumCapabilities;
use crate::wire::ip::checksum;
use crate::wire::{IpAddress, IpProtocol};
use crate::wire::{prefix, read_u16_at, write_u16_at, Buf};

/// A ghost field: carries an integer in the refinement and nothing at runtime.
///
/// UDP's payload window is `8..length`, and `length` lives in the buffer's *contents* -- and
/// contents are not in the refinement, so no accessor's bound can mention it. This is the way
/// to name it anyway. `Packet` holds one of these, and because the struct is a ZST it costs no
/// space and `Packet<T>`'s layout is unchanged.
///
/// The value is anchored by [`Packet::len`], the trusted getter that claims the length field
/// equals the ghost. Everything else is proved.
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val && val <= 65535)]
#[derive(PartialEq, Eq, Clone, Copy)]
struct Ghost;

impl Ghost {
    /// A ghost whose value is unconstrained.
    #[flux_rs::trusted(yes, reason = "opaque: the ghost carries no runtime value")]
    #[flux_rs::sig(fn() -> Ghost{v: 0 <= v && v <= 65535})]
    #[flux_rs::no_panic]
    const fn unknown() -> Ghost {
        Ghost
    }

    /// A ghost pinned to `val`.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the ghost value")]
    #[flux_rs::sig(fn(val: u16) -> Ghost[val])]
    #[flux_rs::no_panic]
    const fn new(_val: u16) -> Ghost {
        Ghost
    }
}

/// A read/write wrapper around an User Datagram Protocol packet buffer.
#[derive(PartialEq, Eq, Clone)]
#[flux_rs::refined_by(buffer: T, len: int)]
#[flux_rs::invariant(0 <= len && len <= 65535)]
pub struct Packet<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
    #[flux_rs::field(Ghost[len])]
    glen: Ghost,
}

// Written out rather than derived so the ghost stays out of the output: a derive would print
// `Packet { buffer: .., glen: Ghost }`, and the ghost is not supposed to be observable. This
// reproduces the derived form for the one field that existed before.
impl<T: AsRef<[u8]> + fmt::Debug> fmt::Debug for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Packet")
            .field("buffer", &self.buffer)
            .finish()
    }
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const LENGTH: Field = 4..6;
    pub const CHECKSUM: Field = 6..8;

    pub const fn PAYLOAD(length: u16) -> Field {
        CHECKSUM.end..(length as usize)
    }
}

pub const HEADER_LEN: usize = field::CHECKSUM.end;

#[allow(clippy::len_without_is_empty)]
impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with UDP packet structure.
    ///
    /// The ghost starts unconstrained: this reads nothing, so it learns nothing. It is pinned
    /// to the length field the first time [`len`](Self::len) is called.
    #[flux_rs::sig(fn(T[@b]) -> Packet<T>{p: p.buffer == b})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet {
            buffer,
            glen: Ghost::unknown(),
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    ///
    /// Deliberately left unrefined. `checked_len` proves `8 <= len <= buffer_len`, and carrying
    /// that out through the `Ok` arm would be the natural next step -- but every caller today is
    /// at a reference or `dyn` self type (`iface/interface/udp.rs`, `ipv4.rs`, `wire/ip.rs`, and
    /// `PrettyPrint::pretty_print` below), so nothing can consume it, while `pretty_print`'s
    /// fixed trait signature over `&dyn AsRef<[u8]>` would gain an obligation no consumer could
    /// ever discharge. Worth doing the moment a reference self type can be refined; see
    /// `wire::Buf`.
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    /// Returns `Err(Error)` if the length field has a value smaller
    /// than the header length.
    ///
    /// The result of this check is invalidated by calling [set_len].
    ///
    /// [set_len]: #method.set_len
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
    /// arm say something, and what it says is exactly the three facts the accessors below want:
    /// the buffer's length is what it is, the length field is not a lie about the buffer, and
    /// the payload window `8..len` does not run backwards.
    ///
    /// All three tests were already here. The third is stated in the bound only because the
    /// ghost makes `len` nameable.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@p])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
                             && 8 <= p.len && p.len <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let buffer_len = self.buffer.as_ref().len();
        if buffer_len < 8 {
            // HEADER_LEN
            Err(Error)
        } else {
            let field_len = self.len() as usize;
            if buffer_len < field_len || field_len < 8 {
                // HEADER_LEN
                Err(Error)
            } else {
                Ok(buffer_len)
            }
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the source port field.
    // Literal offsets rather than `field::SRC_PORT`: flux cannot see through the `Field`
    // (`Range`) const, so the bound has to be written out. Same throughout this impl.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn src_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 0) // field::SRC_PORT
    }

    /// Return the destination port field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16
        requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 2) // field::DST_PORT
    }

    /// The u16 at offset 4, with its bound proved and no claim about its value.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    fn len_field(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 4) // field::LENGTH
    }

    /// Return the length field.
    ///
    /// The anchor for the ghost field: the return type *claims* the u16 at offset 4 is `len`.
    /// Nothing proves that -- the buffer's contents are not in the refinement -- so it is the
    /// assumption the payload and checksum windows rest on, and it is kept true by
    /// [`set_len`](Self::set_len), the only thing that writes those two octets, which updates
    /// the ghost in the same step.
    ///
    /// The read itself stays checked: the trusted body is a call, and the bound is discharged
    /// inside [`len_field`](Self::len_field). All this assumes is the equality, which is the
    /// part flux cannot see.
    #[flux_rs::trusted(yes, reason = "anchors the `len` ghost to the u16 at offset 4")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16[p.len]
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn len(&self) -> u16 {
        self.len_field()
    }

    /// Return the checksum field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 6) // field::CHECKSUM
    }

    /// Validate the partial packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    //
    // No `no_panic`: the family-mismatch panic above lives in `checksum::pseudo_header` and is a
    // *value* obligation on the two addresses, a different axis from the length work here. The
    // `requires` covers only the two header reads.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p], &IpAddress, &IpAddress) -> bool
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    pub fn verify_partial_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp, self.len() as u32)
            == self.checksum()
    }

    /// Validate the packet checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    //
    // See `verify_partial_checksum` for why there is no `no_panic`. `p.len <= as_ref_reft` is
    // the second half of what `checked_len` returns; it is what makes the `..len` window safe.
    #[flux_rs::trusted(no, reason = "panic site: reads the window named by the length field")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p], &IpAddress, &IpAddress) -> bool
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && p.len <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    pub fn verify_checksum(&self, src_addr: &IpAddress, dst_addr: &IpAddress) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        // From the RFC:
        // > An all zero transmitted checksum value means that the transmitter
        // > generated no checksum (for debugging or for higher level protocols
        // > that don't care).
        if self.checksum() == 0 {
            return true;
        }

        let length = self.len() as usize;
        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp, self.len() as u32),
            checksum::data(prefix(data, length)),
        ]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    //
    // Left bounds-checked. The buffer here is `&'a T`, so the length index would have to come
    // from core's blanket `impl<T, U> AsRef<U> for &T`, which carries no associated refinement
    // (`as_ref_reft` is missing). Both halves of the bound -- `8 <= len` and
    // `len <= as_ref_reft(buffer)` -- are therefore unstatable at this self type, not merely
    // unproven, so the ghost does not help here and neither would routing through a helper.
    // Convertible once a reference self type can be refined; see `wire::Buf`.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let length = self.len();
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD(length)]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the source port field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], _)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 0, value) // field::SRC_PORT
    }

    /// Set the destination port field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], _)
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 2, value) // field::DST_PORT
    }

    /// Set the length field.
    ///
    /// Writes the ghost as well as the octets. This is the whole of what keeps
    /// [`len`](Self::len)'s claim true, so the two must not drift apart: `&strg` rather than
    /// `&mut` because a `&mut T{v: ..}` weakening does not compose through a call chain, and
    /// `Repr::emit` needs the new value to survive into `payload_mut` after it.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Packet<T>[@p], value: u16)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures self: Packet<T>[p.buffer, value]
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 4, value); // field::LENGTH
        self.glen = Ghost::new(value);
    }

    /// Set the checksum field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], _)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 6, value) // field::CHECKSUM
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    //
    // See `verify_partial_checksum` for why there is no `no_panic`.
    #[flux_rs::trusted(no, reason = "panic site: reads the window named by the length field")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], &IpAddress, &IpAddress)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
              && 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && p.len <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    pub fn fill_checksum(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress) {
        self.set_checksum(0);
        let checksum = {
            let length = self.len() as usize;
            let data = self.buffer.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp, length as u32),
                checksum::data(prefix(data, length)),
            ])
        };
        // UDP checksum value of 0 means no checksum; if the checksum really is zero,
        // use all-ones, which indicates that the remote end must verify the checksum.
        // Arithmetically, RFC 1071 checksums of all-zeroes and all-ones behave identically,
        // so no action is necessary on the remote end.
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum })
    }

    /// Return a mutable pointer to the payload.
    //
    // Indexed directly rather than through a `wire::buf` helper. The window is written
    // `8..length` rather than `field::PAYLOAD(length)` only because flux cannot see through a
    // `const fn` returning a `Range`; spelled out, both ends are in the `requires` and flux
    // proves the slice itself. A trusted helper here would buy nothing -- a returned `&mut`
    // loses its length index either way (flux-rs/flux#1714) -- and would swap a proved bound
    // for an assumed one.
    #[flux_rs::trusted(no, reason = "panic site: reslices the window named by the length field")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p]) -> &mut [u8]
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 <= p.len && p.len <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let length = self.len() as usize;
        let data = self.buffer.as_mut();
        &mut data[8..length] // field::PAYLOAD(length)
    }

    /// The payload window, as a [`Buf`] so its length survives the return.
    ///
    /// Same window as [`payload_mut`](Self::payload_mut). A `&mut [u8]` loses its length index
    /// on the way back to the caller (flux-rs/flux#1714), so a caller that must write exactly
    /// `len - 8` octets into it -- `Repr::emit`'s two named payload paths -- cannot state that
    /// obligation. `Buf` carries the length in its own refinement instead. The window itself is
    /// still proved here: the body is `trusted(no)`.
    #[flux_rs::trusted(no, reason = "panic site: reslices the window named by the length field")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p]) -> Buf[p.len - 8]
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 <= p.len && p.len <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload_buf(&mut self) -> Buf<'_> {
        let length = self.len() as usize;
        let data = self.buffer.as_mut();
        Buf::with_offset(&mut data[..length], 8) // field::PAYLOAD(length)
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

/// A high-level representation of an User Datagram Protocol packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub src_port: u16,
    pub dst_port: u16,
}

impl Repr {
    /// Parse an User Datagram Protocol packet and return a high-level representation.
    pub fn parse<T>(
        packet: &Packet<&T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        packet.check_len()?;

        // Destination port cannot be omitted (but source port can be).
        if packet.dst_port() == 0 {
            return Err(Error);
        }
        // Valid checksum is expected...
        if checksum_caps.udp.rx() && !packet.verify_checksum(src_addr, dst_addr) {
            match (src_addr, dst_addr) {
                // ... except on UDP-over-IPv4, where it can be omitted.
                #[cfg(feature = "proto-ipv4")]
                (&IpAddress::Ipv4(_), &IpAddress::Ipv4(_)) if packet.checksum() == 0 => (),
                _ => return Err(Error),
            }
        }

        Ok(Repr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
        })
    }

    /// Return the length of the packet header that will be emitted from this high-level representation.
    pub const fn header_len(&self) -> usize {
        HEADER_LEN
    }

    /// Write the source port, destination port and length fields.
    ///
    /// Split out of the three emitters below so the payload window's width is named once. The
    /// `ensures` is the whole point: `set_len` pins the ghost, and the ghost is what
    /// [`payload_buf`](Packet::payload_buf) and `fill_checksum` read the window from.
    ///
    /// `strict` locally, and `8 + payload_len <= 65535` in the `requires`: under the crate's
    /// default `lazy` the sum is modelled as wrapping and the `as u16` cast cannot be equated
    /// with `8 + payload_len`. The bound is not a new restriction -- the length field is a
    /// `u16`, so a longer datagram was already unrepresentable.
    #[flux_rs::opts(check_overflow = "strict")]
    #[flux_rs::trusted(no, reason = "panic site: writes the header at fixed offsets")]
    #[flux_rs::sig(
        fn(&Self, packet: &strg Packet<T>[@p], payload_len: usize)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer) && 8 + payload_len <= 65535
        ensures packet: Packet<T>[p.buffer, 8 + payload_len]
    )]
    #[flux_rs::no_panic]
    fn emit_ports_and_len<T>(&self, packet: &mut Packet<T>, payload_len: usize)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_len((HEADER_LEN + payload_len) as u16);
    }

    /// Fill in or zero the checksum field, whichever the capabilities call for.
    #[flux_rs::trusted(no, reason = "panic site: fill_checksum reads the window")]
    #[flux_rs::sig(
        fn(&Self, packet: &mut Packet<T>[@p], &IpAddress, &IpAddress, &ChecksumCapabilities)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
              && 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && p.len <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    fn emit_checksum<T>(
        &self,
        packet: &mut Packet<T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        checksum_caps: &ChecksumCapabilities,
    ) where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        if checksum_caps.udp.tx() {
            packet.fill_checksum(src_addr, dst_addr)
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }

    /// Emit a high-level representation into an User Datagram Protocol packet.
    ///
    /// This never calculates the checksum, and is intended for internal-use only,
    /// not for packets that are going to be actually sent over the network. For
    /// example, when decompressing 6lowpan.
    //
    // `Packet<T>` with `T: Sized`, not `Packet<&mut T>` with `T: ?Sized`. The old shape
    // instantiated core's blanket `impl<T, U> AsMut<U> for &mut T`, which carries no associated
    // refinement, so `associated refinement 'as_mut_reft' is missing` aborted refinement
    // checking of this whole body -- every setter bound below was silently unchecked. `&mut T`
    // still satisfies the bounds, so every existing caller still resolves; the same move was
    // made for `icmpv4::Repr::emit`.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at fixed offsets")]
    #[flux_rs::sig(
        fn(&Self, packet: &strg Packet<T>[@p], payload_len: usize)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer) && 8 + payload_len <= 65535
        ensures packet: Packet<T>[p.buffer, 8 + payload_len]
    )]
    #[flux_rs::no_panic]
    pub(crate) fn emit_header<T>(&self, packet: &mut Packet<T>, payload_len: usize)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        self.emit_ports_and_len(packet, payload_len);
        packet.set_checksum(0);
    }

    /// Emit a high-level representation into an User Datagram Protocol packet.
    //
    // See `emit_header` for why the buffer parameter is `Packet<T>` rather than
    // `Packet<&mut T>`.
    //
    // The payload window is handed to `emit_payload` as a bare `&mut [u8]`, which carries no
    // length, and a refined bound on the `FnOnce` parameter would not be checked inside a
    // closure body (see `emit_slice`). So what this signature states is what the *header*
    // needs; the window's own obligation is the caller's, and `emit_slice` is the way to
    // discharge it.
    #[flux_rs::trusted(no, reason = "panic site: the header setters and the payload window")]
    #[flux_rs::sig(
        fn(
            &Self,
            packet: &strg Packet<T>[@p],
            &IpAddress,
            &IpAddress,
            payload_len: usize,
            _,
            &ChecksumCapabilities,
        )
        requires 8 + payload_len == <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
              && 8 + payload_len == <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 + payload_len <= 65535
        ensures packet: Packet<T>[p.buffer, 8 + payload_len]
    )]
    pub fn emit<T>(
        &self,
        packet: &mut Packet<T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        payload_len: usize,
        emit_payload: impl FnOnce(&mut [u8]),
        checksum_caps: &ChecksumCapabilities,
    ) where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        self.emit_ports_and_len(packet, payload_len);
        emit_payload(packet.payload_mut());
        self.emit_checksum(packet, src_addr, dst_addr, checksum_caps);
    }

    /// [`emit`](Self::emit), with the payload copied from a slice.
    ///
    /// Exactly `emit(.., payload.len(), |buf| buf.copy_from_slice(payload), ..)`, as a named
    /// function. A refined bound on an `impl FnOnce` parameter is *not* checked inside a
    /// closure body (flux-rs/flux#23), so stating the window's width on `emit`'s closure
    /// parameter would verify vacuously and the `copy_from_slice` would stay unproved. Named,
    /// the copy is an ordinary call and its equal-length obligation is discharged here, from
    /// the window `emit_ports_and_len` just pinned.
    #[flux_rs::trusted(no, reason = "panic site: the header setters and the payload copy")]
    #[flux_rs::sig(
        fn(&Self, packet: &strg Packet<T>[@p], &IpAddress, &IpAddress, payload: &[u8][@m], &ChecksumCapabilities)
        requires 8 + m == <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
              && 8 + m == <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 8 + m <= 65535
        ensures packet: Packet<T>[p.buffer, 8 + m]
    )]
    pub fn emit_slice<T>(
        &self,
        packet: &mut Packet<T>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        payload: &[u8],
        checksum_caps: &ChecksumCapabilities,
    ) where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        self.emit_ports_and_len(packet, payload.len());
        packet.payload_buf().as_mut().copy_from_slice(payload);
        self.emit_checksum(packet, src_addr, dst_addr, checksum_caps);
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Cannot use Repr::parse because we don't have the IP addresses.
        write!(
            f,
            "UDP src={} dst={} len={}",
            self.src_port(),
            self.dst_port(),
            self.payload().len()
        )
    }
}

#[cfg(feature = "defmt")]
impl<'a, T: AsRef<[u8]> + ?Sized> defmt::Format for Packet<&'a T> {
    fn format(&self, fmt: defmt::Formatter) {
        // Cannot use Repr::parse because we don't have the IP addresses.
        defmt::write!(
            fmt,
            "UDP src={} dst={} len={}",
            self.src_port(),
            self.dst_port(),
            self.payload().len()
        );
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UDP src={} dst={}", self.src_port, self.dst_port)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Repr {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "UDP src={} dst={}", self.src_port, self.dst_port);
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        match Packet::new_checked(buffer) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(packet) => write!(f, "{indent}{packet}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "proto-ipv4")]
    use crate::wire::Ipv4Address;

    #[cfg(feature = "proto-ipv4")]
    const SRC_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    #[cfg(feature = "proto-ipv4")]
    const DST_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    #[cfg(feature = "proto-ipv4")]
    static PACKET_BYTES: [u8; 12] = [
        0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[cfg(feature = "proto-ipv4")]
    static NO_CHECKSUM_PACKET: [u8; 12] = [
        0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[cfg(feature = "proto-ipv4")]
    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn ghost_field_is_not_observable() {
        let bytes = [0u8; 12];
        let packet = Packet::new_unchecked(&bytes[..]);
        let s = format!("{packet:?}");
        assert!(!s.contains("Ghost"), "ghost leaked into Debug: {s}");
        assert!(s.starts_with("Packet { buffer: "), "Debug shape changed: {s}");
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.len(), 12);
        assert_eq!(packet.checksum(), 0x124d);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_construct() {
        let mut bytes = vec![0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(48896);
        packet.set_dst_port(53);
        packet.set_len(12);
        packet.set_checksum(0xffff);
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }

    #[test]
    fn test_impossible_len() {
        let mut bytes = vec![0; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_len(4);
        assert_eq!(packet.check_len(), Err(Error));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_zero_checksum() {
        let mut bytes = vec![0; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(1);
        packet.set_dst_port(31881);
        packet.set_len(8);
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(packet.checksum(), 0xffff);
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_no_checksum() {
        let mut bytes = vec![0; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(1);
        packet.set_dst_port(31881);
        packet.set_len(8);
        packet.set_checksum(0);
        assert!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()));
    }

    #[cfg(feature = "proto-ipv4")]
    fn packet_repr() -> Repr {
        Repr {
            src_port: 48896,
            dst_port: 53,
        }
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_parse() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        let repr = Repr::parse(
            &packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.header_len() + PAYLOAD_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(
            &mut packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            PAYLOAD_BYTES.len(),
            |payload| payload.copy_from_slice(&PAYLOAD_BYTES),
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &PACKET_BYTES[..]);
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn test_checksum_omitted() {
        let packet = Packet::new_unchecked(&NO_CHECKSUM_PACKET[..]);
        let repr = Repr::parse(
            &packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr, packet_repr());
    }
}
