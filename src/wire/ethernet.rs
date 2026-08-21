use core::fmt;

use super::{Error, Result};
use crate::wire::{read_u16_at, write_u16_at, Ref};

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
    #[flux_rs::no_panic]
    pub const fn new(a0: u8, a1: u8, a2: u8, a3: u8, a4: u8, a5: u8) -> Address {
        Address {
            o0: a0,
            rest: [a1, a2, a3, a4, a5],
        }
    }

    /// Construct an Ethernet address from an array of octets, in big-endian.
    #[flux_rs::sig(fn([u8; 6]) -> Address)]
    #[flux_rs::no_panic]
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
    /// The six-octet length is a caller obligation rather than a runtime assert, so the
    /// `copy_from_slice` length-mismatch panic is gated rather than defused.
    #[flux_rs::trusted(no, reason = "panic site: copy_from_slice equal-length")]
    #[flux_rs::sig(fn(&[u8][6]) -> Address)]
    #[flux_rs::no_panic]
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        Address::from_octets(bytes)
    }

    /// Return an Ethernet address as an array of octets, in big-endian.
    #[flux_rs::sig(fn(&Address) -> [u8; 6])]
    #[flux_rs::no_panic]
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
    #[flux_rs::no_panic]
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
    //
    // Built by destructuring rather than by two `copy_from_slice`s into slices of a `[u8; 8]`.
    // `[T; N]` has the unit sort, so an indexed range of an array comes back with no length and
    // `copy_from_slice`'s `src.len() == self.len()` was not provable; an irrefutable array
    // pattern has no index to bound at all. `0x02` is the EUI-64 U/L bit, complemented.
    #[flux_rs::no_panic]
    pub fn as_eui_64(&self) -> Option<[u8; 8]> {
        let [o0, o1, o2, o3, o4, o5] = self.octets();
        Some([o0 ^ 0x02, o1, o2, 0xFF, 0xFE, o3, o4, o5])
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
#[flux_rs::refined_by(buffer: T)]
pub struct Frame<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    pub const DESTINATION: Field = 0..6;
    pub const SOURCE: Field = 6..12;
    pub const ETHERTYPE: Field = 12..14;
    pub const PAYLOAD: Rest = 14..;
}

/// The Ethernet header length
pub const HEADER_LEN: usize = field::PAYLOAD.start;

impl<T: AsRef<[u8]>> Frame<T> {
    /// Imbue a raw octet buffer with Ethernet frame structure.
    #[flux_rs::sig(fn(T[@b]) -> Frame<T>[b])]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Frame<T> {
        Frame { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    ///
    /// Deliberately left unrefined. `checked_len` proves `14 <= buffer_len`, but at a reference
    /// or `dyn` self type the `as_ref_reft` that postcondition needs is unstatable, so stating it
    /// here costs an error at [`PrettyPrint::pretty_print`] and buys nothing. The `Ref` buffer is
    /// where the proof can be carried out; see [`new_checked_ref`](Frame::new_checked_ref).
    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked_ref` is correct")]
    #[flux_rs::sig(fn(self: &Frame<T>[@f]) -> Result<()>)]
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
    /// arm say what the test established: the buffer is at least a header long, and that length
    /// is the buffer's own. Both are what the accessors below require.
    ///
    /// The test itself is unchanged. Literal `14` rather than `HEADER_LEN`
    /// (= `field::PAYLOAD.start`): flux cannot see through the `Rest`/`Range` const.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked_ref` is correct")]
    #[flux_rs::sig(
        fn(self: &Frame<T>[@f])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(f.buffer) && 14 <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();
        if len < 14 {
            // HEADER_LEN
            Err(Error)
        } else {
            Ok(len)
        }
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the length of a frame header.
    // Literal rather than `HEADER_LEN` (= `field::PAYLOAD.start`): flux cannot see through the
    // `Rest`/`Range` const. Callers reslice the tx buffer by this, so the value has to be visible.
    #[flux_rs::trusted(no, reason = "14 is what the tx-buffer reslice arithmetic needs")]
    #[flux_rs::sig(fn() -> usize[14])]
    #[flux_rs::no_panic]
    pub const fn header_len() -> usize {
        14
    }

    /// Return the length of a buffer required to hold a packet with the payload
    /// of a given length.
    pub const fn buffer_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    /// Return the destination address field.
    // Literal offsets rather than `field::DESTINATION`: flux cannot see through the `Field`
    // (`Range`) const, so the bound has to be written out. Same throughout this impl.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Frame<T>[@f]) -> Address
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(f.buffer)
    )]
    // Body stays bounds-checked. The `requires` above states the bound, but six in-crate call
    // sites cannot yet discharge it: `dispatch_ethernet` hands its closure an
    // `EthernetFrame<&mut [u8]>`, and at `T = &mut [u8]` the length index would have to come
    // from core's blanket `impl AsMut for &mut T`, which carries no associated refinement.
    // Until those route through `wire::Buf`, indexing unchecked here would trade a panic for an
    // out-of-bounds write rather than prove the panic away (#16). Literal offsets rather than
    // the `field::` consts only because flux cannot see through a `Range` const.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[0..6]) // field::DESTINATION
    }

    /// Return the source address field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Frame<T>[@f]) -> Address
        requires 12 <= <T as AsRef<[u8]>>::as_ref_reft(f.buffer)
    )]
    // Body stays bounds-checked. The `requires` above states the bound, but six in-crate call
    // sites cannot yet discharge it: `dispatch_ethernet` hands its closure an
    // `EthernetFrame<&mut [u8]>`, and at `T = &mut [u8]` the length index would have to come
    // from core's blanket `impl AsMut for &mut T`, which carries no associated refinement.
    // Until those route through `wire::Buf`, indexing unchecked here would trade a panic for an
    // out-of-bounds write rather than prove the panic away (#16). Literal offsets rather than
    // the `field::` consts only because flux cannot see through a `Range` const.
    #[inline]
    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[6..12]) // field::SOURCE
    }

    /// Return the EtherType field, without checking for 802.1Q.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &Frame<T>[@f]) -> EtherType
        requires 14 <= <T as AsRef<[u8]>>::as_ref_reft(f.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        let data = self.buffer.as_ref();
        let raw = read_u16_at(data, 12); // field::ETHERTYPE
        EtherType::from(raw)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Frame<&'a T> {
    /// Return a pointer to the payload, without checking for 802.1Q.
    //
    // Left bounds-checked. The buffer here is `&'a T`, so the length index has to come from
    // core's blanket `impl<T, U> AsRef<U> for &T`, which carries no associated refinement
    // (`as_ref_reft` is missing). The bound `14 <= len` is therefore unstatable at this self
    // type, and routing through the unchecked `suffix` without stating it would trade a panic
    // for UB. The provable twin is on `Frame<Ref<'a>>` below; this one is still here because
    // `InterfaceInner::process_arp` takes a `Frame<&[u8]>`.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<'a> Frame<Ref<'a>> {
    /// [`new_checked`](Self::new_checked) over a [`Ref`], carrying its proof out.
    ///
    /// Over `Ref` the buffer's length is `b.len`, so `checked_len`'s `Ok` arm is statable in the
    /// return type, and what it states is exactly what every accessor on `Frame` requires.
    #[flux_rs::trusted(no, reason = "carries `checked_len`'s proof out through the `Ok` arm")]
    #[flux_rs::sig(
        fn(Ref[@b]) -> Result<Frame<Ref>{f: f.buffer == b && 14 <= b.len}>
    )]
    pub fn new_checked_ref(buffer: Ref<'a>) -> Result<Frame<Ref<'a>>> {
        let frame = Frame::new_unchecked(buffer);
        frame.checked_len()?;
        Ok(frame)
    }

    /// Return a pointer to the payload, without checking for 802.1Q.
    ///
    /// The `Frame<&'a T>` twin of this cannot be proved: a reference in type-parameter position
    /// has the unit sort, so the window bound is unstatable there. Over `Ref<'a>` the buffer's
    /// length is `f.buffer.len`, and the payload's length survives into the caller's index.
    #[flux_rs::trusted(no, reason = "panic site: reslices past the fixed 14-octet header")]
    #[flux_rs::sig(
        fn(&Frame<Ref>[@f]) -> &[u8][f.buffer.len - 14]
        requires 14 <= f.buffer.len
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let len = self.buffer.as_ref().len();
        self.buffer.window(14, len) // field::PAYLOAD
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    /// Set the destination address field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Frame<T>[@f], _)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(f.buffer)
    )]
    // Body stays bounds-checked. The `requires` above states the bound, but six in-crate call
    // sites cannot yet discharge it: `dispatch_ethernet` hands its closure an
    // `EthernetFrame<&mut [u8]>`, and at `T = &mut [u8]` the length index would have to come
    // from core's blanket `impl AsMut for &mut T`, which carries no associated refinement.
    // Until those route through `wire::Buf`, indexing unchecked here would trade a panic for an
    // out-of-bounds write rather than prove the panic away (#16). Literal offsets rather than
    // the `field::` consts only because flux cannot see through a `Range` const.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[0..6].copy_from_slice(value.as_bytes()) // field::DESTINATION
    }

    /// Set the source address field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Frame<T>[@f], _)
        requires 12 <= <T as AsMut<[u8]>>::as_mut_reft(f.buffer)
    )]
    // Body stays bounds-checked. The `requires` above states the bound, but six in-crate call
    // sites cannot yet discharge it: `dispatch_ethernet` hands its closure an
    // `EthernetFrame<&mut [u8]>`, and at `T = &mut [u8]` the length index would have to come
    // from core's blanket `impl AsMut for &mut T`, which carries no associated refinement.
    // Until those route through `wire::Buf`, indexing unchecked here would trade a panic for an
    // out-of-bounds write rather than prove the panic away (#16). Literal offsets rather than
    // the `field::` consts only because flux cannot see through a `Range` const.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[6..12].copy_from_slice(value.as_bytes()) // field::SOURCE
    }

    /// Set the EtherType field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Frame<T>[@f], _)
        requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(f.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 12, value.into()) // field::ETHERTYPE
    }

    /// Return a mutable pointer to the payload.
    #[flux_rs::trusted(no, reason = "panic site: reslices past the fixed 14-octet header")]
    #[flux_rs::sig(
        fn(self: &mut Frame<T>[@f]) -> &mut [u8]
        requires 14 <= <T as AsMut<[u8]>>::as_mut_reft(f.buffer)
    )]
    // Body stays bounds-checked. The `requires` above states the bound, but six in-crate call
    // sites cannot yet discharge it: `dispatch_ethernet` hands its closure an
    // `EthernetFrame<&mut [u8]>`, and at `T = &mut [u8]` the length index would have to come
    // from core's blanket `impl AsMut for &mut T`, which carries no associated refinement.
    // Until those route through `wire::Buf`, indexing unchecked here would trade a panic for an
    // out-of-bounds write rather than prove the panic away (#16). Literal offsets rather than
    // the `field::` consts only because flux cannot see through a `Range` const.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[14..] // field::PAYLOAD
    }
}

#[flux_rs::assoc(
    fn as_ref_reft(source: Self) -> int {
        <T as AsRef<[u8]>>::as_ref_reft(source.buffer)
    }
)]
impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    #[flux_rs::no_panic]
    #[flux_rs::sig(fn(self: &Self[@source]) -> &[u8][Self::as_ref_reft(source)])]
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

// A trait impl's signature is fixed, so this cannot carry the accessors' `requires`. The check
// is taken inside the body instead: `checked_len`'s `Ok` arm proves the bound all three
// accessors want, and the `Err` arm no longer reads a header it never validated.
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
    #[flux_rs::trusted(yes, reason = "ICE flux infer.rs:896: `incompatible types` on a place still blocked (`†`) by a mutable borrow at the join. See ICE-INBOX.md.")]
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        // `Ref::new` off the `dyn`'s own `as_ref`: the trait signature is fixed, so the buffer
        // arrives with no length index, and `Ref` is where it acquires one.
        let frame = match Frame::new_checked_ref(Ref::new(buffer.as_ref())) {
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
    pub fn parse(frame: &Frame<Ref<'_>>) -> Result<Repr> {
        // `checked_len` rather than `check_len`: same test, but its `Ok` arm names the fact the
        // three accessors below need, and over `Ref` it is statable.
        frame.checked_len()?;
        Ok(Repr {
            src_addr: frame.src_addr(),
            dst_addr: frame.dst_addr(),
            ethertype: frame.ethertype(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    // Literal rather than `HEADER_LEN`: flux cannot see through the `Rest`/`Range` const.
    #[flux_rs::trusted(no, reason = "callers reslice by this value")]
    #[flux_rs::sig(fn(&Repr) -> usize[14])]
    #[flux_rs::no_panic]
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into an Ethernet II frame.
    //
    // The assert stays. It is the only thing that establishes `14 <= len` here: nothing proves a
    // caller cannot hand over a shorter buffer, so deleting it in favour of a `requires` would
    // remove a panic the callers do not discharge. Flux reads the passed assert as an assumption,
    // so the three setters discharge their `requires` from it rather than from a caller, which is
    // why `emit` needs no signature of its own.
    //
    // The length is read through `as_mut` rather than `as_ref` because the setters' bounds are
    // stated over `as_mut_reft`, and flux relates the two associated refinements only if the
    // fact arrives in that form. Same check, same condition, same value.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Frame<T>) {
        assert!(frame.buffer.as_mut().len() >= self.buffer_len());
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

    #[test]
    fn eui_64_splits_at_the_oui_and_flips_the_ul_bit() {
        let a = Address::new(0x11, 0x12, 0x13, 0x14, 0x15, 0x16);
        assert_eq!(
            a.as_eui_64(),
            Some([0x13, 0x12, 0x13, 0xff, 0xfe, 0x14, 0x15, 0x16])
        );
    }
}
