use core::{cmp, fmt};

use super::{Error, Result};
use crate::phy::ChecksumCapabilities;
use crate::wire::ip::checksum;
use crate::flux_util::byte_len;
use crate::wire::{Buf, Ipv4Packet, Ipv4Repr, Ref, read_u16_at, write_u16_at};

enum_with_unknown! {
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Echo reply
        EchoReply      =  0,
        /// Destination unreachable
        DstUnreachable =  3,
        /// Message redirect
        Redirect       =  5,
        /// Echo request
        EchoRequest    =  8,
        /// Router advertisement
        RouterAdvert   =  9,
        /// Router solicitation
        RouterSolicit  = 10,
        /// Time exceeded
        TimeExceeded   = 11,
        /// Parameter problem
        ParamProblem   = 12,
        /// Timestamp
        Timestamp      = 13,
        /// Timestamp reply
        TimestampReply = 14
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::EchoReply => write!(f, "echo reply"),
            Message::DstUnreachable => write!(f, "destination unreachable"),
            Message::Redirect => write!(f, "message redirect"),
            Message::EchoRequest => write!(f, "echo request"),
            Message::RouterAdvert => write!(f, "router advertisement"),
            Message::RouterSolicit => write!(f, "router solicitation"),
            Message::TimeExceeded => write!(f, "time exceeded"),
            Message::ParamProblem => write!(f, "parameter problem"),
            Message::Timestamp => write!(f, "timestamp"),
            Message::TimestampReply => write!(f, "timestamp reply"),
            Message::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// Destination network unreachable
        NetUnreachable   =  0,
        /// Destination host unreachable
        HostUnreachable  =  1,
        /// Destination protocol unreachable
        ProtoUnreachable =  2,
        /// Destination port unreachable
        PortUnreachable  =  3,
        /// Fragmentation required, and DF flag set
        FragRequired     =  4,
        /// Source route failed
        SrcRouteFailed   =  5,
        /// Destination network unknown
        DstNetUnknown    =  6,
        /// Destination host unknown
        DstHostUnknown   =  7,
        /// Source host isolated
        SrcHostIsolated  =  8,
        /// Network administratively prohibited
        NetProhibited    =  9,
        /// Host administratively prohibited
        HostProhibited   = 10,
        /// Network unreachable for ToS
        NetUnreachToS    = 11,
        /// Host unreachable for ToS
        HostUnreachToS   = 12,
        /// Communication administratively prohibited
        CommProhibited   = 13,
        /// Host precedence violation
        HostPrecedViol   = 14,
        /// Precedence cutoff in effect
        PrecedCutoff     = 15
    }
}

impl fmt::Display for DstUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DstUnreachable::NetUnreachable => write!(f, "destination network unreachable"),
            DstUnreachable::HostUnreachable => write!(f, "destination host unreachable"),
            DstUnreachable::ProtoUnreachable => write!(f, "destination protocol unreachable"),
            DstUnreachable::PortUnreachable => write!(f, "destination port unreachable"),
            DstUnreachable::FragRequired => write!(f, "fragmentation required, and DF flag set"),
            DstUnreachable::SrcRouteFailed => write!(f, "source route failed"),
            DstUnreachable::DstNetUnknown => write!(f, "destination network unknown"),
            DstUnreachable::DstHostUnknown => write!(f, "destination host unknown"),
            DstUnreachable::SrcHostIsolated => write!(f, "source host isolated"),
            DstUnreachable::NetProhibited => write!(f, "network administratively prohibited"),
            DstUnreachable::HostProhibited => write!(f, "host administratively prohibited"),
            DstUnreachable::NetUnreachToS => write!(f, "network unreachable for ToS"),
            DstUnreachable::HostUnreachToS => write!(f, "host unreachable for ToS"),
            DstUnreachable::CommProhibited => {
                write!(f, "communication administratively prohibited")
            }
            DstUnreachable::HostPrecedViol => write!(f, "host precedence violation"),
            DstUnreachable::PrecedCutoff => write!(f, "precedence cutoff in effect"),
            DstUnreachable::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Redirect Message".
    pub enum Redirect(u8) {
        /// Redirect Datagram for the Network
        Net     = 0,
        /// Redirect Datagram for the Host
        Host    = 1,
        /// Redirect Datagram for the ToS & network
        NetToS  = 2,
        /// Redirect Datagram for the ToS & host
        HostToS = 3
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// TTL expired in transit
        TtlExpired  = 0,
        /// Fragment reassembly time exceeded
        FragExpired = 1
    }
}

impl fmt::Display for TimeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TimeExceeded::TtlExpired => write!(f, "time-to-live exceeded in transit"),
            TimeExceeded::FragExpired => write!(f, "fragment reassembly time exceeded"),
            TimeExceeded::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Pointer indicates the error
        AtPointer     = 0,
        /// Missing a required option
        MissingOption = 1,
        /// Bad length
        BadLength     = 2
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 4 packet buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(buffer: T)]
pub struct Packet<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
}

mod field {
    // The offsets below are also written out as literals at the accessors, which need a value
    // flux can see; these consts stay as the single reviewable statement of the layout, and
    // several of them are now referenced only from those trailing comments.
    #![allow(unused)]

    use crate::wire::field::*;

    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;

    pub const UNUSED: Field = 4..8;

    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with ICMPv4 packet structure.
    #[flux_rs::trusted(no, reason = "carries the buffer length into the Packet index")]
    #[flux_rs::sig(fn(T[@buflen]) -> Packet<T>{v: v.buffer == buflen})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    ///
    /// Deliberately left unrefined. `checked_len` proves `8 <= as_ref_reft(buffer)`, and
    /// carrying that out through the `Ok` payload is
    /// [`new_checked_ref`](Packet::new_checked_ref)'s job; stating it here instead costs an
    /// error at every `T` for which `as_ref_reft` is unstatable, `pretty_print`'s
    /// `&dyn AsRef<[u8]>` among them.
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
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
    /// The whole of `check_len`; the public method just discards the length. `Result<()>`'s `Ok`
    /// payload carries no refinement, so a successful check leaves a caller with nothing to show
    /// for it. Returning the length lets the `Ok` arm say both things the accessors below want:
    /// what the buffer's length is, and that it reaches the end of the fixed header.
    ///
    /// `8 <= len` is the whole precondition of this file. Every field sits at a fixed offset
    /// below 8, and [`header_len`](Self::header_len) is 8 for every message type -- the match on
    /// `msg_type` has the same value on all four arms -- so no window's extent depends on buffer
    /// *contents* and there is no ghost field as in `arp`, `udp` and `tcp`.
    ///
    /// The length is nameable only where `T` is not a reference -- a reference in
    /// type-parameter position has the unit sort. [`Ref`] is that `T`, and the three consumers
    /// are [`new_checked_ref`](Packet::new_checked_ref), [`Repr::parse_ref`] and the `Display`
    /// impl, which take the check inside their own bodies.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@p])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && 8 <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();
        if len < 8 {
            // field::HEADER_END
            Err(Error)
        } else {
            Ok(len)
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    // Literal offsets rather than `field::TYPE`: flux cannot see through a `const` of struct
    // type, and `usize` consts are opaque to it too, so the bound has to be written out. The
    // original spelling is kept in a trailing comment. Same throughout this impl.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> Message requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn msg_type(&self) -> Message {
        let data = self.buffer.as_ref();
        Message::from(data[0]) // field::TYPE
    }

    /// Return the message code field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u8 requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn msg_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[1] // field::CODE
    }

    /// Return the checksum field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 2) // field::CHECKSUM
    }

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 4) // field::ECHO_IDENT
    }

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 6) // field::ECHO_SEQNO
    }

    /// Return the header length.
    /// The result depends on the value of the message type field.
    ///
    /// It does not, in fact, vary: `ECHO_SEQNO.end` and `UNUSED.end` are both 8, so every arm
    /// returns 8 and the postcondition is a constant. That is what lets `data` and `data_mut`
    /// state a fixed window without a ghost field carrying the message type, the way
    /// `icmpv6::Packet::header_len` needs. The arms are kept as they are -- the dispatch is the
    /// code, and a future message type could give it a second value.
    ///
    /// The `requires` is `msg_type`'s, forwarded: the dispatch reads octet 0, so a caller owes
    /// a buffer that has one. Both callers hold far more -- `data` has `8 <= p.buffer.len` from
    /// `checked_len`, `data_mut` has it from `Repr::emit`'s allocation.
    #[flux_rs::trusted(no, reason = "carries the header length to data/data_mut")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> usize[8]
        requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::EchoRequest => 8,    // field::ECHO_SEQNO.end
            Message::EchoReply => 8,      // field::ECHO_SEQNO.end
            Message::DstUnreachable => 8, // field::UNUSED.end
            _ => 8,                       // field::UNUSED.end, a conservative assumption
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    ///
    /// `as_ref_reft <= 65535` is `checksum::data`'s own bound -- its `u32` accumulator cannot
    /// take more than 65535 octets without overflowing. It is a real, satisfiable property of
    /// every ICMPv4 buffer, which are sized from `Repr::buffer_len()` under an IPv4 MTU, so it
    /// is stated as a caller obligation rather than assumed here.
    #[flux_rs::trusted(no, reason = "panic site: checksum::data's length bound")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> bool requires <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535)]
    #[flux_rs::no_panic]
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::data(data) == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(&mut Packet<T>[@p], Message) requires 1 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        let data = self.buffer.as_mut();
        data[0] = value.into() // field::TYPE
    }

    /// Set the message code field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(&mut Packet<T>[@p], u8) requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[1] = value // field::CODE
    }

    /// Set the checksum field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(&mut Packet<T>[@p], u16) requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 2, value) // field::CHECKSUM
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(&mut Packet<T>[@p], u16) requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 4, value) // field::ECHO_IDENT
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(fn(&mut Packet<T>[@p], u16) requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 6, value) // field::ECHO_SEQNO
    }

    /// Compute and fill in the header checksum.
    ///
    /// The `[@p]` on the receiver is the point of the signature: without it the caller's
    /// `4 <= as_mut_reft(buffer)` is havoced across the two `set_checksum` calls. The
    /// `<= 65535` conjunct is `checksum::data`'s bound; see
    /// [`verify_checksum`](Self::verify_checksum).
    #[flux_rs::trusted(no, reason = "panic site: the checksum write and checksum::data's bound")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p])
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
             && <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
    )]
    #[flux_rs::no_panic]
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(data)
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the type-specific data.
    ///
    /// Lives here, on `Packet<T>` with `T: Sized`, rather than on `Packet<&mut T>` with
    /// `T: ?Sized`. That is what makes the bound statable at all: a reference self type gets the
    /// unit sort, so on `Packet<&mut T>` there is no `as_mut_reft` to name. The move is strictly
    /// widening -- `&mut T` is `Sized` and satisfies `AsRef<[u8]> + AsMut<[u8]>` through core's
    /// blanket impls whenever `T` does, so every existing `Packet<&mut T>` caller still resolves,
    /// and `Packet<Vec<u8>>` now resolves too. [`data`](Packet::data) cannot follow, because its
    /// return borrows the buffer's own lifetime rather than `&self`'s; it lives on
    /// `Packet<Ref<'a>>` instead.
    ///
    /// The `as_ref_reft` conjunct is `header_len`'s; the `as_mut_reft` one is the window's.
    /// They are separate facts about the same buffer because `T` is generic here -- at the
    /// `Buf` every caller instantiates, both project to the same field.
    #[flux_rs::trusted(no, reason = "panic site: opens the payload window")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p]) -> &mut [u8][<T as AsMut<[u8]>>::as_mut_reft(p.buffer) - 8]
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
             && 1 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let data = self.buffer.as_mut();
        &mut data[range]
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

/// A high-level representation of an Internet Control Message Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
// Indexed by `buffer_len()`, which is what every caller of `emit` allocates. `data.len()` lives
// inside the `Repr`, so this is the only place the payload copy's length obligation can be
// stated. Same shape as `icmpv6::Repr`, and every variant here is exact -- there is no
// unrefined sub-repr to index `0`.
//
// The literals restate `field::ECHO_SEQNO.end` (8), `field::UNUSED.end` (8) and
// `Ipv4Repr::buffer_len()` (20); flux cannot see through a `Range` const.
#[flux_rs::refined_by(blen: int)]
// Every variant is `8 + m` or `28 + m` for a slice length `m`, so the header always fits.
// Without this the setters' `1 <= as_mut_reft` / `2 <= as_mut_reft` cannot be discharged from
// `emit`'s `as_mut_reft == blen` alone.
#[flux_rs::invariant(8 <= blen)]
pub enum Repr<'a> {
    #[flux_rs::variant({u16, u16, &[u8][@m]} -> Repr[8 + m])]
    EchoRequest {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
    #[flux_rs::variant({u16, u16, &[u8][@m]} -> Repr[8 + m])]
    EchoReply {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
    #[flux_rs::variant({DstUnreachable, Ipv4Repr, &[u8][@m]} -> Repr[28 + m])]
    DstUnreachable {
        reason: DstUnreachable,
        header: Ipv4Repr,
        data: &'a [u8],
    },
    #[flux_rs::variant({TimeExceeded, Ipv4Repr, &[u8][@m]} -> Repr[28 + m])]
    TimeExceeded {
        reason: TimeExceeded,
        header: Ipv4Repr,
        data: &'a [u8],
    },
}

/// The returned datagram carried by an ICMPv4 error message: the IPv4 header it quotes, and the
/// bytes that follow it.
///
/// Shared by the `DstUnreachable` and `TimeExceeded` arms of [`Repr::parse_ref`], which differ
/// only in how the code is read.
///
/// The two length tests are `Ipv4Packet::check_len`'s own, run a second time. That method returns
/// `Result<()>`, so what it established does not survive the call, and the split below needs it
/// stated; by the time either `Err` here is reachable `new_checked` has already returned the same
/// one. Both go away once `wire/ipv4.rs`'s check carries its length out.
#[flux_rs::sig(fn(Ref[@r]) -> Result<(Ipv4Repr, &[u8])>)]
fn returned_datagram<'a>(data: Ref<'a>) -> Result<(Ipv4Repr, &'a [u8])> {
    let len = data.as_ref().len();
    // 20 is `ipv4::field::DST_ADDR.end`, the minimum `Ipv4Packet::check_len` enforces; flux
    // cannot see through the `Range` const.
    if len < 20 {
        return Err(Error);
    }
    let ip_packet = Ipv4Packet::new_checked(data)?;
    let header_len = ip_packet.header_len() as usize;
    if header_len > len {
        return Err(Error);
    }
    let payload = data.window(header_len, len);
    // RFC 792 requires exactly eight bytes to be returned.
    // We allow more, since there isn't a reason not to, but require at least eight.
    if payload.len() < 8 {
        return Err(Error);
    }
    Ok((
        Ipv4Repr {
            src_addr: ip_packet.src_addr(),
            dst_addr: ip_packet.dst_addr(),
            next_header: ip_packet.next_header(),
            payload_len: payload.len(),
            hop_limit: ip_packet.hop_limit(),
        },
        payload,
    ))
}

impl<'a> Repr<'a> {
    /// Parse an Internet Control Message Protocol version 4 packet and return
    /// a high-level representation.
    ///
    /// A thin wrapper over [`parse_ref`](Self::parse_ref). A reference in type-parameter
    /// position has the unit sort, so nothing about `T`'s extent is statable here; [`Ref`] is
    /// where the buffer acquires a length, and `parse_ref` is where the accessors' windows are
    /// proved against it. Callers already holding a `Ref` should call `parse_ref` directly.
    pub fn parse<T>(
        packet: &Packet<&'a T>,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let packet = Packet::new_unchecked(Ref::new(packet.buffer.as_ref()));
        Repr::parse_ref(&packet, checksum_caps)
    }

    /// [`parse`](Self::parse) over a buffer whose length is in the refinement.
    ///
    /// `checked_len` rather than `check_len`: the same test, but its `Ok` arm names what the
    /// accessors below need -- the buffer's length, and that it reaches the end of the fixed
    /// header.
    pub fn parse_ref(
        packet: &Packet<Ref<'a>>,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr<'a>> {
        packet.checked_len()?;

        // Valid checksum is expected.
        if checksum_caps.icmpv4.rx() && !packet.verify_checksum() {
            return Err(Error);
        }

        match (packet.msg_type(), packet.msg_code()) {
            (Message::EchoRequest, 0) => Ok(Repr::EchoRequest {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                data: packet.data(),
            }),

            (Message::EchoReply, 0) => Ok(Repr::EchoReply {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                data: packet.data(),
            }),

            (Message::DstUnreachable, code) => {
                let (header, data) = returned_datagram(Ref::new(packet.data()))?;
                Ok(Repr::DstUnreachable {
                    reason: DstUnreachable::from(code),
                    header,
                    data,
                })
            }

            (Message::TimeExceeded, code) => {
                let (header, data) = returned_datagram(Ref::new(packet.data()))?;
                Ok(Repr::TimeExceeded {
                    reason: TimeExceeded::from(code),
                    header,
                    data,
                })
            }

            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    // `strict` locally, and `byte_len` rather than `len`: under the crate's `lazy` mode flux
    // models `8 + m` as wrapping and the postcondition is unprovable, and under `strict` a bare
    // `data.len()` has no upper bound so the same sum reads as a possible overflow. Both are
    // closed by `byte_len`'s `isize::MAX` fact; see `flux_util::byte_len`.
    #[flux_rs::opts(check_overflow = "strict")]
    #[flux_rs::sig(fn(self: &Self[@r]) -> usize[r.blen])]
    #[flux_rs::no_panic]
    pub const fn buffer_len(&self) -> usize {
        // One arm per variant rather than two or-patterns: an or-pattern joins the arms
        // before the index is read, so flux sees only the join and the postcondition is lost.
        match *self {
            // 8 is `field::ECHO_SEQNO.end`, restated as a literal because flux cannot see
            // through the `Range` const.
            Repr::EchoRequest { data, .. } => 8 + byte_len(data),
            Repr::EchoReply { data, .. } => 8 + byte_len(data),
            // 8 is `field::UNUSED.end`; `header.buffer_len()` is 20.
            Repr::DstUnreachable { header, data, .. } => 8 + header.buffer_len() + byte_len(data),
            Repr::TimeExceeded { header, data, .. } => 8 + header.buffer_len() + byte_len(data),
        }
    }

    /// Emit a high-level representation into an Internet Control Message Protocol version 4
    /// packet.
    // The buffer parameter is `Packet<T>` with `T: Sized`, not `Packet<&mut T>` with
    // `T: ?Sized`. The old shape instantiated core's blanket `impl<T, U> AsMut<U> for &mut T`,
    // which carries no associated refinement, so `associated refinement 'as_mut_reft' is
    // missing` aborted refinement checking of this entire body -- every obligation below was
    // silently unchecked. `&mut [u8]` still satisfies the bounds, so this is strictly more
    // permissive; the same move was made for `icmpv6::Repr::emit` and `Packet::data_mut`.
    //
    // The precondition is an *equality*, not `r.blen <= len`. The two error arms end in
    // `payload.copy_from_slice(data)`, which panics unless the window is exactly `data.len()`
    // wide; that is a real property of this code, not one added here, and it is what every
    // caller already provides by allocating `buffer_len()` bytes.
    #[flux_rs::trusted(no, reason = "panic site: the header setters and the payload copy")]
    #[flux_rs::sig(
        fn(self: &Self[@r], packet: &mut Packet<T>[@p], &ChecksumCapabilities)
        requires <T as AsMut<[u8]>>::as_mut_reft(p.buffer) == r.blen
              && 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
    )]
    pub fn emit<T>(&self, packet: &mut Packet<T>, checksum_caps: &ChecksumCapabilities)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        packet.set_msg_code(0);
        match *self {
            Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                packet.set_msg_type(Message::EchoRequest);
                packet.set_msg_code(0);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
                let window = packet.data_mut();
                let data_len = cmp::min(window.len(), data.len());
                window[..data_len].copy_from_slice(&data[..data_len])
            }

            Repr::EchoReply {
                ident,
                seq_no,
                data,
            } => {
                packet.set_msg_type(Message::EchoReply);
                packet.set_msg_code(0);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
                let window = packet.data_mut();
                let data_len = cmp::min(window.len(), data.len());
                window[..data_len].copy_from_slice(&data[..data_len])
            }

            Repr::DstUnreachable {
                reason,
                header,
                data,
            } => {
                packet.set_msg_type(Message::DstUnreachable);
                packet.set_msg_code(reason.into());

                // Routed through `Buf` so the window keeps its length: a bare `&mut [u8]`
                // instantiates core's blanket `AsMut for &mut T`, which carries no associated
                // refinement, and this body would go unchecked again.
                let mut window = Buf::new(packet.data_mut());
                let mut ip_packet = Ipv4Packet::new_unchecked(window.reborrow());
                header.emit(&mut ip_packet, checksum_caps);
                let payload = &mut window.as_mut()[header.buffer_len()..];
                payload.copy_from_slice(data)
            }

            Repr::TimeExceeded {
                reason,
                header,
                data,
            } => {
                packet.set_msg_type(Message::TimeExceeded);
                packet.set_msg_code(reason.into());

                // Routed through `Buf` so the window keeps its length: a bare `&mut [u8]`
                // instantiates core's blanket `AsMut for &mut T`, which carries no associated
                // refinement, and this body would go unchecked again.
                let mut window = Buf::new(packet.data_mut());
                let mut ip_packet = Ipv4Packet::new_unchecked(window.reborrow());
                header.emit(&mut ip_packet, checksum_caps);
                let payload = &mut window.as_mut()[header.buffer_len()..];
                payload.copy_from_slice(data)
            }
        }

        if checksum_caps.icmpv4.tx() {
            packet.fill_checksum()
        } else {
            // make sure we get a consistently zeroed checksum,
            // since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

// A trait impl's signature is fixed, so it cannot carry the `requires` the header accessors
// want. The check is taken inside the body instead: `checked_len`'s `Ok` arm proves the bound
// `msg_type` and `msg_code` need, and the arm that fails it no longer reads a header it never
// validated -- a panic on a truncated message.
impl fmt::Display for Packet<Ref<'_>> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse_ref(self, &ChecksumCapabilities::default()) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "ICMPv4 ({err})")?;
                match self.checked_len() {
                    // Too short to hold a type or a code; that is what `parse_ref` rejected.
                    Err(_) => Ok(()),
                    Ok(_) => {
                        write!(f, " type={:?}", self.msg_type())?;
                        match self.msg_type() {
                            Message::DstUnreachable => {
                                write!(f, " code={:?}", DstUnreachable::from(self.msg_code()))
                            }
                            Message::TimeExceeded => {
                                write!(f, " code={:?}", TimeExceeded::from(self.msg_code()))
                            }
                            _ => write!(f, " code={}", self.msg_code()),
                        }
                    }
                }
            }
        }
    }
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => write!(
                f,
                "ICMPv4 echo request id={} seq={} len={}",
                ident,
                seq_no,
                data.len()
            ),
            Repr::EchoReply {
                ident,
                seq_no,
                data,
            } => write!(
                f,
                "ICMPv4 echo reply id={} seq={} len={}",
                ident,
                seq_no,
                data.len()
            ),
            Repr::DstUnreachable { reason, .. } => {
                write!(f, "ICMPv4 destination unreachable ({reason})")
            }
            Repr::TimeExceeded { reason, .. } => {
                write!(f, "ICMPv4 time exceeded ({reason})")
            }
        }
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Packet<T> {
    #[flux_rs::trusted(yes, reason = "ICE flux infer.rs:896: `incompatible types` on a place still blocked (`†`) by a mutable borrow at the join. See ICE-INBOX.md.")]
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        // `Ref::new` off the `dyn`'s own `as_ref`: the trait signature is fixed, so the buffer
        // arrives with no length index, and `Ref` is where it acquires one.
        let packet = match Packet::new_checked_ref(Ref::new(buffer.as_ref())) {
            Err(err) => return write!(f, "{indent}({err})"),
            Ok(packet) => packet,
        };
        write!(f, "{indent}{packet}")?;

        match packet.msg_type() {
            Message::DstUnreachable | Message::TimeExceeded => {
                indent.increase(f)?;
                super::Ipv4Packet::<&[u8]>::pretty_print(&packet.data(), f, indent)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static ECHO_PACKET_BYTES: [u8; 12] = [
        0x08, 0x00, 0x8e, 0xfe, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff,
    ];

    static ECHO_DATA_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_echo_deconstruct() {
        let packet = Packet::new_unchecked(Ref::new(&ECHO_PACKET_BYTES[..]));
        assert_eq!(packet.msg_type(), Message::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x8efe);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.data(), &ECHO_DATA_BYTES[..]);
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = vec![0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.data_mut().copy_from_slice(&ECHO_DATA_BYTES[..]);
        packet.fill_checksum();
        assert_eq!(&packet.into_inner()[..], &ECHO_PACKET_BYTES[..]);
    }

    fn echo_packet_repr() -> Repr<'static> {
        Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &ECHO_DATA_BYTES,
        }
    }

    #[test]
    fn test_echo_parse() {
        let packet = Packet::new_unchecked(Ref::new(&ECHO_PACKET_BYTES[..]));
        let repr = Repr::parse_ref(&packet, &ChecksumCapabilities::default()).unwrap();
        assert_eq!(repr, echo_packet_repr());
    }

    #[test]
    fn test_echo_emit() {
        let repr = echo_packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet, &ChecksumCapabilities::default());
        assert_eq!(&packet.into_inner()[..], &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_check_len() {
        let bytes = [0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Packet::new_checked(&[]), Err(Error));
        assert_eq!(Packet::new_checked(&bytes[..4]), Err(Error));
        assert!(Packet::new_checked(&bytes[..]).is_ok());
    }
}

impl<'a> Packet<Ref<'a>> {
    /// [`new_checked`](Self::new_checked) over a [`Ref`], carrying its proof out.
    ///
    /// The generic `new_checked` cannot say this: at a reference or `dyn` self type the
    /// `as_ref_reft` in the postcondition is unstatable, so stating it there costs an error at
    /// `pretty_print` and buys nothing. Over `Ref` the buffer's length is `b.len`, and what
    /// `checked_len` already proves is what every accessor in this module requires.
    #[flux_rs::trusted(no, reason = "carries `checked_len`'s proof out through the `Ok` arm")]
    #[flux_rs::sig(fn(Ref[@b]) -> Result<Packet<Ref>{p: p.buffer == b && 8 <= b.len}>)]
    pub fn new_checked_ref(buffer: Ref<'a>) -> Result<Packet<Ref<'a>>> {
        let packet = Packet::new_unchecked(buffer);
        packet.checked_len()?;
        Ok(packet)
    }

    /// Return a pointer to the type-specific data.
    ///
    /// The `Packet<&'a T>` twin of this cannot be proved: a reference in type-parameter position
    /// has the unit sort, so `p.buffer` cannot be fed to `<&'a T as AsRef<[u8]>>::as_ref_reft`
    /// and neither half of the window bound is statable. Over `Ref<'a>` the buffer's length is
    /// `p.buffer.len`, and the payload's length survives into the caller's index. The return
    /// borrows `'a` from the buffer rather than from `&self`, which is what `Repr::parse_ref`
    /// depends on.
    ///
    #[flux_rs::trusted(no, reason = "panic site: opens the payload window")]
    #[flux_rs::sig(
        fn(&Packet<Ref>[@p]) -> &[u8][p.buffer.len - 8] requires 8 <= p.buffer.len
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let len = self.buffer.as_ref().len();
        self.buffer.window(self.header_len(), len)
    }
}
