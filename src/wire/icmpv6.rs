use byteorder::{ByteOrder, NetworkEndian};
use core::{cmp, fmt};

use super::{Error, Result};
use crate::phy::ChecksumCapabilities;
use crate::wire::MldRepr;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use crate::wire::NdiscRepr;
#[cfg(feature = "proto-rpl")]
use crate::wire::RplRepr;
use crate::wire::ip::checksum;
use crate::wire::{IPV6_HEADER_LEN, IPV6_MIN_MTU};
use crate::wire::{IpProtocol, Ipv6Address, Ipv6Packet, Ipv6Repr};
use crate::wire::{Ref, read_u16_at, read_u32_at};

/// Error packets must not exceed min MTU
const MAX_ERROR_PACKET_LEN: usize = IPV6_MIN_MTU - IPV6_HEADER_LEN;

flux_rs::defs! {
    // `Packet::header_len`, as a function of the message type octet. Kept in lockstep with
    // that method's body, which is `trusted(no)` and so has to prove it returns exactly this.
    // The `_ => 4` default covers `RplControl` and every `Unknown`, matching the comment on
    // the method: types outside RFC 4443 keep the last 32 bits of the header in `payload`.
    fn icmpv6_header_len(code: int) -> int {
        if code == 0x89 { 40 }
        else if code == 0x82 { 28 }
        else if code == 0x87 || code == 0x88 { 24 }
        else if code == 0x86 { 16 }
        else if code == 0x01 || code == 0x02 || code == 0x03 || code == 0x04
             || code == 0x80 || code == 0x81 || code == 0x85 || code == 0x8f { 8 }
        else { 4 }
    }

    // `Repr::buffer_len()` for the four error variants, as a function of `data.len()`:
    // `min(field::UNUSED.end + Ipv6Repr::buffer_len() + m, MAX_ERROR_PACKET_LEN)`
    // = `min(8 + 40 + m, 1240)`. Kept in lockstep with that method's body.
    fn icmpv6_err_buffer_len(m: int) -> int {
        if 48 + m < 1240 { 48 + m } else { 1240 }
    }
}

enum_with_unknown! {
    #[refined]
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Destination Unreachable.
        DstUnreachable  = 0x01,
        /// Packet Too Big.
        PktTooBig       = 0x02,
        /// Time Exceeded.
        TimeExceeded    = 0x03,
        /// Parameter Problem.
        ParamProblem    = 0x04,
        /// Echo Request
        EchoRequest     = 0x80,
        /// Echo Reply
        EchoReply       = 0x81,
        /// Multicast Listener Query
        MldQuery        = 0x82,
        /// Router Solicitation
        RouterSolicit   = 0x85,
        /// Router Advertisement
        RouterAdvert    = 0x86,
        /// Neighbor Solicitation
        NeighborSolicit = 0x87,
        /// Neighbor Advertisement
        NeighborAdvert  = 0x88,
        /// Redirect
        Redirect        = 0x89,
        /// Multicast Listener Report
        MldReport       = 0x8f,
        /// RPL Control Message
        RplControl      = 0x9b,
    }
}

impl Message {
    /// Per [RFC 4443 § 2.1] ICMPv6 message types with the highest order
    /// bit set are informational messages while message types without
    /// the highest order bit set are error messages.
    ///
    /// [RFC 4443 § 2.1]: https://tools.ietf.org/html/rfc4443#section-2.1
    pub fn is_error(&self) -> bool {
        (u8::from(*self) & 0x80) != 0x80
    }

    /// Return a boolean value indicating if the given message type
    /// is an [NDISC] message type.
    ///
    /// [NDISC]: https://tools.ietf.org/html/rfc4861
    pub const fn is_ndisc(&self) -> bool {
        match *self {
            Message::RouterSolicit
            | Message::RouterAdvert
            | Message::NeighborSolicit
            | Message::NeighborAdvert
            | Message::Redirect => true,
            _ => false,
        }
    }

    /// Return a boolean value indicating if the given message type
    /// is an [MLD] message type.
    ///
    /// [MLD]: https://tools.ietf.org/html/rfc3810
    pub const fn is_mld(&self) -> bool {
        match *self {
            Message::MldQuery | Message::MldReport => true,
            _ => false,
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::DstUnreachable => write!(f, "destination unreachable"),
            Message::PktTooBig => write!(f, "packet too big"),
            Message::TimeExceeded => write!(f, "time exceeded"),
            Message::ParamProblem => write!(f, "parameter problem"),
            Message::EchoReply => write!(f, "echo reply"),
            Message::EchoRequest => write!(f, "echo request"),
            Message::RouterSolicit => write!(f, "router solicitation"),
            Message::RouterAdvert => write!(f, "router advertisement"),
            Message::NeighborSolicit => write!(f, "neighbor solicitation"),
            Message::NeighborAdvert => write!(f, "neighbor advert"),
            Message::Redirect => write!(f, "redirect"),
            Message::MldQuery => write!(f, "multicast listener query"),
            Message::MldReport => write!(f, "multicast listener report"),
            Message::RplControl => write!(f, "RPL control message"),
            Message::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// No Route to destination.
        NoRoute         = 0,
        /// Communication with destination administratively prohibited.
        AdminProhibit   = 1,
        /// Beyond scope of source address.
        BeyondScope     = 2,
        /// Address unreachable.
        AddrUnreachable = 3,
        /// Port unreachable.
        PortUnreachable = 4,
        /// Source address failed ingress/egress policy.
        FailedPolicy    = 5,
        /// Reject route to destination.
        RejectRoute     = 6
    }
}

impl fmt::Display for DstUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DstUnreachable::NoRoute => write!(f, "no route to destination"),
            DstUnreachable::AdminProhibit => write!(
                f,
                "communication with destination administratively prohibited"
            ),
            DstUnreachable::BeyondScope => write!(f, "beyond scope of source address"),
            DstUnreachable::AddrUnreachable => write!(f, "address unreachable"),
            DstUnreachable::PortUnreachable => write!(f, "port unreachable"),
            DstUnreachable::FailedPolicy => {
                write!(f, "source address failed ingress/egress policy")
            }
            DstUnreachable::RejectRoute => write!(f, "reject route to destination"),
            DstUnreachable::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for the type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Erroneous header field encountered.
        ErroneousHdrField  = 0,
        /// Unrecognized Next Header type encountered.
        UnrecognizedNxtHdr = 1,
        /// Unrecognized IPv6 option encountered.
        UnrecognizedOption = 2
    }
}

impl fmt::Display for ParamProblem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParamProblem::ErroneousHdrField => write!(f, "erroneous header field."),
            ParamProblem::UnrecognizedNxtHdr => write!(f, "unrecognized next header type."),
            ParamProblem::UnrecognizedOption => write!(f, "unrecognized IPv6 option."),
            ParamProblem::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for the type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// Hop limit exceeded in transit.
        HopLimitExceeded    = 0,
        /// Fragment reassembly time exceeded.
        FragReassemExceeded = 1
    }
}

impl fmt::Display for TimeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TimeExceeded::HopLimitExceeded => write!(f, "hop limit exceeded in transit"),
            TimeExceeded::FragReassemExceeded => write!(f, "fragment reassembly time exceeded"),
            TimeExceeded::Unknown(id) => write!(f, "{id}"),
        }
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 6 packet buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(code: int, buffer: T)]
pub struct Packet<T: AsRef<[u8]>> {
    /// Mirrors `buffer[field::TYPE]`, which Flux cannot see. `new_unchecked` reads it out
    /// of the buffer and `set_msg_type` writes both; nothing else in `wire` writes octet 0.
    #[flux_rs::field(Message[code])]
    ty: Message,
    #[flux_rs::field(T[buffer])]
    pub(super) buffer: T,
}

// Ranges and constants describing key boundaries in the ICMPv6 header.
pub(super) mod field {
    use crate::wire::field::*;

    // ICMPv6: See https://tools.ietf.org/html/rfc4443
    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;

    pub const UNUSED: Field = 4..8;
    pub const MTU: Field = 4..8;
    pub const POINTER: Field = 4..8;
    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;

    // NDISC: See https://tools.ietf.org/html/rfc4861
    // Router Advertisement message offsets
    pub const CUR_HOP_LIMIT: usize = 4;
    pub const ROUTER_FLAGS: usize = 5;
    pub const ROUTER_LT: Field = 6..8;
    pub const REACHABLE_TM: Field = 8..12;
    pub const RETRANS_TM: Field = 12..16;

    // Neighbor Solicitation message offsets
    pub const TARGET_ADDR: Field = 8..24;

    // Neighbor Advertisement message offsets
    pub const NEIGH_FLAGS: usize = 4;

    // Redirected Header message offsets
    pub const DEST_ADDR: Field = 24..40;

    // MLD:
    //   - https://tools.ietf.org/html/rfc3810
    //   - https://tools.ietf.org/html/rfc3810
    // Multicast Listener Query message
    pub const MAX_RESP_CODE: Field = 4..6;
    pub const QUERY_RESV: Field = 6..8;
    pub const QUERY_MCAST_ADDR: Field = 8..24;
    pub const SQRV: usize = 24;
    pub const QQIC: usize = 25;
    pub const QUERY_NUM_SRCS: Field = 26..28;

    // Multicast Listener Report Message
    pub const RECORD_RESV: Field = 4..6;
    pub const NR_MCAST_RCRDS: Field = 6..8;

    // Multicast Address Record Offsets
    pub const RECORD_TYPE: usize = 0;
    pub const AUX_DATA_LEN: usize = 1;
    pub const RECORD_NUM_SRCS: Field = 2..4;
    pub const RECORD_MCAST_ADDR: Field = 4..20;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with ICMPv6 packet structure.
    ///
    /// A buffer with no type octet takes `Message::Unknown(0)`; [check_len] rejects it.
    ///
    /// [check_len]: #method.check_len
    #[flux_rs::trusted(no, reason = "establishes the `ty` mirror of `buffer[field::TYPE]`")]
    #[flux_rs::sig(fn(T[@b]) -> Packet<T>{v: v.buffer == b})]
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        let ty = match buffer.as_ref().first() {
            Some(&octet) => Message::from(octet),
            None => Message::from(0),
        };
        Packet { ty, buffer }
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
    /// for it. Returning the length lets the `Ok` arm say the three things the accessors want:
    /// what the buffer's length is, that a type and a code and a checksum fit in it, and that it
    /// reaches the end of this message type's header -- which is what
    /// [`payload`](Packet::payload) opens its window past.
    ///
    /// The bound is `4 <= v`, not `8 <= v`, because the RPL arm accepts a six-octet message;
    /// `icmpv6_header_len(p.code) <= v` is what carries the rest, and on every arm that reads a
    /// field beyond octet 4 the match on `msg_type` has already pinned `p.code`.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@p])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
                             && 4 <= v && icmpv6_header_len(p.code) <= v}>
    )]
    #[flux_rs::no_panic]
    pub(super) fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();

        if len < 4 {
            return Err(Error);
        }

        match self.msg_type() {
            Message::DstUnreachable
            | Message::PktTooBig
            | Message::TimeExceeded
            | Message::ParamProblem
            | Message::EchoRequest
            | Message::EchoReply
            | Message::MldQuery
            | Message::RouterSolicit
            | Message::RouterAdvert
            | Message::NeighborSolicit
            | Message::NeighborAdvert
            | Message::Redirect
            | Message::MldReport => {
                // 8 is `field::HEADER_END`; flux cannot see through a `usize` const.
                if len < 8 || len < self.header_len() {
                    return Err(Error);
                }
            }
            #[cfg(feature = "proto-rpl")]
            Message::RplControl => match super::rpl::RplControlMessage::from(self.msg_code()) {
                super::rpl::RplControlMessage::DodagInformationSolicitation => {
                    // TODO(thvdveld): replace magic number
                    if len < 6 {
                        return Err(Error);
                    }
                }
                super::rpl::RplControlMessage::DodagInformationObject => {
                    // TODO(thvdveld): replace magic number
                    if len < 28 {
                        return Err(Error);
                    }
                }
                super::rpl::RplControlMessage::DestinationAdvertisementObject => {
                    // TODO(thvdveld): replace magic number
                    if len < 8 || (self.dao_dodag_id_present() && len < 24) {
                        return Err(Error);
                    }
                }
                super::rpl::RplControlMessage::DestinationAdvertisementObjectAck => {
                    // TODO(thvdveld): replace magic number
                    if len < 8 || (self.dao_dodag_id_present() && len < 24) {
                        return Err(Error);
                    }
                }
                super::rpl::RplControlMessage::SecureDodagInformationSolicitation
                | super::rpl::RplControlMessage::SecureDodagInformationObject
                | super::rpl::RplControlMessage::SecureDestinationAdvertisementObject
                | super::rpl::RplControlMessage::SecureDestinationAdvertisementObjectAck
                | super::rpl::RplControlMessage::ConsistencyCheck => return Err(Error),
                super::rpl::RplControlMessage::Unknown(_) => return Err(Error),
            },
            #[cfg(not(feature = "proto-rpl"))]
            Message::RplControl => return Err(Error),
            Message::Unknown(_) => return Err(Error),
        }

        Ok(len)
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[flux_rs::trusted(no, reason = "backs Packet's code index")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> Message[p.code])]
    #[inline]
    pub fn msg_type(&self) -> Message {
        self.ty
    }

    /// Return the message code field.
    // Literal offsets rather than `field::CODE`: flux cannot see through a `const` of struct
    // type, and `usize` consts are opaque to it too, so the bound has to be written out. The
    // original spelling is kept in a trailing comment. Same throughout this impl.
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
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 4) // field::ECHO_IDENT
    }

    /// Return the sequence number field (for echo request and reply packets).
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u16 requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 6) // field::ECHO_SEQNO
    }

    /// Return the MTU field (for packet too big messages).
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u32 requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn pkt_too_big_mtu(&self) -> u32 {
        let data = self.buffer.as_ref();
        read_u32_at(data, 4) // field::MTU
    }

    /// Return the pointer field (for parameter problem messages).
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u32 requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn param_problem_ptr(&self) -> u32 {
        let data = self.buffer.as_ref();
        read_u32_at(data, 4) // field::POINTER
    }

    /// Return the header length. The result depends on the value of
    /// the message type field.
    // The arms return literals rather than `field::X.end`: a `const` of struct type is opaque
    // to Flux, so `field::UNUSED.end` is an unconstrained `usize` and the postcondition below
    // cannot be discharged. The literal on each arm is the value that `const` has; the
    // original spelling is kept in a trailing comment so the two stay reviewable together.
    #[flux_rs::trusted(no, reason = "carries the per-type header length to payload/payload_mut")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> usize[icmpv6_header_len(p.code)])]
    #[flux_rs::no_panic]
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::DstUnreachable => 8,   // field::UNUSED.end
            Message::PktTooBig => 8,        // field::MTU.end
            Message::TimeExceeded => 8,     // field::UNUSED.end
            Message::ParamProblem => 8,     // field::POINTER.end
            Message::EchoRequest => 8,      // field::ECHO_SEQNO.end
            Message::EchoReply => 8,        // field::ECHO_SEQNO.end
            Message::RouterSolicit => 8,    // field::UNUSED.end
            Message::RouterAdvert => 16,    // field::RETRANS_TM.end
            Message::NeighborSolicit => 24, // field::TARGET_ADDR.end
            Message::NeighborAdvert => 24,  // field::TARGET_ADDR.end
            Message::Redirect => 40,        // field::DEST_ADDR.end
            Message::MldQuery => 28,        // field::QUERY_NUM_SRCS.end
            Message::MldReport => 8,        // field::NR_MCAST_RCRDS.end
            // For packets that are not included in RFC 4443, do not
            // include the last 32 bits of the ICMPv6 header in
            // `header_bytes`. This must be done so that these bytes
            // can be accessed in the `payload`.
            //
            // Spelled out rather than left to a `_`, for the same reason as `clear_reserved`:
            // Flux only learns `code != <every named value>` from the named `Unknown` pattern,
            // and that is what discharges `icmpv6_header_len(code) == 4` here.
            Message::RplControl => 4,  // field::CHECKSUM.end
            Message::Unknown(_) => 4,  // field::CHECKSUM.end
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    ///
    /// `as_ref_reft <= 65535` is `checksum::data`'s own bound -- its `u32` accumulator cannot
    /// take more than 65535 octets without overflowing. It is a real, satisfiable property of
    /// every ICMPv6 buffer, which are sized from `Repr::buffer_len()` under `IPV6_MIN_MTU`, so
    /// it is stated as a caller obligation rather than assumed here.
    ///
    /// No `no_panic`: `checksum::combine` and `checksum::pseudo_header_v6` carry none, so the
    /// attribute would report their transitive obligations here rather than the bound above.
    #[flux_rs::trusted(no, reason = "panic site: checksum::data's length bound")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p], &Ipv6Address, &Ipv6Address) -> bool
        requires <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
    )]
    pub fn verify_checksum(&self, src_addr: &Ipv6Address, dst_addr: &Ipv6Address) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::combine(&[
            checksum::pseudo_header_v6(src_addr, dst_addr, IpProtocol::Icmpv6, data.len() as u32),
            checksum::data(data),
        ]) == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[flux_rs::trusted(no, reason = "the `ensures` is the link clear_reserved's proof rests on")]
    #[flux_rs::sig(
        fn(self: &strg Packet<T>[@p], Message[@code])
        requires 0 < <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures self: Packet<T>[code, p.buffer]
    )]
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        self.ty = value;
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into()
    }

    /// Set the message code field.
    #[flux_rs::trusted(no, reason = "the preserved index is a link clear_reserved's proof rests on")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u8)
        requires 1 < <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CODE] = value
    }

    /// Clear any reserved fields in the message header.
    ///
    /// Only the message types that have reserved fields accept this call: MLD query and
    /// report, and the NDISC types other than router advertisement. Set the type first
    /// with [set_msg_type].
    ///
    /// [set_msg_type]: #method.set_msg_type
    #[allow(unsafe_code)]
    #[flux_rs::trusted(no, reason = "discharges the assert(false) licensing unreachable_unchecked")]
    // The buffer bound is per-arm: MLD query also clears `SQRV` at octet 24, MLD report only
    // reaches `RECORD_RESV.end`, and the NDISC types only reach `UNUSED.end`.
    #[flux_rs::sig(fn(&mut Packet<T>[@p])
        requires (p.code == 0x82 || p.code == 0x85 || p.code == 0x87
               || p.code == 0x88 || p.code == 0x89 || p.code == 0x8f)
              && (p.code == 0x82 => 25 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))
              && (p.code == 0x8f => 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))
              && ((p.code == 0x85 || p.code == 0x87 || p.code == 0x88 || p.code == 0x89)
                  => 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)))]
    #[inline]
    pub fn clear_reserved(&mut self) {
        // Ranges spelled out: a `const` of struct type is opaque to Flux, so `field::UNUSED`
        // does not even yield `4 <= 8`.
        match self.msg_type() {
            Message::RouterSolicit
            | Message::NeighborSolicit
            | Message::NeighborAdvert
            | Message::Redirect => {
                let data = self.buffer.as_mut();
                // Two big-endian halves rather than one `write_u32`: see the note on
                // `set_pkt_too_big_mtu`. Writing 0 to 4..6 then 6..8 is the same four bytes.
                crate::wire::write_u16_at(data, 4, 0);
                crate::wire::write_u16_at(data, 6, 0);
            }
            Message::MldQuery => {
                let data = self.buffer.as_mut();
                crate::wire::write_u16_at(data, 6, 0);
                data[field::SQRV] &= 0xf;
            }
            Message::MldReport => {
                let data = self.buffer.as_mut();
                crate::wire::write_u16_at(data, 4, 0);
            }
            // Spelled out rather than left to a `_`: Flux only rules an arm out for named
            // patterns.
            Message::DstUnreachable
            | Message::PktTooBig
            | Message::TimeExceeded
            | Message::ParamProblem
            | Message::EchoRequest
            | Message::EchoReply
            | Message::RouterAdvert
            | Message::RplControl
            | Message::Unknown(_) => {
                // If this assert never fires, Flux has shown this branch unreachable.
                flux_rs::assert(false);
                unsafe { core::hint::unreachable_unchecked() }
            }
        }
    }

    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u16)
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 2, value) // field::CHECKSUM
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u16)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 4, value) // field::ECHO_IDENT
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u16)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 6, value) // field::ECHO_SEQNO
    }

    /// Set the MTU field (for packet too big messages).
    ///
    /// # Panics
    /// This function may panic if this packet is not an packet too big packet.
    // The single `write_u32` over `4..8` is written as the two big-endian halves it is defined
    // to produce. There is no `write_u32_at` helper, and `byteorder::write_u32` has no extern
    // spec (its body is `NoMIRAvailable`), so the u32 form is unprovable; `write_u16` has both.
    // The emitted bytes are identical -- `u32::to_be_bytes(v)` is
    // `to_be_bytes(v >> 16) ++ to_be_bytes(v as u16)`.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u32)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_pkt_too_big_mtu(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 4, (value >> 16) as u16); // field::MTU
        crate::wire::write_u16_at(data, 6, value as u16);
    }

    /// Set the pointer field (for parameter problem messages).
    ///
    /// # Panics
    /// This function may panic if this packet is not a parameter problem message.
    // Split into two big-endian halves for the same reason as `set_pkt_too_big_mtu`.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u32)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_param_problem_ptr(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        crate::wire::write_u16_at(data, 4, (value >> 16) as u16); // field::POINTER
        crate::wire::write_u16_at(data, 6, value as u16);
    }

    /// Compute and fill in the header checksum.
    ///
    /// The `[@p]` on the receiver is the point of the signature: without it the caller's
    /// `40 <= as_mut_reft(buffer)` is havoced across this call (a `&mut T{v: ..}` refinement
    /// does not survive a call to a callee that does not restate the index).
    /// `as_ref_reft <= 65535` is `checksum::data`'s own bound (a `u16` accumulator cannot
    /// take more than 65535 octets without the fold overflowing). It is a real, satisfiable
    /// property of every icmpv6 buffer -- they are sized from `Repr::buffer_len()`, capped at
    /// 1240 -- so it is stated as a caller obligation rather than assumed here.
    #[flux_rs::trusted(no, reason = "panic site: two fixed-offset checksum writes")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p], &Ipv6Address, &Ipv6Address)
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
             && <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
    )]
    pub fn fill_checksum(&mut self, src_addr: &Ipv6Address, dst_addr: &Ipv6Address) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::combine(&[
                checksum::pseudo_header_v6(
                    src_addr,
                    dst_addr,
                    IpProtocol::Icmpv6,
                    data.len() as u32,
                ),
                checksum::data(data),
            ])
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the type-specific data.
    ///
    /// The caller owes room for this message type's header; the bound is exactly what
    /// [check_len] tests at runtime, stated statically.
    ///
    /// [check_len]: #method.check_len
    #[flux_rs::trusted(no, reason = "panic site: the `header_len()..` split")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p]) -> &mut [u8]
        requires icmpv6_header_len(p.code) <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }

    /// The type-specific data, as a length-carrying [`Buf`].
    ///
    /// Same bytes as [`payload_mut`], but the length survives the return: a returned
    /// `&mut [u8]` lands in the caller with no index (flux-rs/flux#1714), so `payload_mut`'s
    /// result cannot be sliced or measured under a refinement. `Buf` does the offsetting
    /// internally and *declares* its length, so the caller gets
    /// `as_mut_reft(buffer) - icmpv6_header_len(code)` back.
    ///
    /// [`payload_mut`]: #method.payload_mut
    /// [`Buf`]: crate::wire::Buf
    #[flux_rs::trusted(no, reason = "carries the payload length out to the caller")]
    #[flux_rs::sig(
        fn(self: &mut Packet<T>[@p])
            -> crate::wire::Buf[<T as AsMut<[u8]>>::as_mut_reft(p.buffer)
                                - icmpv6_header_len(p.code)]
        requires icmpv6_header_len(p.code) <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload_buf(&mut self) -> crate::wire::Buf<'_> {
        let offset = self.header_len();
        let data = self.buffer.as_mut();
        // Same window and the same bounds check as `payload_mut`. Sliced here rather than via
        // `Buf::with_offset`, whose `as_mut` is `get_unchecked_mut(offset..)`: that would turn a
        // buffer shorter than the header from a panic into UB. `Buf::new` carries offset 0, so
        // its `as_mut` is in bounds by construction.
        crate::wire::Buf::new(&mut data[offset..])
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

/// A high-level representation of an Internet Control Message Protocol version 6 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
// Indexed by `buffer_len()`, which is what every caller of `emit` allocates. That is the only
// way to state `emit`'s real precondition: the contained-packet copy needs
// `icmpv6_header_len(code) + 40 + data.len() <= len || 1240 <= len`, and `data.len()` lives
// inside the `Repr`.
//
// The `Ndisc`/`Mld`/`Rpl` variants are indexed `0`, not by their own `buffer_len()`: those
// reprs are not refined (they belong to `ndisc.rs` / `mld.rs` / `rpl.rs`), so the length is
// not statable here. Nothing is lost -- `emit`'s separate `40 <= as_mut_reft(buffer)`
// conjunct still applies to them, and it is all they carried before -- but the bound
// `NdiscRepr::emit` / `MldRepr::emit` actually need is still owed by nobody. Refining those
// two reprs is what closes it.
// Every variant writes at least the 4-octet ICMPv6 header, so `fill_checksum` / `set_checksum`
// (which require `4 <= buffer`) follow from `r.blen <= buffer` alone. Flux checks this against
// each `variant` below, so it is an obligation discharged here, not an assumption.
#[flux_rs::invariant(4 <= blen)]
// See `icmpv4::Repr`: the enclosing IPv6 packet's length field is sixteen bits. The four error
// variants are already capped at `MAX_ERROR_PACKET_LEN` by `icmpv6_err_buffer_len`; the two
// echo variants carry the bound on their payload instead.
#[flux_rs::invariant(blen <= 65535)]
#[flux_rs::refined_by(blen: int)]
pub enum Repr<'a> {
    #[flux_rs::variant({DstUnreachable, Ipv6Repr, &[u8][@m]} -> Repr[icmpv6_err_buffer_len(m)])]
    DstUnreachable {
        reason: DstUnreachable,
        header: Ipv6Repr,
        data: &'a [u8],
    },
    #[flux_rs::variant({u32, Ipv6Repr, &[u8][@m]} -> Repr[icmpv6_err_buffer_len(m)])]
    PktTooBig {
        mtu: u32,
        header: Ipv6Repr,
        data: &'a [u8],
    },
    #[flux_rs::variant({TimeExceeded, Ipv6Repr, &[u8][@m]} -> Repr[icmpv6_err_buffer_len(m)])]
    TimeExceeded {
        reason: TimeExceeded,
        header: Ipv6Repr,
        data: &'a [u8],
    },
    #[flux_rs::variant({ParamProblem, u32, Ipv6Repr, &[u8][@m]} -> Repr[icmpv6_err_buffer_len(m)])]
    ParamProblem {
        reason: ParamProblem,
        pointer: u32,
        header: Ipv6Repr,
        data: &'a [u8],
    },
    #[flux_rs::variant({u16, u16, {&[u8][@m] | m <= 65527}} -> Repr[8 + m])]
    EchoRequest {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
    #[flux_rs::variant({u16, u16, {&[u8][@m] | m <= 65527}} -> Repr[8 + m])]
    EchoReply {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    #[flux_rs::variant((NdiscRepr[@n]) -> Repr[n])]
    Ndisc(NdiscRepr<'a>),
    #[flux_rs::variant((MldRepr[@m]) -> Repr[m])]
    Mld(MldRepr<'a>),
    #[cfg(feature = "proto-rpl")]
    #[flux_rs::variant((RplRepr) -> Repr[4])]
    Rpl(RplRepr<'a>),
}

impl<'a> Repr<'a> {
    /// Parse an Internet Control Message Protocol version 6 packet and return
    /// a high-level representation.
    ///
    /// There is no generic `parse` over `&T`: a reference in type-parameter position has the
    /// unit sort, so such a wrapper could not state the `requires` below and the obligation
    /// surfaced there undischargeable. Callers build a [`Ref`] instead.
    ///
    /// `p.buffer.len <= 65535`: the echo variants' payloads are windows into `packet`, and they
    /// carry the bound that keeps `Repr`'s own `blen <= 65535` true. The packet is an IPv6
    /// payload, whose extent is the sixteen-bit length field, so it holds wherever this is
    /// called; from outside the crate it is the caller's to discharge.
    #[flux_rs::sig(
        fn(&Ipv6Address, &Ipv6Address, &Packet<Ref>[@p], &ChecksumCapabilities) -> Result<Repr>
        requires p.buffer.len <= 65535
    )]
    pub fn parse_ref(
        src_addr: &Ipv6Address,
        dst_addr: &Ipv6Address,
        packet: &Packet<Ref<'a>>,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr<'a>> {
        let len = packet.checked_len()?;

        fn create_packet_from_payload<'a>(payload: Ref<'a>) -> Result<(&'a [u8], Ipv6Repr)> {
            // The packet must be truncated to fit the min MTU. Since we don't know the offset of
            // the ICMPv6 header in the L2 frame, we should only check whether the payload's IPv6
            // header is present, the rest is allowed to be truncated.
            //
            // 40 is `IPV6_HEADER_LEN`, and it is also what `ip_packet.header_len()` returns for
            // every IPv6 packet -- that header is fixed width. Both are spelled as the literal
            // because flux sees through neither a `usize` const nor `Ipv6Packet::header_len`,
            // which carries no signature.
            let len = payload.as_ref().len();
            if len < 40 {
                return Err(Error);
            }
            let ip_packet = Ipv6Packet::new_unchecked(payload);
            let repr = Ipv6Repr {
                src_addr: ip_packet.src_addr(),
                dst_addr: ip_packet.dst_addr(),
                next_header: ip_packet.next_header(),
                // `as usize` rather than `.into()`: `From<u16> for usize` carries no spec, so
                // the result is unbounded and `Ipv6Repr`'s `plen <= 65535` fails under it.
                payload_len: ip_packet.payload_len() as usize,
                hop_limit: ip_packet.hop_limit(),
            };
            Ok((payload.window(40, len), repr))
        }
        // Valid checksum is expected.
        if checksum_caps.icmpv6.rx() && !packet.verify_checksum(src_addr, dst_addr) {
            return Err(Error);
        }

        match (packet.msg_type(), packet.msg_code()) {
            (Message::DstUnreachable, code) => {
                let (payload, repr) = create_packet_from_payload(Ref::new(packet.payload()))?;
                Ok(Repr::DstUnreachable {
                    reason: DstUnreachable::from(code),
                    header: repr,
                    data: payload,
                })
            }
            (Message::PktTooBig, 0) => {
                let (payload, repr) = create_packet_from_payload(Ref::new(packet.payload()))?;
                Ok(Repr::PktTooBig {
                    mtu: packet.pkt_too_big_mtu(),
                    header: repr,
                    data: payload,
                })
            }
            (Message::TimeExceeded, code) => {
                let (payload, repr) = create_packet_from_payload(Ref::new(packet.payload()))?;
                Ok(Repr::TimeExceeded {
                    reason: TimeExceeded::from(code),
                    header: repr,
                    data: payload,
                })
            }
            (Message::ParamProblem, code) => {
                let (payload, repr) = create_packet_from_payload(Ref::new(packet.payload()))?;
                Ok(Repr::ParamProblem {
                    reason: ParamProblem::from(code),
                    pointer: packet.param_problem_ptr(),
                    header: repr,
                    data: payload,
                })
            }
            (Message::EchoRequest, 0) => Ok(Repr::EchoRequest {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                data: packet.payload(),
            }),
            (Message::EchoReply, 0) => Ok(Repr::EchoReply {
                ident: packet.echo_ident(),
                seq_no: packet.echo_seq_no(),
                data: packet.payload(),
            }),
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            (msg_type, 0) if msg_type.is_ndisc() => NdiscRepr::parse(packet).map(Repr::Ndisc),
            (msg_type, 0) if msg_type.is_mld() => MldRepr::parse(packet).map(Repr::Mld),
            // `RplRepr::parse` still takes a `Packet<&'a T>`; the window goes back to a plain
            // slice for it. It runs its own `check_len`, so nothing proved here is lost.
            #[cfg(feature = "proto-rpl")]
            (Message::RplControl, _) => {
                let packet = Packet::new_unchecked(packet.buffer.window(0, len));
                RplRepr::parse(&packet).map(Repr::Rpl)
            }
            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    //
    // 8 restates `field::UNUSED.end` and `field::ECHO_SEQNO.end`: flux cannot see through a
    // `Range` const. `byte_len` carries the slice's `isize::MAX` ceiling, which is what keeps
    // the sums from reading as wrapping under `check_overflow = "lazy"`.
    #[flux_rs::trusted(no, reason = "ties the `blen` index to the emitted length")]
    #[flux_rs::sig(fn(self: &Self[@r]) -> usize[r.blen])]
    #[flux_rs::no_panic]
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::DstUnreachable { header, data, .. }
            | &Repr::PktTooBig { header, data, .. }
            | &Repr::TimeExceeded { header, data, .. }
            | &Repr::ParamProblem { header, data, .. } => cmp::min(
                8 + header.buffer_len() + crate::flux_util::byte_len(data),
                MAX_ERROR_PACKET_LEN,
            ),
            &Repr::EchoRequest { data, .. } | &Repr::EchoReply { data, .. } => {
                8 + crate::flux_util::byte_len(data)
            }
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            &Repr::Ndisc(ndisc) => ndisc.buffer_len(),
            &Repr::Mld(mld) => mld.buffer_len(),
            #[cfg(feature = "proto-rpl")]
            Repr::Rpl(rpl) => rpl.buffer_len(),
        }
    }

    /// Emit a high-level representation into an Internet Control Message Protocol version 6
    /// packet.
    // The buffer parameter is `Packet<T>` with `T: Sized`, not `Packet<&mut T>` with `T: ?Sized`.
    // The old shape instantiated core's blanket `impl<T, U> AsMut<U> for &mut T`, which carries no
    // associated refinement, so every `requires ... as_mut_reft(p.buffer)` on the setters below
    // raised `associated refinement 'as_mut_reft' is missing from implementation` rather than an
    // obligation flux could discharge. The `Sized` form lets a caller pass `wire::Buf`, whose
    // `AsMut` impl is local and refined; `&mut [u8]` still satisfies the bounds, so this is
    // strictly more permissive.
    //
    // `packet` is `&strg`, not `&mut Packet<T>{v: ..}`. The setters change the `code` index, and
    // an existential `&mut` is re-established (i.e. `code` is havoced) after every write, so the
    // four `emit_contained_packet` calls could not see that `icmpv6_header_len(code) == 8`. A
    // `&strg` place carries the index through. This is a flux-only change: the Rust signature is
    // still `&mut Packet<T>`.
    //
    // `requires` reads:
    //   * `40 <= as_mut_reft(buffer)` -- the widest header (Redirect) plus a v6 header.
    //   * `as_ref_reft(buffer) <= 65535` -- `checksum::data`'s own bound, exposed rather than
    //     assumed; every icmpv6 buffer is sized from `buffer_len()`, capped at 1240.
    //   * `r.blen <= as_mut_reft(buffer)` -- `r.blen` *is* `Repr::buffer_len()`, which is what
    //     every caller allocates. It is the only way to state the contained-packet bound
    //     `icmpv6_header_len(code) + 40 + data.len() <= len || 1240 <= len`, because `data.len()`
    //     lives inside the `Repr`.
    //
    // STILL OWED (3 obligations, all outside this file): `NdiscRepr::emit` and `MldRepr::emit`
    // have no flux signature, so `packet`'s buffer index is havoced across those two arms and the
    // trailing `fill_checksum` / `set_checksum` cannot be discharged. Adding
    // `fn(&Self, &mut Packet<T>[@p]) requires 40 <= as_mut_reft(p.buffer)` to each -- no body
    // proof needed -- takes this function to zero errors; verified by probe, then reverted,
    // because those files belong to another slice.
    #[flux_rs::trusted(no, reason = "panic site: every header setter and the payload copy")]
    #[flux_rs::sig(
        fn(self: &Self[@r], &Ipv6Address, &Ipv6Address,
           packet: &strg Packet<T>[@p], &ChecksumCapabilities)
        requires <T as AsRef<[u8]>>::as_ref_reft(p.buffer) <= 65535
              // Equality on the mutable side: the `Mld` arm forwards to `mld::Repr::emit`,
              // whose two `copy_from_slice` calls panic unless the payload window is exactly
              // the data's length.
              && r.blen == <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures packet: Packet<T>
    )]
    pub fn emit<T>(
        &self,
        src_addr: &Ipv6Address,
        dst_addr: &Ipv6Address,
        packet: &mut Packet<T>,
        checksum_caps: &ChecksumCapabilities,
    ) where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        // The bound below is the weakest one this body needs. `payload_len` is
        // `min(data.len(), 1240 - h - 40)` with `h = icmpv6_header_len(code)`, and the two
        // writes together need `h + 40 + payload_len <= len`; that is equivalent to the
        // disjunction, because the second disjunct is exactly the `min` saturating.
        //
        // `header.buffer_len()` is spelled `IPV6_HEADER_LEN`: `Ipv6Repr::buffer_len` is a
        // `const fn` with no flux signature, so its result is an unconstrained `usize` here.
        // Both are 40.
        #[flux_rs::trusted(no, reason = "panic site: the contained-packet copy")]
        #[flux_rs::sig(
            fn(packet: &mut Packet<T>[@p], Ipv6Repr, &[u8][@m])
            requires icmpv6_header_len(p.code) + 40 + m
                         <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
                  || 1240 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        )]
        fn emit_contained_packet<T>(packet: &mut Packet<T>, header: Ipv6Repr, data: &[u8])
        where
            T: AsRef<[u8]> + AsMut<[u8]>,
        {
            let icmp_header_len = packet.header_len();
            // Routed through `Buf` so the destination keeps its length: `&mut [u8]` instantiates
            // core's blanket `AsMut for &mut T`, which carries no associated refinement, and a
            // returned `&mut` loses its index besides (flux-rs/flux#1714).
            let mut payload = packet.payload_buf();
            let mut ip_packet = Ipv6Packet::new_unchecked(payload.reborrow());
            header.emit(&mut ip_packet);
            // FIXME: this should rather be checked at link level, as we can't know in advance how
            // much space we have for the packet due to IPv6 options and etc
            let payload_len = cmp::min(
                data.len(),
                MAX_ERROR_PACKET_LEN - icmp_header_len - IPV6_HEADER_LEN,
            );
            payload.copy_at(IPV6_HEADER_LEN, crate::wire::prefix(data, payload_len));
        }

        match *self {
            Repr::DstUnreachable {
                reason,
                header,
                data,
            } => {
                packet.set_msg_type(Message::DstUnreachable);
                packet.set_msg_code(reason.into());

                emit_contained_packet(packet, header, data);
            }

            Repr::PktTooBig { mtu, header, data } => {
                packet.set_msg_type(Message::PktTooBig);
                packet.set_msg_code(0);
                packet.set_pkt_too_big_mtu(mtu);

                emit_contained_packet(packet, header, data);
            }

            Repr::TimeExceeded {
                reason,
                header,
                data,
            } => {
                packet.set_msg_type(Message::TimeExceeded);
                packet.set_msg_code(reason.into());

                emit_contained_packet(packet, header, data);
            }

            Repr::ParamProblem {
                reason,
                pointer,
                header,
                data,
            } => {
                packet.set_msg_type(Message::ParamProblem);
                packet.set_msg_code(reason.into());
                packet.set_param_problem_ptr(pointer);

                emit_contained_packet(packet, header, data);
            }

            Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                packet.set_msg_type(Message::EchoRequest);
                packet.set_msg_code(0);
                packet.set_echo_ident(ident);
                packet.set_echo_seq_no(seq_no);
                let mut payload = packet.payload_buf();
                let data_len = cmp::min(payload.as_ref().len(), data.len());
                payload.copy_at(0, crate::wire::prefix(data, data_len))
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
                let mut payload = packet.payload_buf();
                let data_len = cmp::min(payload.as_ref().len(), data.len());
                payload.copy_at(0, crate::wire::prefix(data, data_len))
            }

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Repr::Ndisc(ndisc) => ndisc.emit(packet),

            Repr::Mld(mld) => mld.emit(packet),

            #[cfg(feature = "proto-rpl")]
            Repr::Rpl(ref rpl) => rpl.emit(packet),
        }

        if checksum_caps.icmpv6.tx() {
            packet.fill_checksum(src_addr, dst_addr);
        } else {
            // make sure we get a consistently zeroed checksum, since implementations might rely on it
            packet.set_checksum(0);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::{IpProtocol, Ipv6Address, Ipv6Repr};

    const MOCK_IP_ADDR_1: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const MOCK_IP_ADDR_2: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    static ECHO_PACKET_BYTES: [u8; 12] = [
        0x80, 0x00, 0x19, 0xb3, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff,
    ];

    static ECHO_PACKET_PAYLOAD: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    static PKT_TOO_BIG_BYTES: [u8; 60] = [
        0x02, 0x00, 0x0f, 0xc9, 0x00, 0x00, 0x05, 0xdc, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11,
        0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    static PKT_TOO_BIG_IP_PAYLOAD: [u8; 52] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xbf, 0x00, 0x00, 0x35, 0x00,
        0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    static PKT_TOO_BIG_UDP_PAYLOAD: [u8; 12] = [
        0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    fn echo_packet_repr() -> Repr<'static> {
        Repr::EchoRequest {
            ident: 0x1234,
            seq_no: 0xabcd,
            data: &ECHO_PACKET_PAYLOAD,
        }
    }

    fn too_big_packet_repr() -> Repr<'static> {
        Repr::PktTooBig {
            mtu: 1500,
            header: Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                next_header: IpProtocol::Udp,
                payload_len: 12,
                hop_limit: 0x40,
            },
            data: &PKT_TOO_BIG_UDP_PAYLOAD,
        }
    }

    #[test]
    fn test_echo_deconstruct() {
        let packet = Packet::new_unchecked(Ref::new(&ECHO_PACKET_BYTES[..]));
        assert_eq!(packet.msg_type(), Message::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x19b3);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.payload(), &ECHO_PACKET_PAYLOAD[..]);
        assert!(packet.verify_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2));
        assert!(!packet.msg_type().is_error());
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = vec![0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet
            .payload_mut()
            .copy_from_slice(&ECHO_PACKET_PAYLOAD[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&*packet.into_inner(), &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_echo_repr_parse() {
        let packet = Packet::new_unchecked(Ref::new(&ECHO_PACKET_BYTES[..]));
        let repr = Repr::parse_ref(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &packet,
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr, echo_packet_repr());
    }

    #[test]
    fn test_echo_emit() {
        let repr = echo_packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_too_big_deconstruct() {
        let packet = Packet::new_unchecked(Ref::new(&PKT_TOO_BIG_BYTES[..]));
        assert_eq!(packet.msg_type(), Message::PktTooBig);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x0fc9);
        assert_eq!(packet.pkt_too_big_mtu(), 1500);
        assert_eq!(packet.payload(), &PKT_TOO_BIG_IP_PAYLOAD[..]);
        assert!(packet.verify_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2));
        assert!(packet.msg_type().is_error());
    }

    #[test]
    fn test_too_big_construct() {
        let mut bytes = vec![0xa5; 60];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::PktTooBig);
        packet.set_msg_code(0);
        packet.set_pkt_too_big_mtu(1500);
        packet
            .payload_mut()
            .copy_from_slice(&PKT_TOO_BIG_IP_PAYLOAD[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&*packet.into_inner(), &PKT_TOO_BIG_BYTES[..]);
    }

    #[test]
    fn test_too_big_repr_parse() {
        let packet = Packet::new_unchecked(Ref::new(&PKT_TOO_BIG_BYTES[..]));
        let repr = Repr::parse_ref(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &packet,
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr, too_big_packet_repr());
    }

    #[test]
    fn test_too_big_emit() {
        let repr = too_big_packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &PKT_TOO_BIG_BYTES[..]);
    }

    #[test]
    fn test_buffer_length_is_truncated_to_mtu() {
        let repr = Repr::PktTooBig {
            mtu: 1280,
            header: Ipv6Repr {
                src_addr: Ipv6Address::UNSPECIFIED,
                dst_addr: Ipv6Address::UNSPECIFIED,
                next_header: IpProtocol::Tcp,
                hop_limit: 64,
                payload_len: 1280,
            },
            data: &vec![0; 9999],
        };
        assert_eq!(repr.buffer_len(), 1280 - IPV6_HEADER_LEN);
    }

    #[test]
    fn test_mtu_truncated_payload_roundtrip() {
        let ip_packet_repr = Ipv6Repr {
            src_addr: Ipv6Address::UNSPECIFIED,
            dst_addr: Ipv6Address::UNSPECIFIED,
            next_header: IpProtocol::Tcp,
            hop_limit: 64,
            payload_len: IPV6_MIN_MTU - IPV6_HEADER_LEN,
        };
        let mut ip_packet = Ipv6Packet::new_unchecked(vec![0; IPV6_MIN_MTU]);
        ip_packet_repr.emit(&mut ip_packet);

        let repr1 = Repr::PktTooBig {
            mtu: IPV6_MIN_MTU as u32,
            header: ip_packet_repr,
            data: &ip_packet.as_ref()[IPV6_HEADER_LEN..],
        };
        // this is needed to make sure roundtrip gives the same value
        // it is not needed for ensuring the correct bytes get emitted
        let repr1 = Repr::PktTooBig {
            mtu: IPV6_MIN_MTU as u32,
            header: ip_packet_repr,
            data: &ip_packet.as_ref()[IPV6_HEADER_LEN..repr1.buffer_len() - field::UNUSED.end],
        };
        let mut data = vec![0; MAX_ERROR_PACKET_LEN];
        let mut packet = Packet::new_unchecked(&mut data);
        repr1.emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );

        let packet = Packet::new_unchecked(Ref::new(&data));
        let repr2 = Repr::parse_ref(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &packet,
            &ChecksumCapabilities::default(),
        )
        .unwrap();

        assert_eq!(repr1, repr2);
    }

    #[test]
    fn test_truncated_payload_ipv6_header_parse_fails() {
        let repr = too_big_packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(
            &MOCK_IP_ADDR_1,
            &MOCK_IP_ADDR_2,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        let packet =
            Packet::new_unchecked(Ref::new(&bytes[..field::HEADER_END + IPV6_HEADER_LEN - 1]));
        assert!(
            Repr::parse_ref(
                &MOCK_IP_ADDR_1,
                &MOCK_IP_ADDR_2,
                &packet,
                &ChecksumCapabilities::ignored(),
            )
            .is_err()
        );
    }
}

impl<'a> Packet<Ref<'a>> {
    /// [`new_checked`](Self::new_checked) over a [`Ref`], carrying its proof out.
    ///
    /// The generic `new_checked` cannot say this: at a reference or `dyn` self type the
    /// `as_ref_reft` in the postcondition is unstatable. Over `Ref` the buffer's length is
    /// `b.len`, and what `checked_len` already proves is what the accessors require.
    #[flux_rs::trusted(no, reason = "carries `checked_len`'s proof out through the `Ok` arm")]
    #[flux_rs::sig(
        fn(Ref[@b]) -> Result<Packet<Ref>{p: p.buffer == b && 4 <= b.len
                                             && icmpv6_header_len(p.code) <= b.len}>
    )]
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
    /// `p.buffer.len`, the window is the one `payload_mut` proves, and the payload's length
    /// survives into the caller's index. The return borrows `'a` from the buffer rather than
    /// from `&self`, which is what `Repr::parse_ref` depends on.
    #[flux_rs::trusted(no, reason = "panic site: opens the payload window")]
    #[flux_rs::sig(
        fn(&Packet<Ref>[@p]) -> &[u8][p.buffer.len - icmpv6_header_len(p.code)]
        requires icmpv6_header_len(p.code) <= p.buffer.len
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let len = self.buffer.as_ref().len();
        self.buffer.window(self.header_len(), len)
    }
}
