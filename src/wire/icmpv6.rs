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
    pub fn check_len(&self) -> Result<()> {
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
                if len < field::HEADER_END || len < self.header_len() {
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

        Ok(())
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
    #[inline]
    pub fn msg_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CODE]
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_SEQNO])
    }

    /// Return the MTU field (for packet too big messages).
    #[inline]
    pub fn pkt_too_big_mtu(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::MTU])
    }

    /// Return the pointer field (for parameter problem messages).
    #[inline]
    pub fn param_problem_ptr(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::POINTER])
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

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.header_len()..]
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
    pub fn parse<T>(
        src_addr: &Ipv6Address,
        dst_addr: &Ipv6Address,
        packet: &Packet<&'a T>,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        packet.check_len()?;

        fn create_packet_from_payload<'a, T>(packet: &Packet<&'a T>) -> Result<(&'a [u8], Ipv6Repr)>
        where
            T: AsRef<[u8]> + ?Sized,
        {
            // The packet must be truncated to fit the min MTU. Since we don't know the offset of
            // the ICMPv6 header in the L2 frame, we should only check whether the payload's IPv6
            // header is present, the rest is allowed to be truncated.
            let ip_packet = if packet.payload().len() >= IPV6_HEADER_LEN {
                Ipv6Packet::new_unchecked(packet.payload())
            } else {
                return Err(Error);
            };

            let payload = &packet.payload()[ip_packet.header_len()..];
            let repr = Ipv6Repr {
                src_addr: ip_packet.src_addr(),
                dst_addr: ip_packet.dst_addr(),
                next_header: ip_packet.next_header(),
                payload_len: ip_packet.payload_len().into(),
                hop_limit: ip_packet.hop_limit(),
            };
            Ok((payload, repr))
        }
        // Valid checksum is expected.
        if checksum_caps.icmpv6.rx() && !packet.verify_checksum(src_addr, dst_addr) {
            return Err(Error);
        }

        match (packet.msg_type(), packet.msg_code()) {
            (Message::DstUnreachable, code) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
                Ok(Repr::DstUnreachable {
                    reason: DstUnreachable::from(code),
                    header: repr,
                    data: payload,
                })
            }
            (Message::PktTooBig, 0) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
                Ok(Repr::PktTooBig {
                    mtu: packet.pkt_too_big_mtu(),
                    header: repr,
                    data: payload,
                })
            }
            (Message::TimeExceeded, code) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
                Ok(Repr::TimeExceeded {
                    reason: TimeExceeded::from(code),
                    header: repr,
                    data: payload,
                })
            }
            (Message::ParamProblem, code) => {
                let (payload, repr) = create_packet_from_payload(packet)?;
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
            #[cfg(feature = "proto-rpl")]
            (Message::RplControl, _) => RplRepr::parse(packet).map(Repr::Rpl),
            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        match self {
            &Repr::DstUnreachable { header, data, .. }
            | &Repr::PktTooBig { header, data, .. }
            | &Repr::TimeExceeded { header, data, .. }
            | &Repr::ParamProblem { header, data, .. } => cmp::min(
                field::UNUSED.end + header.buffer_len() + data.len(),
                MAX_ERROR_PACKET_LEN,
            ),
            &Repr::EchoRequest { data, .. } | &Repr::EchoReply { data, .. } => {
                field::ECHO_SEQNO.end + data.len()
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
              && r.blen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
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
        let packet = Packet::new_unchecked(&ECHO_PACKET_BYTES[..]);
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
        let packet = Packet::new_unchecked(&ECHO_PACKET_BYTES[..]);
        let repr = Repr::parse(
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
        let packet = Packet::new_unchecked(&PKT_TOO_BIG_BYTES[..]);
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
        let packet = Packet::new_unchecked(&PKT_TOO_BIG_BYTES[..]);
        let repr = Repr::parse(
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

        let packet = Packet::new_unchecked(&data);
        let repr2 = Repr::parse(
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
        let packet = Packet::new_unchecked(&bytes[..field::HEADER_END + IPV6_HEADER_LEN - 1]);
        assert!(
            Repr::parse(
                &MOCK_IP_ADDR_1,
                &MOCK_IP_ADDR_2,
                &packet,
                &ChecksumCapabilities::ignored(),
            )
            .is_err()
        );
    }
}
