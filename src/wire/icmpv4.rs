use byteorder::{ByteOrder, NetworkEndian};
use core::{cmp, fmt};

use super::{Error, Result};
use crate::phy::ChecksumCapabilities;
use crate::wire::ip::checksum;
use crate::wire::{Ipv4Packet, Ipv4Repr};

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
#[flux_rs::refined_by(buf: T)]
pub struct Packet<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buf])]
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    #[flux_rs::constant(core::ops::Range { start: 2, end: 4 })]
    pub const CHECKSUM: Field = 2..4;

    #[flux_rs::constant(core::ops::Range { start: 4, end: 8 })]
    pub const UNUSED: Field = 4..8;

    #[flux_rs::constant(core::ops::Range { start: 4, end: 6 })]
    pub const ECHO_IDENT: Field = 4..6;
    #[flux_rs::constant(core::ops::Range { start: 6, end: 8 })]
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with ICMPv4 packet structure.
    #[flux_rs::trusted(no, reason = "carries the buffer's length index into the wrapper")]
    #[flux_rs::sig(fn(T[@buf]) -> Packet<T>[buf])]
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    /// The `?` is spelled out as a `match`: Flux does not carry a refinement on the
    /// `Ok` payload through `Try`, so `check_len()?` would drop the length fact that
    /// `check_len` just established. xarxa has a single error type, so `From` is the
    /// identity and this is the same code at runtime.
    #[flux_rs::trusted(no, reason = "propagates check_len's length fact to the caller")]
    #[flux_rs::sig(fn(T[@buf]) -> Result<Packet<T>[buf]>{r:
        r => <T as AsRef<[u8]>>::idx(buf) >= field::HEADER_END})]
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        match packet.check_len() {
            Err(e) => Err(e),
            Ok(()) => Ok(packet),
        }
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    ///
    /// The `Ok` case carries the length fact in the return type, so a caller that
    /// inspects the `Result` discharges the accessor preconditions locally instead
    /// of pushing them onto *its* callers.
    #[flux_rs::trusted(no, reason = "states check_len's doc comment as a refinement")]
    #[flux_rs::sig(fn(&Packet<T>[@buf]) -> Result<()>{r:
        r => <T as AsRef<[u8]>>::idx(buf) >= field::HEADER_END})]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::HEADER_END {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[flux_rs::trusted(no, reason = "proves the msg_type read is in bounds")]
    #[flux_rs::sig(fn(&Packet<T>[@buf]) -> Message
        requires <T as AsRef<[u8]>>::idx(buf) > field::TYPE)]
    #[inline]
    pub fn msg_type(&self) -> Message {
        let data = self.buffer.as_ref();
        Message::from(data[field::TYPE])
    }

    /// Return the message code field.
    #[flux_rs::trusted(no, reason = "proves the msg_code read is in bounds")]
    #[flux_rs::sig(fn(&Packet<T>[@buf]) -> u8
        requires <T as AsRef<[u8]>>::idx(buf) > field::CODE)]
    #[inline]
    pub fn msg_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CODE]
    }

    /// Return the checksum field.
    #[flux_rs::trusted(no, reason = "proves the checksum read is in bounds")]
    #[flux_rs::sig(fn(&Packet<T>[@buf]) -> u16
        requires <T as AsRef<[u8]>>::idx(buf) >= field::CHECKSUM.end)]
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "proves the echo ident read is in bounds")]
    #[flux_rs::sig(fn(&Packet<T>[@buf]) -> u16
        requires <T as AsRef<[u8]>>::idx(buf) >= field::ECHO_IDENT.end)]
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "proves the echo seqno read is in bounds")]
    #[flux_rs::sig(fn(&Packet<T>[@buf]) -> u16
        requires <T as AsRef<[u8]>>::idx(buf) >= field::ECHO_SEQNO.end)]
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_SEQNO])
    }

    /// Return the header length.
    /// The result depends on the value of the message type field.
    ///
    /// Every arm is `field::HEADER_END`, so the dependence is nominal: the return
    /// type is the constant 8. That is what lets `data_mut` be proved without a
    /// mirror of the type octet in the struct -- and so without `new_unchecked`
    /// giving up its `const`.
    #[flux_rs::trusted(no, reason = "ties the runtime header_len to the constant 8")]
    #[flux_rs::sig(fn(&Packet<T>[@buf]) -> usize[field::HEADER_END]
        requires <T as AsRef<[u8]>>::idx(buf) > field::TYPE)]
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::EchoRequest => field::ECHO_SEQNO.end,
            Message::EchoReply => field::ECHO_SEQNO.end,
            Message::DstUnreachable => field::UNUSED.end,
            _ => field::UNUSED.end, // make a conservative assumption
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::data(data) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[self.header_len()..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the message type field.
    #[flux_rs::trusted(no, reason = "proves the msg_type write is in bounds")]
    #[flux_rs::sig(fn(&mut Packet<T>[@buf], Message)
        requires <T as AsMut<[u8]>>::idx(buf) > field::TYPE)]
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into()
    }

    /// Set the message code field.
    #[flux_rs::trusted(no, reason = "proves the msg_code write is in bounds")]
    #[flux_rs::sig(fn(&mut Packet<T>[@buf], u8)
        requires <T as AsMut<[u8]>>::idx(buf) > field::CODE)]
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::CODE] = value
    }

    /// Set the checksum field.
    #[flux_rs::trusted(no, reason = "proves the checksum write is in bounds")]
    #[flux_rs::sig(fn(&mut Packet<T>[@buf], u16)
        requires <T as AsMut<[u8]>>::idx(buf) >= field::CHECKSUM.end)]
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "proves the echo ident write is in bounds")]
    #[flux_rs::sig(fn(&mut Packet<T>[@buf], u16)
        requires <T as AsMut<[u8]>>::idx(buf) >= field::ECHO_IDENT.end)]
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_IDENT], value)
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[flux_rs::trusted(no, reason = "proves the echo seqno write is in bounds")]
    #[flux_rs::sig(fn(&mut Packet<T>[@buf], u16)
        requires <T as AsMut<[u8]>>::idx(buf) >= field::ECHO_SEQNO.end)]
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_SEQNO], value)
    }

    /// Return a mutable pointer to the type-specific data.
    ///
    /// Stated over `Packet<T>` rather than `Packet<&mut T>`: the buffer length of a
    /// `&mut T` is only reachable through the auto-deref `AsMut` blanket, whose
    /// elided lifetime an `extern_spec` cannot name, so on the `&mut T` form
    /// `self.buffer.as_mut()` has no expressible length. This form is a superset --
    /// `T` instantiates to `&mut U` at every call site -- and matches how
    /// `icmpv6::Packet::payload_mut` is already declared.
    #[flux_rs::trusted(no, reason = "proves the payload split point is in bounds")]
    #[flux_rs::sig(fn(&mut Packet<T>[@buf])
        -> &mut [u8][<T as AsMut<[u8]>>::idx(buf) - field::HEADER_END]
        requires <T as AsRef<[u8]>>::idx(buf) > field::TYPE
              && <T as AsMut<[u8]>>::idx(buf) >= field::HEADER_END)]
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(data)
        };
        self.set_checksum(checksum)
    }
}

#[flux_rs::assoc(fn idx(s: Self) -> int { <T as AsRef<[u8]>>::idx(s.buf) })]
impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    #[flux_rs::trusted(no, reason = "carries the buffer length through the AsRef impl")]
    #[flux_rs::sig(fn(&Packet<T>[@s]) -> &[u8][<T as AsRef<[u8]>>::idx(s.buf)])]
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an Internet Control Message Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Repr<'a> {
    EchoRequest {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
    EchoReply {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
    DstUnreachable {
        reason: DstUnreachable,
        header: Ipv4Repr,
        data: &'a [u8],
    },
    TimeExceeded {
        reason: TimeExceeded,
        header: Ipv4Repr,
        data: &'a [u8],
    },
}

impl<'a> Repr<'a> {
    /// Parse an Internet Control Message Protocol version 4 packet and return
    /// a high-level representation.
    #[flux_rs::trusted(no, reason = "follows the accessor length obligations to a caller")]
    pub fn parse<T>(
        packet: &Packet<&'a T>,
        checksum_caps: &ChecksumCapabilities,
    ) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        // `?` spelled out as a `match`, so `check_len`'s length fact survives; see
        // `new_checked`. Same code at runtime.
        match packet.check_len() {
            Err(e) => return Err(e),
            Ok(()) => {}
        }

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
                let ip_packet = Ipv4Packet::new_checked(packet.data())?;

                let payload = &packet.data()[ip_packet.header_len() as usize..];
                // RFC 792 requires exactly eight bytes to be returned.
                // We allow more, since there isn't a reason not to, but require at least eight.
                if payload.len() < 8 {
                    return Err(Error);
                }

                Ok(Repr::DstUnreachable {
                    reason: DstUnreachable::from(code),
                    header: Ipv4Repr {
                        src_addr: ip_packet.src_addr(),
                        dst_addr: ip_packet.dst_addr(),
                        next_header: ip_packet.next_header(),
                        payload_len: payload.len(),
                        hop_limit: ip_packet.hop_limit(),
                    },
                    data: payload,
                })
            }

            (Message::TimeExceeded, code) => {
                let ip_packet = Ipv4Packet::new_checked(packet.data())?;

                let payload = &packet.data()[ip_packet.header_len() as usize..];
                // RFC 792 requires exactly eight bytes to be returned.
                // We allow more, since there isn't a reason not to, but require at least eight.
                if payload.len() < 8 {
                    return Err(Error);
                }

                Ok(Repr::TimeExceeded {
                    reason: TimeExceeded::from(code),
                    header: Ipv4Repr {
                        src_addr: ip_packet.src_addr(),
                        dst_addr: ip_packet.dst_addr(),
                        next_header: ip_packet.next_header(),
                        payload_len: payload.len(),
                        hop_limit: ip_packet.hop_limit(),
                    },
                    data: payload,
                })
            }

            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        match self {
            &Repr::EchoRequest { data, .. } | &Repr::EchoReply { data, .. } => {
                field::ECHO_SEQNO.end + data.len()
            }
            &Repr::DstUnreachable { header, data, .. }
            | &Repr::TimeExceeded { header, data, .. } => {
                field::UNUSED.end + header.buffer_len() + data.len()
            }
        }
    }

    /// Emit a high-level representation into an Internet Control Message Protocol version 4
    /// packet.
    #[flux_rs::trusted(no, reason = "follows the accessor length obligations to a caller")]
    #[flux_rs::sig(fn(&Self, packet: &mut Packet<&mut T>[@buf], &ChecksumCapabilities)
        requires <&mut T as AsRef<[u8]>>::idx(buf) >= field::HEADER_END
              && <&mut T as AsMut<[u8]>>::idx(buf) >= field::HEADER_END)]
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>, checksum_caps: &ChecksumCapabilities)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
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
                let data_len = cmp::min(packet.data_mut().len(), data.len());
                packet.data_mut()[..data_len].copy_from_slice(&data[..data_len])
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
                let data_len = cmp::min(packet.data_mut().len(), data.len());
                packet.data_mut()[..data_len].copy_from_slice(&data[..data_len])
            }

            Repr::DstUnreachable {
                reason,
                header,
                data,
            } => {
                packet.set_msg_type(Message::DstUnreachable);
                packet.set_msg_code(reason.into());

                let mut ip_packet = Ipv4Packet::new_unchecked(packet.data_mut());
                header.emit(&mut ip_packet, checksum_caps);
                let payload = &mut ip_packet.into_inner()[header.buffer_len()..];
                payload.copy_from_slice(data)
            }

            Repr::TimeExceeded {
                reason,
                header,
                data,
            } => {
                packet.set_msg_type(Message::TimeExceeded);
                packet.set_msg_code(reason.into());

                let mut ip_packet = Ipv4Packet::new_unchecked(packet.data_mut());
                header.emit(&mut ip_packet, checksum_caps);
                let payload = &mut ip_packet.into_inner()[header.buffer_len()..];
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

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self, &ChecksumCapabilities::default()) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "ICMPv4 ({err})")?;
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
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        let packet = match Packet::new_checked(buffer) {
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
        let packet = Packet::new_unchecked(&ECHO_PACKET_BYTES[..]);
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
        let packet = Packet::new_unchecked(&ECHO_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet, &ChecksumCapabilities::default()).unwrap();
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
