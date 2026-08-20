use core::fmt;

use super::{Error, Result};
use crate::time::Duration;
use crate::wire::ip::checksum;

use crate::wire::{Ipv4Address, copy_window_at, read_u16_at, sub, write_u16_at};

enum_with_unknown! {
    /// Internet Group Management Protocol v1/v2 message version/type.
    pub enum Message(u8) {
        /// Membership Query
        MembershipQuery = 0x11,
        /// Version 2 Membership Report
        MembershipReportV2 = 0x16,
        /// Leave Group
        LeaveGroup = 0x17,
        /// Version 1 Membership Report
        MembershipReportV1 = 0x12
    }
}

/// A read/write wrapper around an Internet Group Management Protocol v1/v2 packet buffer.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(buffer: T)]
pub struct Packet<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
}

mod field {
    // The offsets below are also written out as literals at the accessors, which need a
    // value flux can see; these consts stay as the single reviewable statement of the
    // layout, and several of them are now referenced only from those trailing comments.
    #![allow(unused)]

    use crate::wire::field::*;

    pub const TYPE: usize = 0;
    pub const MAX_RESP_CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;
    pub const GROUP_ADDRESS: Field = 4..8;
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::MembershipQuery => write!(f, "membership query"),
            Message::MembershipReportV2 => write!(f, "version 2 membership report"),
            Message::LeaveGroup => write!(f, "leave group"),
            Message::MembershipReportV1 => write!(f, "version 1 membership report"),
            Message::Unknown(id) => write!(f, "{id}"),
        }
    }
}

/// Internet Group Management Protocol v1/v2 defined in [RFC 2236].
///
/// [RFC 2236]: https://tools.ietf.org/html/rfc2236
impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with IGMPv2 packet structure.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
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
    /// for it. Returning the length lets the `Ok` arm say what the buffer's length is and that it
    /// reaches the end of the header.
    ///
    /// Nothing consumes that yet: `new_checked`'s callers instantiate `T` at a reference type,
    /// which flux gives the unit sort, so none of them can name `as_ref_reft`. Worth wiring
    /// through the moment a reference self type can be refined; see `wire::Buf`.
    ///
    /// This message is eight octets of fixed-offset fields with nothing after them, so this
    /// single test is the whole precondition of the file -- no window's extent depends on buffer
    /// *contents*, and hence there is no ghost field as in `arp`, `udp` and `tcp`.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Packet<T>[@p])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(p.buffer) && 8 <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();
        if len < 8 {
            // field::GROUP_ADDRESS.end
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
    // Literal offsets rather than the `field::X` consts: flux cannot see through the `Field`
    // (`Range`) const, so the bound has to be written out. Same throughout this impl.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> Message requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn msg_type(&self) -> Message {
        let data = self.buffer.as_ref();
        Message::from(data[0]) // field::TYPE
    }

    /// Return the maximum response time, using the encoding specified in
    /// [RFC 3376]: 4.1.1. Max Resp Code.
    ///
    /// [RFC 3376]: https://tools.ietf.org/html/rfc3376
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> u8 requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn max_resp_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[1] // field::MAX_RESP_CODE
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

    /// Return the source address field.
    ///
    /// The equal-length `copy_from_slice` stands in for `try_into().unwrap()`, which flux cannot
    /// prove -- it does not model `TryInto<[u8; 4]> for &[u8]`. Both panic on a length mismatch
    /// and `8 <= len` rules both out, so the check is gated rather than removed.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(fn(&Packet<T>[@p]) -> Ipv4Address requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn group_addr(&self) -> Ipv4Address {
        let data = self.buffer.as_ref();
        let mut octets = [0; 4];
        octets.copy_from_slice(sub(data, 4, 4)); // field::GROUP_ADDRESS
        Ipv4Address::from_octets(octets)
    }

    /// Validate the header checksum.
    ///
    /// `as_ref_reft <= 65535` is `checksum::data`'s own bound -- its `u32` accumulator cannot take
    /// more than 65535 octets without overflowing. It is a real, satisfiable property of every
    /// IGMP buffer, which are sized from `Repr::buffer_len()` under an IPv4 MTU, so it is stated
    /// as a caller obligation rather than assumed here.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
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
    // Literal offsets rather than the `field::X` consts, as in the impl above.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], value: Message) requires 1 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        let data = self.buffer.as_mut();
        data[0] = value.into() // field::TYPE
    }

    /// Set the maximum response time, using the encoding specified in
    /// [RFC 3376]: 4.1.1. Max Resp Code.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], value: u8) requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_max_resp_code(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[1] = value; // field::MAX_RESP_CODE
    }

    /// Set the checksum field.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], value: u16) requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 2, value) // field::CHECKSUM
    }

    /// Set the group address field
    ///
    /// No `no_panic`: `copy_window_at` deliberately keeps `copy_from_slice`'s equal-length
    /// assert, which is the bounds check this line had before. The `requires` is stated alongside
    /// it, not instead of it.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(fn(self: &mut Packet<T>[@p], addr: Ipv4Address) requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer))]
    #[inline]
    pub fn set_group_address(&mut self, addr: Ipv4Address) {
        let data = self.buffer.as_mut();
        copy_window_at(data, 4, 4, &addr.octets()); // field::GROUP_ADDRESS
    }

    /// Compute and fill in the header checksum.
    ///
    /// The `<= 65535` conjunct is `checksum::data`'s bound; see
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
}

/// A high-level representation of an Internet Group Management Protocol v1/v2 header.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr {
    MembershipQuery {
        max_resp_time: Duration,
        group_addr: Ipv4Address,
        version: IgmpVersion,
    },
    MembershipReport {
        group_addr: Ipv4Address,
        version: IgmpVersion,
    },
    LeaveGroup {
        group_addr: Ipv4Address,
    },
}

/// Type of IGMP membership report version
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IgmpVersion {
    /// IGMPv1
    Version1,
    /// IGMPv2
    Version2,
}

impl Repr {
    /// Parse an Internet Group Management Protocol v1/v2 packet and return
    /// a high-level representation.
    pub fn parse<T>(packet: &Packet<&T>) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        packet.check_len()?;

        // Check if the address is 0.0.0.0 or multicast
        let addr = packet.group_addr();
        if !addr.is_unspecified() && !addr.is_multicast() {
            return Err(Error);
        }

        // construct a packet based on the Type field
        match packet.msg_type() {
            Message::MembershipQuery => {
                let max_resp_time = max_resp_code_to_duration(packet.max_resp_code());
                // See RFC 3376: 7.1. Query Version Distinctions
                let version = if packet.max_resp_code() == 0 {
                    IgmpVersion::Version1
                } else {
                    IgmpVersion::Version2
                };
                Ok(Repr::MembershipQuery {
                    max_resp_time,
                    group_addr: addr,
                    version,
                })
            }
            Message::MembershipReportV2 => Ok(Repr::MembershipReport {
                group_addr: packet.group_addr(),
                version: IgmpVersion::Version2,
            }),
            Message::LeaveGroup => Ok(Repr::LeaveGroup {
                group_addr: packet.group_addr(),
            }),
            Message::MembershipReportV1 => {
                // for backwards compatibility with IGMPv1
                Ok(Repr::MembershipReport {
                    group_addr: packet.group_addr(),
                    version: IgmpVersion::Version1,
                })
            }
            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        // always 8 bytes
        field::GROUP_ADDRESS.end
    }

    /// Emit a high-level representation into an Internet Group Management Protocol v2 packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        match *self {
            Repr::MembershipQuery {
                max_resp_time,
                group_addr,
                version,
            } => {
                packet.set_msg_type(Message::MembershipQuery);
                match version {
                    IgmpVersion::Version1 => packet.set_max_resp_code(0),
                    IgmpVersion::Version2 => {
                        packet.set_max_resp_code(duration_to_max_resp_code(max_resp_time))
                    }
                }
                packet.set_group_address(group_addr);
            }
            Repr::MembershipReport {
                group_addr,
                version,
            } => {
                match version {
                    IgmpVersion::Version1 => packet.set_msg_type(Message::MembershipReportV1),
                    IgmpVersion::Version2 => packet.set_msg_type(Message::MembershipReportV2),
                };
                packet.set_max_resp_code(0);
                packet.set_group_address(group_addr);
            }
            Repr::LeaveGroup { group_addr } => {
                packet.set_msg_type(Message::LeaveGroup);
                packet.set_group_address(group_addr);
            }
        }

        packet.fill_checksum()
    }
}

fn max_resp_code_to_duration(value: u8) -> Duration {
    let value: u64 = value.into();
    let decisecs = if value < 128 {
        value
    } else {
        let mant = value & 0xF;
        let exp = (value >> 4) & 0x7;
        (mant | 0x10) << (exp + 3)
    };
    Duration::from_millis(decisecs * 100)
}

const fn duration_to_max_resp_code(duration: Duration) -> u8 {
    let decisecs = duration.total_millis() / 100;
    if decisecs < 128 {
        decisecs as u8
    } else if decisecs < 31744 {
        let mut mant = decisecs >> 3;
        let mut exp = 0u8;
        while mant > 0x1F && exp < 0x8 {
            mant >>= 1;
            exp += 1;
        }
        0x80 | (exp << 4) | (mant as u8 & 0xF)
    } else {
        0xFF
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Packet<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => write!(f, "IGMP ({err})"),
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Repr::MembershipQuery {
                max_resp_time,
                group_addr,
                version,
            } => write!(
                f,
                "IGMP membership query max_resp_time={max_resp_time} group_addr={group_addr} version={version:?}"
            ),
            Repr::MembershipReport {
                group_addr,
                version,
            } => write!(
                f,
                "IGMP membership report group_addr={group_addr} version={version:?}"
            ),
            Repr::LeaveGroup { group_addr } => {
                write!(f, "IGMP leave group group_addr={group_addr})")
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
        match Packet::new_checked(buffer) {
            Err(err) => writeln!(f, "{indent}({err})"),
            Ok(packet) => writeln!(f, "{indent}{packet}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static LEAVE_PACKET_BYTES: [u8; 8] = [0x17, 0x00, 0x02, 0x69, 0xe0, 0x00, 0x06, 0x96];
    static REPORT_PACKET_BYTES: [u8; 8] = [0x16, 0x00, 0x08, 0xda, 0xe1, 0x00, 0x00, 0x25];

    #[test]
    fn test_leave_group_deconstruct() {
        let packet = Packet::new_unchecked(&LEAVE_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::LeaveGroup);
        assert_eq!(packet.max_resp_code(), 0);
        assert_eq!(packet.checksum(), 0x269);
        assert_eq!(
            packet.group_addr(),
            Ipv4Address::from_octets([224, 0, 6, 150])
        );
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_report_deconstruct() {
        let packet = Packet::new_unchecked(&REPORT_PACKET_BYTES[..]);
        assert_eq!(packet.msg_type(), Message::MembershipReportV2);
        assert_eq!(packet.max_resp_code(), 0);
        assert_eq!(packet.checksum(), 0x08da);
        assert_eq!(
            packet.group_addr(),
            Ipv4Address::from_octets([225, 0, 0, 37])
        );
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_leave_construct() {
        let mut bytes = vec![0xa5; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::LeaveGroup);
        packet.set_max_resp_code(0);
        packet.set_group_address(Ipv4Address::from_octets([224, 0, 6, 150]));
        packet.fill_checksum();
        assert_eq!(&*packet.into_inner(), &LEAVE_PACKET_BYTES[..]);
    }

    #[test]
    fn test_report_construct() {
        let mut bytes = vec![0xa5; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::MembershipReportV2);
        packet.set_max_resp_code(0);
        packet.set_group_address(Ipv4Address::from_octets([225, 0, 0, 37]));
        packet.fill_checksum();
        assert_eq!(&*packet.into_inner(), &REPORT_PACKET_BYTES[..]);
    }

    #[test]
    fn max_resp_time_to_duration_and_back() {
        for i in 0..256usize {
            let time1 = i as u8;
            let duration = max_resp_code_to_duration(time1);
            let time2 = duration_to_max_resp_code(duration);
            assert!(time1 == time2);
        }
    }

    #[test]
    fn duration_to_max_resp_time_max() {
        for duration in 31744..65536 {
            let time = duration_to_max_resp_code(Duration::from_millis(duration * 100));
            assert_eq!(time, 0xFF);
        }
    }
}
