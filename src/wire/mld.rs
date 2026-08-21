// Packet implementation for the Multicast Listener Discovery
// protocol. See [RFC 3810] and [RFC 2710].
//
// [RFC 3810]: https://tools.ietf.org/html/rfc3810
// [RFC 2710]: https://tools.ietf.org/html/rfc2710

use super::{Error, Result};
use crate::wire::Ipv6Address;
use crate::wire::Ref;
use crate::wire::icmpv6::{Message, Packet, field};
use crate::wire::{read_u16_at, write_octets16_at, write_u16_at};

enum_with_unknown! {
    /// MLDv2 Multicast Listener Report Record Type. See [RFC 3810 § 5.2.12] for
    /// more details.
    ///
    /// [RFC 3810 § 5.2.12]: https://tools.ietf.org/html/rfc3010#section-5.2.12
    pub enum RecordType(u8) {
        /// Interface has a filter mode of INCLUDE for the specified multicast address.
        ModeIsInclude   = 0x01,
        /// Interface has a filter mode of EXCLUDE for the specified multicast address.
        ModeIsExclude   = 0x02,
        /// Interface has changed to a filter mode of INCLUDE for the specified
        /// multicast address.
        ChangeToInclude = 0x03,
        /// Interface has changed to a filter mode of EXCLUDE for the specified
        /// multicast address.
        ChangeToExclude = 0x04,
        /// Interface wishes to listen to the sources in the specified list.
        AllowNewSources = 0x05,
        /// Interface no longer wishes to listen to the sources in the specified list.
        BlockOldSources = 0x06
    }
}

/// Read the 16 octets at `at` as an IPv6 address.
///
/// This is the read-side twin of [`crate::wire::write_octets16_at`] and belongs next to it in
/// `wire::buf`; it lives here, shared with `wire::ndisc`, only because `wire/buf.rs` is owned
/// by another slice of this work. Trusted for the same reason every helper there is: the length of
/// `data[at..at + 16]` is not recoverable (flux-rs/flux#1714). The `requires` is what keeps
/// the caller's bounds obligation alive, and `no_panic` is sound under it for the same reason
/// it is on `read_u16_at`: the window is exactly sixteen octets, so the `try_into` cannot fail.
#[flux_rs::trusted(yes, reason = "sub-slice length is not recoverable; see flux-rs/flux#1714")]
#[flux_rs::sig(fn(&[u8][@n], at: usize) -> Ipv6Address requires at + 16 <= n)]
#[flux_rs::no_panic]
#[inline]
pub(super) fn read_ipv6_addr_at(data: &[u8], at: usize) -> Ipv6Address {
    Ipv6Address::from_octets(data[at..at + 16].try_into().unwrap())
}

/// Getters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
//
// Every offset below is spelled as the literal the `field::` const holds, with the original
// spelling kept in a trailing comment: a `const` of struct type (`Field = Range<usize>`) is
// opaque to Flux, so `field::MAX_RESP_CODE.start` is an unconstrained `usize` and no bound
// can be discharged from it. Same convention as `icmpv6::Packet::header_len`.
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the maximum response code field.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16
        requires 6 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn max_resp_code(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 4) // field::MAX_RESP_CODE
    }

    /// Return the address being queried.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> Ipv6Address
        requires 24 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        read_ipv6_addr_at(data, 8) // field::QUERY_MCAST_ADDR
    }

    /// Return the Suppress Router-Side Processing flag.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> bool
        requires 25 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn s_flag(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[field::SQRV] & 0x08) != 0
    }

    /// Return the Querier's Robustness Variable.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u8
        requires 25 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn qrv(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::SQRV] & 0x7
    }

    /// Return the Querier's Query Interval Code.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u8
        requires 26 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn qqic(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::QQIC]
    }

    /// Return number of sources.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16
        requires 28 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn num_srcs(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 26) // field::QUERY_NUM_SRCS
    }
}

/// Getters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the number of Multicast Address Records.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Packet<T>[@p]) -> u16
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn nr_mcast_addr_rcrds(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 6) // field::NR_MCAST_RCRDS
    }
}

/// Setters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the maximum response code field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u16)
        requires 6 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_max_resp_code(&mut self, code: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 4, code) // field::MAX_RESP_CODE
    }

    /// Set the address being queried.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], _)
        requires 24 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Address) {
        let data = self.buffer.as_mut();
        write_octets16_at(data, 8, &addr.octets()) // field::QUERY_MCAST_ADDR
    }

    /// Set the Suppress Router-Side Processing flag.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p])
        requires 25 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_s_flag(&mut self) {
        let data = self.buffer.as_mut();
        let current = data[field::SQRV];
        data[field::SQRV] = 0x8 | (current & 0x7);
    }

    /// Clear the Suppress Router-Side Processing flag.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p])
        requires 25 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn clear_s_flag(&mut self) {
        let data = self.buffer.as_mut();
        data[field::SQRV] &= 0x7;
    }

    /// Set the Querier's Robustness Variable.
    ///
    /// # Panics
    /// This function panics if `value` does not fit in three bits. The `requires` below is
    /// that documented contract, stated so the caller owes it rather than the assert.
    #[flux_rs::trusted(no, reason = "panic site: the assert plus a write at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u8[@value])
        requires value < 8 && 25 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_qrv(&mut self, value: u8) {
        assert!(value < 8);
        let data = self.buffer.as_mut();
        data[field::SQRV] = (data[field::SQRV] & 0x8) | value & 0x7;
    }

    /// Set the Querier's Query Interval Code.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u8)
        requires 26 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_qqic(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::QQIC] = value;
    }

    /// Set number of sources.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u16)
        requires 28 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_num_srcs(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 26, value) // field::QUERY_NUM_SRCS
    }
}

/// Setters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the number of Multicast Address Records.
    #[flux_rs::trusted(no, reason = "panic site: writes into the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut Packet<T>[@p], u16)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_nr_mcast_addr_rcrds(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 6, value) // field::NR_MCAST_RCRDS
    }
}

/// A read/write wrapper around an MLDv2 Listener Report Message Address Record.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(buffer: T)]
pub struct AddressRecord<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
}

impl<T: AsRef<[u8]>> AddressRecord<T> {
    /// Imbue a raw octet buffer with a Address Record structure.
    #[flux_rs::trusted(no, reason = "carries the buffer index into the AddressRecord wrapper")]
    #[flux_rs::sig(fn(T[@b]) -> AddressRecord<T>{v: v.buffer == b})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Self {
        Self { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::RECORD_MCAST_ADDR.end {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

/// Getters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsRef<[u8]>> AddressRecord<T> {
    /// Return the record type for the given sources.
    #[flux_rs::trusted(no, reason = "panic site: reads the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&AddressRecord<T>[@r]) -> RecordType
        requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn record_type(&self) -> RecordType {
        let data = self.buffer.as_ref();
        RecordType::from(data[field::RECORD_TYPE])
    }

    /// Return the length of the auxiliary data.
    #[flux_rs::trusted(no, reason = "panic site: reads the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&AddressRecord<T>[@r]) -> u8
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::AUX_DATA_LEN]
    }

    /// Return the number of sources field.
    #[flux_rs::trusted(no, reason = "panic site: reads the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&AddressRecord<T>[@r]) -> u16
        requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn num_srcs(&self) -> u16 {
        let data = self.buffer.as_ref();
        read_u16_at(data, 2) // field::RECORD_NUM_SRCS
    }

    /// Return the multicast address field.
    #[flux_rs::trusted(no, reason = "panic site: reads the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&AddressRecord<T>[@r]) -> Ipv6Address
        requires 20 <= <T as AsRef<[u8]>>::as_ref_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        read_ipv6_addr_at(data, 4) // field::RECORD_MCAST_ADDR
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> AddressRecord<&'a T> {
    /// Return a pointer to the address records.
    //
    // No signature: the receiver is `AddressRecord<&'a T>`, so the buffer index has the unit
    // sort (a reference self type carries no associated refinement -- core's blanket
    // `impl AsRef<U> for &T` has none), and `<&'a T as AsRef<[u8]>>::as_ref_reft` cannot be
    // named. Stating the `20 <= len` bound here needs the same `T: Sized` reshaping C1 did to
    // `Packet`, applied to `AddressRecordRepr::parse`'s parameter.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::RECORD_MCAST_ADDR.end..]
    }
}

/// Setters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<T: AsMut<[u8]> + AsRef<[u8]>> AddressRecord<T> {
    /// Return the record type for the given sources.
    #[flux_rs::trusted(no, reason = "panic site: writes into the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut AddressRecord<T>[@r], _)
        requires 1 <= <T as AsMut<[u8]>>::as_mut_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_record_type(&mut self, rty: RecordType) {
        let data = self.buffer.as_mut();
        data[field::RECORD_TYPE] = rty.into();
    }

    /// Return the length of the auxiliary data.
    #[flux_rs::trusted(no, reason = "panic site: writes into the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut AddressRecord<T>[@r], u8)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_aux_data_len(&mut self, len: u8) {
        let data = self.buffer.as_mut();
        data[field::AUX_DATA_LEN] = len;
    }

    /// Return the number of sources field.
    #[flux_rs::trusted(no, reason = "panic site: writes into the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut AddressRecord<T>[@r], u16)
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_num_srcs(&mut self, num_srcs: u16) {
        let data = self.buffer.as_mut();
        write_u16_at(data, 2, num_srcs) // field::RECORD_NUM_SRCS
    }

    /// Return the multicast address field.
    ///
    /// # Panics
    /// This function panics if the given address is not a multicast address.
    //
    // No `#[no_panic]`, unlike its three siblings above: the body's
    // `assert!(addr.is_multicast())` is a live panic site that Flux does not owe under the
    // stated `requires`, so callers see this as `may panic` rather than as a discharged
    // call. That is deliberate -- see below.
    //
    // PARKED: `flux_specs::net` now refines `Ipv6Addr` by `is_multicast`, so
    // `requires ... && addr.is_multicast` (plus `#[no_panic]`) is expressible and the body
    // then verifies. It is not stated because no caller discharges it:
    //   * `AddressRecordRepr::emit` passes `self.mcast_addr`, a field of an unrefined
    //     `&Self`; measured, that call reports `a precondition cannot be proved`.
    //   * above it, every record is built by `MldAddressRecordRepr::new` in
    //     `iface::interface::multicast` from a key of `multicast.groups` or from
    //     `MldReportState::ToSpecificQuery{group}`. Both really are multicast --
    //     `join_multicast_group` rejects non-multicast, and `group` is gated on
    //     `has_multicast_group` -- but that is an invariant of a `heapless` map whose keys
    //     carry no refinement, so it cannot be handed down.
    // Stating the `requires` anyway would move a live `assert!` onto callers that do not
    // meet it, and onto out-of-crate callers as an assumed precondition. Refining
    // `AddressRecordRepr` by its `mcast_addr` flag is the first half of the fix; the
    // `groups` map is the second and is the same missing piece as elsewhere.
    #[flux_rs::trusted(no, reason = "panic site: writes into the record at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut AddressRecord<T>[@r], _)
        requires 20 <= <T as AsMut<[u8]>>::as_mut_reft(r.buffer)
    )]
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Address) {
        assert!(addr.is_multicast());
        let data = self.buffer.as_mut();
        write_octets16_at(data, 4, &addr.octets()) // field::RECORD_MCAST_ADDR
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AddressRecord<T> {
    /// Return a pointer to the address records.
    //
    // No signature: the return is a `&mut [u8]` whose length the caller cannot recover
    // (flux-rs/flux#1714), so a bound stated here buys nothing downstream. `Repr::emit`
    // reaches the same bytes through `wire::Buf` instead.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::RECORD_MCAST_ADDR.end..]
    }
}

/// A high level representation of an MLDv2 Listener Report Message Address Record.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddressRecordRepr<'a> {
    pub record_type: RecordType,
    pub aux_data_len: u8,
    pub num_srcs: u16,
    pub mcast_addr: Ipv6Address,
    pub payload: &'a [u8],
}

impl<'a> AddressRecordRepr<'a> {
    /// Create a new MLDv2 address record representation with an empty payload.
    pub const fn new(record_type: RecordType, mcast_addr: Ipv6Address) -> Self {
        Self {
            record_type,
            aux_data_len: 0,
            num_srcs: 0,
            mcast_addr,
            payload: &[],
        }
    }

    /// Parse an MLDv2 address record and return a high-level representation.
    pub fn parse<T>(record: &AddressRecord<&'a T>) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(Self {
            num_srcs: record.num_srcs(),
            mcast_addr: record.mcast_addr(),
            record_type: record.record_type(),
            aux_data_len: record.aux_data_len(),
            payload: record.payload(),
        })
    }

    /// Return the length of a record that will be emitted from this high-level
    /// representation, not including any payload data.
    // Literal rather than `field::RECORD_MCAST_ADDR.end`, for the same reason as everywhere
    // else in this file: Flux cannot see through a `Range` const.
    #[flux_rs::trusted(no, reason = "20 is the constant Repr::emit's record loop needs")]
    #[flux_rs::sig(fn(&Self) -> usize[20])]
    #[flux_rs::no_panic]
    pub fn buffer_len(&self) -> usize {
        20 // field::RECORD_MCAST_ADDR.end
    }

    /// Emit a high-level representation into an MLDv2 address record.
    #[flux_rs::trusted(no, reason = "calls the four record setters")]
    #[flux_rs::sig(
        fn(&Self, record: &mut AddressRecord<T>[@r])
        requires 20 <= <T as AsMut<[u8]>>::as_mut_reft(r.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, record: &mut AddressRecord<T>) {
        record.set_record_type(self.record_type);
        record.set_aux_data_len(self.aux_data_len);
        record.set_num_srcs(self.num_srcs);
        record.set_mcast_addr(self.mcast_addr);
    }
}

/// A high-level representation of an MLDv2 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// Indexed to agree with `buffer_len()` exactly, variant for variant: `28 + data.len()` for
// Query (`field::QUERY_NUM_SRCS.end`), `8 + data.len()` for Report (`NR_MCAST_RCRDS.end`) and
// a bare `8` for ReportRecordReprs.
//
// The `ReportRecordReprs` index is deliberately *approximate*: `buffer_len()` returns only 8 for
// that variant, omitting `20 * records.len()`, and `iface::interface::ipv6` compensates by adding
// the record lengths at the call site. `AddressRecordRepr` is unrefined, so the true length is not
// statable here anyway. Indexing it 8 reproduces today's behaviour and today's obligation -- the
// record loop's `8 + 20 * records.len() <= buffer` stays owed by nobody, exactly as before. It is
// NOT fixed here, because correcting `buffer_len()` would change what `ipv6.rs` allocates.
// Smallest variant is Report/ReportRecordReprs at `field::NR_MCAST_RCRDS.end` == 8. Flux checks
// this against the `variant` indices below; `Icmpv6Repr`'s `4 <= blen` invariant rests on it.
#[flux_rs::invariant(8 <= blen)]
#[flux_rs::refined_by(blen: int)]
pub enum Repr<'a> {
    #[flux_rs::variant({u16, Ipv6Address, bool, u8, u8, u16, &[u8][@m]} -> Repr[28 + m])]
    Query {
        max_resp_code: u16,
        mcast_addr: Ipv6Address,
        s_flag: bool,
        qrv: u8,
        qqic: u8,
        num_srcs: u16,
        data: &'a [u8],
    },
    #[flux_rs::variant({u16, &[u8][@m]} -> Repr[8 + m])]
    Report {
        nr_mcast_addr_rcrds: u16,
        data: &'a [u8],
    },
    #[flux_rs::variant((&[AddressRecordRepr]) -> Repr[8])]
    ReportRecordReprs(&'a [AddressRecordRepr<'a>]),
}

impl<'a> Repr<'a> {
    /// Parse an MLDv2 packet and return a high-level representation.
    pub fn parse(packet: &Packet<Ref<'a>>) -> Result<Repr<'a>> {
        // `checked_len` rather than `check_len`: the same test, but its `Ok` arm names the
        // buffer's length, which is what `payload` opens its window against.
        packet.checked_len()?;
        match packet.msg_type() {
            Message::MldQuery => Ok(Repr::Query {
                max_resp_code: packet.max_resp_code(),
                mcast_addr: packet.mcast_addr(),
                s_flag: packet.s_flag(),
                qrv: packet.qrv(),
                qqic: packet.qqic(),
                num_srcs: packet.num_srcs(),
                data: packet.payload(),
            }),
            Message::MldReport => Ok(Repr::Report {
                nr_mcast_addr_rcrds: packet.nr_mcast_addr_rcrds(),
                data: packet.payload(),
            }),
            _ => Err(Error),
        }
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub const fn buffer_len(&self) -> usize {
        match self {
            Repr::Query { data, .. } => field::QUERY_NUM_SRCS.end + data.len(),
            Repr::Report { data, .. } => field::NR_MCAST_RCRDS.end + data.len(),
            Repr::ReportRecordReprs(_data) => field::NR_MCAST_RCRDS.end,
        }
    }

    /// Emit a high-level representation into an MLDv2 packet.
    //
    // `packet` is `&strg`, not `&mut`: `icmpv6::Packet` is indexed by the message-type octet as
    // well as the buffer, and `set_msg_type` performs a strong update on that index. Behind a
    // plain `&mut Packet<T>{..}` Flux cannot see the new `code`, and `clear_reserved` -- whose
    // `requires` is a disjunction over `p.code` -- then fails in all three arms. The `ensures`
    // re-states only what the callee preserves: the buffer, not the type octet.
    //
    // The bound is 28, the query header (`field::QUERY_NUM_SRCS.end`), which is the largest a
    // header setter here needs; the report arms need 8.
    //
    // What is NOT proved, and why -- all four reduce to the same missing piece, `Repr` refined
    // by its `buffer_len()`:
    //   * `set_qrv(*qrv)` owes `*qrv < 8`. `qrv` is a field of `self: &Repr`, unindexed.
    //   * both `copy_from_slice(&data[..])` calls owe `payload_mut().len() == data.len()`.
    //     `payload_mut` returns a `&mut [u8]` whose index the caller cannot recover
    //     (flux-rs/flux#1714), and `data.len()` lives in `self: &Repr`.
    //   * the record loop owes `8 + 20 * records.len() <= buffer.len()`. Note the caller has to
    //     supply that separately today: `Repr::buffer_len()` returns just 8 for
    //     `ReportRecordReprs`, and `iface::interface::ipv6::mldv2_report_packet` adds the record
    //     lengths itself.
    // Refining `Repr` would also let `Icmpv6Repr::emit` state its own `emit_contained_packet`
    // bound; see the parked note there.
    #[flux_rs::trusted(no, reason = "calls the header setters, clear_reserved and the record loop")]
    #[flux_rs::sig(
        fn(&Self[@r], packet: &strg Packet<T>[@p])
        requires r.blen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures packet: Packet<T>{v: v.buffer == p.buffer}
    )]
    pub fn emit<T>(&self, packet: &mut Packet<T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        match self {
            Repr::Query {
                max_resp_code,
                mcast_addr,
                s_flag,
                qrv,
                qqic,
                num_srcs,
                data,
            } => {
                packet.set_msg_type(Message::MldQuery);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_max_resp_code(*max_resp_code);
                packet.set_mcast_addr(*mcast_addr);
                if *s_flag {
                    packet.set_s_flag();
                } else {
                    packet.clear_s_flag();
                }
                packet.set_qrv(*qrv);
                packet.set_qqic(*qqic);
                packet.set_num_srcs(*num_srcs);
                packet.payload_mut().copy_from_slice(&data[..]);
            }
            Repr::Report {
                nr_mcast_addr_rcrds,
                data,
            } => {
                packet.set_msg_type(Message::MldReport);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_nr_mcast_addr_rcrds(*nr_mcast_addr_rcrds);
                packet.payload_mut().copy_from_slice(&data[..]);
            }
            Repr::ReportRecordReprs(records) => {
                packet.set_msg_type(Message::MldReport);
                packet.set_msg_code(0);
                packet.clear_reserved();
                packet.set_nr_mcast_addr_rcrds(records.len() as u16);
                // Was: `let mut payload = packet.payload_mut();` followed by
                // `payload = &mut payload[record.buffer_len()..]` each iteration. Same bytes at
                // the same offsets -- after `set_msg_type(MldReport)` the header is 8 octets, so
                // the walk is 8, 28, 48, ... -- but expressed as an offset into the packet
                // buffer rather than a chain of reborrowed sub-slices. Two reasons:
                //   * `AddressRecord::new_unchecked(&mut *payload)` instantiates
                //     `AddressRecord<&mut [u8]>`, which hits core's blanket
                //     `impl AsMut<U> for &mut T`: `associated refinement 'as_mut_reft' is
                //     missing from implementation`. That is a *spec* error, and it aborts the
                //     check of this whole function -- the other two arms then verify vacuously.
                //     `wire::Buf`'s `AsMut` impl is local and refined, so the bound is an
                //     ordinary obligation again.
                //   * a reborrowed sub-slice loses its length (flux-rs/flux#1714), so the
                //     original form could not state the per-record bound at all.
                // `test_report_record_reprs_emit` pins the resulting bytes.
                let mut offset = 8; // field::NR_MCAST_RCRDS.end
                for record in *records {
                    let data = packet.buffer.as_mut();
                    let buf = crate::wire::Buf::with_offset(data, offset);
                    record.emit(&mut AddressRecord::new_unchecked(buf));
                    offset += record.buffer_len();
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::phy::ChecksumCapabilities;
    use crate::wire::icmpv6::Message;
    use crate::wire::{IPV6_LINK_LOCAL_ALL_NODES, IPV6_LINK_LOCAL_ALL_ROUTERS, Icmpv6Repr};

    static QUERY_PACKET_BYTES: [u8; 44] = [
        0x82, 0x00, 0x73, 0x74, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x12, 0x00, 0x01, 0xff, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];

    static QUERY_PACKET_PAYLOAD: [u8; 16] = [
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];

    static REPORT_PACKET_BYTES: [u8; 44] = [
        0x8f, 0x00, 0x73, 0x85, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];

    static REPORT_PACKET_PAYLOAD: [u8; 36] = [
        0x01, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];

    fn create_repr<'a>(ty: Message) -> Icmpv6Repr<'a> {
        match ty {
            Message::MldQuery => Icmpv6Repr::Mld(Repr::Query {
                max_resp_code: 0x400,
                mcast_addr: IPV6_LINK_LOCAL_ALL_NODES,
                s_flag: true,
                qrv: 0x02,
                qqic: 0x12,
                num_srcs: 0x01,
                data: &QUERY_PACKET_PAYLOAD,
            }),
            Message::MldReport => Icmpv6Repr::Mld(Repr::Report {
                nr_mcast_addr_rcrds: 1,
                data: &REPORT_PACKET_PAYLOAD,
            }),
            _ => {
                panic!("Message type must be a MLDv2 message type");
            }
        }
    }

    #[test]
    fn test_query_deconstruct() {
        let packet = Packet::new_unchecked(Ref::new(&QUERY_PACKET_BYTES[..]));
        assert_eq!(packet.msg_type(), Message::MldQuery);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x7374);
        assert_eq!(packet.max_resp_code(), 0x0400);
        assert_eq!(packet.mcast_addr(), IPV6_LINK_LOCAL_ALL_NODES);
        assert!(packet.s_flag());
        assert_eq!(packet.qrv(), 0x02);
        assert_eq!(packet.qqic(), 0x12);
        assert_eq!(packet.num_srcs(), 0x01);
        assert_eq!(
            Ipv6Address::from_octets(packet.payload().try_into().unwrap()),
            IPV6_LINK_LOCAL_ALL_ROUTERS
        );
    }

    #[test]
    fn test_query_construct() {
        let mut bytes = [0xff; 44];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_msg_type(Message::MldQuery);
        packet.set_msg_code(0);
        packet.set_max_resp_code(0x0400);
        packet.set_mcast_addr(IPV6_LINK_LOCAL_ALL_NODES);
        packet.set_s_flag();
        packet.set_qrv(0x02);
        packet.set_qqic(0x12);
        packet.set_num_srcs(0x01);
        packet
            .payload_mut()
            .copy_from_slice(&IPV6_LINK_LOCAL_ALL_ROUTERS.octets());
        packet.clear_reserved();
        packet.fill_checksum(&IPV6_LINK_LOCAL_ALL_NODES, &IPV6_LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(&*packet.into_inner(), &QUERY_PACKET_BYTES[..]);
    }

    #[test]
    fn test_record_deconstruct() {
        let packet = Packet::new_unchecked(Ref::new(&REPORT_PACKET_BYTES[..]));
        assert_eq!(packet.msg_type(), Message::MldReport);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x7385);
        assert_eq!(packet.nr_mcast_addr_rcrds(), 0x01);
        let addr_rcrd = AddressRecord::new_unchecked(packet.payload());
        assert_eq!(addr_rcrd.record_type(), RecordType::ModeIsInclude);
        assert_eq!(addr_rcrd.aux_data_len(), 0x00);
        assert_eq!(addr_rcrd.num_srcs(), 0x01);
        assert_eq!(addr_rcrd.mcast_addr(), IPV6_LINK_LOCAL_ALL_NODES);
        assert_eq!(
            Ipv6Address::from_octets(addr_rcrd.payload().try_into().unwrap()),
            IPV6_LINK_LOCAL_ALL_ROUTERS
        );
    }

    #[test]
    fn test_record_construct() {
        let mut bytes = [0xff; 44];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_msg_type(Message::MldReport);
        packet.set_msg_code(0);
        packet.clear_reserved();
        packet.set_nr_mcast_addr_rcrds(1);
        {
            let mut addr_rcrd = AddressRecord::new_unchecked(packet.payload_mut());
            addr_rcrd.set_record_type(RecordType::ModeIsInclude);
            addr_rcrd.set_aux_data_len(0);
            addr_rcrd.set_num_srcs(1);
            addr_rcrd.set_mcast_addr(IPV6_LINK_LOCAL_ALL_NODES);
            addr_rcrd
                .payload_mut()
                .copy_from_slice(&IPV6_LINK_LOCAL_ALL_ROUTERS.octets());
        }
        packet.fill_checksum(&IPV6_LINK_LOCAL_ALL_NODES, &IPV6_LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(&*packet.into_inner(), &REPORT_PACKET_BYTES[..]);
    }

    #[test]
    fn test_query_repr_parse() {
        let packet = Packet::new_unchecked(&QUERY_PACKET_BYTES[..]);
        let repr = Icmpv6Repr::parse(
            &IPV6_LINK_LOCAL_ALL_NODES,
            &IPV6_LINK_LOCAL_ALL_ROUTERS,
            &packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(repr, Ok(create_repr(Message::MldQuery)));
    }

    #[test]
    fn test_report_repr_parse() {
        let packet = Packet::new_unchecked(&REPORT_PACKET_BYTES[..]);
        let repr = Icmpv6Repr::parse(
            &IPV6_LINK_LOCAL_ALL_NODES,
            &IPV6_LINK_LOCAL_ALL_ROUTERS,
            &packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(repr, Ok(create_repr(Message::MldReport)));
    }

    #[test]
    fn test_query_repr_emit() {
        let mut bytes = [0x2a; 44];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        let repr = create_repr(Message::MldQuery);
        repr.emit(
            &IPV6_LINK_LOCAL_ALL_NODES,
            &IPV6_LINK_LOCAL_ALL_ROUTERS,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &QUERY_PACKET_BYTES[..]);
    }

    #[test]
    fn test_report_repr_emit() {
        let mut bytes = [0x2a; 44];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        let repr = create_repr(Message::MldReport);
        repr.emit(
            &IPV6_LINK_LOCAL_ALL_NODES,
            &IPV6_LINK_LOCAL_ALL_ROUTERS,
            &mut packet,
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&*packet.into_inner(), &REPORT_PACKET_BYTES[..]);
    }

    // Pins the byte layout of the `ReportRecordReprs` arm of `Repr::emit`, which no other test
    // reaches. Added alongside the rewrite of that arm's payload walk, and passes unchanged
    // against the pre-rewrite body.
    #[test]
    fn test_report_record_reprs_emit() {
        let mut bytes = [0x2a; 48];
        {
            let mut packet = Packet::new_unchecked(&mut bytes[..]);
            let records = [
                AddressRecordRepr::new(RecordType::ModeIsInclude, IPV6_LINK_LOCAL_ALL_NODES),
                AddressRecordRepr::new(RecordType::ModeIsExclude, IPV6_LINK_LOCAL_ALL_ROUTERS),
            ];
            Repr::ReportRecordReprs(&records).emit(&mut packet);
        }

        let mut expected = [0x2a; 48];
        expected[0] = 0x8f; // MldReport
        expected[1] = 0x00; // code
        expected[4] = 0x00; // RECORD_RESV
        expected[5] = 0x00;
        expected[6] = 0x00; // NR_MCAST_RCRDS
        expected[7] = 0x02;
        expected[8] = 0x01; // record 0: ModeIsInclude
        expected[9] = 0x00; // record 0: aux_data_len
        expected[10] = 0x00; // record 0: num_srcs
        expected[11] = 0x00;
        expected[12..28].copy_from_slice(&IPV6_LINK_LOCAL_ALL_NODES.octets());
        expected[28] = 0x02; // record 1: ModeIsExclude
        expected[29] = 0x00;
        expected[30] = 0x00;
        expected[31] = 0x00;
        expected[32..48].copy_from_slice(&IPV6_LINK_LOCAL_ALL_ROUTERS.octets());

        assert_eq!(bytes, expected);
    }
}
