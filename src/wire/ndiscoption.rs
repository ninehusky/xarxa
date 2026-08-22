use bitflags::bitflags;
use core::fmt;

flux_rs::defs! {
    // An NDISC option's length is a whole number of eight-octet units, so every arm of
    // `Repr::buffer_len` rounds its octet count up to a multiple of eight. Kept in lockstep
    // with the arms, which spell the rounding out rather than calling `div_ceil` -- that
    // method carries no spec, so the equality could not be proved through it.
    fn round8(n: int) -> int {
        if n % 8 == 0 { n } else { n + 8 - n % 8 }
    }
}

use super::{Error, Result};
use crate::time::Duration;
use crate::wire::{Ipv6Address, Ipv6AddressExt, Ipv6Packet, Ipv6Repr, MAX_HARDWARE_ADDRESS_LEN};

use crate::wire::RawHardwareAddress;
use crate::wire::Ref;
use crate::wire::mld::read_ipv6_addr_at;

enum_with_unknown! {
    /// NDISC Option Type
    pub enum Type(u8) {
        /// Source Link-layer Address
        SourceLinkLayerAddr = 0x1,
        /// Target Link-layer Address
        TargetLinkLayerAddr = 0x2,
        /// Prefix Information
        PrefixInformation   = 0x3,
        /// Redirected Header
        RedirectedHeader    = 0x4,
        /// MTU
        Mtu                 = 0x5
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Type::SourceLinkLayerAddr => write!(f, "source link-layer address"),
            Type::TargetLinkLayerAddr => write!(f, "target link-layer address"),
            Type::PrefixInformation => write!(f, "prefix information"),
            Type::RedirectedHeader => write!(f, "redirected header"),
            Type::Mtu => write!(f, "mtu"),
            Type::Unknown(id) => write!(f, "{id}"),
        }
    }
}

bitflags! {
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct PrefixInfoFlags: u8 {
        const ON_LINK  = 0b10000000;
        const ADDRCONF = 0b01000000;
    }
}

/// A ghost field: carries an integer in the refinement and nothing at runtime.
///
/// The option's data field spans `2..data_len() * 8`, and `data_len()` lives in the buffer's
/// *contents* -- contents are not in the refinement, so no accessor's bound can mention them.
/// This is the way to name it anyway. `NdiscOption` holds one of these, and because the struct
/// is a ZST the layout of `NdiscOption<T>` is unchanged.
///
/// The value is anchored by [`NdiscOption::data_len`], the trusted getter that asserts the
/// octet at offset 1 equals the ghost. Everything else is proved.
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

/// A read/write wrapper around an [NDISC Option].
///
/// [NDISC Option]: https://tools.ietf.org/html/rfc4861#section-4.6
#[derive(PartialEq, Eq)]
#[flux_rs::refined_by(buffer: T, len: int)]
#[flux_rs::invariant(0 <= len && len <= 255)]
pub struct NdiscOption<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
    #[flux_rs::field(Ghost[len])]
    len: Ghost,
}

// Written out rather than derived so the ghost stays out of the output: a derive would print
// `NdiscOption { buffer: .., len: Ghost }`, and the ghost is not supposed to be observable.
// These reproduce the derived form for the one field that existed before.
impl<T: AsRef<[u8]> + fmt::Debug> fmt::Debug for NdiscOption<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NdiscOption")
            .field("buffer", &self.buffer)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<T: AsRef<[u8]> + defmt::Format> defmt::Format for NdiscOption<T> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "NdiscOption {{ buffer: {} }}", self.buffer)
    }
}

// Format of an NDISC Option
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |    Length     |              ...              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// ~                              ...                              ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc4861#section-4.6 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    // 8-bit identifier of the type of option.
    pub const TYPE: usize = 0;
    // 8-bit unsigned integer. Length of the option, in units of 8 octets.
    pub const LENGTH: usize = 1;
    // Minimum length of an option.
    pub const MIN_OPT_LEN: usize = 8;
    // Variable-length field. Option-Type-specific data.
    pub const fn DATA(length: u8) -> Field {
        2..length as usize * 8
    }

    // Source/Target Link-layer Option fields.
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |    Length     |    Link-Layer Address ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix Information Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                         Valid Lifetime                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                       Preferred Lifetime                      |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved2                           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +                            Prefix                             +
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix length.
    pub const PREFIX_LEN: usize = 2;
    // Flags field of prefix header.
    pub const FLAGS: usize = 3;
    // Valid lifetime.
    // Kept for documentation: the accessors spell `4` and `6` as literals, because a `const`
    // of struct type is opaque to Flux, and cite this name in a comment.
    #[allow(dead_code)]
    pub const VALID_LT: Field = 4..8;
    // Preferred lifetime. Kept for documentation; see `VALID_LT`.
    #[allow(dead_code)]
    pub const PREF_LT: Field = 8..12;
    // Reserved bits. Kept for documentation; see `VALID_LT`.
    #[allow(dead_code)]
    pub const PREF_RESERVED: Field = 12..16;
    // Prefix
    pub const PREFIX: Field = 16..32;

    // Redirected Header Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |            Reserved           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved                            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  ~                       IP header + data                        ~
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Reserved bits.
    pub const REDIRECTED_RESERVED: Field = 2..8;
    pub const REDIR_MIN_SZ: usize = 48;

    // MTU Option fields
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |           Reserved            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                              MTU                              |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  MTU
    pub const MTU: Field = 4..8;
}

/// Core getter methods relevant to any type of NDISC option.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Create a raw octet buffer with an NDISC Option structure.
    ///
    /// The ghost starts unconstrained: this reads nothing, so it learns nothing. It is pinned to
    /// the length octet the first time [`data_len`](Self::data_len) is called.
    #[flux_rs::trusted(no, reason = "carries the buffer index into the wrapper")]
    #[flux_rs::sig(fn(T[@b]) -> NdiscOption<T>{v: v.buffer == b})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> NdiscOption<T> {
        NdiscOption {
            buffer,
            len: Ghost::unknown(),
        }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<NdiscOption<T>> {
        let opt = Self::new_unchecked(buffer);
        opt.checked_len()?;

        // A data length field of 0 is invalid.
        if opt.data_len() == 0 {
            return Err(Error);
        }

        Ok(opt)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_data_len].
    ///
    /// [set_data_len]: #method.set_data_len
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(fn(self: &NdiscOption<T>[@p]) -> Result<()>)]
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
    /// for it -- and every option accessor below wants something from it. Returning the length
    /// lets the `Ok` arm say both facts: the buffer holds an option header, and the option's own
    /// declared extent `8 * len` fits inside it. The per-type arms need no bound of their own;
    /// `Repr::parse` tests `data_len` again for each type, and `8 * len <= v` turns that test
    /// into the octet count that type's fields need.
    ///
    /// The reads are spelled out: `field::DATA` returns a `Range` and `field::MIN_OPT_LEN`,
    /// `field::PREFIX.end` and `field::REDIR_MIN_SZ` are `usize` consts, all of which flux
    /// treats as opaque. The literals are the values those consts have.
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &NdiscOption<T>[@p])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
                             && 8 <= v && 8 * p.len <= v}>
    )]
    pub(super) fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();

        if len < 8 {
            // field::MIN_OPT_LEN
            Err(Error)
        } else {
            // `field::DATA(data_len).end`. Read through `data_len` rather than the octet, so
            // the ghost is what the bound below is stated over.
            let data_end = self.data_len() as usize * 8;
            if len < data_end {
                Err(Error)
            } else {
                match self.option_type() {
                    Type::SourceLinkLayerAddr | Type::TargetLinkLayerAddr | Type::Mtu => Ok(len),
                    Type::PrefixInformation if data_end >= 32 => Ok(len), // field::PREFIX.end
                    Type::RedirectedHeader if data_end >= 48 => Ok(len), // field::REDIR_MIN_SZ
                    Type::Unknown(_) => Ok(len),
                    _ => Err(Error),
                }
            }
        }
    }

    /// Consume the NDISC option, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the option type.
    #[flux_rs::trusted(no, reason = "panic site: reads the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> Type
        requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn option_type(&self) -> Type {
        let data = self.buffer.as_ref();
        Type::from(data[field::TYPE])
    }

    /// Read the length octet, with no claim about the ghost.
    #[flux_rs::trusted(no, reason = "panic site: reads the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> u8
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    fn data_len_octet(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::LENGTH]
    }

    /// Return the length of the data.
    ///
    /// The anchor for the ghost field: the return type *claims* the octet at offset 1 is `len`.
    /// Nothing proves that -- the buffer's contents are not in the refinement -- so it is the
    /// assumption [`data_mut`](Self::data_mut)'s bound rests on, and it is kept true by
    /// [`set_data_len`](Self::set_data_len), the only thing that writes this octet, which
    /// updates the ghost in the same step.
    ///
    /// The read itself stays checked: the trusted body is a call and an index expression it does
    /// not contain. All this assumes is the equality, which is the part Flux cannot see.
    #[flux_rs::trusted(yes, reason = "anchors the `len` ghost to the octet at offset 1")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> u8[p.len]
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn data_len(&self) -> u8 {
        self.data_len_octet()
    }
}

/// Getter methods only relevant for Source/Target Link-layer Address options.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Return the Source/Target Link-layer Address.
    ///
    /// Both halves of the `requires` come from `checked_len` and the `data_len >= 1` its callers
    /// test: `1 <= len` is what keeps `8 * len - 2` from running backwards, and `8 * len` is
    /// the far end of the window the address is read from.
    #[flux_rs::trusted(no, reason = "panic site: opens the link-layer address window")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> RawHardwareAddress
        requires 1 <= p.len && 8 * p.len <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn link_layer_addr(&self) -> RawHardwareAddress {
        // `core::cmp::min` rather than `usize::min`: the free function is the one xarxa
        // refines (see `flux_specs::cmp`), so the `len <= MAX_HARDWARE_ADDRESS_LEN` that
        // `RawHardwareAddress::from_bytes` requires stays visible. Same value.
        let len = core::cmp::min(MAX_HARDWARE_ADDRESS_LEN, self.data_len() as usize * 8 - 2);
        let data = self.buffer.as_ref();
        RawHardwareAddress::from_bytes(&data[2..len + 2])
    }
}

/// Getter methods only relevant for the MTU option.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Return the MTU value.
    #[flux_rs::trusted(no, reason = "panic site: reads the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> u32
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn mtu(&self) -> u32 {
        let data = self.buffer.as_ref();
        // field::MTU (4..8), read as two big-endian halves: there is no `read_u32_at` helper,
        // and `NetworkEndian::read_u32` takes a sub-slice whose length the caller cannot
        // recover (flux-rs/flux#1714). Same four bytes, same value.
        let hi = crate::wire::read_u16_at(data, 4) as u32;
        let lo = crate::wire::read_u16_at(data, 6) as u32;
        (hi << 16) | lo
    }
}

/// Getter methods only relevant for the Prefix Information option.
impl<T: AsRef<[u8]>> NdiscOption<T> {
    /// Return the prefix length.
    #[flux_rs::trusted(no, reason = "panic site: reads the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> u8
        requires 3 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.buffer.as_ref()[field::PREFIX_LEN]
    }

    /// Return the prefix information flags.
    #[flux_rs::trusted(no, reason = "panic site: reads the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> PrefixInfoFlags
        requires 4 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn prefix_flags(&self) -> PrefixInfoFlags {
        PrefixInfoFlags::from_bits_truncate(self.buffer.as_ref()[field::FLAGS])
    }

    /// Return the valid lifetime of the prefix.
    #[flux_rs::trusted(no, reason = "panic site: reads the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> Duration
        requires 8 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn valid_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        // field::VALID_LT (4..8), split for the same reason as `mtu`.
        let hi = crate::wire::read_u16_at(data, 4) as u32;
        let lo = crate::wire::read_u16_at(data, 6) as u32;
        Duration::from_secs(((hi << 16) | lo) as u64)
    }

    /// Return the preferred lifetime of the prefix.
    #[flux_rs::trusted(no, reason = "panic site: reads the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> Duration
        requires 12 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[inline]
    pub fn preferred_lifetime(&self) -> Duration {
        let data = self.buffer.as_ref();
        // field::PREF_LT (8..12), split for the same reason as `mtu`.
        let hi = crate::wire::read_u16_at(data, 8) as u32;
        let lo = crate::wire::read_u16_at(data, 10) as u32;
        Duration::from_secs(((hi << 16) | lo) as u64)
    }

    /// Return the prefix.
    #[flux_rs::trusted(no, reason = "panic site: reads the option at a fixed offset")]
    #[flux_rs::sig(
        fn(&NdiscOption<T>[@p]) -> Ipv6Address
        requires 32 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn prefix(&self) -> Ipv6Address {
        let data = self.buffer.as_ref();
        read_ipv6_addr_at(data, 16) // field::PREFIX
    }
}

impl<'a> NdiscOption<Ref<'a>> {
    /// [`new_checked`](Self::new_checked) over a [`Ref`], carrying its proof out.
    ///
    /// The generic `new_checked` cannot say this: at a reference or `dyn` self type the
    /// `as_ref_reft` in the postcondition is unstatable. `1 <= p.len` is the zero-length test
    /// below, which is this constructor's and not `checked_len`'s.
    #[flux_rs::trusted(no, reason = "carries `checked_len`'s proof out through the `Ok` arm")]
    #[flux_rs::sig(
        fn(Ref[@b]) -> Result<NdiscOption<Ref>{p: p.buffer == b && 8 <= b.len
                                                  && 8 * p.len <= b.len && 1 <= p.len}>
    )]
    pub fn new_checked_ref(buffer: Ref<'a>) -> Result<NdiscOption<Ref<'a>>> {
        let opt = NdiscOption::new_unchecked(buffer);
        opt.checked_len()?;

        // A data length field of 0 is invalid.
        if opt.data_len() == 0 {
            return Err(Error);
        }

        Ok(opt)
    }

    /// Return the option data.
    ///
    /// The `NdiscOption<&'a T>` twin of this cannot be proved: a reference in type-parameter
    /// position has the unit sort, so the far end of the window -- which is the ghost scaled by
    /// eight -- has no buffer length to be compared against. Over `Ref<'a>` it does, and the
    /// data's length survives into the caller's index.
    #[flux_rs::trusted(no, reason = "panic site: opens the option data window")]
    #[flux_rs::sig(
        fn(&NdiscOption<Ref>[@p]) -> &[u8][8 * p.len - 2]
        requires 1 <= p.len && 8 * p.len <= p.buffer.len
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        // `field::DATA(len)` is `2..len * 8`.
        self.buffer.window(2, self.data_len() as usize * 8)
    }
}

/// Core setter methods relevant to any type of NDISC option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the option type.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], Type)
        requires 1 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_option_type(&mut self, value: Type) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = value.into();
    }

    /// Set the option data length.
    ///
    /// Writes the ghost as well as the octet. This is the whole of what keeps
    /// [`data_len`](Self::data_len)'s claim true, so the two must not drift apart: `&strg`
    /// rather than `&mut` because a `&mut T{v: ..}` weakening does not compose through a call
    /// chain, and [`data_mut`](Self::data_mut) needs the new value to survive into it.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg NdiscOption<T>[@p], value: u8)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures self: NdiscOption<T>[p.buffer, value]
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_data_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::LENGTH] = value;
        self.len = Ghost::new(value);
    }
}

/// Setter methods only relevant for Source/Target Link-layer Address options.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the Source/Target Link-layer Address.
    //
    // `2 + addr.len()` rather than the simpler `10`: 10 is the maximum over both cfgs
    // (`MAX_HARDWARE_ADDRESS_LEN` is 6 without `medium-ieee802154` and 8 with it), but an
    // option carrying a six-octet address is only eight octets long, so a caller holding
    // exactly `buffer_len()` octets could not discharge 10. The exact bound is what
    // `emit_link_layer_addr` can supply from the option's own index.
    #[flux_rs::trusted(no, reason = "panic site: the link-layer address copy")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], RawHardwareAddress[@a])
        requires 2 + a.len <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_link_layer_addr(&mut self, addr: RawHardwareAddress) {
        let data = self.buffer.as_mut();
        data[2..2 + addr.len()].copy_from_slice(addr.as_bytes())
    }
}

/// Setter methods only relevant for the MTU option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the MTU value.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], u32)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_mtu(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        // field::MTU (4..8), written as the two big-endian halves it is defined to produce --
        // there is no `write_u32_at` helper. Identical bytes.
        crate::wire::write_u16_at(data, 4, (value >> 16) as u16);
        crate::wire::write_u16_at(data, 6, value as u16);
    }
}

/// Setter methods only relevant for the Prefix Information option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Set the prefix length.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], u8)
        requires 3 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_prefix_len(&mut self, value: u8) {
        self.buffer.as_mut()[field::PREFIX_LEN] = value;
    }

    /// Set the prefix information flags.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], PrefixInfoFlags)
        requires 4 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_prefix_flags(&mut self, flags: PrefixInfoFlags) {
        self.buffer.as_mut()[field::FLAGS] = flags.bits();
    }

    /// Set the valid lifetime of the prefix.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], Duration)
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_valid_lifetime(&mut self, time: Duration) {
        let data = self.buffer.as_mut();
        // field::VALID_LT (4..8), split for the same reason as `set_mtu`.
        let v = time.secs() as u32;
        crate::wire::write_u16_at(data, 4, (v >> 16) as u16);
        crate::wire::write_u16_at(data, 6, v as u16);
    }

    /// Set the preferred lifetime of the prefix.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], Duration)
        requires 12 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn set_preferred_lifetime(&mut self, time: Duration) {
        let data = self.buffer.as_mut();
        // field::PREF_LT (8..12), split for the same reason as `set_mtu`.
        let v = time.secs() as u32;
        crate::wire::write_u16_at(data, 8, (v >> 16) as u16);
        crate::wire::write_u16_at(data, 10, v as u16);
    }

    /// Clear the reserved bits.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p])
        requires 16 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn clear_prefix_reserved(&mut self) {
        let data = self.buffer.as_mut();
        // field::PREF_RESERVED (12..16), split for the same reason as `set_mtu`. Writing 0 to
        // 12..14 then 14..16 is the same four zero bytes.
        crate::wire::write_u16_at(data, 12, 0);
        crate::wire::write_u16_at(data, 14, 0);
    }

    /// Set the prefix.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p], Ipv6Address)
        requires 32 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_prefix(&mut self, addr: Ipv6Address) {
        let data = self.buffer.as_mut();
        // field::PREFIX (16..32)
        crate::wire::write_octets16_at(data, 16, &addr.octets());
    }
}

/// Setter methods only relevant for the Redirected Header option.
impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Clear the reserved bits.
    #[flux_rs::trusted(no, reason = "panic site: writes the option header at a fixed offset")]
    #[flux_rs::sig(
        fn(&mut NdiscOption<T>[@p])
        requires 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn clear_redirected_reserved(&mut self) {
        let data = self.buffer.as_mut();
        // field::REDIRECTED_RESERVED (2..8). The original `fill_with(|| 0)` runs inside a
        // closure, whose body Flux does not check; three big-endian zero halves write exactly
        // the same six bytes and are checked.
        crate::wire::write_u16_at(data, 2, 0);
        crate::wire::write_u16_at(data, 4, 0);
        crate::wire::write_u16_at(data, 6, 0);
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NdiscOption<T> {
    /// Return a mutable pointer to the option data.
    ///
    /// The data spans `2..data_len() * 8`, so the bound is a property of the length octet. The
    /// `len` ghost names that octet, which is what makes `1 <= p.len` (the range is non-empty)
    /// and `p.len * 8 <= n` (it fits) statable at all. The obligation is now passed up rather
    /// than erased; the only caller, `emit_unknown`, is where it stops.
    #[flux_rs::trusted(no, reason = "panic site: slices the buffer at a content-dependent end")]
    #[flux_rs::sig(
        fn(self: &mut NdiscOption<T>[@p]) -> &mut [u8]
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(p.buffer)
              && 1 <= p.len
              && p.len * 8 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    )]
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.data_len();
        let data = self.buffer.as_mut();
        // field::DATA(len) (2..len * 8) spelled as arithmetic: a `const fn` returning a
        // `Range<usize>` is opaque to Flux, so `r.start <= r.end` is unprovable however well the
        // length is known.
        &mut data[2..len as usize * 8]
    }
}

// The buffer arrives with no length index, and `Ref` is where it acquires one; the body is on
// the `NdiscOption<Ref>` impl below.
impl<T: AsRef<[u8]> + ?Sized> fmt::Display for NdiscOption<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&NdiscOption::new_unchecked(Ref::new(self.buffer.as_ref())), f)
    }
}

impl fmt::Display for NdiscOption<Ref<'_>> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "NDISC Option ({err})")?;
                Ok(())
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrefixInformation {
    pub prefix_len: u8,
    pub flags: PrefixInfoFlags,
    pub valid_lifetime: Duration,
    pub preferred_lifetime: Duration,
    pub prefix: Ipv6Address,
}

impl PrefixInformation {
    /// Validates the prefix information option against check a, b, c in
    /// <https://www.rfc-editor.org/rfc/rfc4862#section-5.5.3>
    pub fn is_valid_prefix_info(&self) -> bool {
        self.flags.contains(PrefixInfoFlags::ADDRCONF)
            && !self.prefix.is_link_local()
            && self.preferred_lifetime <= self.valid_lifetime
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(dlen: int)]
#[flux_rs::invariant(0 <= dlen)]
pub struct RedirectedHeader<'a> {
    pub header: Ipv6Repr,
    #[flux_rs::field(&[u8][dlen])]
    pub data: &'a [u8],
}

/// A high-level representation of an NDISC Option.
//
// Indexed by the octets `emit` writes, which is what `buffer_len` returns. The two link-layer
// arms and the redirected-header arm are content-dependent, which is why this is not a set of
// constants: `RawHardwareAddress` carries its length and `RedirectedHeader` now carries its
// data's, so both are statable. 48 is `8 + Ipv6Repr::buffer_len()`, the latter a constant 40.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[flux_rs::refined_by(blen: int)]
// Not `8 <= blen`, which every arm but one satisfies: `Unknown` carries a declared length of
// zero. Non-negativity is what `ndisc::emit_option_at` needs to get from its own
// `header_len + offset + blen <= buffer` down to the two bounds its body uses.
#[flux_rs::invariant(0 <= blen)]
pub enum Repr<'a> {
    #[flux_rs::variant((RawHardwareAddress[@a]) -> Repr[round8(2 + a.len)])]
    SourceLinkLayerAddr(RawHardwareAddress),
    #[flux_rs::variant((RawHardwareAddress[@a]) -> Repr[round8(2 + a.len)])]
    TargetLinkLayerAddr(RawHardwareAddress),
    #[flux_rs::variant((PrefixInformation) -> Repr[32])]
    PrefixInformation(PrefixInformation),
    #[flux_rs::variant((RedirectedHeader[@h]) -> Repr[round8(48 + h.dlen)])]
    RedirectedHeader(RedirectedHeader<'a>),
    #[flux_rs::variant((u32) -> Repr[8])]
    Mtu(u32),
    #[flux_rs::variant({u8, u8[@l], &[u8]} -> Repr[8 * l])]
    Unknown {
        type_: u8,
        length: u8,
        data: &'a [u8],
    },
}

impl<'a> Repr<'a> {
    /// Parse an NDISC Option and return a high-level representation.
    ///
    /// `checked_len` rather than `check_len`: the same test, but its `Ok` arm names the buffer's
    /// length and the option's declared extent, and over [`Ref`] both are statable. Each arm
    /// below already tests `data_len` for its own type; against `8 * len <= buffer.len` those
    /// tests become the octet counts the fields need.
    pub fn parse(opt: &NdiscOption<Ref<'a>>) -> Result<Repr<'a>> {
        opt.checked_len()?;

        match opt.option_type() {
            Type::SourceLinkLayerAddr => {
                if opt.data_len() >= 1 {
                    Ok(Repr::SourceLinkLayerAddr(opt.link_layer_addr()))
                } else {
                    Err(Error)
                }
            }
            Type::TargetLinkLayerAddr => {
                if opt.data_len() >= 1 {
                    Ok(Repr::TargetLinkLayerAddr(opt.link_layer_addr()))
                } else {
                    Err(Error)
                }
            }
            Type::PrefixInformation => {
                if opt.data_len() == 4 {
                    Ok(Repr::PrefixInformation(PrefixInformation {
                        prefix_len: opt.prefix_len(),
                        flags: opt.prefix_flags(),
                        valid_lifetime: opt.valid_lifetime(),
                        preferred_lifetime: opt.preferred_lifetime(),
                        prefix: opt.prefix(),
                    }))
                } else {
                    Err(Error)
                }
            }
            Type::RedirectedHeader => {
                // If the options data length is less than 6, the option
                // does not have enough data to fill out the IP header
                // and common option fields.
                if opt.data_len() < 6 {
                    Err(Error)
                } else {
                    // 6 is `field::REDIRECTED_RESERVED.len()`; flux cannot see through a
                    // `Range` const, and `data` already starts at offset 2.
                    let redirected_packet = &opt.data()[6..];

                    let ip_packet = Ipv6Packet::new_checked(redirected_packet)?;
                    let ip_repr = Ipv6Repr::parse(&ip_packet)?;

                    // 40 is `ip_repr.buffer_len()`, which is `IPV6_HEADER_LEN` for every IPv6
                    // packet -- that header is fixed width -- spelled as the literal because
                    // `Ipv6Repr::buffer_len` is a `const fn` with no signature.
                    let payload = &redirected_packet[40..];
                    // `Ipv6Packet::check_len` tested this and returns `Result<()>`, so what it
                    // established did not survive the call; by the time this `Err` is reachable
                    // `new_checked` above has already returned the same one. Rung 2 on
                    // `wire/ipv6.rs` retires it. Stated as a comparison rather than
                    // `40 + payload_len <= len`, whose sum flux models as wrapping.
                    // Bound once, not read twice: `Ipv6Repr` carries no refinement, so each
                    // read of the field is a fresh unconstrained `usize` and the test would
                    // not be about the same value as the window.
                    let payload_len = ip_repr.payload_len;
                    if payload_len > payload.len() {
                        return Err(Error);
                    }

                    Ok(Repr::RedirectedHeader(RedirectedHeader {
                        header: ip_repr,
                        data: &payload[..payload_len],
                    }))
                }
            }
            Type::Mtu => {
                if opt.data_len() == 1 {
                    Ok(Repr::Mtu(opt.mtu()))
                } else {
                    Err(Error)
                }
            }
            Type::Unknown(id) => {
                // A length of 0 is invalid.
                if opt.data_len() != 0 {
                    Ok(Repr::Unknown {
                        type_: id,
                        length: opt.data_len(),
                        data: opt.data(),
                    })
                } else {
                    Err(Error)
                }
            }
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    //
    // The round up is spelled out rather than `div_ceil(8) * 8`: that method carries no flux
    // spec, so `round8` could not be proved equal to it. Same value either way.
    #[flux_rs::trusted(no, reason = "ties the `blen` index to the emitted length")]
    #[flux_rs::sig(fn(self: &Self[@r]) -> usize[r.blen])]
    #[flux_rs::no_panic]
    pub const fn buffer_len(&self) -> usize {
        match self {
            &Repr::SourceLinkLayerAddr(addr) | &Repr::TargetLinkLayerAddr(addr) => {
                let len = 2 + addr.len();
                if len % 8 == 0 { len } else { len + 8 - len % 8 }
            }
            // 32, 8 and `length * 8` restate `field::PREFIX.end`, `field::MTU.end` and
            // `field::DATA(length).end`: flux cannot see through a `Range` const.
            &Repr::PrefixInformation(_) => 32,
            &Repr::RedirectedHeader(RedirectedHeader { data, .. }) => {
                // 40 is `Ipv6Repr::buffer_len()`, a constant; restated because that method
                // returns an unindexed `usize`.
                let len = 8 + 40 + crate::flux_util::byte_len(data);
                if len % 8 == 0 { len } else { len + 8 - len % 8 }
            }
            &Repr::Mtu(_) => 8,
            &Repr::Unknown { length, .. } => length as usize * 8,
        }
    }

    /// Emit a high-level representation into an NDISC Option.
    ///
    /// The caller owes `field::REDIR_MIN_SZ` (48) octets: that is the largest *fixed* lower
    /// bound any arm needs (Prefix Information reaches `field::PREFIX.end` = 32, a Redirected
    /// Header at least 48). It is a lower bound, not the full contract -- the variable-length
    /// arms additionally need `buffer_len()`, which is content-dependent. See the notes on
    /// `emit_redirected_header`, `emit_unknown` and `data_mut` for what is still owed.
    ///
    /// The blanket 48 is kept as well as the per-arm `r.blen`: the arms' setters reach past
    /// their own option's length -- a Redirected Header writes an `Ipv6Repr` at a fixed offset --
    /// so `r.blen` alone does not discharge them. What `r.blen` adds is the bound the *caller*
    /// can now supply, `ndisc::Repr` being indexed by its full `buffer_len()`.
    #[flux_rs::trusted(no, reason = "carries the option buffer bound to the setters")]
    #[flux_rs::sig(
        fn(&Repr[@r], opt: &strg NdiscOption<T>[@p])
        requires r.blen <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
        ensures opt: NdiscOption<T>{v: v.buffer == p.buffer}
    )]
    pub fn emit<T>(&self, opt: &mut NdiscOption<T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        match *self {
            Repr::SourceLinkLayerAddr(addr) => {
                emit_link_layer_addr(opt, Type::SourceLinkLayerAddr, addr);
            }
            Repr::TargetLinkLayerAddr(addr) => {
                emit_link_layer_addr(opt, Type::TargetLinkLayerAddr, addr);
            }
            Repr::PrefixInformation(PrefixInformation {
                prefix_len,
                flags,
                valid_lifetime,
                preferred_lifetime,
                prefix,
            }) => {
                opt.clear_prefix_reserved();
                opt.set_option_type(Type::PrefixInformation);
                opt.set_data_len(4);
                opt.set_prefix_len(prefix_len);
                opt.set_prefix_flags(flags);
                opt.set_valid_lifetime(valid_lifetime);
                opt.set_preferred_lifetime(preferred_lifetime);
                opt.set_prefix(prefix);
            }
            Repr::RedirectedHeader(RedirectedHeader { header, data }) => {
                emit_redirected_header(opt, header, data);
            }
            Repr::Mtu(mtu) => {
                opt.set_option_type(Type::Mtu);
                opt.set_data_len(1);
                opt.set_mtu(mtu);
            }
            Repr::Unknown {
                type_: id,
                length,
                data,
            } => {
                emit_unknown(opt, id, length, data);
            }
        }
    }
}

/// Emit a Source/Target Link-layer Address option.
///
/// Lifted out of [`Repr::emit`] so each arm's bound can be stated separately. The bound the
/// body needs is `10`, which `RawHardwareAddress`'s `len <= MAX_HARDWARE_ADDRESS_LEN`
/// invariant supplies: it is what puts `opt_len = addr.len() + 2` in range and so rules out
/// the `self + rhs - 1` overflow inside `opt_len.div_ceil(8)`.
#[flux_rs::trusted(no, reason = "panic site: the link-layer address option body")]
// The bound is stated over the address the option carries, which is what its `blen` is a
// function of and what `emit` now supplies. It used to be `emit`'s blanket 48; that was over-
// strong -- a six-octet address needs 8 -- and unsatisfiable for a small NDISC packet.
#[flux_rs::sig(
    fn(opt: &strg NdiscOption<T>[@p], Type, RawHardwareAddress[@a])
    requires round8(2 + a.len) <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    ensures opt: NdiscOption<T>{v: v.buffer == p.buffer}
)]
fn emit_link_layer_addr<T>(opt: &mut NdiscOption<T>, ty: Type, addr: RawHardwareAddress)
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    opt.set_option_type(ty);
    let opt_len = addr.len() + 2;
    opt.set_data_len(opt_len.div_ceil(8) as u8); // round to next multiple of 8.
    opt.set_link_layer_addr(addr);
}

/// Emit an option of an unrecognised type.
///
/// OBLIGATION STOPS HERE, and for two separate reasons.
///
/// The first is a *real* reachable panic, not a Flux limitation. `copy_from_slice` requires
/// `data_mut().len() == data.len()`, i.e. `data.len() == length as usize * 8 - 2`, and nothing
/// in the type rules that out: `Repr::Unknown { type_: 0x42, length: 2, data: &[1, 2, 3] }`
/// emitted into a 64-octet buffer panics here today with "source slice length (3) does not
/// match destination slice length (14)". Recorded, not fixed -- fixing it is a behaviour
/// change, which is out of scope.
///
/// The second is that the equality is not even statable at this call. [`NdiscOption::data_mut`]
/// hands back a bare `&mut [u8]`, and a *returned* `&mut` loses its length index
/// (flux-rs/flux#1714), so the destination side of the equality has no name here. Giving it one
/// means routing the data through [`crate::wire::Buf`], the way `redirected_packet_buf` does.
///
/// The buffer-space half of the obligation *is* statable now that `len` is a ghost --
/// `1 <= length && length * 8 <= as_mut_reft(opt.buffer)`, which is what `data_mut` requires.
/// Nothing discharges it: [`Repr::emit`] holds only the fixed 48, and a Redirected-Header-sized
/// bound says nothing about an `Unknown` arm whose `length` octet can reach 255. Measured, not
/// inferred: stating all of it here and dropping to `trusted(no)` takes the crate from 343
/// errors to 348 -- three unprovable conjuncts at the call in `Repr::emit`, and two left in
/// this body for the `&mut`-index reason above. Closing it needs [`Repr`] refined by its
/// `buffer_len()`, the way `icmpv6::Repr` is refined by `blen`.
#[flux_rs::trusted(yes, reason = "copy_from_slice's length equality is unstatable: data_mut \
returns a bare &mut [u8], whose index is lost (flux-rs/flux#1714). The mismatch is moreover \
reachable -- see the doc comment")]
// Stated over the option's own declared extent, as on `emit_link_layer_addr`.
#[flux_rs::sig(
    fn(opt: &strg NdiscOption<T>[@p], u8, length: u8, &[u8])
    requires 8 * length <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    ensures opt: NdiscOption<T>[p.buffer, length]
)]
fn emit_unknown<T>(opt: &mut NdiscOption<T>, id: u8, length: u8, data: &[u8])
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    opt.set_option_type(Type::Unknown(id));
    opt.set_data_len(length);
    opt.data_mut().copy_from_slice(data);
}

/// Emit a Redirected Header option.
///
/// Lifted out of [`Repr::emit`] so that the rest of that function can be checked. This arm
/// cannot be: it nests an `Ipv6Packet` over `&mut &mut [u8]`, which instantiates core's blanket
/// `impl<T, U> AsMut<U> for &mut T`. That impl has no associated refinement, and one cannot be
/// written -- Flux gives a reference self type the *unit* sort, so an extern spec fails with
/// `mismatched sorts: expected 'T::sort', found '()'`. Confirmed by running: with `trusted(no)`
/// the body reports `associated refinement 'as_mut_reft' is missing from implementation` at the
/// `header.emit(&mut ip_packet)` call.
///
/// The stated `requires` is `field::REDIR_MIN_SZ` (48), the *minimum* a Redirected Header
/// option occupies. It is not the full bound: the true requirement is
/// `(8 + header.buffer_len() + data.len()).div_ceil(8) * 8 <= n`, which is content-dependent
/// and needs `Repr` refined by its `buffer_len()`. This helper therefore assumes more than it
/// states, and the residual obligation is recorded rather than discharged.
#[flux_rs::trusted(yes, reason = "flux limitation: Ipv6Packet over `&mut &mut [u8]` hits core's \
blanket AsMut impl, which has no associated refinement and cannot be given one (unit sort)")]
#[flux_rs::sig(
    fn(opt: &strg NdiscOption<T>[@p], Ipv6Repr, &[u8])
    requires 48 <= <T as AsMut<[u8]>>::as_mut_reft(p.buffer)
    ensures opt: NdiscOption<T>{v: v.buffer == p.buffer}
)]
fn emit_redirected_header<T>(opt: &mut NdiscOption<T>, header: Ipv6Repr, data: &[u8])
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    // TODO(thvdveld): I think we need to check if the data we are sending is not
    // exceeding the MTU.
    opt.clear_redirected_reserved();
    opt.set_option_type(Type::RedirectedHeader);
    opt.set_data_len((8 + header.buffer_len() + data.len()).div_ceil(8) as u8);
    let mut packet = &mut opt.data_mut()[field::REDIRECTED_RESERVED.end - 2..];
    let mut ip_packet = Ipv6Packet::new_unchecked(&mut packet);
    header.emit(&mut ip_packet);
    ip_packet.payload_mut().copy_from_slice(data);
}

impl<'a> fmt::Display for Repr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NDISC Option: ")?;
        match *self {
            Repr::SourceLinkLayerAddr(addr) => {
                write!(f, "SourceLinkLayer addr={addr}")
            }
            Repr::TargetLinkLayerAddr(addr) => {
                write!(f, "TargetLinkLayer addr={addr}")
            }
            Repr::PrefixInformation(PrefixInformation {
                prefix, prefix_len, ..
            }) => {
                write!(f, "PrefixInformation prefix={prefix}/{prefix_len}")
            }
            Repr::RedirectedHeader(RedirectedHeader { header, .. }) => {
                write!(f, "RedirectedHeader header={header}")
            }
            Repr::Mtu(mtu) => {
                write!(f, "MTU mtu={mtu}")
            }
            Repr::Unknown {
                type_: id, length, ..
            } => {
                write!(f, "Unknown({id}) length={length}")
            }
        }
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for NdiscOption<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        // `Ref::new` off the `dyn`'s own `as_ref`: the trait signature is fixed, so the buffer
        // arrives with no length index, and `Ref` is where it acquires one.
        match NdiscOption::new_checked_ref(Ref::new(buffer.as_ref())) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(ndisc) => match Repr::parse(&ndisc) {
                Err(_) => Ok(()),
                Ok(repr) => {
                    write!(f, "{indent}{repr}")
                }
            },
        }
    }
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
#[cfg(test)]
mod test {
    use super::Error;
    use super::{NdiscOption, PrefixInfoFlags, PrefixInformation, Repr, Type};
    use crate::time::Duration;
    use crate::wire::Ipv6Address;
    use crate::wire::Ref;

    #[cfg(feature = "medium-ethernet")]
    use crate::wire::EthernetAddress;
    #[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ieee802154"))]
    use crate::wire::Ieee802154Address;

    static PREFIX_OPT_BYTES: [u8; 32] = [
        0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00,
        0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];

    #[test]
    fn ghost_field_is_not_observable() {
        let bytes = [0u8; 8];
        let opt = NdiscOption::new_unchecked(&bytes[..]);
        let s = format!("{opt:?}");
        assert!(!s.contains("Ghost"), "ghost leaked into Debug: {s}");
        assert!(s.starts_with("NdiscOption { buffer: "), "Debug shape changed: {s}");
    }

    #[test]
    fn test_deconstruct() {
        let opt = NdiscOption::new_unchecked(&PREFIX_OPT_BYTES[..]);
        assert_eq!(opt.option_type(), Type::PrefixInformation);
        assert_eq!(opt.data_len(), 4);
        assert_eq!(opt.prefix_len(), 64);
        assert_eq!(
            opt.prefix_flags(),
            PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF
        );
        assert_eq!(opt.valid_lifetime(), Duration::from_secs(900));
        assert_eq!(opt.preferred_lifetime(), Duration::from_secs(1000));
        assert_eq!(opt.prefix(), Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_construct() {
        let mut bytes = [0x00; 32];
        let mut opt = NdiscOption::new_unchecked(&mut bytes[..]);
        opt.set_option_type(Type::PrefixInformation);
        opt.set_data_len(4);
        opt.set_prefix_len(64);
        opt.set_prefix_flags(PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF);
        opt.set_valid_lifetime(Duration::from_secs(900));
        opt.set_preferred_lifetime(Duration::from_secs(1000));
        opt.set_prefix(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(&PREFIX_OPT_BYTES[..], &*opt.into_inner());
    }

    #[test]
    fn test_short_packet() {
        assert_eq!(NdiscOption::new_checked(&[0x00, 0x00]), Err(Error));
        let bytes = [0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(NdiscOption::new_checked(&bytes), Err(Error));
    }

    #[cfg(feature = "medium-ethernet")]
    #[test]
    fn test_repr_parse_link_layer_opt_ethernet() {
        let mut bytes = [0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34];
        let addr = EthernetAddress::from_octets([0x54, 0x52, 0x00, 0x12, 0x23, 0x34]);
        {
            assert_eq!(
                Repr::parse(&NdiscOption::new_unchecked(Ref::new(&bytes))),
                Ok(Repr::SourceLinkLayerAddr(addr.into()))
            );
        }
        bytes[0] = 0x02;
        {
            assert_eq!(
                Repr::parse(&NdiscOption::new_unchecked(Ref::new(&bytes))),
                Ok(Repr::TargetLinkLayerAddr(addr.into()))
            );
        }
    }

    #[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ieee802154"))]
    #[test]
    fn test_repr_parse_link_layer_opt_ieee802154() {
        let mut bytes = [
            0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let addr = Ieee802154Address::Extended([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        {
            assert_eq!(
                Repr::parse(&NdiscOption::new_unchecked(Ref::new(&bytes))),
                Ok(Repr::SourceLinkLayerAddr(addr.into()))
            );
        }
        bytes[0] = 0x02;
        {
            assert_eq!(
                Repr::parse(&NdiscOption::new_unchecked(Ref::new(&bytes))),
                Ok(Repr::TargetLinkLayerAddr(addr.into()))
            );
        }
    }

    #[test]
    fn test_repr_parse_prefix_info() {
        let repr = Repr::PrefixInformation(PrefixInformation {
            prefix_len: 64,
            flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(900),
            preferred_lifetime: Duration::from_secs(1000),
            prefix: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        });
        assert_eq!(
            Repr::parse(&NdiscOption::new_unchecked(Ref::new(&PREFIX_OPT_BYTES))),
            Ok(repr)
        );
    }

    #[test]
    fn test_repr_emit_prefix_info() {
        let mut bytes = [0x2a; 32];
        let repr = Repr::PrefixInformation(PrefixInformation {
            prefix_len: 64,
            flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(900),
            preferred_lifetime: Duration::from_secs(1000),
            prefix: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        });
        let mut opt = NdiscOption::new_unchecked(&mut bytes);
        repr.emit(&mut opt);
        assert_eq!(&opt.into_inner()[..], &PREFIX_OPT_BYTES[..]);
    }

    #[test]
    fn test_repr_parse_mtu() {
        let bytes = [0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc];
        assert_eq!(
            Repr::parse(&NdiscOption::new_unchecked(Ref::new(&bytes))),
            Ok(Repr::Mtu(1500))
        );
    }
}
