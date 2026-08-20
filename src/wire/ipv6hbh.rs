use super::{Error, Ipv6Option, Ipv6OptionRepr, Ipv6OptionsIterator, Result};
use crate::config;
use crate::wire::ipv6option::RouterAlert;
use heapless::Vec;

/// A read/write wrapper around an IPv6 Hop-by-Hop Header buffer.
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Hop-by-Hop Header structure.
    pub const fn new_unchecked(buffer: T) -> Self {
        Header { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.as_ref().is_empty() {
            return Err(Error);
        }

        Ok(())
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Header<&'a T> {
    /// Return the options of the IPv6 Hop-by-Hop header.
    pub fn options(&self) -> &'a [u8] {
        self.buffer.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Return a mutable pointer to the options of the IPv6 Hop-by-Hop header.
    ///
    /// Lives here, on `Header<T>` with `T: Sized`, rather than on `Header<&mut T>` with
    /// `T: ?Sized`: a reference self type gets the unit sort, so on `Header<&mut T>` there is no
    /// `as_mut_reft` to name and no buffer bound can be written. The move is strictly widening --
    /// `&mut T` is `Sized` and satisfies `AsRef<[u8]> + AsMut<[u8]>` through core's blanket impls
    /// whenever `T` does, so every existing `Header<&mut T>` caller still resolves.
    ///
    /// No bound is stated, because the body has no panic site to gate: it hands back the whole
    /// buffer without indexing it. The two out-of-bounds obligations in this file are in
    /// [`Repr::emit`], on the slices it takes *of the returned* `&mut [u8]`, and a returned `&mut`
    /// has already lost its length index (flux-rs/flux#1714), so they are out of reach from here.
    pub fn options_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

/// A ghost field: carries `buffer_len()` in the refinement and nothing at runtime.
///
/// The emitted length is the sum of the options' lengths. A sum over a `Vec` is not statable
/// as a field index -- the element type's refinement is not reachable through the container --
/// so the total is accumulated as each option is added and named here instead. Because the
/// struct is a ZST it costs no space. Same device as `ipv6option::Ghost`.
///
/// The value is anchored by [`Repr::buffer_len`], the trusted getter that claims the runtime
/// sum equals the ghost. That holds because `options` is private and every path that adds to
/// it -- `parse`, `mldv2_router_alert`, `push_padn_option` -- adds the same amount here.
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val)]
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Ghost;

impl Ghost {
    #[flux_rs::trusted(yes, reason = "opaque: establishes the ghost value")]
    #[flux_rs::sig(fn(val: usize) -> Ghost[val])]
    #[flux_rs::no_panic]
    const fn new(_val: usize) -> Ghost {
        Ghost
    }
}

/// A high-level representation of an IPv6 Hop-by-Hop Header.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// Indexed by the octets `emit` writes, which is what a caller sizes the hop-by-hop window from.
#[flux_rs::refined_by(blen: int)]
#[flux_rs::invariant(0 <= blen)]
pub struct Repr<'a> {
    // Private: the ghost below records the emitted length as options are added, so a caller
    // pushing directly would desynchronise it. Use `push_padn_option`, or `options()` to read.
    options: Vec<Ipv6OptionRepr<'a>, { config::IPV6_HBH_MAX_OPTIONS }>,
    #[flux_rs::field(Ghost[blen])]
    ghost: Ghost,
}

impl<'a> Repr<'a> {
    /// Parse an IPv6 Hop-by-Hop Header and return a high-level representation.
    pub fn parse<T>(header: &'a Header<&'a T>) -> Result<Repr<'a>>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        header.check_len()?;

        let mut options = Vec::new();

        let iter = Ipv6OptionsIterator::new(header.options());

        let mut blen = 0usize;

        for option in iter {
            let option = option?;
            let option_len = option.buffer_len();

            if let Err(e) = options.push(option) {
                net_trace!("error when parsing hop-by-hop options: {}", e);
                break;
            }
            blen += option_len;
        }

        Ok(Self {
            options,
            ghost: Ghost::new(blen),
        })
    }

    /// The options this header will emit.
    ///
    /// Trusted: `heapless::Vec`'s `Deref` has no MIR available, so the call reads as
    /// transitively panicking. It does not touch the `blen` ghost.
    #[flux_rs::trusted(yes, reason = "heapless Deref has no MIR; read-only, no ghost effect")]
    #[flux_rs::no_panic]
    pub fn options(&self) -> &[Ipv6OptionRepr<'a>] {
        &self.options
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    ///
    /// Trusted: this is the anchor for the `blen` ghost. The sum below is over a `Vec`, whose
    /// elements' refinements are not reachable through the container, so the equality is stated
    /// rather than derived. It holds by the argument on [`Ghost`].
    #[flux_rs::trusted(yes, reason = "anchors the `blen` ghost; the sum is over a Vec")]
    #[flux_rs::sig(fn(self: &Self[@r]) -> usize[r.blen])]
    #[flux_rs::no_panic]
    pub fn buffer_len(&self) -> usize {
        self.options.iter().map(|o| o.buffer_len()).sum()
    }

    /// Emit a high-level representation into an IPv6 Hop-by-Hop Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        let mut buffer = header.options_mut();

        for opt in &self.options {
            opt.emit(&mut Ipv6Option::new_unchecked(
                &mut buffer[..opt.buffer_len()],
            ));
            buffer = &mut buffer[opt.buffer_len()..];
        }
    }

    /// The hop-by-hop header containing a MLDv2 router alert option
    ///
    /// The 4 is `Ipv6OptionRepr::RouterAlert`'s index: a two-octet preamble plus
    /// `RouterAlert::DATA_LEN`.
    #[flux_rs::sig(fn() -> Repr[4])]
    pub fn mldv2_router_alert() -> Self {
        let mut options = Vec::new();
        options
            .push(Ipv6OptionRepr::RouterAlert(
                RouterAlert::MulticastListenerDiscovery,
            ))
            .unwrap();
        Self {
            options,
            ghost: Ghost::new(4),
        }
    }

    /// Append a PadN option to the vector of hop-by-hop options
    ///
    /// `&strg` so the caller keeps the updated length; an existential `&mut` would havoc it.
    #[flux_rs::trusted(yes, reason = "ghost update: the strong update does not survive the push")]
    #[flux_rs::sig(
        fn(self: &strg Repr[@r], n: u8) ensures self: Repr[r.blen + 2 + n]
    )]
    pub fn push_padn_option(&mut self, n: u8) {
        // Read before the push: `ghost_val` is indexed off `self`, and the push borrows a field
        // mutably, after which the place's index is no longer the one the postcondition names.
        let blen = self.ghost_val() + 2 + n as usize;
        self.options.push(Ipv6OptionRepr::PadN(n)).unwrap();
        self.ghost = Ghost::new(blen);
    }

    /// The accumulated emitted length, read back for `push_padn_option`'s update.
    #[flux_rs::trusted(yes, reason = "opaque ghost: reads the value back")]
    #[flux_rs::sig(fn(self: &Self[@r]) -> usize[r.blen])]
    #[flux_rs::no_panic]
    fn ghost_val(&self) -> usize {
        self.options.iter().map(|o| o.buffer_len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Error;

    // A Hop-by-Hop Option header with a PadN option of option data length 4.
    static REPR_PACKET_PAD4: [u8; 6] = [0x1, 0x4, 0x0, 0x0, 0x0, 0x0];

    // A Hop-by-Hop Option header with a PadN option of option data length 12.
    static REPR_PACKET_PAD12: [u8; 14] = [
        0x1, 0x0C, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    #[test]
    fn test_check_len() {
        // zero byte buffer
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&REPR_PACKET_PAD4[..0]).check_len()
        );
        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&REPR_PACKET_PAD4).check_len());
        // valid
        assert_eq!(
            Ok(()),
            Header::new_unchecked(&REPR_PACKET_PAD12).check_len()
        );
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&REPR_PACKET_PAD4);
        let repr = Repr::parse(&header).unwrap();

        let mut options = Vec::new();
        options.push(Ipv6OptionRepr::PadN(4)).unwrap();
        assert_eq!(repr, Repr { options });

        let header = Header::new_unchecked(&REPR_PACKET_PAD12);
        let repr = Repr::parse(&header).unwrap();

        let mut options = Vec::new();
        options.push(Ipv6OptionRepr::PadN(12)).unwrap();
        assert_eq!(repr, Repr { options });
    }

    #[test]
    fn test_repr_emit() {
        let mut options = Vec::new();
        options.push(Ipv6OptionRepr::PadN(4)).unwrap();
        let repr = Repr { options };

        let mut bytes = [0u8; 6];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);

        assert_eq!(header.into_inner(), &REPR_PACKET_PAD4[..]);

        let mut options = Vec::new();
        options.push(Ipv6OptionRepr::PadN(12)).unwrap();
        let repr = Repr { options };

        let mut bytes = [0u8; 14];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);

        assert_eq!(header.into_inner(), &REPR_PACKET_PAD12[..]);
    }
}
