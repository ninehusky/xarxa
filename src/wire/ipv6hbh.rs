use super::{Buf, Error, Ipv6Option, Ipv6OptionRepr, Ipv6OptionsIterator, Result};
use crate::config;
use crate::wire::ipv6option::RouterAlert;
use heapless::Vec;

/// A read/write wrapper around an IPv6 Hop-by-Hop Header buffer.
#[flux_rs::refined_by(buffer: T)]
pub struct Header<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Hop-by-Hop Header structure.
    #[flux_rs::sig(fn(T[@b]) -> Header<T>{h: h.buffer == b})]
    #[flux_rs::no_panic]
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

    /// The option window, as a [`Buf`] so its length survives the return.
    ///
    /// Same window as [`options_mut`](Self::options_mut). A returned `&mut [u8]` loses its
    /// length index (flux-rs/flux#1714), which is why the two slices in [`Repr::emit`] had
    /// nothing to bound themselves against. `Buf` carries the length in its own refinement.
    #[flux_rs::sig(fn(self: &mut Header<T>[@h]) -> Buf[<T as AsMut<[u8]>>::as_mut_reft(h.buffer)])]
    #[flux_rs::no_panic]
    pub fn options_buf(&mut self) -> Buf<'_> {
        Buf::new(self.buffer.as_mut())
    }
}

/// A cursor over a [`Repr`]'s options, carrying the octets its remaining options will emit.
///
/// [`Repr::emit`] writes each option into a window it reslices as it walks, so at every step it
/// owes `opt.buffer_len() <= window.len()`. That is a claim about the sum of the option list's
/// tail, and a sum over a `Vec` is not statable: the container carries no refinement to name, so
/// there is no term to put on the right-hand side of `blen == sum(options)`. The cursor states
/// the same claim one element at a time instead. `remaining` starts at the `Repr`'s `blen` and
/// [`Self::advance`] subtracts exactly the option just handed back, so [`Self::peek`]'s bound is
/// the [`Ghost`] argument unfolded rather than a second, larger assumption.
///
/// Private, and the only cursor in the module: `remaining` cannot be set by a caller, which is
/// what keeps [`Self::peek`]'s claim scoped. A free function taking a `Repr` and an option could
/// not say the option came *from* that `Repr` -- membership is the same missing refinement -- so
/// it would be asserting the bound for any pair, which is false.
#[flux_rs::refined_by(remaining: int)]
#[flux_rs::invariant(0 <= remaining && remaining <= 1028)]
struct OptionsCursor<'a, 'b> {
    opts: &'b [Ipv6OptionRepr<'a>],
    pos: usize,
    #[flux_rs::field(usize[remaining])]
    remaining: usize,
}

impl<'a, 'b> OptionsCursor<'a, 'b> {
    /// A cursor over `repr`'s options, owing every octet `repr` emits.
    #[flux_rs::sig(fn(&Repr[@r]) -> OptionsCursor[r.blen])]
    #[flux_rs::no_panic]
    fn new(repr: &'b Repr<'a>) -> Self {
        OptionsCursor {
            opts: repr.options(),
            pos: 0,
            remaining: repr.buffer_len(),
        }
    }

    /// The option at the cursor, if any.
    ///
    /// Trusted, and this is the whole container claim: `remaining` is the octets the options
    /// from `pos` onward emit, so the one at `pos` emits at most that many. Same statement
    /// [`Ghost`] rests on, restricted to a single element.
    #[flux_rs::trusted(yes, reason = "the container claim: `remaining` sums the untraversed tail")]
    #[flux_rs::sig(fn(&OptionsCursor[@c]) -> Option<&Ipv6OptionRepr{o: o.blen <= c.remaining}>)]
    #[flux_rs::no_panic]
    fn peek(&self) -> Option<&'b Ipv6OptionRepr<'a>> {
        self.opts.get(self.pos)
    }

    /// Step past `opt`, which [`Self::peek`] must have just returned.
    ///
    /// Not trusted: `remaining` is an ordinary `usize`, so the subtraction is checked, and the
    /// `requires` is exactly what rules out its underflow.
    #[flux_rs::sig(
        fn(self: &strg OptionsCursor[@c], &Ipv6OptionRepr[@o])
        requires o.blen <= c.remaining
        ensures self: OptionsCursor[c.remaining - o.blen]
    )]
    #[flux_rs::no_panic]
    fn advance(&mut self, opt: &Ipv6OptionRepr<'a>) {
        self.pos += 1;
        self.remaining -= opt.buffer_len();
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
// At most `config::IPV6_HBH_MAX_OPTIONS` options, each at most `Ipv6OptionRepr`'s 257, so the
// total fits in 1028. The ceiling is what keeps sums over this value from wrapping.
#[flux_rs::invariant(0 <= val && val <= 1028)]
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Ghost;

impl Ghost {
    /// A ghost pinned to `val`.
    #[flux_rs::trusted(yes, reason = "opaque: establishes the ghost value")]
    #[flux_rs::sig(fn(val: usize) -> Ghost[val])]
    #[flux_rs::no_panic]
    const fn new(_val: usize) -> Ghost {
        Ghost
    }

    /// A ghost whose value is unconstrained.
    ///
    /// For the paths where the emitted length is not a compile-time constant. The ghost holds
    /// no runtime value, so there is nothing to compute: the index comes from the signature of
    /// whoever produces the `Repr`, not from this call.
    #[flux_rs::trusted(yes, reason = "opaque: the ghost carries no runtime value")]
    #[flux_rs::sig(fn() -> Ghost{v: 0 <= v && v <= 1028})]
    #[flux_rs::no_panic]
    const fn unknown() -> Ghost {
        Ghost
    }
}

/// A high-level representation of an IPv6 Hop-by-Hop Header.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// Indexed by the octets `emit` writes, which is what a caller sizes the hop-by-hop window from.
#[flux_rs::refined_by(blen: int)]
#[flux_rs::invariant(0 <= blen && blen <= 1028)]
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

        for option in iter {
            let option = option?;

            if let Err(e) = options.push(option) {
                net_trace!("error when parsing hop-by-hop options: {}", e);
                break;
            }
        }

        // A parsed header's emitted length is not statically known, and no caller needs it to
        // be -- `buffer_len()` still reports it at runtime. Unconstrained rather than computed:
        // the ghost holds no runtime value, so an accumulator here would be dead arithmetic.
        Ok(Self {
            options,
            ghost: Ghost::unknown(),
        })
    }

    /// Build a header from a list of options.
    ///
    /// `options` is private, so this is how a caller outside the module makes one. The emitted
    /// length is left unconstrained; `buffer_len()` still reports it at runtime.
    pub fn new(options: Vec<Ipv6OptionRepr<'a>, { config::IPV6_HBH_MAX_OPTIONS }>) -> Self {
        Self {
            options,
            ghost: Ghost::unknown(),
        }
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
    ///
    /// `Header<T>` with `T: Sized` rather than `Header<&mut T>` with `T: ?Sized`, for the reason
    /// [`Header::options_mut`] gives: a reference self type has the unit sort, so `as_mut_reft`
    /// is not nameable there and the window bound below could not be written. Strictly widening
    /// -- `&mut T` is `Sized` and satisfies both bounds -- so existing callers still resolve, but
    /// they must pass a `Buf` to get a window length that is worth anything.
    #[flux_rs::sig(
        fn(&Repr[@r], header: &mut Header<T>[@h])
        requires r.blen <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        let mut buffer = header.options_buf();
        let mut cursor = OptionsCursor::new(self);

        // `remaining <= buffer.len()` is the loop invariant, and both sides fall by exactly
        // `n` each step. It holds on entry from this function's `requires`.
        while let Some(opt) = cursor.peek() {
            let n = opt.buffer_len();
            // Routed through `Buf` so the option window keeps its length: a bare `&mut [u8]`
            // instantiates core's blanket `AsMut for &mut T`, which carries no associated
            // refinement, and `Ipv6OptionRepr::emit`'s buffer bound would then abort this body.
            opt.emit(&mut Ipv6Option::new_unchecked(Buf::new(
                &mut buffer.as_mut()[..n],
            )));
            buffer.advance(n);
            cursor.advance(opt);
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
    /// Trusted, and this is the one unproved step in the ghost's argument. `Ipv6OptionRepr::PadN(n)`
    /// is indexed `2 + n`, so the `ensures` is what the push actually does; but a strong update
    /// cannot establish it here, because the mutable borrow of `options` invalidates the place's
    /// index before the ghost is reassigned. The assignment below is a no-op -- `Ghost` is a ZST --
    /// so the index comes from this signature, and its correctness rests on the sentence above.
    #[flux_rs::trusted(yes, reason = "ghost update: no strong update survives the borrow of `options`")]
    #[flux_rs::sig(
        fn(self: &strg Repr[@r], n: u8) ensures self: Repr[r.blen + 2 + n]
    )]
    pub fn push_padn_option(&mut self, n: u8) {
        self.options.push(Ipv6OptionRepr::PadN(n)).unwrap();
        self.ghost = Ghost::unknown();
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
        assert_eq!(repr, Repr::new(options));

        let header = Header::new_unchecked(&REPR_PACKET_PAD12);
        let repr = Repr::parse(&header).unwrap();

        let mut options = Vec::new();
        options.push(Ipv6OptionRepr::PadN(12)).unwrap();
        assert_eq!(repr, Repr::new(options));
    }

    #[test]
    fn test_repr_emit() {
        let mut options = Vec::new();
        options.push(Ipv6OptionRepr::PadN(4)).unwrap();
        let repr = Repr::new(options);

        let mut bytes = [0u8; 6];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);

        assert_eq!(header.into_inner(), &REPR_PACKET_PAD4[..]);

        let mut options = Vec::new();
        options.push(Ipv6OptionRepr::PadN(12)).unwrap();
        let repr = Repr::new(options);

        let mut bytes = [0u8; 14];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);

        assert_eq!(header.into_inner(), &REPR_PACKET_PAD12[..]);
    }
}
