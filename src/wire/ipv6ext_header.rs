#![allow(unused)]

use core::fmt;

use super::IpProtocol;
use super::{Error, Result};
use crate::wire::Ref;

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const MIN_HEADER_SIZE: usize = 8;

    pub const NXT_HDR: usize = 0;
    pub const LENGTH: usize = 1;
    // Variable-length field.
    //
    // Length of the header is in 8-octet units, not including the first 8 octets.
    // The first two octets are the next header type and the header length.
    pub const fn PAYLOAD(length_field: u8) -> Field {
        let bytes = length_field as usize * 8 + 8;
        2..bytes
    }
}

/// A ghost field: carries an integer in the refinement and nothing at runtime.
///
/// The payload window is `2..(length * 8 + 8)`, where `length` is the octet at offset 1 --
/// buffer *contents*, which are not in the refinement, so no accessor's bound can mention it.
/// This is the way to name it anyway. `Header` holds one of these, and because the struct is a
/// ZST it costs no space and `Header<T>`'s layout is unchanged.
///
/// The value is anchored by [`Header::header_len`], the trusted getter that claims the octet
/// equals the ghost. Everything else is proved.
#[flux_rs::opaque]
#[flux_rs::refined_by(val: int)]
#[flux_rs::invariant(0 <= val && val <= 255)]
#[derive(PartialEq, Eq, Clone, Copy)]
struct Ghost;

impl Ghost {
    /// A ghost whose value is unconstrained.
    ///
    /// The bound is the `u8` range and nothing more, which is all a buffer nobody has written
    /// or checked supports.
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

/// A read/write wrapper around an IPv6 Extension Header buffer.
///
/// # Why the ghost is sound
///
/// [`header_len`](Header::header_len) claims the octet at offset 1 equals `hlen`. That claim
/// survives because every way the octet or the ghost can change keeps the two together, by
/// enumeration over this file:
///
/// * `new_unchecked` is the only `Header { .. }` literal, and it leaves the ghost unconstrained,
///   so it claims nothing about a buffer it has not read.
/// * `set_header_len` is the only writer of offset 1, and it assigns the ghost in the same body.
/// * `set_next_header` writes offset 0 only; `payload`/`payload_mut` hand out a window starting
///   at offset 2, so neither can reach offset 1 through the returned slice.
/// * `into_inner` consumes the header, and there is no `AsMut for Header<T>`, so the buffer is
///   not otherwise reachable.
#[derive(PartialEq, Eq)]
#[flux_rs::refined_by(buffer: T, hlen: int)]
#[flux_rs::invariant(0 <= hlen && hlen <= 255)]
pub struct Header<T: AsRef<[u8]>> {
    #[flux_rs::field(T[buffer])]
    buffer: T,
    #[flux_rs::field(Ghost[hlen])]
    ghlen: Ghost,
}

// Written out rather than derived so the ghost stays out of the output: a derive would print
// `Header { buffer: .., ghlen: Ghost }`, and the ghost is not supposed to be observable. Both
// impls reproduce the derived form for the one field that existed before.
impl<T: AsRef<[u8]> + fmt::Debug> fmt::Debug for Header<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("buffer", &self.buffer)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<T: AsRef<[u8]> + defmt::Format> defmt::Format for Header<T> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "Header {{ buffer: {} }}", self.buffer)
    }
}

/// Core getter methods relevant to any IPv6 extension header.
impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Extension Header structure.
    ///
    /// The ghost starts unconstrained: this reads nothing, so it learns nothing. It is pinned to
    /// the length octet the first time [`header_len`](Self::header_len) is called.
    #[flux_rs::sig(fn(T[@b]) -> Header<T>{h: h.buffer == b})]
    #[flux_rs::no_panic]
    pub const fn new_unchecked(buffer: T) -> Self {
        Header {
            buffer,
            ghlen: Ghost::unknown(),
        }
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
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(fn(self: &Header<T>[@h]) -> Result<()>)]
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
    /// for it. Returning the length lets the `Ok` arm say what the four fixed-offset accessors
    /// below want: what the buffer's length is, and that it reaches the end of the fixed header.
    ///
    /// Both of its tests are stated. The second compares the length against the payload window,
    /// whose extent comes from the buffer's *contents*; it is nameable only because the ghost
    /// carries the length octet, and it is exactly `payload_mut`'s second precondition.
    ///
    /// The length is nameable only where `T` is not a reference -- a reference in
    /// type-parameter position has the unit sort. [`Ref`] is that `T`, and the two consumers are
    /// [`new_checked_ref`](Header::new_checked_ref) and [`Repr::parse_ref`].
    #[flux_rs::trusted(no, reason = "spec needed to prove `new_checked` is correct")]
    #[flux_rs::sig(
        fn(self: &Header<T>[@h])
            -> Result<usize{v: v == <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
                            && 8 <= v
                            && h.hlen * 8 + 8 <= v}>
    )]
    #[flux_rs::no_panic]
    fn checked_len(&self) -> Result<usize> {
        let len = self.buffer.as_ref().len();
        if len < field::MIN_HEADER_SIZE {
            return Err(Error);
        }

        // `field::PAYLOAD(self.header_len()).end`, written out: flux cannot see through the
        // `Field` (`Range`) const. Same value, and reading the octet through `header_len` is
        // what ties the test to the ghost.
        let end = self.header_len() as usize * 8 + 8;
        if len < end {
            return Err(Error);
        }

        Ok(len)
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the next header field.
    //
    // Body stays bounds-checked. The `requires` states the bound, but it cannot be discharged
    // unchecked yet: the only in-crate caller is `Repr::parse` below, which is over
    // `Header<&T>`, and at a reference self type the length index would have to come from
    // core's blanket `impl AsRef for &T`, which carries no associated refinement. Indexing
    // unchecked here would trade a panic for an out-of-bounds read rather than prove the panic
    // away (#16).
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Header<T>[@h]) -> IpProtocol
        requires 1 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn next_header(&self) -> IpProtocol {
        let data = self.buffer.as_ref();
        IpProtocol::from(data[field::NXT_HDR])
    }

    /// Return the header length field.
    ///
    /// The ghost's anchor. `trusted(yes)` claims exactly one thing -- that the octet at offset 1
    /// *is* the ghost value -- which flux cannot see, because it does not track buffer contents.
    /// It assumes no index: the body is a bare call to [`header_len_field`](Self::header_len_field),
    /// which is checked and discharges the read's bound itself.
    #[flux_rs::trusted(yes, reason = "anchors the ghost: the length octet is the ghost value")]
    #[flux_rs::sig(
        fn(&Header<T>[@h]) -> u8[h.hlen]
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    pub fn header_len(&self) -> u8 {
        self.header_len_field()
    }

    /// The raw length octet, with its read bounds-checked and proved.
    #[flux_rs::trusted(no, reason = "panic site: reads the header at a fixed offset")]
    #[flux_rs::sig(
        fn(&Header<T>[@h]) -> u8
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    fn header_len_field(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::LENGTH]
    }
}

impl<'h> Header<Ref<'h>> {
    /// [`new_checked`](Self::new_checked) over a [`Ref`], carrying its proof out.
    ///
    /// The generic `new_checked` cannot say this: at a reference or `dyn` self type the
    /// `as_ref_reft` in the postcondition is unstatable. Over `Ref` the buffer's length is
    /// `b.len`, and the two facts `checked_len` already proves are what
    /// [`payload`](Self::payload) requires.
    #[flux_rs::trusted(no, reason = "carries `checked_len`'s proof out through the `Ok` arm")]
    #[flux_rs::sig(
        fn(Ref[@b]) -> Result<Header<Ref>{h: h.buffer == b && 8 <= b.len
                                             && 8 * h.hlen + 8 <= b.len}>
    )]
    pub fn new_checked_ref(buffer: Ref<'h>) -> Result<Header<Ref<'h>>> {
        let header = Header::new_unchecked(buffer);
        header.checked_len()?;
        Ok(header)
    }

    /// Return the payload of the IPv6 extension header.
    ///
    /// The `Header<&'h T>` twin of this was doubly blocked: the ghost bounds the window's
    /// extent, but it is `as_ref_reft` that bounds the buffer, and at a reference self type
    /// there is none to name. Over `Ref<'h>` the buffer's length is `h.buffer.len`, the far end
    /// is the ghost scaled, and the payload's length survives into the caller's index.
    /// `payload_mut` below is the same window on the write side.
    #[flux_rs::trusted(no, reason = "panic site: opens the payload window")]
    #[flux_rs::sig(
        fn(&Header<Ref>[@h]) -> &[u8][8 * h.hlen + 6]
        requires 8 * h.hlen + 8 <= h.buffer.len
    )]
    #[flux_rs::no_panic]
    pub fn payload(&self) -> &'h [u8] {
        // `field::PAYLOAD(len)` is `2..len * 8 + 8`.
        self.buffer.window(2, self.header_len() as usize * 8 + 8)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the next header field.
    ///
    /// The `requires` is an *exposed* obligation: this is `pub`, so a consumer outside the crate
    /// owes the bound and is assumed to have been checked for it. The body keeps its bounds
    /// check, so an unchecked consumer still gets the panic rather than an out-of-bounds write.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h], value: IpProtocol)
        requires 1 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR] = value.into();
    }

    /// Set the extension header data length. The length of the header is
    /// in 8-octet units, not including the first 8 octets.
    ///
    /// The `requires` is an exposed obligation; see [`set_next_header`](Self::set_next_header).
    ///
    /// Writes the ghost as well as the octet. This is the whole of what keeps
    /// [`header_len`](Self::header_len)'s claim true, so the two must not drift apart. `&strg`
    /// rather than `&mut` because a `&mut T{v: ..}` weakening does not compose through a call
    /// chain, and a caller needs the new value to survive into `payload_mut` after it.
    #[flux_rs::trusted(no, reason = "panic site: writes the header at a fixed offset")]
    #[flux_rs::sig(
        fn(self: &strg Header<T>[@h], value: u8)
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
        ensures self: Header<T>[h.buffer, value]
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::LENGTH] = value;
        self.ghlen = Ghost::new(value);
    }

    /// Return a mutable pointer to the payload data.
    ///
    /// Moved here from an `impl Header<&mut T>`: at a reference self type the length index would
    /// have to come from core's blanket `AsMut for &mut T`, which carries no associated
    /// refinement, so the bound could not be stated at all. `Header<&mut U>` still reaches this
    /// method, since `&mut U: AsRef<[u8]> + AsMut<[u8]>`, and the returned borrow is tied to
    /// `&mut self` exactly as before.
    ///
    /// `2 <= as_ref_reft` is what [`header_len`](Self::header_len) needs; the second conjunct is
    /// the window. Both are *exposed* obligations: this is `pub`, so a consumer outside the
    /// crate owes them and is assumed to have been checked for them. The body keeps its bounds
    /// check, so an unchecked consumer still gets the panic.
    #[flux_rs::trusted(no, reason = "panic site: opens the payload window at the header length")]
    #[flux_rs::sig(
        fn(self: &mut Header<T>[@h]) -> &mut [u8]
        requires 2 <= <T as AsRef<[u8]>>::as_ref_reft(h.buffer)
              && h.hlen * 8 + 8 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
    )]
    #[flux_rs::no_panic]
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // Literal bounds rather than `field::PAYLOAD(len)`: flux cannot see through the `Field`
        // (`Range`) const, so the window has to be written out. Same value.
        let len = self.header_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[2..(len * 8 + 8)] // field::PAYLOAD(len)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr<'a> {
    pub next_header: IpProtocol,
    pub length: u8,
    pub data: &'a [u8],
}

impl<'a> Repr<'a> {
    /// Parse an IPv6 Extension Header Header and return a high-level representation.
    ///
    /// A reference in type-parameter position has the unit sort, so no bound on `T`'s buffer is
    /// statable here and neither the header reads nor the payload window would be provable. The
    /// body lives on [`parse_ref`](Self::parse_ref), over a buffer whose length is nameable;
    /// this re-wraps the same bytes and forwards, which repeats no work the old body did not do.
    pub fn parse<T>(header: &Header<&'a T>) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Repr::parse_ref(&Header::new_unchecked(Ref::new(header.buffer.as_ref())))
    }

    /// [`parse`](Self::parse) over a [`Ref`], where the buffer's length is in the refinement.
    ///
    /// `checked_len` rather than `check_len`: the same test, but its `Ok` arm names both facts
    /// the three reads below need -- that the buffer holds the fixed header, and that the
    /// payload window the length octet declares fits inside it.
    pub fn parse_ref(header: &Header<Ref<'a>>) -> Result<Self> {
        header.checked_len()?;
        Ok(Self {
            next_header: header.next_header(),
            length: header.header_len(),
            data: header.payload(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    // The 2 is `field::MIN_HEADER_SIZE`; stated as an index so callers can relate the octets
    // this writes to the buffer they were handed. `iface::packet`'s hop-by-hop arm needs it to
    // place the options that follow.
    #[flux_rs::trusted(no, reason = "2 is the constant the hop-by-hop layout rests on")]
    #[flux_rs::sig(fn(self: &Self) -> usize[2])]
    #[flux_rs::no_panic]
    pub const fn header_len(&self) -> usize {
        2
    }

    /// Emit a high-level representation into an IPv6 Extension Header.
    // The buffer parameter is `Header<T>` with `T: Sized`, not `Header<&mut T>` with `T: ?Sized`.
    // The old shape instantiated core's blanket `impl<T, U> AsMut<U> for &mut T`, which carries no
    // associated refinement, so naming `as_mut_reft` for the setters below raised `associated
    // refinement 'as_mut_reft' is missing from implementation` -- a spec error, which aborts the
    // whole body. The `Sized` form lets a caller pass `wire::Buf`, whose `AsMut` impl is local and
    // refined; `&mut [u8]` still satisfies the bounds, so this is strictly more permissive.
    //
    // `header` is `&strg` because `set_header_len` is: it writes the `hlen` ghost, and a caller
    // that reads `header_len` afterwards needs the new value to survive the call.
    //
    // 2 is `header_len()`, i.e. `field::MIN_HEADER_SIZE`, and is the reach of `set_header_len`.
    #[flux_rs::sig(
        fn(&Repr, header: &strg Header<T>[@h])
        requires 2 <= <T as AsMut<[u8]>>::as_mut_reft(h.buffer)
        ensures header: Header<T>{v: v.buffer == h.buffer}
    )]
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_next_header(self.next_header);
        header.set_header_len(self.length);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A Hop-by-Hop Option header with a PadN option of option data length 4.
    static REPR_PACKET_PAD4: [u8; 8] = [0x6, 0x0, 0x1, 0x4, 0x0, 0x0, 0x0, 0x0];

    // A Hop-by-Hop Option header with a PadN option of option data length 12.
    static REPR_PACKET_PAD12: [u8; 16] = [
        0x06, 0x1, 0x1, 0x0C, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    #[test]
    fn test_check_len() {
        // zero byte buffer
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&REPR_PACKET_PAD4[..0]).check_len()
        );
        // no length field
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&REPR_PACKET_PAD4[..1]).check_len()
        );
        // less than 8 bytes
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&REPR_PACKET_PAD4[..7]).check_len()
        );
        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&REPR_PACKET_PAD4).check_len());
        // valid
        assert_eq!(
            Ok(()),
            Header::new_unchecked(&REPR_PACKET_PAD12).check_len()
        );
        // length field value greater than number of bytes
        let header: [u8; 8] = [0x06, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        assert_eq!(Err(Error), Header::new_unchecked(&header).check_len());
    }

    #[test]
    fn ghost_field_is_not_observable() {
        let header = Header::new_unchecked(&REPR_PACKET_PAD4[..]);
        let s = format!("{header:?}");
        assert!(!s.contains("Ghost"), "ghost leaked into Debug: {s}");
        assert!(s.starts_with("Header { buffer: "), "Debug shape changed: {s}");
    }

    /// Pins the one writer the ghost's soundness argument rests on: `set_header_len` is the only
    /// path that changes the octet at offset 1, and `set_next_header` must leave it alone.
    #[test]
    fn set_next_header_preserves_header_len() {
        let mut bytes = REPR_PACKET_PAD12;
        let mut header = Header::new_unchecked(&mut bytes[..]);
        header.set_header_len(1);
        header.set_next_header(IpProtocol::Udp);
        assert_eq!(header.header_len(), 1);
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(Ref::new(&REPR_PACKET_PAD4[..]));
        assert_eq!(header.next_header(), IpProtocol::Tcp);
        assert_eq!(header.header_len(), 0);
        assert_eq!(header.payload(), &REPR_PACKET_PAD4[2..]);

        let header = Header::new_unchecked(Ref::new(&REPR_PACKET_PAD12[..]));
        assert_eq!(header.next_header(), IpProtocol::Tcp);
        assert_eq!(header.header_len(), 1);
        assert_eq!(header.payload(), &REPR_PACKET_PAD12[2..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD4[..]);
        bytes.push(0);

        assert_eq!(
            Header::new_unchecked(Ref::new(&bytes[..])).payload().len(),
            REPR_PACKET_PAD4[2..].len()
        );
        assert_eq!(
            Header::new_unchecked(&mut bytes).payload_mut().len(),
            REPR_PACKET_PAD4[2..].len()
        );

        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_PAD12[..]);
        bytes.push(0);

        assert_eq!(
            Header::new_unchecked(Ref::new(&bytes[..])).payload().len(),
            REPR_PACKET_PAD12[2..].len()
        );
        assert_eq!(
            Header::new_unchecked(&mut bytes).payload_mut().len(),
            REPR_PACKET_PAD12[2..].len()
        );
    }

    #[test]
    fn test_header_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(REPR_PACKET_PAD4);
        let len = bytes.len() as u8;
        Header::new_unchecked(&mut bytes).set_header_len(len + 1);

        assert_eq!(Header::new_checked(&bytes).unwrap_err(), Error);

        let mut bytes = vec![];
        bytes.extend(REPR_PACKET_PAD12);
        let len = bytes.len() as u8;
        Header::new_unchecked(&mut bytes).set_header_len(len + 1);

        assert_eq!(Header::new_checked(&bytes).unwrap_err(), Error);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&REPR_PACKET_PAD4);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                next_header: IpProtocol::Tcp,
                length: 0,
                data: &REPR_PACKET_PAD4[2..]
            }
        );

        let header = Header::new_unchecked(&REPR_PACKET_PAD12);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                next_header: IpProtocol::Tcp,
                length: 1,
                data: &REPR_PACKET_PAD12[2..]
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            next_header: IpProtocol::Tcp,
            length: 0,
            data: &REPR_PACKET_PAD4[2..],
        };
        let mut bytes = [0u8; 2];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &REPR_PACKET_PAD4[..2]);

        let repr = Repr {
            next_header: IpProtocol::Tcp,
            length: 1,
            data: &REPR_PACKET_PAD12[2..],
        };
        let mut bytes = [0u8; 2];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &REPR_PACKET_PAD12[..2]);
    }
}
