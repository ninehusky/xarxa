use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use crate::iface::Context;
use crate::phy::PacketMeta;
use crate::socket::PollAt;
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;
use crate::storage::{Empty, Full};
use crate::wire::{IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, IpRepr, UdpRepr};

/// Metadata for a sent or received UDP packet.
///
/// Refined by the destination's IP version. `local_address`, when set, is constrained to that
/// same version: a source and destination of different versions cannot form an IP packet.
/// See [`Socket`] for the obligation this helps discharge.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[flux_rs::refined_by(dst_ty: int)]
pub struct UdpMetadata {
    /// The IP endpoint from which an incoming datagram was received, or to which an outgoing
    /// datagram will be sent.
    #[flux_rs::field(IpEndpoint[dst_ty])]
    pub endpoint: IpEndpoint,
    /// The IP address to which an incoming datagram was sent, or from which an outgoing datagram
    /// will be sent. Incoming datagrams always have this set. On outgoing datagrams, if it is not
    /// set, and the socket is not bound to a single address anyway, a suitable address will be
    /// determined using the algorithms of RFC 6724 (candidate source address selection) or some
    /// heuristic (for IPv4).
    #[flux_rs::field(Option<IpAddress{v : v == dst_ty}>)]
    pub local_address: Option<IpAddress>,
    pub meta: PacketMeta,
}

impl<T: Into<IpEndpoint>> From<T> for UdpMetadata {
    #[flux_rs::trusted(no, reason = "establishes UdpMetadata's version invariant")]
    fn from(value: T) -> Self {
        Self {
            endpoint: value.into(),
            local_address: None,
            meta: PacketMeta::default(),
        }
    }
}

impl core::fmt::Display for UdpMetadata {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "packetmeta-id")]
        return write!(f, "{}, PacketID: {:?}", self.endpoint, self.meta);

        #[cfg(not(feature = "packetmeta-id"))]
        write!(f, "{}", self.endpoint)
    }
}

/// A UDP packet metadata.
pub type PacketMetadata = crate::storage::PacketMetadata<UdpMetadata>;

/// A UDP packet ring buffer.
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, UdpMetadata>;

/// Error returned by [`Socket::bind`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BindError {
    InvalidState,
    Unaddressable,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    Unaddressable,
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecvError {
    Exhausted,
    Truncated,
}

impl core::fmt::Display for RecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl core::error::Error for RecvError {}

/// A User Datagram Protocol socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
///
/// Refined by the IP version of the address the socket is bound to, or `-1` for a bare port.
///
/// Two facts together discharge `IpRepr::new`'s precondition — that its source and
/// destination addresses are the same IP version — where `dispatch` calls it:
///
/// 1. **Here, on `tx_buffer`:** a socket bound to a specific address only ever has queued
///    datagrams of that version. Vacuous at `-1`, which is what keeps a bare-port socket
///    dual-stack rather than pinning it to whichever family it happens to send first.
/// 2. **On [`UdpMetadata`]:** a datagram's `local_address`, when set, is the same version as
///    that same datagram's destination.
///
/// `dispatch` takes the source address from `local_address` if set (fact 2), else from the
/// socket's bound address (fact 1), else from `Context::get_source_address`, which returns
/// an address of the destination's version by construction.
///
/// `rx_buffer` is deliberately unconstrained — incoming metadata carries the *remote*
/// endpoint, which has no relation to what we bound to.
#[derive(Debug)]
#[flux_rs::refined_by(addr_ty: int)]
pub struct Socket<'a> {
    #[flux_rs::field(IpListenEndpoint[addr_ty])]
    endpoint: IpListenEndpoint,
    rx_buffer: PacketBuffer<'a>,
    #[flux_rs::field(crate::storage::PacketBuffer<UdpMetadata{m: addr_ty == -1 || m.dst_ty == addr_ty}>)]
    tx_buffer: PacketBuffer<'a>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

/// `PacketBuffer::dequeue_with`, with the header hidden from the callback.
///
/// Trusted, for a narrow reason. Flux instantiates `dequeue_with`'s `H` from the Rust type,
/// which erases the buffer's element predicate — `H` appears under `&mut` inside the
/// `FnOnce` bound, and `&mut` is invariant in the refinement index. (`peek` and `dequeue`,
/// where `H` is behind `&` or returned by value, keep it fine.) Since `f` here never
/// receives the header, it cannot observe or modify it, and `dequeue_with` only removes
/// packets — so every remaining element still satisfies whatever predicate it arrived with.
/// The `65527` on the callback's buffer is `Socket::send`'s bound, carried across the ring.
/// `send` is the only path that enqueues into a transmit buffer -- one `enqueue` call, at the
/// site above -- so every payload the ring can yield came through it. `PacketBuffer` cannot
/// state this itself: `RingBuffer` does not index its elements, so a per-element length is not
/// reachable through the container.
#[flux_rs::trusted(reason = "dequeue_with's H erases the element predicate; f cannot touch the header")]
#[flux_rs::sig(fn(IpListenEndpoint[@t],
                  &mut crate::storage::PacketBuffer<UdpMetadata{m: t == -1 || m.dst_ty == t}>,
                  F) -> Result<Result<R, E>, Empty>
               where F: FnOnce(&mut [u8]{v: v <= 65527}) -> Result<R, E>)]
fn dequeue_payload<'c, R, E, F>(
    _endpoint: IpListenEndpoint,
    buf: &'c mut PacketBuffer<'_>,
    f: F,
) -> Result<Result<R, E>, Empty>
where
    F: FnOnce(&'c mut [u8]) -> Result<R, E>,
{
    buf.dequeue_with(|_header, payload_buf| f(payload_buf))
}

/// Empty a transmit buffer and re-type its elements for `endpoint`.
///
/// Trusted because `&mut` is invariant in the refinement index, so the element predicate
/// cannot be changed by subtyping even when the buffer is empty and every predicate holds
/// vacuously. `reset` clears the ring, which is what makes the `ensures` sound for any `t`.
/// Passing the endpoint by value is how `t` gets value-determined.
#[flux_rs::trusted(reason = "reset empties the buffer; any element predicate then holds vacuously")]
#[flux_rs::sig(fn(buf: &strg crate::storage::PacketBuffer<UdpMetadata{m: o == -1 || m.dst_ty == o}>,
                  IpListenEndpoint[@o],
                  IpListenEndpoint[@t])
                 ensures buf: crate::storage::PacketBuffer<UdpMetadata{m: t == -1 || m.dst_ty == t}>)]
fn reset_tx_buffer(buf: &mut PacketBuffer<'_>, _old: IpListenEndpoint, _new: IpListenEndpoint) {
    buf.reset();
}

/// `PacketBuffer::enqueue_with_infallible`, with the header hidden from the callback.
///
/// Same reason as [`dequeue_payload`]: the generic `F` makes Flux instantiate `H` from the
/// Rust type, erasing the element predicate. The header goes in by value and `f` only ever
/// sees the payload, so the predicate the caller proves for `meta` is the one the buffer ends
/// up holding.
#[flux_rs::trusted(reason = "enqueue_with_infallible's H erases the element predicate; f cannot touch the header")]
#[flux_rs::sig(fn(IpListenEndpoint[@t],
                  &mut crate::storage::PacketBuffer<UdpMetadata{m: t == -1 || m.dst_ty == t}>,
                  usize,
                  UdpMetadata{m: t == -1 || m.dst_ty == t},
                  F) -> Result<usize, Full>)]
fn enqueue_payload<F>(
    _endpoint: IpListenEndpoint,
    buf: &mut PacketBuffer<'_>,
    max_size: usize,
    meta: UdpMetadata,
    f: F,
) -> Result<usize, Full>
where
    F: FnOnce(&mut [u8]) -> usize,
{
    buf.enqueue_with_infallible(max_size, meta, f)
}




impl<'a> Socket<'a> {
    /// Create an UDP socket with the given buffers.
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn new(rx_buffer: PacketBuffer<'a>, tx_buffer: PacketBuffer<'a>) -> Socket<'a> {
        Socket {
            endpoint: IpListenEndpoint::unspecified(),
            rx_buffer,
            tx_buffer,
            hop_limit: None,
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpListenEndpoint {
        self.endpoint
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Bind the socket to the given endpoint.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    #[flux_rs::sig(fn(self: &strg Socket[@old], IpListenEndpoint[@y]) -> Result<(), BindError>
                     ensures self: Socket{v: v == old || v == y})]
    pub fn bind(&mut self, endpoint: IpListenEndpoint) -> Result<(), BindError> {
        if endpoint.port() == 0 {
            return Err(BindError::Unaddressable);
        }

        if self.is_open() {
            return Err(BindError::InvalidState);
        }

        // No-op at runtime: enqueueing requires an open socket and re-binding requires
        // `close`, which resets, so the buffer is already empty here. Flux cannot see that,
        // and binding re-indexes the socket, so the reset is what licenses the new type.
        let old = self.endpoint;
        reset_tx_buffer(&mut self.tx_buffer, old, endpoint);
        self.endpoint = endpoint;

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }

        Ok(())
    }

    /// Close the socket.
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    #[flux_rs::sig(fn(self: &strg Socket) ensures self: Socket[-1])]
    pub fn close(&mut self) {
        // Clear the bound endpoint of the socket.
        let old = self.endpoint;
        let endpoint = IpListenEndpoint::unspecified();
        reset_tx_buffer(&mut self.tx_buffer, old, endpoint);
        self.endpoint = endpoint;

        self.rx_buffer.reset();

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    /// Check whether the socket is open.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.endpoint.port() != 0
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Return the maximum number packets the socket can receive.
    #[inline]
    pub fn packet_recv_capacity(&self) -> usize {
        self.rx_buffer.packet_capacity()
    }

    /// Return the maximum number packets the socket can transmit.
    #[inline]
    pub fn packet_send_capacity(&self) -> usize {
        self.tx_buffer.packet_capacity()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn payload_recv_capacity(&self) -> usize {
        self.rx_buffer.payload_capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn payload_send_capacity(&self) -> usize {
        self.tx_buffer.payload_capacity()
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// `Err(Error::Unaddressable)` if local or remote port, or remote address are unspecified,
    /// and `Err(Error::Truncated)` if there is not enough transmit buffer capacity
    /// to ever send this packet.
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    /// `n <= 65527` is `65535 - 8`, the largest payload a UDP length field can describe.
    /// **This is an exposed obligation**: xarxa does not check it, and `emit_ports_and_len`
    /// truncates via `as u16` if it is violated, so a larger datagram would go out with a wrong
    /// length. Stating it here makes the caller responsible rather than leaving the bound owed
    /// by nobody. See the ledger entry for the underlying defect.
    #[flux_rs::sig(fn(self: &mut Socket[@t], usize[@n],
                      UdpMetadata{m: t == -1 || m.dst_ty == t})
                     -> Result<&mut [u8][n], SendError>
                     requires n <= 65527)]
    pub fn send(
        &mut self,
        size: usize,
        meta: UdpMetadata,
    ) -> Result<&mut [u8], SendError> {
        if self.endpoint.port() == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.addr.is_unspecified() {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }

        let payload_buf = self
            .tx_buffer
            .enqueue(size, meta)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "udp:{}:{}: buffer to send {} octets",
            self.endpoint,
            meta.endpoint,
            size
        );
        Ok(payload_buf)
    }

    /// Enqueue a packet to be send to a given remote endpoint and pass the buffer
    /// to the provided closure. The closure then returns the size of the data written
    /// into the buffer.
    ///
    /// Also see [send](#method.send).
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    #[flux_rs::sig(fn(self: &mut Socket[@t], usize, UdpMetadata{m: t == -1 || m.dst_ty == t}, F)
                     -> Result<usize, SendError>)]
    pub fn send_with<F>(
        &mut self,
        max_size: usize,
        meta: UdpMetadata,
        f: F,
    ) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        if self.endpoint.port() == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.addr.is_unspecified() {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }

        let endpoint = self.endpoint;
        let size = enqueue_payload(endpoint, &mut self.tx_buffer, max_size, meta, f)
            .map_err(|_| SendError::BufferFull)?;

        net_trace!(
            "udp:{}:{}: buffer to send {} octets",
            self.endpoint,
            meta.endpoint,
            size
        );
        Ok(size)
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    /// `k <= 65527` is [`Socket::send`]'s bound, which this forwards to; see it for why the
    /// obligation is the caller's.
    #[flux_rs::sig(fn(self: &mut Socket[@t], &[u8][@k], UdpMetadata{m: t == -1 || m.dst_ty == t})
                     -> Result<(), SendError>
                     requires k <= 65527)]
    pub fn send_slice(
        &mut self,
        data: &[u8],
        meta: UdpMetadata,
    ) -> Result<(), SendError> {
        self.send(data.len(), meta)?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn recv(&mut self) -> Result<(&[u8], UdpMetadata), RecvError> {
        let (remote_endpoint, payload_buf) =
            self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "udp:{}:{}: receive {} buffered octets",
            self.endpoint,
            remote_endpoint.endpoint,
            payload_buf.len()
        );
        Ok((payload_buf, remote_endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the endpoint.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// the packet is dropped and a `RecvError::Truncated` error is returned.
    ///
    /// See also [recv](#method.recv).
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, UdpMetadata), RecvError> {
        let (buffer, endpoint) = self.recv().map_err(|_| RecvError::Exhausted)?;

        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    /// Peek at a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn peek(&mut self) -> Result<(&[u8], &UdpMetadata), RecvError> {
        let endpoint = self.endpoint;
        self.rx_buffer.peek().map_err(|_| RecvError::Exhausted).map(
            |(remote_endpoint, payload_buf)| {
                net_trace!(
                    "udp:{}:{}: peek {} buffered octets",
                    endpoint,
                    remote_endpoint.endpoint,
                    payload_buf.len()
                );
                (payload_buf, remote_endpoint)
            },
        )
    }

    /// Peek at a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the endpoint without removing the
    /// packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// no data is copied into the provided buffer and a `RecvError::Truncated` error is returned.
    ///
    /// See also [peek](#method.peek).
    #[flux_rs::trusted(no, reason = "checking Socket invariant")]
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<(usize, &UdpMetadata), RecvError> {
        let (buffer, endpoint) = self.peek()?;

        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.payload_bytes_count()
    }

    /// Return the amount of octets queued in the receive buffer. This value can be larger than
    /// the slice read by the next `recv` or `peek` call because it includes all queued octets,
    /// and not only the octets that may be returned as a contiguous slice.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.payload_bytes_count()
    }

    pub(crate) fn accepts(&self, cx: &mut Context, ip_repr: &IpRepr, repr: &UdpRepr) -> bool {
        if self.endpoint.port() != repr.dst_port {
            return false;
        }
        if self.endpoint.has_addr()
            && self.endpoint.addr() != Some(ip_repr.dst_addr())
            && !cx.is_broadcast(&ip_repr.dst_addr())
            && !ip_repr.dst_addr().is_multicast()
        {
            return false;
        }

        true
    }

    #[flux_rs::trusted(no, reason = "establishes UdpMetadata's version invariant")]
    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        meta: PacketMeta,
        ip_repr: &IpRepr,
        repr: &UdpRepr,
        payload: &[u8],
    ) {
        debug_assert!(self.accepts(cx, ip_repr, repr));

        let size = payload.len();

        let remote_endpoint = IpEndpoint {
            addr: ip_repr.src_addr(),
            port: repr.src_port,
        };

        net_trace!(
            "udp:{}:{}: receiving {} octets",
            self.endpoint,
            remote_endpoint,
            size
        );

        let metadata = UdpMetadata {
            endpoint: remote_endpoint,
            local_address: Some(ip_repr.dst_addr()),
            meta,
        };

        match self.rx_buffer.enqueue(size, metadata) {
            Ok(buf) => buf.copy_from_slice(payload),
            Err(_) => net_trace!(
                "udp:{}:{}: buffer full, dropped incoming packet",
                self.endpoint,
                remote_endpoint
            ),
        }

        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }

    #[flux_rs::trusted(no, reason = "calls IpRepr::new")]
    #[flux_rs::sig(
        fn(self: &mut Socket[@t], &mut Context, F) -> Result<(), E>
        where F: FnOnce(&mut Context, PacketMeta, (IpRepr[@ipr], UdpRepr, &[u8]{v: ipr.plen == 8 + v})) -> Result<(), E>
    )]
    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, PacketMeta, (IpRepr, UdpRepr, &[u8])) -> Result<(), E>,
    {
        let endpoint = self.endpoint;
        let hop_limit = self.hop_limit.unwrap_or(64);

        // The source-address choice is done out here, off a `peek`, rather than inside
        // `dequeue_with`'s closure. `dequeue_with` hands the closure `&mut H`, and Flux
        // erases the buffer's element predicate through `&mut` in a higher-order position;
        // `peek` yields `&H` and keeps it. `UdpMetadata` is `Copy`, so the whole record is
        // copied out — copying the two fields separately would lose the relation between
        // `local_address` and `endpoint` that the metadata's own invariant provides.
        //
        // Only the addresses move out. The payload length stays inside the closure:
        // `peek`'s slice is clamped at the ring wrap and can be shorter than the packet.
        let packet_meta = match self.tx_buffer.peek() {
            Ok((packet_meta, _)) => *packet_meta,
            Err(Empty) => return Ok(()),
        };

        let src_addr = if let Some(s) = packet_meta.local_address {
            s
        } else {
            match endpoint.addr() {
                Some(addr) => addr,
                None => match cx.get_source_address(&packet_meta.endpoint.addr) {
                    Some(addr) => addr,
                    None => {
                        net_trace!(
                            "udp:{}:{}: cannot find suitable source address, dropping.",
                            endpoint,
                            packet_meta.endpoint
                        );
                        // Consume the packet, as returning `Ok` from the closure used to.
                        let _ = self.tx_buffer.dequeue();
                        #[cfg(feature = "async")]
                        self.tx_waker.wake();
                        return Ok(());
                    }
                },
            }
        };

        let repr = UdpRepr {
            src_port: endpoint.port(),
            dst_port: packet_meta.endpoint.port,
        };

        // Built here, where `src_addr` and the destination are both in scope and their
        // versions are known to agree — that agreement is `IpRepr::new`'s precondition and
        // it does not survive into the closure. The length is a placeholder; the true one
        // is only known once the payload is dequeued, and `payload_len` is not part of
        // `IpRepr`'s refinement, so setting it below preserves the version index.
        let mut ip_repr = IpRepr::new(
            src_addr,
            packet_meta.endpoint.addr,
            IpProtocol::Udp,
            0,
            hop_limit,
        );

        let res = dequeue_payload(endpoint, &mut self.tx_buffer, move |payload_buf| {
            net_trace!(
                "udp:{}:{}: sending {} octets",
                endpoint,
                packet_meta.endpoint,
                payload_buf.len()
            );

            ip_repr.set_payload_len(repr.header_len() + payload_buf.len());

            call_emit(cx, packet_meta.meta, ip_repr, repr, payload_buf, emit)
        });
        match res {
            Err(Empty) => Ok(()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => {
                #[cfg(feature = "async")]
                self.tx_waker.wake();
                Ok(())
            }
        }
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}


/// Calls `emit` on a datagram, discharging its payload-length precondition.
///
/// A verification shim, not an abstraction, and the exact analogue of `phy::call_with_buf`.
/// [`Socket::dispatch`]'s signature states that `emit` is only ever called with an `IpRepr`
/// whose `payload_len` is `8 + payload.len()`, and flux checks that at a call in a *function*
/// body -- but not at one inside a *closure* body. `dispatch` calls `emit` from inside the
/// closure it hands to `dequeue_payload`, so the call has to be hoisted into a named function
/// to be checked at all. Call `emit` through this and the obligation is discharged; call it
/// directly from the closure and `dispatch` asserts its own contract instead of proving it.
#[flux_rs::trusted(no, reason = "checks Socket::dispatch's payload-length contract, #23")]
#[flux_rs::sig(
    fn(&mut Context, PacketMeta, IpRepr[@ipr], UdpRepr, &[u8][@m], F) -> R
    requires ipr.plen == 8 + m
    where
        F: FnOnce(&mut Context, PacketMeta, (IpRepr[@i], UdpRepr, &[u8]{v: i.plen == 8 + v})) -> R
)]
fn call_emit<'a, R, F>(
    cx: &mut Context,
    meta: PacketMeta,
    ip_repr: IpRepr,
    udp_repr: UdpRepr,
    payload: &'a [u8],
    emit: F,
) -> R
where
    F: FnOnce(&mut Context, PacketMeta, (IpRepr, UdpRepr, &'a [u8])) -> R,
{
    emit(cx, meta, (ip_repr, udp_repr, payload))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::{IpRepr, UdpRepr};

    use crate::phy::Medium;
    use crate::tests::setup;
    use rstest::*;

    fn buffer(packets: usize) -> PacketBuffer<'static> {
        PacketBuffer::new(
            (0..packets)
                .map(|_| PacketMetadata::EMPTY)
                .collect::<Vec<_>>(),
            vec![0; 16 * packets],
        )
    }

    fn socket(
        rx_buffer: PacketBuffer<'static>,
        tx_buffer: PacketBuffer<'static>,
    ) -> Socket<'static> {
        Socket::new(rx_buffer, tx_buffer)
    }

    const LOCAL_PORT: u16 = 53;
    const REMOTE_PORT: u16 = 49500;

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;
            use crate::wire::Ipv4Repr as IpvXRepr;
            use IpRepr::Ipv4 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;
            use crate::wire::Ipv6Repr as IpvXRepr;
            use IpRepr::Ipv6 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        }
    }

    fn remote_metadata_with_local() -> UdpMetadata {
        // Would be great as a const once we have const `.into()`.
        UdpMetadata {
            local_address: Some(LOCAL_ADDR.into()),
            ..REMOTE_END.into()
        }
    }

    pub const LOCAL_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    pub const REMOTE_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    pub const BAD_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: OTHER_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    const LOCAL_UDP_REPR: UdpRepr = UdpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
    };

    const REMOTE_UDP_REPR: UdpRepr = UdpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
    };

    const PAYLOAD: &[u8] = b"abcdef";

    #[test]
    fn test_bind_unaddressable() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(0.into()), Err(BindError::Unaddressable));
    }

    #[test]
    fn test_bind_twice() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(1.into()), Ok(()));
        assert_eq!(socket.bind(2.into()), Err(BindError::InvalidState));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket(buffer(0), buffer(1));
        s.set_hop_limit(Some(0));
    }

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));

        assert_eq!(
            socket.send_slice(b"abcdef", REMOTE_END.into()),
            Err(SendError::Unaddressable)
        );
        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));
        assert_eq!(
            socket.send_slice(
                b"abcdef",
                IpEndpoint {
                    addr: IpvXAddress::UNSPECIFIED.into(),
                    ..REMOTE_END
                }
                .into()
            ),
            Err(SendError::Unaddressable)
        );
        assert_eq!(
            socket.send_slice(
                b"abcdef",
                IpEndpoint {
                    port: 0,
                    ..REMOTE_END
                }
                .into()
            ),
            Err(SendError::Unaddressable)
        );
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END.into()), Ok(()));
    }

    #[test]
    fn test_send_with_source() {
        let mut socket = socket(buffer(0), buffer(1));

        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));
        assert_eq!(
            socket.send_slice(b"abcdef", remote_metadata_with_local()),
            Ok(())
        );
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_send_dispatch(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(1));

        assert_eq!(socket.bind(LOCAL_END.into()), Ok(()));

        assert!(socket.can_send());
        assert_eq!(
            socket.dispatch(cx, |_, _, _| unreachable!()),
            Ok::<_, ()>(())
        );

        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END.into()), Ok(()));
        assert_eq!(
            socket.send_slice(b"123456", REMOTE_END.into()),
            Err(SendError::BufferFull)
        );
        assert!(!socket.can_send());

        assert_eq!(
            socket.dispatch(cx, |_, _, (ip_repr, udp_repr, payload)| {
                assert_eq!(ip_repr, LOCAL_IP_REPR);
                assert_eq!(udp_repr, LOCAL_UDP_REPR);
                assert_eq!(payload, PAYLOAD);
                Err(())
            }),
            Err(())
        );
        assert!(!socket.can_send());

        assert_eq!(
            socket.dispatch(cx, |_, _, (ip_repr, udp_repr, payload)| {
                assert_eq!(ip_repr, LOCAL_IP_REPR);
                assert_eq!(udp_repr, LOCAL_UDP_REPR);
                assert_eq!(payload, PAYLOAD);
                Ok::<_, ()>(())
            }),
            Ok(())
        );
        assert!(socket.can_send());
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_recv_process(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));

        assert!(!socket.can_recv());
        assert_eq!(socket.recv(), Err(RecvError::Exhausted));

        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );
        assert!(socket.can_recv());

        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );

        assert_eq!(
            socket.recv(),
            Ok((&b"abcdef"[..], remote_metadata_with_local()))
        );
        assert!(!socket.can_recv());
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_peek_process(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));

        assert_eq!(socket.peek(), Err(RecvError::Exhausted));

        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );
        assert_eq!(
            socket.peek(),
            Ok((&b"abcdef"[..], &remote_metadata_with_local(),))
        );
        assert_eq!(
            socket.recv(),
            Ok((&b"abcdef"[..], remote_metadata_with_local(),))
        );
        assert_eq!(socket.peek(), Err(RecvError::Exhausted));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_recv_truncated_slice(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));

        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );

        let mut slice = [0; 4];
        assert_eq!(socket.recv_slice(&mut slice[..]), Err(RecvError::Truncated));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_peek_truncated_slice(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));

        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );

        let mut slice = [0; 4];
        assert_eq!(socket.peek_slice(&mut slice[..]), Err(RecvError::Truncated));
        assert_eq!(socket.recv_slice(&mut slice[..]), Err(RecvError::Truncated));
        assert_eq!(socket.peek_slice(&mut slice[..]), Err(RecvError::Exhausted));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_set_hop_limit(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut s = socket(buffer(0), buffer(1));

        assert_eq!(s.bind(LOCAL_END.into()), Ok(()));

        s.set_hop_limit(Some(0x2a));
        assert_eq!(s.send_slice(b"abcdef", REMOTE_END.into()), Ok(()));
        assert_eq!(
            s.dispatch(cx, |_, _, (ip_repr, _, _)| {
                assert_eq!(
                    ip_repr,
                    IpReprIpvX(IpvXRepr {
                        src_addr: LOCAL_ADDR,
                        dst_addr: REMOTE_ADDR,
                        next_header: IpProtocol::Udp,
                        payload_len: 8 + 6,
                        hop_limit: 0x2a,
                    })
                );
                Ok::<_, ()>(())
            }),
            Ok(())
        );
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_doesnt_accept_wrong_port(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));

        let mut udp_repr = REMOTE_UDP_REPR;
        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &udp_repr));
        udp_repr.dst_port += 1;
        assert!(!socket.accepts(cx, &REMOTE_IP_REPR, &udp_repr));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_doesnt_accept_wrong_ip(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut port_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(port_bound_socket.bind(LOCAL_PORT.into()), Ok(()));
        assert!(port_bound_socket.accepts(cx, &BAD_IP_REPR, &REMOTE_UDP_REPR));

        let mut ip_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(ip_bound_socket.bind(LOCAL_END.into()), Ok(()));
        assert!(!ip_bound_socket.accepts(cx, &BAD_IP_REPR, &REMOTE_UDP_REPR));
    }

    #[test]
    fn test_send_large_packet() {
        // buffer(4) creates a payload buffer of size 16*4
        let mut socket = socket(buffer(0), buffer(4));
        assert_eq!(socket.bind(LOCAL_END.into()), Ok(()));

        let too_large = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefx";
        assert_eq!(
            socket.send_slice(too_large, REMOTE_END.into()),
            Err(SendError::BufferFull)
        );
        assert_eq!(socket.send_slice(&too_large[..16 * 4], REMOTE_END.into()), Ok(()));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_process_empty_payload(#[case] medium: Medium) {
        let meta = Box::leak(Box::new([PacketMetadata::EMPTY]));
        let recv_buffer = PacketBuffer::new(&mut meta[..], vec![]);
        let mut socket = socket(recv_buffer, buffer(0));

        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));

        let repr = UdpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
        };
        socket.process(cx, PacketMeta::default(), &REMOTE_IP_REPR, &repr, &[]);
        assert_eq!(socket.recv(), Ok((&[][..], remote_metadata_with_local())));
    }

    #[test]
    fn test_closing() {
        let meta = Box::leak(Box::new([PacketMetadata::EMPTY]));
        let recv_buffer = PacketBuffer::new(&mut meta[..], vec![]);
        let mut socket = socket(recv_buffer, buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT.into()), Ok(()));

        assert!(socket.is_open());
        socket.close();
        assert!(!socket.is_open());
    }
}
