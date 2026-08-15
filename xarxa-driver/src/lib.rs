#![no_std]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

/// Type of medium of a device.
///
/// This indicates what kind of packet the sent/received bytes are, and determines
/// some behaviors of the interface. For example, ARP/NDISC address resolution is only
/// done for Ethernet mediums.
///
/// All variants are always present, regardless of which Cargo features `xarxa` is built
/// with. Creating an interface on a device whose medium the stack was not built for panics.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Medium {
    /// Ethernet medium. Devices of this type send and receive Ethernet frames,
    /// and interfaces using it must do neighbor discovery via ARP or NDISC.
    ///
    /// Examples of devices of this type are Ethernet, WiFi (802.11), Linux `tap`, and VPNs in tap (layer 2) mode.
    #[default]
    Ethernet,

    /// IP medium. Devices of this type send and receive IP frames, without an
    /// Ethernet header. MAC addresses are not used, and no neighbor discovery (ARP, NDISC) is done.
    ///
    /// Examples of devices of this type are the Linux `tun`, PPP interfaces, VPNs in tun (layer 3) mode.
    Ip,

    /// IEEE 802.15.4 medium. Devices of this type send and receive IEEE 802.15.4 frames,
    /// carrying 6LoWPAN-compressed IPv6 packets.
    Ieee802154,
}

/// A representation of a hardware packet timestamp.
///
/// This is a reading of the *device's own clock*, not of the `Instant` the stack is polled
/// with. Such a clock is usually called a "PTP hardware clock" or PHC. It has an arbitrary
/// epoch (often, but not necessarily, the time since the device was reset) and it drifts
/// with respect to any other clock in the system unless something is actively disciplining
/// it. Do not mix `Timestamp` and `Instant` values.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default)]
pub struct Timestamp {
    /// Whole seconds.
    pub seconds: u32,
    /// Fraction of a second, in units of 0.25 nanoseconds.
    ///
    /// Always less than `4_000_000_000`, i.e. less than one whole second.
    pub quarter_nanos: u32,
}

impl Timestamp {
    /// Construct a timestamp from seconds and nanoseconds.
    pub const fn from_seconds_and_nanos(seconds: u32, nanos: u32) -> Self {
        Self {
            seconds,
            quarter_nanos: nanos << 2,
        }
    }
}

/// Metadata associated to a packet.
///
/// The packet metadata is a set of attributes associated to network packets
/// as they travel up or down the stack. The metadata is get/set by the
/// [`Driver`] implementations or by the user when sending/receiving packets from a
/// socket.
///
/// Metadata fields are enabled via Cargo features. If no field is enabled, this
/// struct becomes zero-sized, which allows the compiler to optimize it out as if
/// the packet metadata mechanism didn't exist at all.
///
/// This struct is marked as `#[non_exhaustive]`. This means it is not possible to
/// create it directly by specifying all fields. You have to instead create it with
/// default values and then set the fields you want. This makes adding metadata
/// fields a non-breaking change.
///
/// ```rust
/// let mut meta = xarxa_driver::PacketMeta::default();
/// #[cfg(feature = "packetmeta-id")]
/// {
///     meta.id = 15;
/// }
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Default)]
#[non_exhaustive]
pub struct PacketMeta {
    /// An opaque identifier for this packet.
    ///
    /// On received packets, this is set by the [`Device`]. On packets to transmit,
    /// this is set by the user and passed down to the [`Device`]; it is also what
    /// correlates a transmit timestamp back to the packet that produced it, see
    /// [`Device::poll_tx_timestamp`].
    #[cfg(feature = "packetmeta-id")]
    pub id: u32,

    /// The time at which this packet was received, as measured by the device.
    ///
    /// `None` if the device did not timestamp this packet. Devices commonly only
    /// timestamp a subset of received packets, e.g. only PTP event messages.
    ///
    /// This field is only meaningful on received packets. It is ignored on packets
    /// to transmit: at the time a packet is handed to the device, it has not been
    /// transmitted yet, so its transmit timestamp does not exist yet. Use
    /// [`Self::request_timestamp`] and [`Device::poll_tx_timestamp`] instead.
    #[cfg(feature = "packetmeta-timestamp")]
    pub timestamp: Option<Timestamp>,

    /// Request that the device timestamp this packet as it is transmitted.
    ///
    /// The resulting timestamp is reported back later, out of band, via
    /// [`Device::poll_tx_timestamp`], tagged with this packet's [`Self::id`].
    ///
    /// This field is only meaningful on packets to transmit. It is ignored on
    /// received packets.
    ///
    /// Timestamping is opt-in per packet because hardware typically has only a
    /// handful of transmit timestamp slots. Requesting a timestamp for every packet
    /// will cause most of them to be dropped.
    #[cfg(feature = "packetmeta-timestamp")]
    pub request_timestamp: bool,
}

/// The timestamp of a transmitted packet, reported by [`Device::poll_tx_timestamp`].
#[cfg(feature = "packetmeta-timestamp")]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxTimestamp {
    /// The [`PacketMeta::id`] of the packet this timestamp belongs to.
    pub id: u32,

    /// The time at which the packet was transmitted, as measured by the device.
    pub timestamp: Timestamp,
}

/// A description of checksum behavior for a particular protocol.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Checksum {
    /// Verify checksum when receiving and compute checksum when sending.
    #[default]
    Both,
    /// Verify checksum when receiving.
    Rx,
    /// Compute checksum before sending.
    Tx,
    /// Ignore checksum completely.
    None,
}

impl Checksum {
    /// Returns whether checksum should be verified when receiving.
    pub fn rx(&self) -> bool {
        matches!(*self, Checksum::Both | Checksum::Rx)
    }

    /// Returns whether checksum should be verified when sending.
    pub fn tx(&self) -> bool {
        matches!(*self, Checksum::Both | Checksum::Tx)
    }
}

/// A description of checksum behavior for every supported protocol.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct ChecksumCapabilities {
    /// Checksum behavior for IPv4.
    pub ipv4: Checksum,
    /// Checksum behavior for UDP.
    pub udp: Checksum,
    /// Checksum behavior for TCP.
    pub tcp: Checksum,
    /// Checksum behavior for ICMPv4.
    pub icmpv4: Checksum,
    /// Checksum behavior for ICMPv6.
    pub icmpv6: Checksum,
}

impl ChecksumCapabilities {
    /// Checksum behavior that results in not computing or verifying checksums
    /// for any of the supported protocols.
    pub fn ignored() -> Self {
        ChecksumCapabilities {
            ipv4: Checksum::None,
            udp: Checksum::None,
            tcp: Checksum::None,
            icmpv4: Checksum::None,
            icmpv6: Checksum::None,
        }
    }
}

/// A description of device capabilities.
///
/// Higher-level protocols may achieve higher throughput or lower latency if they consider
/// the bandwidth or packet size limitations.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct DeviceCapabilities {
    /// Medium of the device.
    ///
    /// This indicates what kind of packet the sent/received bytes are, and determines
    /// some behaviors of Interface. For example, ARP/NDISC address resolution is only done
    /// for Ethernet mediums.
    pub medium: Medium,

    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the value returned
    /// by this function.
    ///
    /// For Ethernet devices, this is the maximum Ethernet frame size, including the Ethernet header (14 octets), but
    /// *not* including the Ethernet FCS (4 octets). Therefore, Ethernet MTU = IP MTU + 14.
    ///
    /// Note that in Linux and other OSes, "MTU" is the IP MTU, not the Ethernet MTU, even for Ethernet
    /// devices. This is a common source of confusion.
    ///
    /// Most common IP MTU is 1500. Minimum is 576 (for IPv4) or 1280 (for IPv6). Maximum is 9216 octets.
    pub max_transmission_unit: usize,

    /// Maximum burst size, in terms of MTU.
    ///
    /// The network device is unable to send or receive bursts large than the value returned
    /// by this function.
    ///
    /// If `None`, there is no fixed limit on burst size, e.g. if network buffers are
    /// dynamically allocated.
    pub max_burst_size: Option<usize>,

    /// Checksum behavior.
    ///
    /// If the network device is capable of verifying or computing checksums for some protocols,
    /// it can request that the stack not do so in software to improve performance.
    pub checksum: ChecksumCapabilities,
}

/// An interface for sending and receiving raw network frames.
///
/// The interface is based on _tokens_, which are types that allow to receive/transmit a
/// single packet. The `receive` and `transmit` functions only construct such tokens, the
/// real sending/receiving operation are performed when the tokens are consumed.
///
/// # Examples
///
/// An implementation for a simple hardware Ethernet controller could look as follows:
///
/// ```rust
/// use xarxa_driver::{Driver, DeviceCapabilities, Medium, RxToken, TxToken};
///
/// struct StmPhy {
///     rx_buffer: [u8; 1536],
///     tx_buffer: [u8; 1536],
/// }
///
/// impl Driver for StmPhy {
///     type RxToken<'a> = StmPhyRxToken<'a> where Self: 'a;
///     type TxToken<'a> = StmPhyTxToken<'a> where Self: 'a;
///
///     fn receive(&mut self) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
///         Some((StmPhyRxToken(&mut self.rx_buffer[..]),
///               StmPhyTxToken(&mut self.tx_buffer[..])))
///     }
///
///     fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
///         Some(StmPhyTxToken(&mut self.tx_buffer[..]))
///     }
///
///     fn capabilities(&self) -> DeviceCapabilities {
///         let mut caps = DeviceCapabilities::default();
///         caps.max_transmission_unit = 1536;
///         caps.max_burst_size = Some(1);
///         caps.medium = Medium::Ethernet;
///         caps
///     }
/// }
///
/// struct StmPhyRxToken<'a>(&'a mut [u8]);
///
/// impl<'a> RxToken for StmPhyRxToken<'a> {
///     fn consume<R, F>(self, f: F) -> R
///         where F: FnOnce(&[u8]) -> R
///     {
///         // TODO: receive packet into buffer
///         f(&self.0)
///     }
/// }
///
/// struct StmPhyTxToken<'a>(&'a mut [u8]);
///
/// impl<'a> TxToken for StmPhyTxToken<'a> {
///     fn consume<R, F>(self, len: usize, f: F) -> R
///         where F: FnOnce(&mut [u8]) -> R
///     {
///         let result = f(&mut self.0[..len]);
///         // TODO: send packet out
///         result
///     }
/// }
/// ```
pub trait Device {
    /// A token to receive a single network packet.
    type RxToken<'a>: RxToken
    where
        Self: 'a;

    /// A token to transmit a single network packet.
    type TxToken<'a>: TxToken
    where
        Self: 'a;

    /// Construct a token pair consisting of one receive token and one transmit token.
    ///
    /// The additional transmit token makes it possible to generate a reply packet based
    /// on the contents of the received packet. For example, this makes it possible to
    /// handle arbitrarily large ICMP echo ("ping") requests, where the all received bytes
    /// need to be sent back, without heap allocation.
    fn receive(&mut self) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)>;

    /// Construct a transmit token.
    ///
    /// Note that [`TxToken::consume`] is infallible, so it is not allowed to return a token
    /// if there is no free space and fail later.
    fn transmit(&mut self) -> Option<Self::TxToken<'_>>;

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities;

    /// Poll for the timestamp of an already-transmitted packet.
    ///
    /// Returns the transmit timestamp of a packet previously sent with
    /// [`PacketMeta::request_timestamp`] set, tagged with that packet's
    /// [`PacketMeta::id`], or `None` if no timestamp is available right now.
    ///
    /// Transmit timestamps are reported out of band, rather than through
    /// [`PacketMeta`] like receive timestamps are, because a packet's transmit
    /// timestamp does not exist yet when [`TxToken::consume`] returns: the packet has
    /// not gone out on the wire yet at that point.
    ///
    /// Callers must be robust against all of the following:
    ///
    /// * Timestamps become available an arbitrary time after [`TxToken::consume`]
    ///   returned, so this should be polled repeatedly, not just once after sending.
    /// * Timestamps may be reported out of order with respect to transmission.
    /// * Timestamps may never arrive at all, e.g. because the hardware ran out of
    ///   timestamp slots. Never block waiting for a particular `id` to show up
    ///   without a timeout.
    ///
    /// Devices that do not support transmit timestamping always return `None`, which
    /// is the default implementation.
    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<TxTimestamp> {
        None
    }
}

impl<T: ?Sized + Device> Device for &mut T {
    type RxToken<'a>
        = T::RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = T::TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        T::receive(self)
    }

    fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
        T::transmit(self)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        T::capabilities(self)
    }

    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<TxTimestamp> {
        T::poll_tx_timestamp(self)
    }
}

/// A token to receive a single network packet.
pub trait RxToken {
    /// Consumes the token to receive a single network packet.
    ///
    /// This method receives a packet and then calls the given closure `f` with the raw
    /// packet bytes as argument.
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R;

    /// The packet metadata associated with the frame received by this [`RxToken`].
    fn meta(&self) -> PacketMeta {
        PacketMeta::default()
    }
}

/// A token to transmit a single network packet.
pub trait TxToken {
    /// Consumes the token to send a single network packet.
    ///
    /// This method constructs a transmit buffer of size `len` and calls the passed
    /// closure `f` with a mutable reference to that buffer. The closure should construct
    /// a valid network packet (e.g. an ethernet packet) in the buffer. When the closure
    /// returns, the transmit buffer is sent out.
    #[flux_rs::sig(
        fn(self: Self, len: usize[@n], f: F) -> R
        where
            F: FnOnce(&mut [u8]{v : v == n}) -> R
    )]
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R;

    /// The packet metadata to be associated with the frame to be transmitted by this [`TxToken`].
    #[allow(unused_variables)]
    fn set_meta(&mut self, meta: PacketMeta) {}
}

#[cfg(flux)]
#[allow(dead_code)]
mod spec_is_live {
    use super::TxToken;

    /// Accepts only a slice whose length is exactly `n`.
    #[flux_rs::sig(fn(&mut [u8][@m], usize[@n]) requires m == n)]
    fn demand_len(_buf: &mut [u8], _n: usize) {}

    /// Positive control. Discharging `m == n` is possible *only* through the
    /// `FnOnce(&mut [u8]{v : v == n})` bound on `consume`. If that bound stops
    /// being applied, this stops verifying and `cargo flux` fails here.
    pub fn consume_hands_back_exactly_len<T: TxToken>(tok: T, len: usize) {
        tok.consume(len, |buf| demand_len(buf, len))
    }

    /// Negative control, off by default. Demands one byte more than `consume`
    /// promises, so Flux *must* reject it. If this ever verifies, the closure
    /// refinement is vacuous and the positive control above proves nothing.
    ///
    /// Run with:
    ///   RUSTFLAGS='--cfg flux_negative_control' cargo flux
    /// Expect exactly one error, on the `demand_len` call below.
    #[cfg(flux_negative_control)]
    pub fn negative_control<T: TxToken>(tok: T, len: usize) {
        tok.consume(len, |buf| demand_len(buf, len + 1))
    }
}
