use super::*;

use crate::wire::Ref;

impl InterfaceInner {
    pub(super) fn process_ethernet<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: crate::phy::PacketMeta,
        frame: &'frame [u8],
        fragments: &'frame mut FragmentsBuffer,
    ) -> Option<EthernetPacket<'frame>> {
        let eth_frame = check!(EthernetFrame::new_checked_ref(Ref::new(frame)));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr
        {
            return None;
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => {
                // `process_arp` takes a `Frame<&[u8]>`, so the frame is rebuilt at that type;
                // `new_checked_ref` above has already run the length check on these bytes.
                self.process_arp(self.now, &EthernetFrame::new_unchecked(frame))
            }
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(eth_frame.payload()));

                self.process_ipv4(
                    sockets,
                    meta,
                    eth_frame.src_addr().into(),
                    &ipv4_packet,
                    fragments,
                )
                .map(EthernetPacket::Ip)
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = check!(Ipv6Packet::new_checked_ref(Ref::new(eth_frame.payload())));
                self.process_ipv6(sockets, meta, eth_frame.src_addr().into(), &ipv6_packet)
                    .map(EthernetPacket::Ip)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    /// Calls `f` on an Ethernet frame, discharging `f`'s frame-length precondition.
    ///
    /// A verification shim, not an abstraction, and the exact analogue of
    /// [`phy::call_with_buf`]. `dispatch_ethernet` hands `f` its frame from inside the closure
    /// it gives to [`TxToken::consume`], and flux does not check a call to an `Fn`-typed
    /// parameter inside a *closure* body -- only inside a *function* body. Routed through here
    /// the length obligation is posed; called directly from the closure it is not.
    ///
    /// [`phy::call_with_buf`]: crate::phy::call_with_buf
    #[flux_rs::trusted(no, reason = "checks the closure's frame-length contract, #23")]
    #[flux_rs::sig(
        fn(EthernetFrame<Buf>[@fr], F)
        where F: FnOnce(EthernetFrame<Buf>{g: g.buffer == fr.buffer})
    )]
    fn call_with_frame<F>(frame: EthernetFrame<Buf<'_>>, f: F)
    where
        F: FnOnce(EthernetFrame<Buf>),
    {
        f(frame)
    }

    /// Emit an Ethernet frame with `buffer_len` octets of payload, filling in the source
    /// address and handing the frame to `f`.
    ///
    /// The frame's buffer is a [`Buf`] rather than a `&mut [u8]`: at `T = &mut [u8]` the length
    /// index would have to come from core's blanket `impl AsMut for &mut T`, which carries no
    /// associated refinement, and *that is a spec error* -- it aborts refinement checking of
    /// this whole body, so every header write inside stops being checked. `Buf`'s `AsMut` impl
    /// is local and refined, so the frame length reaches the setters and reaches `f`.
    ///
    /// `tx_len` is `header_len() + buffer_len` rather than `EthernetFrame::buffer_len()`
    /// because the latter has no signature -- see the note there. `strict` locally, because
    /// `lazy` models the sum as wrapping and so proves nothing about `tx_len`; the
    /// `buffer_len <= 65535` premise is what rules the overflow out, and both call sites pass
    /// `ArpRepr::buffer_len()`, which is 28.
    #[flux_rs::opts(check_overflow = "strict")]
    #[flux_rs::trusted(no, reason = "poses the Ethernet header writes' buffer bound")]
    #[flux_rs::sig(
        fn(self: &mut InterfaceInner, Tx, buffer_len: usize[@bl], F)
            -> Result<(), DispatchError>
        requires bl <= 65535
        where F: FnOnce(EthernetFrame<Buf>{f: f.buffer == 14 + bl})
    )]
    pub(super) fn dispatch_ethernet<Tx, F>(
        &mut self,
        tx_token: Tx,
        buffer_len: usize,
        f: F,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<Buf>),
    {
        let tx_len = EthernetFrame::<&[u8]>::header_len() + buffer_len;
        tx_token.consume(tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(Buf::new(tx_buffer));

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);

            Self::call_with_frame(frame, f);
        });

        Ok(())
    }
}
