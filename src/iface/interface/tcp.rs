use super::*;

use crate::socket::tcp::Socket;

impl InterfaceInner {
    /// `ip_payload.len() <= 65535`: the payload is an IP packet's, and both families bound
    /// their extent with a sixteen-bit length field -- IPv4's `total_len`, IPv6's
    /// `payload_len`. `Repr::parse_ref` needs it because `verify_checksum` hands the whole
    /// buffer to `checksum::data`, whose own precondition it is. Nothing is assumed here: the
    /// two callers read the bound off the header they already parsed. Same shape as
    /// `process_icmpv4`.
    #[flux_rs::trusted(no, reason = "IpRepr::new fan-in cone")]
    #[flux_rs::sig(
        fn(&mut Self, &mut SocketSet, bool, IpRepr, &[u8][@n]) -> Option<Packet>
        requires n <= 65535
    )]
    pub(crate) fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());

        // Per RFC 1122 §3.2.1.3, the unspecified address must never appear as a source
        // or destination in any IP datagram. Drop such TCP segments early to avoid
        // creating sockets with unspecified peers (which would later panic on egress).
        // This is not done at the iface level because it might be useful with
        // UDP or raw sockets, but it's definitely not useful for TCP.
        if src_addr.is_unspecified() || dst_addr.is_unspecified() {
            return None;
        }

        // Through `Ref` and `parse_ref`, as `process_icmpv4` does: the generic `parse` is over
        // a `&T` self type whose unit sort cannot state `parse_ref`'s buffer bound.
        let tcp_packet = check!(TcpPacket::new_checked_ref(Ref::new(ip_payload)));
        let tcp_repr = check!(TcpRepr::parse_ref(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        for tcp_socket in sockets
            .items_mut()
            .filter_map(|i| Socket::downcast_mut(&mut i.socket))
        {
            if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                return tcp_socket
                    .process(self, &ip_repr, &tcp_repr)
                    .map(|reply| Packet::new(reply.ip_repr, IpPayload::Tcp(reply.repr)));
            }
        }

        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
            || handled_by_raw_socket
        {
            // Never reply to a TCP RST packet with another TCP RST packet.
            // Never send a TCP RST packet with unspecified addresses.
            // Never send a TCP RST when packet has been handled by raw socket.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let reply = tcp::Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(reply.ip_repr, IpPayload::Tcp(reply.repr)))
        }
    }
}
