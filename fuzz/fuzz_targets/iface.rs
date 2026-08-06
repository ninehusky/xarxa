#![no_main]
use libfuzzer_sys::fuzz_target;
use xarxa::iface::{Config, Interface, SocketSet};
use xarxa::phy::{DriverMedium, Loopback};
use xarxa::socket::tcp;
use xarxa::time::{Duration, Instant};
use xarxa::wire::{EthernetAddress, IpAddress, IpCidr};

#[cfg(feature = "log")]
use std::fs::File;
#[cfg(feature = "log")]
use xarxa::phy::{PcapMode, PcapWriter, Tracer};

mod mock {
    use std::sync::atomic::{AtomicU64, Ordering};
    use xarxa::time::{Duration, Instant};

    /// Milliseconds since the clock was created.
    ///
    /// This is a global rather than a field of [`Clock`] so that [`now`] can be passed as a
    /// plain `fn() -> Instant` to the phy middleware.
    static NOW: AtomicU64 = AtomicU64::new(0);

    /// The current mock time.
    pub fn now() -> Instant {
        Instant::from_millis(NOW.load(Ordering::SeqCst) as i64)
    }

    #[derive(Debug, Clone)]
    pub struct Clock;

    impl Clock {
        pub fn new() -> Clock {
            NOW.store(0, Ordering::SeqCst);
            Clock
        }

        pub fn advance(&self, duration: Duration) {
            NOW.fetch_add(duration.total_millis(), Ordering::SeqCst);
        }

        pub fn elapsed(&self) -> Instant {
            now()
        }
    }
}

struct TcpHeaderFuzzer {
    data: Vec<u8>,
    pos: usize,
}

impl TcpHeaderFuzzer {
    pub fn new(data: &[u8]) -> TcpHeaderFuzzer {
        Self {
            data: data.to_vec(),
            pos: 0,
        }
    }

    fn read_u8(&mut self) -> u8 {
        let res = self.data.get(self.pos).cloned().unwrap_or(0);
        self.pos += 1;
        res
    }

    fn read_data(&mut self, dest: &mut [u8]) {
        if let Some(data) = self.data.get(self.pos..self.pos + dest.len()) {
            dest.copy_from_slice(data)
        }
        self.pos += dest.len()
    }
}

impl xarxa::phy::Fuzzer for TcpHeaderFuzzer {
    fn fuzz_packet(&mut self, frame_data: &mut [u8]) {
        loop {
            let len = self.read_u8() as usize;
            if len == 0 {
                break;
            }

            let pos = self.read_u8() as usize;
            if let Some(dest) = frame_data.get_mut(pos..pos + len) {
                self.read_data(dest)
            } else {
                self.pos += len;
            }
        }
    }
}

struct EmptyFuzzer();

impl xarxa::phy::Fuzzer for EmptyFuzzer {
    fn fuzz_packet(&mut self, _: &mut [u8]) {}
}

fuzz_target!(|data: &[u8]| {
    #[cfg(feature = "log")]
    let _ = env_logger::try_init();

    let clock = mock::Clock::new();

    let device = Loopback::new(DriverMedium::Ethernet);
    let device = xarxa::phy::FuzzInjector::new(device, EmptyFuzzer(), TcpHeaderFuzzer::new(data));

    #[cfg(feature = "log")]
    let device = PcapWriter::new(
        device,
        File::create("fuzz.pcap").expect("cannot open file"),
        PcapMode::Both,
        mock::now,
    );

    #[cfg(feature = "log")]
    let device = Tracer::new(device, |_printer| {
        log::trace!("{}", _printer);
    });

    let mut device = device;

    let config = Config::new(EthernetAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
    let mut iface = Interface::new(config, &mut device, clock.elapsed());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
            .unwrap();
    });

    let server_socket = {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let client_socket = {
        let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
        tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    };

    let mut sockets: [_; 2] = Default::default();
    let mut sockets = SocketSet::new(&mut sockets[..]);
    let server_handle = sockets.add(server_socket);
    let client_handle = sockets.add(client_socket);

    let mut did_listen = false;
    let mut did_connect = false;
    let mut done = false;
    while !done && clock.elapsed() < Instant::from_millis(4_000) {
        #[cfg(feature = "log")]
        log::info!("poll");

        iface.poll(clock.elapsed(), &mut device, &mut sockets);

        {
            let socket = sockets.get_mut::<tcp::Socket>(server_handle);
            if !socket.is_active() && !socket.is_listening() {
                if !did_listen {
                    socket.listen(1234).unwrap();
                    did_listen = true;
                }
            }

            if socket.can_recv() {
                socket.close();
                done = true;
            }
        }

        {
            let socket = sockets.get_mut::<tcp::Socket>(client_handle);
            let cx = iface.context();
            if !socket.is_open() {
                if !did_connect {
                    socket
                        .connect(cx, (IpAddress::v4(127, 0, 0, 1), 1234), 65000)
                        .unwrap();
                    did_connect = true;
                }
            }

            if socket.can_send() {
                socket
                    .send_slice(b"0123456789abcdef0123456789abcdef0123456789abcdef")
                    .unwrap();
                socket.close();
            }
        }

        match iface.poll_delay(clock.elapsed(), &sockets) {
            Some(Duration::ZERO) => {}
            Some(delay) => clock.advance(delay),
            None => break,
        }
    }
});
