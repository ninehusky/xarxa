use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, DriverMedium};

/// A loopback device.
#[derive(Debug)]
pub struct Loopback {
    pub(crate) queue: VecDeque<Vec<u8>>,
    medium: DriverMedium,
}

#[allow(clippy::new_without_default)]
impl Loopback {
    /// Creates a loopback device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new(medium: DriverMedium) -> Loopback {
        Loopback {
            queue: VecDeque::new(),
            medium,
        }
    }
}

impl Device for Loopback {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 65535;
        caps.medium = self.medium;
        caps.checksum = ChecksumCapabilities::ignored();
        caps
    }

    fn receive(&mut self) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer };
            let tx = TxToken {
                queue: &mut self.queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.queue,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    #[flux_rs::trusted(no, reason = "checks TxToken::consume's buffer-length contract, #23")]
    #[flux_rs::sig(
        fn(self: Self, len: usize[@n], f: F) -> R
        where
            F: FnOnce(&mut [u8]{v : v == n}) -> R
    )]
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let (result, buffer) = phy::with_zeroed_buf(len, f);
        self.queue.push_back(buffer);
        result
    }
}
