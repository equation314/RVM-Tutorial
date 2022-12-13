//! Emulated Intel 8259 Programmable Interrupt Controller. (ref: https://wiki.osdev.org/8259_PIC)

use super::PortIoDevice;
use rvm::{RvmError, RvmResult};

pub struct I8259Pic {
    port_base: u16,
}

impl PortIoDevice for I8259Pic {
    fn port_range(&self) -> core::ops::Range<u16> {
        self.port_base..self.port_base + 2
    }

    fn read(&self, _port: u16, _access_size: u8) -> RvmResult<u32> {
        Err(RvmError::Unsupported) // report error for read
    }

    fn write(&self, _port: u16, _access_size: u8, _value: u32) -> RvmResult {
        Ok(()) // ignore write
    }
}

impl I8259Pic {
    pub const fn new(port_base: u16) -> Self {
        Self { port_base }
    }
}
