//! Emulated UART 16550. (ref: https://wiki.osdev.org/Serial_Ports)

use super::PortIoDevice;
use crate::arch::uart;

use rvm::{RvmError, RvmResult};
use spin::Mutex;

const DATA_REG: u16 = 0;
const INT_EN_REG: u16 = 1;
const FIFO_CTRL_REG: u16 = 2;
const LINE_CTRL_REG: u16 = 3;
const MODEM_CTRL_REG: u16 = 4;
const LINE_STATUS_REG: u16 = 5;
const MODEM_STATUS_REG: u16 = 6;
const SCRATCH_REG: u16 = 7;

const UART_FIFO_CAPACITY: usize = 16;

bitflags::bitflags! {
    /// Line status flags
    struct LineStsFlags: u8 {
        const INPUT_FULL = 1;
        // 1 to 4 unknown
        const OUTPUT_EMPTY = 1 << 5;
        // 6 and 7 unknown
    }
}

/// FIFO queue for caching bytes read.
struct Fifo<const CAP: usize> {
    buf: [u8; CAP],
    head: usize,
    num: usize,
}

impl<const CAP: usize> Fifo<CAP> {
    const fn new() -> Self {
        Self {
            buf: [0; CAP],
            head: 0,
            num: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.num == 0
    }

    fn is_full(&self) -> bool {
        self.num == CAP
    }

    fn push(&mut self, value: u8) {
        assert!(self.num < CAP);
        self.buf[(self.head + self.num) % CAP] = value;
        self.num += 1;
    }

    fn pop(&mut self) -> u8 {
        assert!(self.num > 0);
        let ret = self.buf[self.head];
        self.head += 1;
        self.head %= CAP;
        self.num -= 1;
        ret
    }
}

pub struct Uart16550 {
    port_base: u16,
    fifo: Mutex<Fifo<UART_FIFO_CAPACITY>>,
}

impl PortIoDevice for Uart16550 {
    fn port_range(&self) -> core::ops::Range<u16> {
        self.port_base..self.port_base + 8
    }

    fn read(&self, port: u16, access_size: u8) -> RvmResult<u32> {
        if access_size != 1 {
            error!("Invalid serial port I/O read size: {} != 1", access_size);
            return Err(RvmError::InvalidParam);
        }
        let ret = match port - self.port_base {
            DATA_REG => {
                // read a byte from FIFO
                let mut fifo = self.fifo.lock();
                if fifo.is_empty() {
                    0
                } else {
                    fifo.pop()
                }
            }
            LINE_STATUS_REG => {
                // check if the physical serial port has an available byte, and push it to FIFO.
                let mut fifo = self.fifo.lock();
                if !fifo.is_full() {
                    if let Some(c) = uart::console_getchar() {
                        fifo.push(c);
                    }
                }
                let mut lsr = LineStsFlags::OUTPUT_EMPTY;
                if !fifo.is_empty() {
                    lsr |= LineStsFlags::INPUT_FULL;
                }
                lsr.bits()
            }
            INT_EN_REG | FIFO_CTRL_REG | LINE_CTRL_REG | MODEM_CTRL_REG | MODEM_STATUS_REG
            | SCRATCH_REG => {
                info!("Unimplemented serial port I/O read: {:#x}", port); // unimplemented
                0
            }
            _ => unreachable!(),
        };
        Ok(ret as u32)
    }

    fn write(&self, port: u16, access_size: u8, value: u32) -> RvmResult {
        if access_size != 1 {
            error!("Invalid serial port I/O write size: {} != 1", access_size);
            return Err(RvmError::InvalidParam);
        }
        match port - self.port_base {
            DATA_REG => uart::console_putchar(value as u8),
            INT_EN_REG | FIFO_CTRL_REG | LINE_CTRL_REG | MODEM_CTRL_REG | SCRATCH_REG => {
                info!("Unimplemented serial port I/O write: {:#x}", port); // unimplemented
            }
            LINE_STATUS_REG => {} // ignore
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl Uart16550 {
    pub const fn new(port_base: u16) -> Self {
        Self {
            port_base,
            fifo: Mutex::new(Fifo::new()),
        }
    }
}
