mod i8259_pic;
mod lapic;
mod uart16550;

use alloc::{sync::Arc, vec, vec::Vec};

pub use self::lapic::VirtLocalApic;

pub trait PortIoDevice: Send + Sync {
    fn port_range(&self) -> core::ops::Range<u16>;
    fn read(&self, port: u16, access_size: u8) -> rvm::RvmResult<u32>;
    fn write(&self, port: u16, access_size: u8, value: u32) -> rvm::RvmResult;
}

pub struct VirtDeviceList {
    port_io_devices: Vec<Arc<dyn PortIoDevice>>,
}

impl VirtDeviceList {
    pub fn find_port_io_device(&self, port: u16) -> Option<&Arc<dyn PortIoDevice>> {
        self.port_io_devices
            .iter()
            .find(|dev| dev.port_range().contains(&port))
    }
}

lazy_static::lazy_static! {
    static ref VIRT_DEVICES : VirtDeviceList = VirtDeviceList {
        port_io_devices: vec![
            Arc::new(uart16550::Uart16550::new(0x3f8)), // COM1
            Arc::new(i8259_pic::I8259Pic::new(0x20)), // PIC1
            Arc::new(i8259_pic::I8259Pic::new(0xA0)), // PIC2
        ],
    };
}

pub fn all_virt_devices() -> &'static VirtDeviceList {
    &VIRT_DEVICES
}
