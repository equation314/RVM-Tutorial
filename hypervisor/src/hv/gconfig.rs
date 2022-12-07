use rvm::{GuestPhysAddr, HostPhysAddr};

pub const BIOS_PADDR: HostPhysAddr = 0x400_0000;
pub const BIOS_SIZE: usize = 0x1000;

pub const GUEST_IMAGE_PADDR: HostPhysAddr = 0x400_1000;
pub const GUEST_IMAGE_SIZE: usize = 0x10_0000; // 1M

pub const GUEST_PHYS_MEMORY_BASE: GuestPhysAddr = 0;
pub const BIOS_ENTRY: GuestPhysAddr = 0x8000;
pub const GUEST_ENTRY: GuestPhysAddr = 0x20_0000;
pub const GUEST_PHYS_MEMORY_SIZE: usize = 0x100_0000; // 16M
