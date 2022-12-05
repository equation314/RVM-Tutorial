use rvm::GuestPhysAddr;

pub const GUEST_PHYS_MEMORY_BASE: GuestPhysAddr = 0;
pub const GUEST_PHYS_MEMORY_SIZE: usize = 0x100_0000; // 16M

pub const GUEST_PT1: GuestPhysAddr = 0x1000;
pub const GUEST_PT2: GuestPhysAddr = 0x2000;
pub const GUEST_ENTRY: GuestPhysAddr = 0x8000;
pub const GUEST_STACK_TOP: GuestPhysAddr = 0x7000;
