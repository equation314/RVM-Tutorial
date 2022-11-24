pub const PHYS_VIRT_OFFSET: usize = 0xffff_ff80_0000_0000;

pub const BOOT_KERNEL_STACK_SIZE: usize = 4096 * 4; // 16K
pub const KERNEL_HEAP_SIZE: usize = 0x40_0000; // 4M

pub const PHYS_MEMORY_BASE: usize = 0;
pub const PHYS_MEMORY_SIZE: usize = 0x400_0000; // 64M
pub const PHYS_MEMORY_END: usize = PHYS_MEMORY_BASE + PHYS_MEMORY_SIZE;

pub const TICKS_PER_SEC: u64 = 100;
