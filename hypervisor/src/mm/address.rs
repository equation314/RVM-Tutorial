use super::PAGE_SIZE;
use crate::config::PHYS_VIRT_OFFSET;

pub(super) type PhysAddr = usize;
pub(super) type VirtAddr = usize;

pub const fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    paddr + PHYS_VIRT_OFFSET
}

pub const fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    vaddr - PHYS_VIRT_OFFSET
}

pub const fn align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

pub const fn align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub const fn is_aligned(addr: usize) -> bool {
    (addr & (PAGE_SIZE - 1)) == 0
}
