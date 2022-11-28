use rvm::{HostPhysAddr, HostVirtAddr, RvmHal};

use crate::mm::{address, frame};

pub struct RvmHalImpl;

impl RvmHal for RvmHalImpl {
    fn alloc_page() -> Option<HostPhysAddr> {
        unsafe { frame::alloc_page() }
    }

    fn dealloc_page(paddr: HostPhysAddr) {
        unsafe { frame::dealloc_page(paddr) }
    }

    fn phys_to_virt(paddr: HostPhysAddr) -> HostVirtAddr {
        address::phys_to_virt(paddr)
    }

    fn virt_to_phys(vaddr: HostVirtAddr) -> HostPhysAddr {
        address::virt_to_phys(vaddr)
    }
}
