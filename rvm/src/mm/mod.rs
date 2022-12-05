mod page_table;

use core::marker::PhantomData;

use crate::{RvmHal, RvmResult};

pub use page_table::{GenericPTE, Level4PageTable};

pub const PAGE_SIZE: usize = 0x1000;

/// Guest virtual address.
pub type GuestVirtAddr = usize;
/// Guest physical address.
pub type GuestPhysAddr = usize;
/// Host virtual address.
pub type HostVirtAddr = usize;
/// Host physical address.
pub type HostPhysAddr = usize;

bitflags::bitflags! {
    /// Permission and type of a guest physical memory region.
    pub struct MemFlags: u64 {
        const READ          = 1 << 0;
        const WRITE         = 1 << 1;
        const EXECUTE       = 1 << 2;
        const DEVICE        = 1 << 3;
    }
}

/// Information about nested page faults.
#[derive(Debug)]
pub struct NestedPageFaultInfo {
    /// Access type that caused the nested page fault.
    pub access_flags: MemFlags,
    /// Guest physical address that caused the nested page fault.
    pub fault_guest_paddr: GuestPhysAddr,
}

/// A 4K-sized contiguous physical memory page, it will deallocate the page
/// automatically on drop.
#[derive(Debug)]
pub struct PhysFrame<H: RvmHal> {
    start_paddr: HostPhysAddr,
    _phantom: PhantomData<H>,
}

impl<H: RvmHal> PhysFrame<H> {
    pub fn alloc() -> RvmResult<Self> {
        let start_paddr = H::alloc_page()
            .ok_or_else(|| rvm_err_type!(OutOfMemory, "allocate physical frame failed"))?;
        assert_ne!(start_paddr, 0);
        debug!("[RVM] allocated PhysFrame({:#x})", start_paddr);
        Ok(Self {
            start_paddr,
            _phantom: PhantomData,
        })
    }

    pub fn alloc_zero() -> RvmResult<Self> {
        let mut f = Self::alloc()?;
        f.fill(0);
        Ok(f)
    }

    pub const unsafe fn uninit() -> Self {
        Self {
            start_paddr: 0,
            _phantom: PhantomData,
        }
    }

    pub fn start_paddr(&self) -> HostPhysAddr {
        self.start_paddr
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        H::phys_to_virt(self.start_paddr) as *mut u8
    }

    pub fn fill(&mut self, byte: u8) {
        unsafe { core::ptr::write_bytes(self.as_mut_ptr(), byte, PAGE_SIZE) }
    }
}

impl<H: RvmHal> Drop for PhysFrame<H> {
    fn drop(&mut self) {
        if self.start_paddr > 0 {
            H::dealloc_page(self.start_paddr);
            debug!("[RVM] deallocated PhysFrame({:#x})", self.start_paddr);
        }
    }
}
