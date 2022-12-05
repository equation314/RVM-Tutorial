use alloc::{vec, vec::Vec};
use core::{fmt::Debug, marker::PhantomData};

use super::{MemFlags, PhysFrame, PAGE_SIZE};
use crate::{RvmHal, RvmResult};

const LEVELS: usize = 4;
const ENTRY_COUNT: usize = 512;

type VirtAddr = super::GuestPhysAddr;
type PhysAddr = super::HostPhysAddr;

const fn p4_index(vaddr: VirtAddr) -> usize {
    (vaddr >> (12 + 27)) & (ENTRY_COUNT - 1)
}

const fn p3_index(vaddr: VirtAddr) -> usize {
    (vaddr >> (12 + 18)) & (ENTRY_COUNT - 1)
}

const fn p2_index(vaddr: VirtAddr) -> usize {
    (vaddr >> (12 + 9)) & (ENTRY_COUNT - 1)
}

const fn p1_index(vaddr: VirtAddr) -> usize {
    (vaddr >> 12) & (ENTRY_COUNT - 1)
}

const fn align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

const fn page_offset(addr: usize) -> usize {
    addr & (PAGE_SIZE - 1)
}

pub trait GenericPTE: Debug + Clone + Copy + Sync + Send + Sized {
    // Create a page table entry point to a terminate 4K-sized page or a huge page.
    fn new_page(paddr: PhysAddr, flags: MemFlags, is_huge: bool) -> Self;
    // Create a page table entry point to a next level page table.
    fn new_table(paddr: PhysAddr) -> Self;

    /// Returns the physical address mapped by this entry.
    fn paddr(&self) -> PhysAddr;
    /// Returns the flags of this entry.
    fn flags(&self) -> MemFlags;
    /// Returns whether this entry is zero.
    fn is_unused(&self) -> bool;
    /// Returns whether this entry flag indicates present.
    fn is_present(&self) -> bool;
    /// For non-last level translation, returns whether this entry maps to a
    /// huge frame.
    fn is_huge(&self) -> bool;
    /// Set this entry to zero.
    fn clear(&mut self);
}

/// A generic 4-level page table structures.
pub struct Level4PageTable<H: RvmHal, PTE: GenericPTE> {
    root_paddr: PhysAddr,
    intrm_tables: Vec<PhysFrame<H>>,
    _phantom: PhantomData<PTE>,
}

impl<H: RvmHal, PTE: GenericPTE> Level4PageTable<H, PTE> {
    /// Create a page table instance.
    pub fn new() -> RvmResult<Self> {
        let root_frame = PhysFrame::alloc_zero()?;
        Ok(Self {
            root_paddr: root_frame.start_paddr(),
            intrm_tables: vec![root_frame],
            _phantom: PhantomData,
        })
    }

    /// Physical address of the page table root.
    pub fn root_paddr(&self) -> PhysAddr {
        self.root_paddr
    }

    /// Create a mapping from the virtual address `vaddr` to the physical address
    /// `paddr`, with memory permissions and types described by `flags`.
    pub fn map(&mut self, vaddr: VirtAddr, paddr: PhysAddr, flags: MemFlags) -> RvmResult {
        let entry = self.get_entry_mut_or_create(vaddr)?;
        if !entry.is_unused() {
            return rvm_err!(
                InvalidParam,
                format_args!("try to map an already mapped page {:#x}", vaddr)
            );
        }
        *entry = GenericPTE::new_page(align_down(paddr), flags, false);
        Ok(())
    }

    /// Remove mappings for the virtual address `vaddr`.
    pub fn unmap(&mut self, vaddr: VirtAddr) -> RvmResult<PhysAddr> {
        let entry = self.get_entry_mut(vaddr)?;
        if entry.is_unused() {
            return rvm_err!(
                InvalidParam,
                format_args!("try to unmap an unmapped page {:#x}", vaddr)
            );
        }
        let paddr = entry.paddr();
        entry.clear();
        Ok(paddr)
    }

    /// Query the mapping target for the virtual address `vaddr`, return the
    /// target physical address and memory permissions.
    pub fn query(&self, vaddr: VirtAddr) -> RvmResult<(PhysAddr, MemFlags)> {
        let entry = self.get_entry_mut(vaddr)?;
        if entry.is_unused() {
            return rvm_err!(
                InvalidParam,
                format_args!("queried page {:#x} is not mapped", vaddr)
            );
        }
        let off = page_offset(vaddr);
        Ok((entry.paddr() + off, entry.flags()))
    }

    /// Update the mapping target for the virtual address `vaddr`.
    pub fn update(
        &mut self,
        vaddr: VirtAddr,
        paddr: Option<PhysAddr>,
        flags: Option<MemFlags>,
    ) -> RvmResult {
        let entry = self.get_entry_mut(vaddr)?;
        let paddr = align_down(paddr.unwrap_or_else(|| entry.paddr()));
        let flags = flags.unwrap_or_else(|| entry.flags());
        *entry = GenericPTE::new_page(paddr, flags, entry.is_huge());
        Ok(())
    }

    /// Print the page table contents recursively for debugging.
    pub fn dump(&self, limit: usize) {
        info!("Root: {:x?}", self.root_paddr());
        self.walk(
            self.table_of(self.root_paddr()),
            0,
            0,
            limit,
            &|level: usize, idx: usize, vaddr: VirtAddr, entry: &PTE| {
                for _ in 0..level {
                    info!("  ");
                }
                info!("[{} - {:x}], 0x{:08x?}: {:x?}", level, idx, vaddr, entry);
            },
        );
    }
}

impl<H: RvmHal, PTE: GenericPTE> Level4PageTable<H, PTE> {
    fn table_of<'a>(&self, paddr: PhysAddr) -> &'a [PTE] {
        let ptr = H::phys_to_virt(paddr) as *const PTE;
        unsafe { core::slice::from_raw_parts(ptr, ENTRY_COUNT) }
    }

    fn table_of_mut<'a>(&self, paddr: PhysAddr) -> &'a mut [PTE] {
        let ptr = H::phys_to_virt(paddr) as *mut PTE;
        unsafe { core::slice::from_raw_parts_mut(ptr, ENTRY_COUNT) }
    }

    fn next_table_mut<'a>(&self, entry: &PTE) -> RvmResult<&'a mut [PTE]> {
        if !entry.is_present() {
            rvm_err!(BadState, "next table entry not present")
        } else if entry.is_huge() {
            rvm_err!(BadState, "next table entry is huge")
        } else {
            Ok(self.table_of_mut(entry.paddr()))
        }
    }

    fn next_table_mut_or_create<'a>(&mut self, entry: &mut PTE) -> RvmResult<&'a mut [PTE]> {
        if entry.is_unused() {
            let paddr = self.alloc_intrm_table()?;
            *entry = GenericPTE::new_table(paddr);
            Ok(self.table_of_mut(paddr))
        } else {
            self.next_table_mut(entry)
        }
    }

    fn alloc_intrm_table(&mut self) -> RvmResult<PhysAddr> {
        let frame = PhysFrame::alloc_zero()?;
        let paddr = frame.start_paddr();
        self.intrm_tables.push(frame);
        Ok(paddr)
    }

    fn get_entry_mut(&self, vaddr: VirtAddr) -> RvmResult<&mut PTE> {
        let p4 = self.table_of_mut(self.root_paddr());
        let p4e = &mut p4[p4_index(vaddr)];

        let p3 = self.next_table_mut(p4e)?;
        let p3e = &mut p3[p3_index(vaddr)];

        let p2 = self.next_table_mut(p3e)?;
        let p2e = &mut p2[p2_index(vaddr)];

        let p1 = self.next_table_mut(p2e)?;
        let p1e = &mut p1[p1_index(vaddr)];
        Ok(p1e)
    }

    fn get_entry_mut_or_create(&mut self, vaddr: VirtAddr) -> RvmResult<&mut PTE> {
        let p4 = self.table_of_mut(self.root_paddr());
        let p4e = &mut p4[p4_index(vaddr)];

        let p3 = self.next_table_mut_or_create(p4e)?;
        let p3e = &mut p3[p3_index(vaddr)];

        let p2 = self.next_table_mut_or_create(p3e)?;
        let p2e = &mut p2[p2_index(vaddr)];

        let p1 = self.next_table_mut_or_create(p2e)?;
        let p1e = &mut p1[p1_index(vaddr)];
        Ok(p1e)
    }

    fn walk(
        &self,
        table: &[PTE],
        level: usize,
        start_vaddr: VirtAddr,
        limit: usize,
        func: &impl Fn(usize, usize, VirtAddr, &PTE),
    ) {
        let mut n = 0;
        for (i, entry) in table.iter().enumerate() {
            let vaddr = start_vaddr + (i << (12 + (LEVELS - 1 - level) * 9));
            if entry.is_present() {
                func(level, i, vaddr, entry);
                if level < LEVELS - 1 && !entry.is_huge() {
                    let table_entry = self.next_table_mut(entry).unwrap();
                    self.walk(table_entry, level + 1, vaddr, limit, func);
                }
                n += 1;
                if n >= limit {
                    break;
                }
            }
        }
    }
}
