use core::{convert::TryFrom, fmt};

use bit_field::BitField;

use crate::mm::{GenericPTE, HostPhysAddr, Level4PageTable, MemFlags};

bitflags::bitflags! {
    /// EPT entry flags. (SDM Vol. 3C, Section 28.3.2)
    struct EPTFlags: u64 {
        /// Read access.
        const READ =                1 << 0;
        /// Write access.
        const WRITE =               1 << 1;
        /// Execute access.
        const EXECUTE =             1 << 2;
        /// EPT memory type. Only for terminate pages.
        const MEM_TYPE_MASK =       0b111 << 3;
        /// Ignore PAT memory type. Only for terminate pages.
        const IGNORE_PAT =          1 << 6;
        /// Specifies that the entry maps a huge frame instead of a page table.
        /// Only allowed in P2 or P3 tables.
        const HUGE_PAGE =           1 << 7;
        /// If bit 6 of EPTP is 1, accessed flag for EPT.
        const ACCESSED =            1 << 8;
        /// If bit 6 of EPTP is 1, dirty flag for EPT.
        const DIRTY =               1 << 9;
        /// Execute access for user-mode linear addresses.
        const EXECUTE_FOR_USER =    1 << 10;
    }
}

numeric_enum_macro::numeric_enum! {
    #[repr(u8)]
    #[derive(Debug, PartialEq, Clone, Copy)]
    /// EPT memory typing. (SDM Vol. 3C, Section 28.3.7)
    enum EPTMemType {
        Uncached = 0,
        WriteCombining = 1,
        WriteThrough = 4,
        WriteProtected = 5,
        WriteBack = 6,
    }
}

impl EPTFlags {
    fn set_mem_type(&mut self, mem_type: EPTMemType) {
        let mut bits = self.bits();
        bits.set_bits(3..6, mem_type as u64);
        *self = Self::from_bits_truncate(bits)
    }
    fn mem_type(&self) -> Result<EPTMemType, u8> {
        EPTMemType::try_from(self.bits().get_bits(3..6) as u8)
    }
}

impl From<MemFlags> for EPTFlags {
    fn from(f: MemFlags) -> Self {
        if f.is_empty() {
            return Self::empty();
        }
        let mut ret = Self::empty();
        if f.contains(MemFlags::READ) {
            ret |= Self::READ;
        }
        if f.contains(MemFlags::WRITE) {
            ret |= Self::WRITE;
        }
        if f.contains(MemFlags::EXECUTE) {
            ret |= Self::EXECUTE;
        }
        if !f.contains(MemFlags::DEVICE) {
            ret.set_mem_type(EPTMemType::WriteBack);
        }
        ret
    }
}

impl From<EPTFlags> for MemFlags {
    fn from(f: EPTFlags) -> Self {
        let mut ret = MemFlags::empty();
        if f.contains(EPTFlags::READ) {
            ret |= Self::READ;
        }
        if f.contains(EPTFlags::WRITE) {
            ret |= Self::WRITE;
        }
        if f.contains(EPTFlags::EXECUTE) {
            ret |= Self::EXECUTE;
        }
        if let Ok(EPTMemType::Uncached) = f.mem_type() {
            ret |= Self::DEVICE;
        }
        ret
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct EPTEntry(u64);

const PHYS_ADDR_MASK: usize = 0x000f_ffff_ffff_f000; // 12..52

impl GenericPTE for EPTEntry {
    fn new_page(paddr: HostPhysAddr, flags: MemFlags, is_huge: bool) -> Self {
        let mut flags = EPTFlags::from(flags);
        if is_huge {
            flags |= EPTFlags::HUGE_PAGE;
        }
        Self(flags.bits() | (paddr & PHYS_ADDR_MASK) as u64)
    }
    fn new_table(paddr: HostPhysAddr) -> Self {
        let flags = EPTFlags::READ | EPTFlags::WRITE | EPTFlags::EXECUTE;
        Self(flags.bits() | (paddr & PHYS_ADDR_MASK) as u64)
    }
    fn paddr(&self) -> HostPhysAddr {
        self.0 as usize & PHYS_ADDR_MASK
    }
    fn flags(&self) -> MemFlags {
        EPTFlags::from_bits_truncate(self.0).into()
    }
    fn is_unused(&self) -> bool {
        self.0 == 0
    }
    fn is_present(&self) -> bool {
        self.0 & 0x7 != 0 // RWX != 0
    }
    fn is_huge(&self) -> bool {
        EPTFlags::from_bits_truncate(self.0).contains(EPTFlags::HUGE_PAGE)
    }
    fn clear(&mut self) {
        self.0 = 0
    }
}

impl fmt::Debug for EPTEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EPTEntry")
            .field("raw", &self.0)
            .field("hpaddr", &self.paddr())
            .field("flags", &self.flags())
            .field("mem_type", &EPTFlags::from_bits_truncate(self.0).mem_type())
            .finish()
    }
}

/// The VMX extended page table. (SDM Vol. 3C, Section 28.3)
pub type ExtendedPageTable<H> = Level4PageTable<H, EPTEntry>;
