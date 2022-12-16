use bit_field::BitField;
use bitflags::bitflags;

use crate::arch::msr::{Msr, MsrReadWrite};
use crate::mm::{PhysFrame, PAGE_SIZE};
use crate::{HostPhysAddr, RvmHal, RvmResult};

/// VMCS/VMXON region in 4K size. (SDM Vol. 3C, Section 24.2)
#[derive(Debug)]
pub struct VmxRegion<H: RvmHal> {
    frame: PhysFrame<H>,
}

impl<H: RvmHal> VmxRegion<H> {
    pub const unsafe fn uninit() -> Self {
        Self {
            frame: PhysFrame::uninit(),
        }
    }

    pub fn new(revision_id: u32, shadow_indicator: bool) -> RvmResult<Self> {
        let frame = PhysFrame::alloc_zero()?;
        unsafe {
            (*(frame.as_mut_ptr() as *mut u32))
                .set_bits(0..=30, revision_id)
                .set_bit(31, shadow_indicator);
        }
        Ok(Self { frame })
    }

    pub fn phys_addr(&self) -> HostPhysAddr {
        self.frame.start_paddr()
    }
}

#[derive(Debug)]
pub struct MsrBitmap<H: RvmHal> {
    frame: PhysFrame<H>,
}

impl<H: RvmHal> MsrBitmap<H> {
    pub fn passthrough_all() -> RvmResult<Self> {
        Ok(Self {
            frame: PhysFrame::alloc_zero()?,
        })
    }

    #[allow(unused)]
    pub fn intercept_all() -> RvmResult<Self> {
        let mut frame = PhysFrame::alloc()?;
        frame.fill(u8::MAX);
        Ok(Self { frame })
    }

    pub fn phys_addr(&self) -> HostPhysAddr {
        self.frame.start_paddr()
    }

    fn set_intercept(&mut self, msr: u32, is_write: bool, intercept: bool) {
        let offset = if msr <= 0x1fff {
            if !is_write {
                0 // Read bitmap for low MSRs (0x0000_0000..0x0000_1FFF)
            } else {
                2 // Write bitmap for low MSRs (0x0000_0000..0x0000_1FFF)
            }
        } else if (0xc000_0000..=0xc000_1fff).contains(&msr) {
            if !is_write {
                1 // Read bitmap for high MSRs (0xC000_0000..0xC000_1FFF)
            } else {
                3 // Write bitmap for high MSRs (0xC000_0000..0xC000_1FFF)
            }
        } else {
            unreachable!()
        } * 1024;
        let bitmap =
            unsafe { core::slice::from_raw_parts_mut(self.frame.as_mut_ptr().add(offset), 1024) };
        let msr = msr & 0x1fff;
        let byte = (msr / 8) as usize;
        let bits = msr % 8;
        if intercept {
            bitmap[byte] |= 1 << bits;
        } else {
            bitmap[byte] &= !(1 << bits);
        }
    }

    pub fn set_read_intercept(&mut self, msr: u32, intercept: bool) {
        self.set_intercept(msr, false, intercept);
    }

    pub fn set_write_intercept(&mut self, msr: u32, intercept: bool) {
        self.set_intercept(msr, true, intercept);
    }
}

/// Reporting Register of Basic VMX Capabilities. (SDM Vol. 3D, Appendix A.1)
#[derive(Debug)]
pub struct VmxBasic {
    /// The 31-bit VMCS revision identifier used by the processor.
    pub revision_id: u32,
    /// The number of bytes that software should allocate for the VMXON region
    /// and any VMCS region.
    pub region_size: u16,
    /// The width of the physical addresses that may be used for the VMXON
    /// region, each VMCS, and data structures referenced by pointers in a VMCS.
    pub is_32bit_address: bool,
    /// The memory type that should be used for the VMCS, for data structures
    /// referenced by pointers in the VMCS.
    pub mem_type: u8,
    /// The processor reports information in the VM-exit instruction-information
    /// field on VM exits due to execution of the INS and OUTS instructions.
    pub io_exit_info: bool,
    /// If any VMX controls that default to 1 may be cleared to 0.
    pub vmx_flex_controls: bool,
}

impl MsrReadWrite for VmxBasic {
    const MSR: Msr = Msr::IA32_VMX_BASIC;
}

impl VmxBasic {
    pub const VMX_MEMORY_TYPE_WRITE_BACK: u8 = 6;

    /// Read the current IA32_VMX_BASIC flags.
    pub fn read() -> Self {
        let msr = Self::read_raw();
        Self {
            revision_id: msr.get_bits(0..31) as u32,
            region_size: msr.get_bits(32..45) as u16,
            is_32bit_address: msr.get_bit(48),
            mem_type: msr.get_bits(50..54) as u8,
            io_exit_info: msr.get_bit(54),
            vmx_flex_controls: msr.get_bit(55),
        }
    }
}

bitflags! {
    /// IA32_FEATURE_CONTROL flags.
    pub struct FeatureControlFlags: u64 {
       /// Lock bit: when set, locks this MSR from being written. when clear,
       /// VMXON causes a #GP.
       const LOCKED = 1 << 0;
       /// Enable VMX inside SMX operation.
       const VMXON_ENABLED_INSIDE_SMX = 1 << 1;
       /// Enable VMX outside SMX operation.
       const VMXON_ENABLED_OUTSIDE_SMX = 1 << 2;
   }
}

/// Control Features in Intel 64 Processor. (SDM Vol. 3C, Section 23.7)
pub struct FeatureControl;

impl MsrReadWrite for FeatureControl {
    const MSR: Msr = Msr::IA32_FEATURE_CONTROL;
}

impl FeatureControl {
    /// Read the current IA32_FEATURE_CONTROL flags.
    pub fn read() -> FeatureControlFlags {
        FeatureControlFlags::from_bits_truncate(Self::read_raw())
    }

    /// Write IA32_FEATURE_CONTROL flags, preserving reserved values.
    pub fn write(flags: FeatureControlFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(FeatureControlFlags::all().bits());
        let new_value = reserved | flags.bits();
        unsafe { Self::write_raw(new_value) };
    }
}

bitflags! {
    /// Extended-Page-Table Pointer. (SDM Vol. 3C, Section 24.6.11)
    pub struct EPTPointer: u64 {
        /// EPT paging-structure memory type: Uncacheable (UC).
        #[allow(clippy::identity_op)]
        const MEM_TYPE_UC = 0 << 0;
        /// EPT paging-structure memory type: Write-back (WB).
        #[allow(clippy::identity_op)]
        const MEM_TYPE_WB = 6 << 0;
        /// EPT page-walk length 1.
        const WALK_LENGTH_1 = 0 << 3;
        /// EPT page-walk length 2.
        const WALK_LENGTH_2 = 1 << 3;
        /// EPT page-walk length 3.
        const WALK_LENGTH_3 = 2 << 3;
        /// EPT page-walk length 4.
        const WALK_LENGTH_4 = 3 << 3;
        /// Setting this control to 1 enables accessed and dirty flags for EPT.
        const ENABLE_ACCESSED_DIRTY = 1 << 6;
    }
}

impl EPTPointer {
    pub fn from_table_phys(pml4_paddr: HostPhysAddr) -> Self {
        let aligned_addr = pml4_paddr & !(PAGE_SIZE - 1);
        let flags = unsafe { Self::from_bits_unchecked(aligned_addr as u64) };
        flags | Self::MEM_TYPE_WB | Self::WALK_LENGTH_4 | Self::ENABLE_ACCESSED_DIRTY
    }
}
