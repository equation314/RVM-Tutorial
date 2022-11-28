use bit_field::BitField;
use bitflags::bitflags;

use crate::arch::msr::{Msr, MsrReadWrite};
use crate::mm::PhysFrame;
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
