use x86::msr::{rdmsr, wrmsr};

/// X86 model-specific registers. (SDM Vol. 4)
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum Msr {
    IA32_FEATURE_CONTROL = 0x3a,
    IA32_VMX_BASIC = 0x480,

    IA32_VMX_CR0_FIXED0 = 0x486,
    IA32_VMX_CR0_FIXED1 = 0x487,
    IA32_VMX_CR4_FIXED0 = 0x488,
    IA32_VMX_CR4_FIXED1 = 0x489,
}

impl Msr {
    /// Read 64 bits msr register.
    #[inline(always)]
    pub fn read(self) -> u64 {
        unsafe { rdmsr(self as _) }
    }

    /// Write 64 bits to msr register.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this write operation has no unsafe side
    /// effects.
    #[inline(always)]
    pub unsafe fn write(self, value: u64) {
        wrmsr(self as _, value)
    }
}

pub(super) trait MsrReadWrite {
    const MSR: Msr;

    fn read_raw() -> u64 {
        Self::MSR.read()
    }

    unsafe fn write_raw(flags: u64) {
        Self::MSR.write(flags);
    }
}
