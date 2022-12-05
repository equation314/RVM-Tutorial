use core::arch::asm;
use x86::bits64::rflags::{self, RFlags};
use x86::vmx::{Result, VmFail};

/// Helper used to extract VMX-specific Result in accordance with
/// conventions described in Intel SDM, Volume 3C, Section 30.2.
// We inline this to provide an obstruction-free path from this function's
// call site to the moment where `rflags::read()` reads RFLAGS. Otherwise it's
// possible for RFLAGS register to be clobbered by a function prologue,
// see https://github.com/gz/rust-x86/pull/50.
#[inline(always)]
fn vmx_capture_status() -> Result<()> {
    let flags = rflags::read();

    if flags.contains(RFlags::FLAGS_ZF) {
        Err(VmFail::VmFailValid)
    } else if flags.contains(RFlags::FLAGS_CF) {
        Err(VmFail::VmFailInvalid)
    } else {
        Ok(())
    }
}

/// INVEPT type. (SDM Vol. 3C, Section 30.3)
#[repr(u64)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum InvEptType {
    /// The logical processor invalidates all mappings associated with bits
    /// 51:12 of the EPT pointer (EPTP) specified in the INVEPT descriptor.
    /// It may invalidate other mappings as well.
    SingleContext = 1,
    /// The logical processor invalidates mappings associated with all EPTPs.
    Global = 2,
}

/// Invalidate Translations Derived from EPT. (SDM Vol. 3C, Section 30.3)
///
/// Invalidates mappings in the translation lookaside buffers (TLBs) and
/// paging-structure caches that were derived from extended page tables (EPT).
/// (See Chapter 28, “VMX Support for Address Translation”.) Invalidation is
/// based on the INVEPT type specified in the register operand and the INVEPT
/// descriptor specified in the memory operand.
pub unsafe fn invept(inv_type: InvEptType, eptp: u64) -> Result<()> {
    let invept_desc = [eptp, 0];
    asm!("invept {0}, [{1}]", in(reg) inv_type as u64, in(reg) &invept_desc);
    vmx_capture_status()
}
