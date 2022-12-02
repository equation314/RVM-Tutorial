mod structs;
mod vcpu;
mod vmcs;

use raw_cpuid::CpuId;
use x86::{bits64::vmx, vmx::VmFail};
use x86_64::registers::control::{Cr0, Cr4, Cr4Flags};

use self::structs::{FeatureControl, FeatureControlFlags, VmxBasic, VmxRegion};
use crate::arch::msr::Msr;
use crate::error::{RvmError, RvmResult};
use crate::hal::RvmHal;

pub use self::vcpu::VmxVcpu as RvmVcpu;
pub use self::VmxPerCpuState as ArchPerCpuState;

pub fn has_hardware_support() -> bool {
    if let Some(feature) = CpuId::new().get_feature_info() {
        feature.has_vmx()
    } else {
        false
    }
}

pub struct VmxPerCpuState<H: RvmHal> {
    vmcs_revision_id: u32,
    vmx_region: VmxRegion<H>,
}

impl<H: RvmHal> VmxPerCpuState<H> {
    pub const fn new() -> Self {
        Self {
            vmcs_revision_id: 0,
            vmx_region: unsafe { VmxRegion::uninit() },
        }
    }

    pub fn is_enabled(&self) -> bool {
        Cr4::read().contains(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS)
    }

    pub fn hardware_enable(&mut self) -> RvmResult {
        if !has_hardware_support() {
            return rvm_err!(Unsupported, "CPU does not support feature VMX");
        }
        if self.is_enabled() {
            return rvm_err!(ResourceBusy, "VMX is already turned on");
        }

        // Enable VMXON, if required.
        let ctrl = FeatureControl::read();
        let locked = ctrl.contains(FeatureControlFlags::LOCKED);
        let vmxon_outside = ctrl.contains(FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX);
        if !locked {
            FeatureControl::write(
                ctrl | FeatureControlFlags::LOCKED | FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX,
            )
        } else if !vmxon_outside {
            return rvm_err!(Unsupported, "VMX disabled by BIOS");
        }

        // Check control registers are in a VMX-friendly state. (SDM Vol. 3C, Appendix A.7, A.8)
        macro_rules! cr_is_valid {
            ($value: expr, $crx: ident) => {{
                use Msr::*;
                let value = $value;
                let fixed0 = concat_idents!(IA32_VMX_, $crx, _FIXED0).read();
                let fixed1 = concat_idents!(IA32_VMX_, $crx, _FIXED1).read();
                (!fixed0 | value != 0) && (fixed1 | !value != 0)
            }};
        }
        if !cr_is_valid!(Cr0::read().bits(), CR0) {
            return rvm_err!(BadState, "host CR0 is not valid in VMX operation");
        }
        if !cr_is_valid!(Cr4::read().bits(), CR4) {
            return rvm_err!(BadState, "host CR4 is not valid in VMX operation");
        }

        // Get VMCS revision identifier in IA32_VMX_BASIC MSR.
        let vmx_basic = VmxBasic::read();
        if vmx_basic.region_size as usize != crate::mm::PAGE_SIZE {
            return rvm_err!(Unsupported);
        }
        if vmx_basic.mem_type != VmxBasic::VMX_MEMORY_TYPE_WRITE_BACK {
            return rvm_err!(Unsupported);
        }
        if vmx_basic.is_32bit_address {
            return rvm_err!(Unsupported);
        }
        if !vmx_basic.io_exit_info {
            return rvm_err!(Unsupported);
        }
        if !vmx_basic.vmx_flex_controls {
            return rvm_err!(Unsupported);
        }
        self.vmcs_revision_id = vmx_basic.revision_id;
        self.vmx_region = VmxRegion::new(vmx_basic.revision_id, false)?;

        unsafe {
            // Enable VMX using the VMXE bit.
            Cr4::write(Cr4::read() | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS);
            // Execute VMXON.
            vmx::vmxon(self.vmx_region.phys_addr() as _)?;
        }
        info!("[RVM] successed to turn on VMX.");

        Ok(())
    }

    pub fn hardware_disable(&mut self) -> RvmResult {
        if !self.is_enabled() {
            return rvm_err!(BadState, "VMX is not enabled");
        }

        unsafe {
            // Execute VMXOFF.
            vmx::vmxoff()?;
            // Remove VMXE bit in CR4.
            Cr4::update(|cr4| cr4.remove(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS));
        };
        info!("[RVM] successed to turn off VMX.");

        self.vmx_region = unsafe { VmxRegion::uninit() };
        Ok(())
    }
}

impl From<VmFail> for RvmError {
    fn from(err: VmFail) -> Self {
        rvm_err_type!(BadState, format_args!("VMX instruction failed: {:?}", err))
    }
}
