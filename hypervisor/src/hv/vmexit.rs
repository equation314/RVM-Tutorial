use super::hal::RvmHalImpl;
use rvm::arch::VmxExitReason;
use rvm::{RvmResult, RvmVcpu};

type Vcpu = RvmVcpu<RvmHalImpl>;

const VM_EXIT_INSTR_LEN_CPUID: u8 = 2;
const VM_EXIT_INSTR_LEN_VMCALL: u8 = 3;

fn handle_cpuid(vcpu: &mut Vcpu) -> RvmResult {
    use raw_cpuid::{cpuid, CpuIdResult};

    const LEAF_FEATURE_INFO: u32 = 0x1;
    const LEAF_HYPERVISOR_INFO: u32 = 0x4000_0000;
    const LEAF_HYPERVISOR_FEATURE: u32 = 0x4000_0001;
    const VENDOR_STR: &[u8; 12] = b"RVMRVMRVMRVM";
    let vendor_regs = unsafe { &*(VENDOR_STR.as_ptr() as *const [u32; 3]) };

    let regs = vcpu.regs_mut();
    let function = regs.rax as u32;
    let res = match function {
        LEAF_FEATURE_INFO => {
            const FEATURE_VMX: u32 = 1 << 5;
            const FEATURE_HYPERVISOR: u32 = 1 << 31;
            let mut res = cpuid!(regs.rax, regs.rcx);
            res.ecx &= !FEATURE_VMX;
            res.ecx |= FEATURE_HYPERVISOR;
            res
        }
        LEAF_HYPERVISOR_INFO => CpuIdResult {
            eax: LEAF_HYPERVISOR_FEATURE,
            ebx: vendor_regs[0],
            ecx: vendor_regs[1],
            edx: vendor_regs[2],
        },
        LEAF_HYPERVISOR_FEATURE => CpuIdResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        _ => cpuid!(regs.rax, regs.rcx),
    };

    debug!(
        "VM exit: CPUID({:#x}, {:#x}): {:?}",
        regs.rax, regs.rcx, res
    );
    regs.rax = res.eax as _;
    regs.rbx = res.ebx as _;
    regs.rcx = res.ecx as _;
    regs.rdx = res.edx as _;
    vcpu.advance_rip(VM_EXIT_INSTR_LEN_CPUID)?;
    Ok(())
}

fn handle_hypercall(vcpu: &mut Vcpu) -> RvmResult {
    let regs = vcpu.regs();
    info!(
        "VM exit: VMCALL({:#x}): {:?}",
        regs.rax,
        [regs.rdi, regs.rsi, regs.rdx, regs.rcx]
    );
    vcpu.advance_rip(VM_EXIT_INSTR_LEN_VMCALL)?;
    Ok(())
}

fn handle_ept_violation(vcpu: &Vcpu, guest_rip: usize) -> RvmResult {
    let fault_info = vcpu.nested_page_fault_info()?;
    panic!(
        "VM exit: EPT violation @ {:#x}, fault_paddr={:#x}, access_flags=({:?})",
        guest_rip, fault_info.fault_guest_paddr, fault_info.access_flags
    );
}

pub fn vmexit_handler(vcpu: &mut Vcpu) -> RvmResult {
    let exit_info = vcpu.exit_info()?;
    trace!("VM exit: {:#x?}", exit_info);

    if exit_info.entry_failure {
        panic!("VM entry failed: {:#x?}", exit_info);
    }

    let res = match exit_info.exit_reason {
        VmxExitReason::CPUID => handle_cpuid(vcpu),
        VmxExitReason::VMCALL => handle_hypercall(vcpu),
        VmxExitReason::EPT_VIOLATION => handle_ept_violation(vcpu, exit_info.guest_rip),
        _ => panic!(
            "Unhandled VM-Exit reason {:?}:\n{:#x?}",
            exit_info.exit_reason, vcpu
        ),
    };

    if res.is_err() {
        panic!(
            "Failed to handle VM-exit {:?}:\n{:#x?}",
            exit_info.exit_reason, vcpu
        );
    }

    Ok(())
}
