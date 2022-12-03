use core::fmt::{Debug, Formatter, Result};
use core::{arch::asm, mem::size_of};

use bit_field::BitField;
use x86::bits64::vmx;
use x86::dtables::{self, DescriptorTablePointer};
use x86::segmentation::SegmentSelector;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags};

use super::structs::VmxRegion;
use super::vmcs::{
    self, VmcsControl32, VmcsControl64, VmcsControlNW, VmcsGuest16, VmcsGuest32, VmcsGuest64,
    VmcsGuestNW, VmcsHost16, VmcsHost32, VmcsHost64, VmcsHostNW,
};
use super::VmxPerCpuState;
use crate::arch::{msr::Msr, GeneralRegisters};
use crate::{GuestPhysAddr, RvmHal, RvmResult};

/// A virtual CPU within a guest.
#[repr(C)]
pub struct VmxVcpu<H: RvmHal> {
    guest_regs: GeneralRegisters,
    host_stack_top: u64,
    vmcs: VmxRegion<H>,
}

impl<H: RvmHal> VmxVcpu<H> {
    pub(crate) fn new(percpu: &VmxPerCpuState<H>, entry: GuestPhysAddr) -> RvmResult<Self> {
        let mut vcpu = Self {
            guest_regs: GeneralRegisters::default(),
            host_stack_top: 0,
            vmcs: VmxRegion::new(percpu.vmcs_revision_id, false)?,
        };
        vcpu.setup_vmcs(entry)?;
        info!("[RVM] created VmxVcpu(vmcs: {:#x})", vcpu.vmcs.phys_addr());
        Ok(vcpu)
    }

    /// Run the guest, never return.
    pub fn run(&mut self) -> ! {
        VmcsHostNW::RSP
            .write(&self.host_stack_top as *const _ as usize)
            .unwrap();
        unsafe { self.vmx_launch() }
    }

    /// Basic information about VM exits.
    pub fn exit_info(&self) -> RvmResult<vmcs::VmxExitInfo> {
        vmcs::exit_info()
    }

    /// Guest general-purpose registers.
    pub fn regs(&self) -> &GeneralRegisters {
        &self.guest_regs
    }

    /// Mutable reference of guest general-purpose registers.
    pub fn regs_mut(&mut self) -> &mut GeneralRegisters {
        &mut self.guest_regs
    }

    /// Advance guest `RIP` by `instr_len` bytes.
    pub fn advance_rip(&mut self, instr_len: u8) -> RvmResult {
        Ok(VmcsGuestNW::RIP.write(VmcsGuestNW::RIP.read()? + instr_len as usize)?)
    }
}

// Implementation of private methods
impl<H: RvmHal> VmxVcpu<H> {
    fn setup_vmcs(&mut self, entry: GuestPhysAddr) -> RvmResult {
        let paddr = self.vmcs.phys_addr() as u64;
        unsafe {
            vmx::vmclear(paddr)?;
            vmx::vmptrld(paddr)?;
        }
        self.setup_vmcs_host()?;
        self.setup_vmcs_guest(entry)?;
        self.setup_vmcs_control()?;
        Ok(())
    }

    fn setup_vmcs_host(&mut self) -> RvmResult {
        VmcsHost64::IA32_PAT.write(Msr::IA32_PAT.read())?;
        VmcsHost64::IA32_EFER.write(Msr::IA32_EFER.read())?;

        VmcsHostNW::CR0.write(Cr0::read_raw() as _)?;
        VmcsHostNW::CR3.write(Cr3::read_raw().0.start_address().as_u64() as _)?;
        VmcsHostNW::CR4.write(Cr4::read_raw() as _)?;

        VmcsHost16::ES_SELECTOR.write(x86::segmentation::es().bits())?;
        VmcsHost16::CS_SELECTOR.write(x86::segmentation::cs().bits())?;
        VmcsHost16::SS_SELECTOR.write(x86::segmentation::ss().bits())?;
        VmcsHost16::DS_SELECTOR.write(x86::segmentation::ds().bits())?;
        VmcsHost16::FS_SELECTOR.write(x86::segmentation::fs().bits())?;
        VmcsHost16::GS_SELECTOR.write(x86::segmentation::gs().bits())?;
        VmcsHostNW::FS_BASE.write(Msr::IA32_FS_BASE.read() as _)?;
        VmcsHostNW::GS_BASE.write(Msr::IA32_GS_BASE.read() as _)?;

        let tr = unsafe { x86::task::tr() };
        let mut gdtp = DescriptorTablePointer::<u64>::default();
        let mut idtp = DescriptorTablePointer::<u64>::default();
        unsafe {
            dtables::sgdt(&mut gdtp);
            dtables::sidt(&mut idtp);
        }
        VmcsHost16::TR_SELECTOR.write(tr.bits())?;
        VmcsHostNW::TR_BASE.write(get_tr_base(tr, &gdtp) as _)?;
        VmcsHostNW::GDTR_BASE.write(gdtp.base as _)?;
        VmcsHostNW::IDTR_BASE.write(idtp.base as _)?;
        VmcsHostNW::RIP.write(Self::vmx_exit as usize)?;

        VmcsHostNW::IA32_SYSENTER_ESP.write(0)?;
        VmcsHostNW::IA32_SYSENTER_EIP.write(0)?;
        VmcsHost32::IA32_SYSENTER_CS.write(0)?;
        Ok(())
    }

    fn setup_vmcs_guest(&mut self, entry: GuestPhysAddr) -> RvmResult {
        // enable protected mode and paging.
        let cr0_guest = Cr0Flags::PROTECTED_MODE_ENABLE
            | Cr0Flags::EXTENSION_TYPE
            | Cr0Flags::NUMERIC_ERROR
            | Cr0Flags::PAGING;
        let cr0_host_owned =
            Cr0Flags::NUMERIC_ERROR | Cr0Flags::NOT_WRITE_THROUGH | Cr0Flags::CACHE_DISABLE;
        let cr0_read_shadow = Cr0Flags::NUMERIC_ERROR;
        VmcsGuestNW::CR0.write(cr0_guest.bits() as _)?;
        VmcsControlNW::CR0_GUEST_HOST_MASK.write(cr0_host_owned.bits() as _)?;
        VmcsControlNW::CR0_READ_SHADOW.write(cr0_read_shadow.bits() as _)?;

        // enable physical address extensions that required in IA-32e mode.
        let cr4_guest = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
        let cr4_host_owned = Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
        let cr4_read_shadow = 0;
        VmcsGuestNW::CR4.write(cr4_guest.bits() as _)?;
        VmcsControlNW::CR4_GUEST_HOST_MASK.write(cr4_host_owned.bits() as _)?;
        VmcsControlNW::CR4_READ_SHADOW.write(cr4_read_shadow)?;

        macro_rules! set_guest_segment {
            ($seg: ident, $access_rights: expr) => {{
                use VmcsGuest16::*;
                use VmcsGuest32::*;
                use VmcsGuestNW::*;
                concat_idents!($seg, _SELECTOR).write(0)?;
                concat_idents!($seg, _BASE).write(0)?;
                concat_idents!($seg, _LIMIT).write(0xffff)?;
                concat_idents!($seg, _ACCESS_RIGHTS).write($access_rights)?;
            }};
        }

        set_guest_segment!(ES, 0x93); // 16-bit, present, data, read/write, accessed
        set_guest_segment!(CS, 0x209b); // 64-bit, present, code, exec/read, accessed
        set_guest_segment!(SS, 0x93);
        set_guest_segment!(DS, 0x93);
        set_guest_segment!(FS, 0x93);
        set_guest_segment!(GS, 0x93);
        set_guest_segment!(TR, 0x8b); // present, system, 32-bit TSS busy
        set_guest_segment!(LDTR, 0x82); // present, system, LDT

        VmcsGuestNW::GDTR_BASE.write(0)?;
        VmcsGuest32::GDTR_LIMIT.write(0xffff)?;
        VmcsGuestNW::IDTR_BASE.write(0)?;
        VmcsGuest32::IDTR_LIMIT.write(0xffff)?;

        VmcsGuestNW::CR3.write(Cr3::read_raw().0.start_address().as_u64() as _)?; // TODO
        VmcsGuestNW::DR7.write(0x400)?;
        VmcsGuestNW::RSP.write(0)?;
        VmcsGuestNW::RIP.write(entry)?;
        VmcsGuestNW::RFLAGS.write(0x2)?;
        VmcsGuestNW::PENDING_DBG_EXCEPTIONS.write(0)?;
        VmcsGuestNW::IA32_SYSENTER_ESP.write(0)?;
        VmcsGuestNW::IA32_SYSENTER_EIP.write(0)?;
        VmcsGuest32::IA32_SYSENTER_CS.write(0)?;

        VmcsGuest32::INTERRUPTIBILITY_STATE.write(0)?;
        VmcsGuest32::ACTIVITY_STATE.write(0)?;
        VmcsGuest32::VMX_PREEMPTION_TIMER_VALUE.write(0)?;

        VmcsGuest64::LINK_PTR.write(u64::MAX)?; // SDM Vol. 3C, Section 24.4.2
        VmcsGuest64::IA32_DEBUGCTL.write(0)?;
        VmcsGuest64::IA32_PAT.write(Msr::IA32_PAT.read())?;
        VmcsGuest64::IA32_EFER.write(Msr::IA32_EFER.read())?; // required in IA-32e mode
        Ok(())
    }

    fn setup_vmcs_control(&mut self) -> RvmResult {
        // Intercept NMI, pass-through external interrupts.
        use super::vmcs::controls::*;
        use PinbasedControls as PinCtrl;
        vmcs::set_control(
            VmcsControl32::PINBASED_EXEC_CONTROLS,
            Msr::IA32_VMX_TRUE_PINBASED_CTLS,
            Msr::IA32_VMX_PINBASED_CTLS.read() as u32,
            PinCtrl::NMI_EXITING.bits(),
            0,
        )?;

        // Activate secondary controls, disable CR3 load/store interception.
        use PrimaryControls as CpuCtrl;
        vmcs::set_control(
            VmcsControl32::PRIMARY_PROCBASED_EXEC_CONTROLS,
            Msr::IA32_VMX_TRUE_PROCBASED_CTLS,
            Msr::IA32_VMX_PROCBASED_CTLS.read() as u32,
            CpuCtrl::SECONDARY_CONTROLS.bits(),
            (CpuCtrl::CR3_LOAD_EXITING | CpuCtrl::CR3_STORE_EXITING).bits(),
        )?;

        // Enable RDTSCP, INVPCID.
        use SecondaryControls as CpuCtrl2;
        vmcs::set_control(
            VmcsControl32::SECONDARY_PROCBASED_EXEC_CONTROLS,
            Msr::IA32_VMX_PROCBASED_CTLS2,
            0,
            (CpuCtrl2::ENABLE_RDTSCP | CpuCtrl2::ENABLE_INVPCID).bits(),
            0,
        )?;

        // Switch to 64-bit host, switch IA32_PAT/IA32_EFER on VM exit.
        use ExitControls as ExitCtrl;
        vmcs::set_control(
            VmcsControl32::VMEXIT_CONTROLS,
            Msr::IA32_VMX_TRUE_EXIT_CTLS,
            Msr::IA32_VMX_EXIT_CTLS.read() as u32,
            (ExitCtrl::HOST_ADDRESS_SPACE_SIZE
                | ExitCtrl::SAVE_IA32_PAT
                | ExitCtrl::LOAD_IA32_PAT
                | ExitCtrl::SAVE_IA32_EFER
                | ExitCtrl::LOAD_IA32_EFER)
                .bits(),
            0,
        )?;

        // Switch to 64-bit guest, load guest IA32_PAT/IA32_EFER on VM entry.
        use EntryControls as EntryCtrl;
        vmcs::set_control(
            VmcsControl32::VMENTRY_CONTROLS,
            Msr::IA32_VMX_TRUE_ENTRY_CTLS,
            Msr::IA32_VMX_ENTRY_CTLS.read() as u32,
            (EntryCtrl::IA32E_MODE_GUEST | EntryCtrl::LOAD_IA32_PAT | EntryCtrl::LOAD_IA32_EFER)
                .bits(),
            0,
        )?;

        // No MSR switches if hypervisor doesn't use and there is only one vCPU.
        VmcsControl32::VMEXIT_MSR_STORE_COUNT.write(0)?;
        VmcsControl32::VMEXIT_MSR_LOAD_COUNT.write(0)?;
        VmcsControl32::VMENTRY_MSR_LOAD_COUNT.write(0)?;

        // Pass-through exceptions, I/O instructions, and MSR read/write.
        VmcsControl32::EXCEPTION_BITMAP.write(0)?;
        VmcsControl64::IO_BITMAP_A_ADDR.write(0)?;
        VmcsControl64::IO_BITMAP_B_ADDR.write(0)?;
        VmcsControl64::MSR_BITMAPS_ADDR.write(0)?; // TODO
        Ok(())
    }

    #[naked]
    unsafe extern "C" fn vmx_launch(&mut self) -> ! {
        asm!(
            "mov    [rdi + {host_stack_top}], rsp", // save current RSP to Vcpu::host_stack_top
            "mov    rsp, rdi",                      // set RSP to guest regs area
            restore_regs_from_stack!(),
            "vmlaunch",
            "jmp    {failed}",
            host_stack_top = const size_of::<GeneralRegisters>(),
            failed = sym Self::vmx_entry_failed,
            options(noreturn),
        )
    }

    #[naked]
    unsafe extern "C" fn vmx_exit(&mut self) -> ! {
        asm!(
            save_regs_to_stack!(),
            "mov    r15, rsp",                      // save temporary RSP to r15
            "mov    rdi, rsp",                      // set the first arg to &Vcpu
            "mov    rsp, [rsp + {host_stack_top}]", // set RSP to Vcpu::host_stack_top
            "call   {vmexit_handler}",              // call vmexit_handler
            "mov    rsp, r15",                      // load temporary RSP from r15
            restore_regs_from_stack!(),
            "vmresume",
            "jmp    {failed}",
            host_stack_top = const size_of::<GeneralRegisters>(),
            vmexit_handler = sym Self::vmexit_handler,
            failed = sym Self::vmx_entry_failed,
            options(noreturn),
        );
    }

    fn vmx_entry_failed() -> ! {
        panic!("{}", vmcs::instruction_error().as_str())
    }

    fn vmexit_handler(&mut self) {
        H::vmexit_handler(self);
    }
}

impl<H: RvmHal> Drop for VmxVcpu<H> {
    fn drop(&mut self) {
        unsafe { vmx::vmclear(self.vmcs.phys_addr() as u64).unwrap() };
        info!("[RVM] dropped VmxVcpu(vmcs: {:#x})", self.vmcs.phys_addr());
    }
}

fn get_tr_base(tr: SegmentSelector, gdt: &DescriptorTablePointer<u64>) -> u64 {
    let index = tr.index() as usize;
    let table_len = (gdt.limit as usize + 1) / core::mem::size_of::<u64>();
    let table = unsafe { core::slice::from_raw_parts(gdt.base, table_len) };
    let entry = table[index];
    if entry & (1 << 47) != 0 {
        // present
        let base_low = entry.get_bits(16..40) | entry.get_bits(56..64) << 24;
        let base_high = table[index + 1] & 0xffff_ffff;
        base_low | base_high << 32
    } else {
        // no present
        0
    }
}

impl<H: RvmHal> Debug for VmxVcpu<H> {
    fn fmt(&self, f: &mut Formatter) -> Result {
        (|| -> RvmResult<Result> {
            Ok(f.debug_struct("VmxVcpu")
                .field("guest_regs", &self.guest_regs)
                .field("rip", &VmcsGuestNW::RIP.read()?)
                .field("rsp", &VmcsGuestNW::RSP.read()?)
                .field("rflags", &VmcsGuestNW::RFLAGS.read()?)
                .field("cr0", &VmcsGuestNW::CR0.read()?)
                .field("cr3", &VmcsGuestNW::CR3.read()?)
                .field("cr4", &VmcsGuestNW::CR4.read()?)
                .field("cs", &VmcsGuest16::CS_SELECTOR.read()?)
                .field("fs_base", &VmcsGuestNW::FS_BASE.read()?)
                .field("gs_base", &VmcsGuestNW::GS_BASE.read()?)
                .field("tss", &VmcsGuest16::TR_SELECTOR.read()?)
                .finish())
        })()
        .unwrap()
    }
}
