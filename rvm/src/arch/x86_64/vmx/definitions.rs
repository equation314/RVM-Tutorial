use core::fmt::{Debug, Formatter, Result};

/// VM instruction error numbers. (SDM Vol. 3C, Section 30.4)
pub struct VmxInstructionError(u32);

impl VmxInstructionError {
    pub fn as_str(&self) -> &str {
        match self.0 {
            0 => "OK",
            1 => "VMCALL executed in VMX root operation",
            2 => "VMCLEAR with invalid physical address",
            3 => "VMCLEAR with VMXON pointer",
            4 => "VMLAUNCH with non-clear VMCS",
            5 => "VMRESUME with non-launched VMCS",
            6 => "VMRESUME after VMXOFF (VMXOFF and VMXON between VMLAUNCH and VMRESUME)",
            7 => "VM entry with invalid control field(s)",
            8 => "VM entry with invalid host-state field(s)",
            9 => "VMPTRLD with invalid physical address",
            10 => "VMPTRLD with VMXON pointer",
            11 => "VMPTRLD with incorrect VMCS revision identifier",
            12 => "VMREAD/VMWRITE from/to unsupported VMCS component",
            13 => "VMWRITE to read-only VMCS component",
            15 => "VMXON executed in VMX root operation",
            16 => "VM entry with invalid executive-VMCS pointer",
            17 => "VM entry with non-launched executive VMCS",
            18 => "VM entry with executive-VMCS pointer not VMXON pointer (when attempting to deactivate the dual-monitor treatment of SMIs and SMM)",
            19 => "VMCALL with non-clear VMCS (when attempting to activate the dual-monitor treatment of SMIs and SMM)",
            20 => "VMCALL with invalid VM-exit control fields",
            22 => "VMCALL with incorrect MSEG revision identifier (when attempting to activate the dual-monitor treatment of SMIs and SMM)",
            23 => "VMXOFF under dual-monitor treatment of SMIs and SMM",
            24 => "VMCALL with invalid SMM-monitor features (when attempting to activate the dual-monitor treatment of SMIs and SMM)",
            25 => "VM entry with invalid VM-execution control fields in executive VMCS (when attempting to return from SMM)",
            26 => "VM entry with events blocked by MOV SS",
            28 => "Invalid operand to INVEPT/INVVPID",
            _ => "[INVALID]",
        }
    }
}

impl From<u32> for VmxInstructionError {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Debug for VmxInstructionError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "VmxInstructionError({}, {:?})", self.0, self.as_str())
    }
}

numeric_enum_macro::numeric_enum! {
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(non_camel_case_types)]
/// VMX basic exit reasons. (SDM Vol. 3D, Appendix C)
pub enum VmxExitReason {
    EXCEPTION_NMI = 0,
    EXTERNAL_INTERRUPT = 1,
    TRIPLE_FAULT = 2,
    INIT = 3,
    SIPI = 4,
    SMI = 5,
    OTHER_SMI = 6,
    INTERRUPT_WINDOW = 7,
    NMI_WINDOW = 8,
    TASK_SWITCH = 9,
    CPUID = 10,
    GETSEC = 11,
    HLT = 12,
    INVD = 13,
    INVLPG = 14,
    RDPMC = 15,
    RDTSC = 16,
    RSM = 17,
    VMCALL = 18,
    VMCLEAR = 19,
    VMLAUNCH = 20,
    VMPTRLD = 21,
    VMPTRST = 22,
    VMREAD = 23,
    VMRESUME = 24,
    VMWRITE = 25,
    VMOFF = 26,
    VMON = 27,
    CR_ACCESS = 28,
    DR_ACCESS = 29,
    IO_INSTRUCTION = 30,
    MSR_READ = 31,
    MSR_WRITE = 32,
    INVALID_GUEST_STATE = 33,
    MSR_LOAD_FAIL = 34,
    MWAIT_INSTRUCTION = 36,
    MONITOR_TRAP_FLAG = 37,
    MONITOR_INSTRUCTION = 39,
    PAUSE_INSTRUCTION = 40,
    MCE_DURING_VMENTRY = 41,
    TPR_BELOW_THRESHOLD = 43,
    APIC_ACCESS = 44,
    VIRTUALIZED_EOI = 45,
    GDTR_IDTR = 46,
    LDTR_TR = 47,
    EPT_VIOLATION = 48,
    EPT_MISCONFIG = 49,
    INVEPT = 50,
    RDTSCP = 51,
    PREEMPTION_TIMER = 52,
    INVVPID = 53,
    WBINVD = 54,
    XSETBV = 55,
    APIC_WRITE = 56,
    RDRAND = 57,
    INVPCID = 58,
    VMFUNC = 59,
    ENCLS = 60,
    RDSEED = 61,
    PML_FULL = 62,
    XSAVES = 63,
    XRSTORS = 64,
    PCONFIG = 65,
    SPP_EVENT = 66,
    UMWAIT = 67,
    TPAUSE = 68,
    LOADIWKEY = 69,
}
}

numeric_enum_macro::numeric_enum! {
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// The interruption type (bits 10:8) in VM-Entry Interruption-Information Field
/// and VM-Exit Interruption-Information Field. (SDM Vol. 3C, Section 24.8.3, 24.9.2)
pub enum VmxInterruptionType {
    /// External interrupt
    External = 0,
    /// Reserved
    Reserved = 1,
    /// Non-maskable interrupt (NMI)
    NMI = 2,
    /// Hardware exception (e.g,. #PF)
    HardException = 3,
    /// Software interrupt (INT n)
    SoftIntr = 4,
    /// Privileged software exception (INT1)
    PrivSoftException = 5,
    /// Software exception (INT3 or INTO)
    SoftException = 6,
    /// Other event
    Other = 7,
}
}

impl VmxInterruptionType {
    /// Whether the exception/interrupt with `vector` has an error code.
    pub const fn vector_has_error_code(vector: u8) -> bool {
        use x86::irq::*;
        matches!(
            vector,
            DOUBLE_FAULT_VECTOR
                | INVALID_TSS_VECTOR
                | SEGMENT_NOT_PRESENT_VECTOR
                | STACK_SEGEMENT_FAULT_VECTOR
                | GENERAL_PROTECTION_FAULT_VECTOR
                | PAGE_FAULT_VECTOR
                | ALIGNMENT_CHECK_VECTOR
        )
    }

    /// Determine interruption type by the interrupt vector.
    pub const fn from_vector(vector: u8) -> Self {
        // SDM Vol. 3C, Section 24.8.3
        use x86::irq::*;
        match vector {
            DEBUG_VECTOR => Self::PrivSoftException,
            NONMASKABLE_INTERRUPT_VECTOR => Self::NMI,
            BREAKPOINT_VECTOR | OVERFLOW_VECTOR => Self::SoftException,
            // SDM Vol. 3A, Section 6.15: All other vectors from 0 to 21 are exceptions.
            0..=VIRTUALIZATION_VECTOR => Self::HardException,
            32..=255 => Self::External,
            _ => Self::Other,
        }
    }

    /// For software interrupt, software exception, or privileged software
    /// exception,we need to set VM-Entry Instruction Length Field.
    pub const fn is_soft(&self) -> bool {
        matches!(
            *self,
            Self::SoftIntr | Self::SoftException | Self::PrivSoftException
        )
    }
}
