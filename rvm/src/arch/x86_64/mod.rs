pub(crate) mod msr;

#[macro_use]
pub(crate) mod regs;

cfg_if::cfg_if! {
    if #[cfg(feature = "vmx")] {
        mod vmx;
        use vmx as vender;
        pub use vmx::{VmxExitInfo, VmxExitReason};
    }
}

pub(crate) use vender::{has_hardware_support, ArchPerCpuState};

pub use regs::GeneralRegisters;
pub use vender::{NestedPageTable, RvmVcpu};
