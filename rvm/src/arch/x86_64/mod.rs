pub(crate) mod msr;
pub(crate) mod regs;

cfg_if::cfg_if! {
    if #[cfg(feature = "vmx")] {
        mod vmx;
        use vmx as vender;
    }
}

pub use vender::{has_hardware_support, ArchPerCpuState, RvmVcpu};
