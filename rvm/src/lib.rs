#![no_std]
#![feature(concat_idents)]

#[macro_use]
extern crate log;

#[macro_use]
mod error;

mod arch;
mod hal;
mod mm;

use arch::{ArchPerCpuState, RvmVcpu};

pub use error::{RvmError, RvmResult};
pub use hal::RvmHal;
pub use mm::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};

/// Whether the hardware has virtualization support.
pub fn has_hardware_support() -> bool {
    arch::has_hardware_support()
}

/// Host per-CPU states to run the guest. All methods must be called on the corresponding CPU.
pub struct RvmPerCpu<H: RvmHal> {
    _cpu_id: usize,
    arch: ArchPerCpuState<H>,
}

impl<H: RvmHal> RvmPerCpu<H> {
    /// Create an uninitialized instance.
    pub fn new(cpu_id: usize) -> Self {
        Self {
            _cpu_id: cpu_id,
            arch: ArchPerCpuState::new(),
        }
    }

    /// Whether the current CPU has hardware virtualization enabled.
    pub fn is_enabled(&self) -> bool {
        self.arch.is_enabled()
    }

    /// Enable hardware virtualization on the current CPU.
    pub fn hardware_enable(&mut self) -> RvmResult {
        self.arch.hardware_enable()
    }

    /// Disable hardware virtualization on the current CPU.
    pub fn hardware_disable(&mut self) -> RvmResult {
        self.arch.hardware_disable()
    }

    /// Create a [`RvmVcpu`].
    pub fn create_vcpu(&self) -> RvmResult<RvmVcpu<H>> {
        if !self.is_enabled() {
            rvm_err!(BadState, "virtualization is not enabled")
        } else {
            RvmVcpu::new(&self.arch)
        }
    }
}

impl<H: RvmHal> Drop for RvmPerCpu<H> {
    fn drop(&mut self) {
        if self.is_enabled() {
            self.hardware_disable().unwrap();
        }
    }
}
