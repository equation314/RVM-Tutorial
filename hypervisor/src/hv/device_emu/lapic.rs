//! Emulated Local APIC. (SDM Vol. 3A, Chapter 10)

#![allow(dead_code)]

use rvm::{RvmError, RvmResult, RvmVcpu};

type Vcpu = RvmVcpu<crate::hv::hal::RvmHalImpl>;

/// ID register.
const APICID: u32 = 0x2;
/// Version register.
const VERSION: u32 = 0x3;
/// EOI register.
const EOI: u32 = 0xB;
/// Logical Destination Register.
const LDR: u32 = 0xD;
/// Spurious Interrupt Vector register.
const SIVR: u32 = 0xF;
/// Interrupt Command register.
const ICR: u32 = 0x30;
/// LVT Timer Interrupt register.
const LVT_TIMER: u32 = 0x32;
/// LVT Thermal Sensor Interrupt register.
const LVT_THERMAL: u32 = 0x33;
/// LVT Performance Monitor register.
const LVT_PMI: u32 = 0x34;
/// LVT LINT0 register.
const LVT_LINT0: u32 = 0x35;
/// LVT LINT1 register.
const LVT_LINT1: u32 = 0x36;
/// LVT Error register.
const LVT_ERR: u32 = 0x37;
///  Initial Count register.
const INIT_COUNT: u32 = 0x38;
/// Current Count register.
const CUR_COUNT: u32 = 0x39;
/// Divide Configuration register.
const DIV_CONF: u32 = 0x3E;

pub struct VirtLocalApic;

impl VirtLocalApic {
    pub const fn msr_range() -> core::ops::Range<u32> {
        0x800..0x840
    }

    pub fn rdmsr(vcpu: &mut Vcpu, msr: u32) -> RvmResult<u64> {
        Self::read(vcpu, msr - 0x800)
    }

    pub fn wrmsr(vcpu: &mut Vcpu, msr: u32, value: u64) -> RvmResult {
        Self::write(vcpu, msr - 0x800, value)
    }
}

impl VirtLocalApic {
    fn read(vcpu: &mut Vcpu, offset: u32) -> RvmResult<u64> {
        let apic_timer = vcpu.apic_timer_mut();
        match offset {
            SIVR => Ok(0x1ff), // SDM Vol. 3A, Section 10.9, Figure 10-23 (with Software Enable bit)
            LVT_THERMAL | LVT_PMI | LVT_LINT0 | LVT_LINT1 | LVT_ERR => {
                Ok(0x1_0000) // SDM Vol. 3A, Section 10.5.1, Figure 10-8 (with Mask bit)
            }
            LVT_TIMER => Ok(apic_timer.lvt_timer() as u64),
            INIT_COUNT => Ok(apic_timer.initial_count() as u64),
            DIV_CONF => Ok(apic_timer.divide() as u64),
            CUR_COUNT => Ok(apic_timer.current_counter() as u64),
            _ => Err(RvmError::Unsupported),
        }
    }

    fn write(vcpu: &mut Vcpu, offset: u32, value: u64) -> RvmResult {
        if offset != ICR && (value >> 32) != 0 {
            return Err(RvmError::InvalidParam); // all registers except ICR are 32-bits
        }
        let apic_timer = vcpu.apic_timer_mut();
        match offset {
            EOI => {
                if value != 0 {
                    Err(RvmError::InvalidParam) // write a non-zero value causes #GP
                } else {
                    Ok(())
                }
            }
            SIVR | LVT_THERMAL | LVT_PMI | LVT_LINT0 | LVT_LINT1 | LVT_ERR => {
                Ok(()) // ignore these register writes
            }
            LVT_TIMER => apic_timer.set_lvt_timer(value as u32),
            INIT_COUNT => apic_timer.set_initial_count(value as u32),
            DIV_CONF => apic_timer.set_divide(value as u32),
            _ => Err(RvmError::Unsupported),
        }
    }
}
