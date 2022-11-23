use raw_cpuid::CpuId;
use x2apic::lapic::{TimerDivide, TimerMode};

use crate::config::TICKS_PER_SEC;

use super::lapic::local_apic;

const LAPIC_TICKS_PER_SEC: u64 = 1_000_000_000; // TODO: need to calibrate

static mut CPU_FREQ_MHZ: u64 = 4_000;

pub fn current_ticks() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn ticks_to_nanos(ticks: u64) -> u64 {
    ticks * 1_000 / unsafe { CPU_FREQ_MHZ }
}

pub fn init() {
    if let Some(freq) = CpuId::new()
        .get_processor_frequency_info()
        .map(|info| info.processor_base_frequency())
    {
        if freq > 0 {
            println!("Got TSC frequency by CPUID: {} MHz", freq);
            unsafe { CPU_FREQ_MHZ = freq as u64 }
        }
    }

    let lapic = local_apic();
    unsafe {
        lapic.set_timer_mode(TimerMode::Periodic);
        lapic.set_timer_divide(TimerDivide::Div256); // indeed it is Div1, the name is confusing.
        lapic.set_timer_initial((LAPIC_TICKS_PER_SEC / TICKS_PER_SEC) as u32);
    }
}
