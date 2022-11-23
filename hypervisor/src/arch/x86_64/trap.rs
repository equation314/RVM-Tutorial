use core::arch::global_asm;

use x86::{controlregs::cr2, irq::*};

use super::lapic::{local_apic, vectors::*};

global_asm!(include_str!("trap.S"));

const IRQ_VECTOR_START: u8 = 0x20;
const IRQ_VECTOR_END: u8 = 0xff;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TrapFrame {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // Pushed by 'trap.S'
    pub vector: u64,
    pub error_code: u64,

    // Pushed by CPU
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[no_mangle]
fn x86_trap_handler(tf: &mut TrapFrame) {
    trace!("trap {} @ {:#x}: {:#x?}", tf.vector, tf.rip, tf);
    match tf.vector as u8 {
        PAGE_FAULT_VECTOR => {
            panic!(
                "Hypervisor Page Fault @ {:#x}, fault_vaddr={:#x}, error_code={:#x}",
                tf.rip,
                unsafe { cr2() },
                tf.error_code,
            );
        }
        GENERAL_PROTECTION_FAULT_VECTOR => {
            panic!(
                "General Protection Exception @ {:#x}, error_code = {:#x}, kernel killed it.",
                tf.rip, tf.error_code,
            );
        }
        IRQ_VECTOR_START..=IRQ_VECTOR_END => handle_irq(tf.vector as u8),
        _ => {
            panic!(
                "Unhandled exception {} (error_code = {:#x}) @ {:#x}:\n{:#x?}",
                tf.vector, tf.error_code, tf.rip, tf
            );
        }
    }
}

pub fn handle_irq(vector: u8) {
    match vector {
        APIC_TIMER_VECTOR => {
            trace!("TIMER");
            unsafe { local_apic().end_of_interrupt() };
        }
        _ => warn!("Unhandled IRQ {}", vector),
    }
}
