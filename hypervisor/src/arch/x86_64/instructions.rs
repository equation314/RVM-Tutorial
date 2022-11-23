#![allow(dead_code)]

use core::arch::asm;

use x86_64::registers::{rflags, rflags::RFlags};

#[inline]
pub fn enable_irqs() {
    unsafe { asm!("sti") };
}

#[inline]
pub fn disable_irqs() {
    unsafe { asm!("cli") };
}

#[inline]
pub fn irqs_disabled() -> bool {
    !rflags::read().contains(RFlags::INTERRUPT_FLAG)
}

#[inline]
pub fn wait_for_ints() {
    if !irqs_disabled() {
        x86_64::instructions::hlt();
    }
}
