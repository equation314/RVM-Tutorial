mod boot;
mod gdt;
mod idt;
mod lapic;
mod trap;

pub mod instructions;
pub mod timer;
pub mod uart16550;

pub use trap::handle_irq;
pub use uart16550 as uart;

pub fn init_early() {
    uart::init();
}

pub fn init() {
    gdt::init();
    idt::init();
    lapic::init();
    timer::init();
}
