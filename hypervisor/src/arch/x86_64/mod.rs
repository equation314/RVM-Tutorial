mod boot;

pub mod uart16550;

pub use uart16550 as uart;

pub fn init_early() {
    uart::init();
}
