mod heap;

pub mod address;
pub mod frame;

pub const PAGE_SIZE: usize = 0x1000;

pub fn init_heap_early() {
    heap::init();
}

pub fn init() {
    frame::init();
}
