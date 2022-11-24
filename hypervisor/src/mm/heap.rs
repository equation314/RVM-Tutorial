use buddy_system_allocator::LockedHeap;
use core::{alloc::Layout, mem::size_of};

use crate::config::KERNEL_HEAP_SIZE;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

#[alloc_error_handler]
fn handle_alloc_error(layout: Layout) -> ! {
    panic!("Heap allocation error, layout = {:?}", layout);
}

static mut HEAP_SPACE: [u64; KERNEL_HEAP_SIZE / size_of::<u64>()] =
    [0; KERNEL_HEAP_SIZE / size_of::<u64>()];

pub(super) fn init() {
    let heap_start = unsafe { HEAP_SPACE.as_ptr() as usize };
    println!(
        "Initializing heap at: [{:#x}, {:#x})",
        heap_start,
        heap_start + KERNEL_HEAP_SIZE
    );
    unsafe { HEAP_ALLOCATOR.lock().init(heap_start, KERNEL_HEAP_SIZE) }
}
