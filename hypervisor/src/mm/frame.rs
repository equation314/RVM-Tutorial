use bitmap_allocator::BitAlloc;
use spin::Mutex;

use super::address::{align_down, align_up, virt_to_phys, PhysAddr};
use super::PAGE_SIZE;
use crate::config::PHYS_MEMORY_END;

// Support max 1M * 4096 = 1GB memory.
type FrameAlloc = bitmap_allocator::BitAlloc1M;

static FRAME_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::empty());

struct FrameAllocator {
    base: PhysAddr,
    inner: FrameAlloc,
}

impl FrameAllocator {
    const fn empty() -> Self {
        Self {
            base: 0,
            inner: FrameAlloc::DEFAULT,
        }
    }

    fn init(&mut self, base: PhysAddr, size: usize) {
        self.base = align_up(base);
        let page_count = align_up(size) / PAGE_SIZE;
        self.inner.insert(0..page_count);
    }

    unsafe fn alloc(&mut self) -> Option<PhysAddr> {
        let ret = self.inner.alloc().map(|idx| idx * PAGE_SIZE + self.base);
        trace!("Allocate frame: {:x?}", ret);
        ret
    }

    unsafe fn dealloc(&mut self, target: PhysAddr) {
        trace!("Deallocate frame: {:x}", target);
        self.inner.dealloc((target - self.base) / PAGE_SIZE)
    }
}

pub unsafe fn alloc_page() -> Option<PhysAddr> {
    FRAME_ALLOCATOR.lock().alloc()
}

pub unsafe fn dealloc_page(paddr: PhysAddr) {
    FRAME_ALLOCATOR.lock().dealloc(paddr)
}

pub(super) fn init() {
    extern "C" {
        fn ekernel();
    }

    let mem_pool_start = align_up(virt_to_phys(ekernel as usize));
    let mem_pool_end = align_down(PHYS_MEMORY_END);
    let mem_pool_size = mem_pool_end - mem_pool_start;
    println!(
        "Initializing frame allocator at: [{:#x?}, {:#x?})",
        mem_pool_start, mem_pool_end
    );
    FRAME_ALLOCATOR.lock().init(mem_pool_start, mem_pool_size);
}
