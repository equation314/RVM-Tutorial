mod gconfig;
mod gpm;
mod hal;
mod vmexit;

use rvm::{GuestPhysAddr, HostVirtAddr, MemFlags, RvmPerCpu, RvmResult};

use self::gconfig::*;
use self::gpm::{GuestMemoryRegion, GuestPhysMemorySet};
use self::hal::RvmHalImpl;
use crate::mm::address::virt_to_phys;

#[repr(align(4096))]
struct AlignedMemory<const LEN: usize>([u8; LEN]);

static mut GUEST_PHYS_MEMORY: AlignedMemory<GUEST_PHYS_MEMORY_SIZE> =
    AlignedMemory([0; GUEST_PHYS_MEMORY_SIZE]);

fn gpa_as_mut_ptr(guest_paddr: GuestPhysAddr) -> *mut u8 {
    let offset = unsafe { &GUEST_PHYS_MEMORY as *const _ as usize };
    let host_vaddr = guest_paddr + offset;
    host_vaddr as *mut u8
}

fn setup_guest_page_table() {
    use x86_64::structures::paging::{PageTable, PageTableFlags as PTF};
    let pt1 = unsafe { &mut *(gpa_as_mut_ptr(GUEST_PT1) as *mut PageTable) };
    let pt2 = unsafe { &mut *(gpa_as_mut_ptr(GUEST_PT2) as *mut PageTable) };
    // identity mapping
    pt1[0].set_addr(
        x86_64::PhysAddr::new(GUEST_PT2 as _),
        PTF::PRESENT | PTF::WRITABLE,
    );
    pt2[0].set_addr(
        x86_64::PhysAddr::new(0),
        PTF::PRESENT | PTF::WRITABLE | PTF::HUGE_PAGE,
    );
}

fn setup_gpm() -> RvmResult<GuestPhysMemorySet> {
    setup_guest_page_table();

    // copy guest code
    unsafe {
        core::ptr::copy_nonoverlapping(
            test_guest as usize as *const u8,
            gpa_as_mut_ptr(GUEST_ENTRY),
            0x100,
        );
    }

    // create nested page table and add mapping
    let mut gpm = GuestPhysMemorySet::new()?;
    let guest_memory_regions = [GuestMemoryRegion {
        // RAM
        gpa: GUEST_PHYS_MEMORY_BASE,
        hpa: virt_to_phys(gpa_as_mut_ptr(GUEST_PHYS_MEMORY_BASE) as HostVirtAddr),
        size: GUEST_PHYS_MEMORY_SIZE,
        flags: MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
    }];
    for r in guest_memory_regions.into_iter() {
        gpm.map_region(r.into())?;
    }
    Ok(gpm)
}

pub fn run() -> ! {
    println!("Starting virtualization...");
    println!("Hardware support: {:?}", rvm::has_hardware_support());

    let mut percpu = RvmPerCpu::<RvmHalImpl>::new(0);
    percpu.hardware_enable().unwrap();

    let gpm = setup_gpm().unwrap();
    info!("{:#x?}", gpm);

    let mut vcpu = percpu
        .create_vcpu(GUEST_ENTRY, gpm.nest_page_table_root())
        .unwrap();
    vcpu.set_page_table_root(GUEST_PT1);
    vcpu.set_stack_pointer(GUEST_STACK_TOP);
    info!("{:#x?}", vcpu);

    println!("Running guest...");
    vcpu.run();
}

unsafe extern "C" fn test_guest() -> ! {
    for i in 0..100 {
        core::arch::asm!(
            "vmcall",
            inout("rax") i => _,
            in("rdi") 2,
            in("rsi") 3,
            in("rdx") 3,
            in("rcx") 3,
        );
    }
    core::arch::asm!("mov qword ptr [$0xffff233], $2333"); // panic
    loop {}
}
