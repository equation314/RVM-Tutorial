mod gconfig;
mod gpm;
mod hal;
mod vmexit;

use rvm::{GuestPhysAddr, HostPhysAddr, HostVirtAddr, MemFlags, RvmPerCpu, RvmResult};

use self::gconfig::*;
use self::gpm::{GuestMemoryRegion, GuestPhysMemorySet};
use self::hal::RvmHalImpl;
use crate::mm::address::{phys_to_virt, virt_to_phys};

#[repr(align(4096))]
struct AlignedMemory<const LEN: usize>([u8; LEN]);

static mut GUEST_PHYS_MEMORY: AlignedMemory<GUEST_PHYS_MEMORY_SIZE> =
    AlignedMemory([0; GUEST_PHYS_MEMORY_SIZE]);

fn gpa_as_mut_ptr(guest_paddr: GuestPhysAddr) -> *mut u8 {
    let offset = unsafe { &GUEST_PHYS_MEMORY as *const _ as usize };
    let host_vaddr = guest_paddr + offset;
    host_vaddr as *mut u8
}

fn load_guest_image(hpa: HostPhysAddr, load_gpa: GuestPhysAddr, size: usize) {
    let image_ptr = phys_to_virt(hpa) as *const u8;
    let image = unsafe { core::slice::from_raw_parts(image_ptr, size) };
    unsafe {
        core::slice::from_raw_parts_mut(gpa_as_mut_ptr(load_gpa), size).copy_from_slice(image)
    }
}

fn setup_gpm() -> RvmResult<GuestPhysMemorySet> {
    // copy BIOS and guest images
    load_guest_image(BIOS_PADDR, BIOS_ENTRY, BIOS_SIZE);
    load_guest_image(GUEST_IMAGE_PADDR, GUEST_ENTRY, GUEST_IMAGE_SIZE);

    // create nested page table and add mapping
    let mut gpm = GuestPhysMemorySet::new()?;
    let guest_memory_regions = [
        GuestMemoryRegion {
            // RAM
            gpa: GUEST_PHYS_MEMORY_BASE,
            hpa: virt_to_phys(gpa_as_mut_ptr(GUEST_PHYS_MEMORY_BASE) as HostVirtAddr),
            size: GUEST_PHYS_MEMORY_SIZE,
            flags: MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        },
        GuestMemoryRegion {
            // IO APIC
            gpa: 0xfec0_0000,
            hpa: 0xfec0_0000,
            size: 0x1000,
            flags: MemFlags::READ | MemFlags::WRITE | MemFlags::DEVICE,
        },
        GuestMemoryRegion {
            // HPET
            gpa: 0xfed0_0000,
            hpa: 0xfed0_0000,
            size: 0x1000,
            flags: MemFlags::READ | MemFlags::WRITE | MemFlags::DEVICE,
        },
        GuestMemoryRegion {
            // Local APIC
            gpa: 0xfee0_0000,
            hpa: 0xfee0_0000,
            size: 0x1000,
            flags: MemFlags::READ | MemFlags::WRITE | MemFlags::DEVICE,
        },
    ];
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
        .create_vcpu(BIOS_ENTRY, gpm.nest_page_table_root())
        .unwrap();

    println!("Running guest...");
    vcpu.run();
}
