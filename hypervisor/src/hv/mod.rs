mod hal;
mod vmexit;

use rvm::RvmPerCpu;

use self::hal::RvmHalImpl;

pub fn run() -> ! {
    println!("Starting virtualization...");
    println!("Hardware support: {:?}", rvm::has_hardware_support());

    let mut percpu = RvmPerCpu::<RvmHalImpl>::new(0);
    percpu.hardware_enable().unwrap();

    let mut vcpu = percpu.create_vcpu(test_guest as usize).unwrap();
    info!("{:#x?}", vcpu);
    println!("Running guest...");
    vcpu.run();
}

#[naked]
unsafe extern "C" fn test_guest() -> ! {
    core::arch::asm!(
        "
        mov     rax, 0
        mov     rdi, 2
        mov     rsi, 3
        mov     rdx, 3
        mov     rcx, 3
    2:
        vmcall
        add     rax, 1
        jmp     2b",
        options(noreturn),
    );
}
