mod hal;

use rvm::RvmPerCpu;

use self::hal::RvmHalImpl;

pub fn run() {
    println!("Starting virtualization...");
    println!("Hardware support: {:?}", rvm::has_hardware_support());

    let mut percpu = RvmPerCpu::<RvmHalImpl>::new(0);
    percpu.hardware_enable().unwrap();

    let mut vcpu = percpu.create_vcpu().unwrap();
    info!("{:#x?}", vcpu);
    vcpu.run();
}
