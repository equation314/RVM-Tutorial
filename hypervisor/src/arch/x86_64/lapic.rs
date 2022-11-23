use x2apic::lapic::{LocalApic, LocalApicBuilder};
use x86_64::instructions::port::Port;

use self::vectors::*;

pub mod vectors {
    pub const APIC_TIMER_VECTOR: u8 = 0xf0;
    pub const APIC_SPURIOUS_VECTOR: u8 = 0xf1;
    pub const APIC_ERROR_VECTOR: u8 = 0xf2;
}

static mut LOCAL_APIC: Option<LocalApic> = None;

pub fn local_apic<'a>() -> &'a mut LocalApic {
    // It's safe as LAPIC is per-cpu.
    unsafe { LOCAL_APIC.as_mut().unwrap() }
}

pub fn init() {
    println!("Initializing Local APIC...");

    unsafe {
        // Disable 8259A interrupt controllers
        Port::<u8>::new(0x20).write(0xff);
        Port::<u8>::new(0xA0).write(0xff);
    }

    let mut lapic = LocalApicBuilder::new()
        .timer_vector(APIC_TIMER_VECTOR as _)
        .error_vector(APIC_ERROR_VECTOR as _)
        .spurious_vector(APIC_SPURIOUS_VECTOR as _)
        .build()
        .unwrap();
    unsafe {
        lapic.enable();
        LOCAL_APIC = Some(lapic);
    }
}
