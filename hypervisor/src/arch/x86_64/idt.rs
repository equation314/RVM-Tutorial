use x86_64::structures::idt::{Entry, HandlerFunc, InterruptDescriptorTable};

const NUM_INT: usize = 256;

lazy_static::lazy_static! {
    static ref IDT: IdtStruct = IdtStruct::new();
}

struct IdtStruct {
    table: InterruptDescriptorTable,
}

impl IdtStruct {
    fn new() -> Self {
        extern "C" {
            #[link_name = "trap_handler_table"]
            static ENTRIES: [extern "C" fn(); NUM_INT];
        }
        let mut idt = Self {
            table: InterruptDescriptorTable::new(),
        };

        let entries = unsafe {
            core::slice::from_raw_parts_mut(
                &mut idt.table as *mut _ as *mut Entry<HandlerFunc>,
                NUM_INT,
            )
        };
        for i in 0..NUM_INT {
            entries[i].set_handler_fn(unsafe { core::mem::transmute(ENTRIES[i]) });
        }
        idt
    }

    fn load(&'static self) {
        self.table.load();
    }
}

pub fn init() {
    println!("Initializing IDT...");
    lazy_static::initialize(&IDT);
    IDT.load();
}
