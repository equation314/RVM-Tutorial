use x86_64::instructions::tables::{lgdt, load_tss};
use x86_64::registers::segmentation::{Segment, SegmentSelector, CS};
use x86_64::structures::gdt::{Descriptor, DescriptorFlags};
use x86_64::structures::{tss::TaskStateSegment, DescriptorTablePointer};
use x86_64::{addr::VirtAddr, PrivilegeLevel};

lazy_static::lazy_static! {
    static ref TSS: TaskStateSegment = TaskStateSegment::new();
    static ref GDT: GdtStruct = GdtStruct::new(&TSS);
}

struct GdtStruct {
    table: [u64; 16],
}

impl GdtStruct {
    pub const KCODE_SELECTOR: SegmentSelector = SegmentSelector::new(1, PrivilegeLevel::Ring0);
    pub const _KDATA_SELECTOR: SegmentSelector = SegmentSelector::new(2, PrivilegeLevel::Ring0);
    pub const TSS_SELECTOR: SegmentSelector = SegmentSelector::new(3, PrivilegeLevel::Ring0);

    pub fn new(tss: &'static TaskStateSegment) -> Self {
        let mut table = [0; 16];
        table[1] = DescriptorFlags::KERNEL_CODE64.bits(); // 0x00af9b000000ffff
        table[2] = DescriptorFlags::KERNEL_DATA.bits(); // 0x00cf93000000ffff
        if let Descriptor::SystemSegment(low, high) = Descriptor::tss_segment(tss) {
            table[3] = low;
            table[4] = high;
        }
        Self { table }
    }

    fn pointer(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            base: VirtAddr::new(self.table.as_ptr() as u64),
            limit: (core::mem::size_of_val(&self.table) - 1) as u16,
        }
    }

    pub fn load(&'static self) {
        unsafe {
            lgdt(&self.pointer());
            CS::set_reg(GdtStruct::KCODE_SELECTOR);
        }
    }

    pub fn load_tss(&'static self, selector: SegmentSelector) {
        unsafe { load_tss(selector) };
    }
}

pub fn init() {
    println!("Initializing GDT...");
    lazy_static::initialize(&GDT);
    GDT.load();
    GDT.load_tss(GdtStruct::TSS_SELECTOR);
}
