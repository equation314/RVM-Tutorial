# Arguments
ARCH ?= x86_64
MODE ?= release
LOG ?= warn

BIOS_IMG ?= ../guest/bios/out/rvm-bios.bin
GUEST_IMG ?= ../guest/nimbos/kernel/target/x86_64/release/nimbos.bin

export ARCH
export MODE
export LOG

# Paths
target_elf := target/$(ARCH)/$(MODE)/rvm-hypervisor
target_bin := $(target_elf).bin

build_args := --target $(ARCH).json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
ifeq ($(MODE), release)
  build_args += --release
endif

# Binutils
OBJDUMP := rust-objdump -d --print-imm-hex --x86-asm-syntax=intel
OBJCOPY := rust-objcopy --binary-architecture=$(ARCH)
GDB := gdb-multiarch

# QEMU
qemu := qemu-system-$(ARCH)
qemu_args := -nographic -m 128M

qemu_args += -cpu host,+x2apic,+vmx -accel kvm \
	-device loader,addr=0x4000000,file=$(BIOS_IMG),force-raw=on \
	-device loader,addr=0x4001000,file=$(GUEST_IMG),force-raw=on

ifeq ($(ARCH), x86_64)
  qemu_args += \
    -machine q35 \
    -serial mon:stdio \
    -kernel $(target_elf)
endif

build: $(target_bin)

$(target_bin): elf
	@$(OBJCOPY) $(target_elf) --strip-all -O binary $@

elf:
	@echo Arch: $(ARCH)
	cargo build $(build_args)

clean:
	cargo clean

clippy:
	cargo clippy $(build_args)

fmt:
	cargo fmt

disasm:
	@$(OBJDUMP) $(target_elf) | less

run: build justrun

justrun:
	$(qemu) $(qemu_args)

.PHONY: build elf clean clippy disasm run justrun
