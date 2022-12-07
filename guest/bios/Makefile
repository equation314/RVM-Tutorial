OUT ?= out

SRC := boot16.S
ldscript := rvm-bios.lds
target := $(OUT)/rvm-bios
target-obj := $(target).o
target-elf := $(target).elf
target-bin := $(target).bin
target-disasm := $(target).asm

AS ?= as
LD ?= ld
OBJCOPY ?= objcopy
OBJDUMP ?= objdump

all: $(OUT) $(target).bin

disasm:
	$(OBJDUMP) -d -m i8086 -M intel $(target).elf | less

$(OUT):
	mkdir -p $(OUT)

$(target-obj): $(SRC)
	$(AS) --32 -msyntax=intel -mnaked-reg $< -o $@

$(target-elf): $(target-obj) $(ldscript)
	$(LD) -T$(ldscript) $< -o $@
	$(OBJDUMP) -d -m i8086 -M intel $@ > $(target-disasm)

$(target-bin): $(target-elf)
	$(OBJCOPY) $< --strip-all -O binary $@

clean:
	rm -rf $(OUT)

.PHONY: all disasm clean
