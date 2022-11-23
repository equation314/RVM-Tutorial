# RVM-Tutorial

Let's write an x86 hypervisor in Rust from scratch!

## Install Build Dependencies

Install [cargo-binutils](https://github.com/rust-embedded/cargo-binutils) to use `rust-objcopy` and `rust-objdump` tools:

```console
$ cargo install cargo-binutils
```

## Build & Run Hypervisor

```console
$ cd hypervisor
$ make run [LOG=warn|info|debug|trace]
......
Booting from ROM..

    RRRRRR  VV     VV MM    MM
    RR   RR VV     VV MMM  MMM
    RRRRRR   VV   VV  MM MM MM
    RR  RR    VV VV   MM    MM
    RR   RR    VVV    MM    MM
     ___    ____    ___    ___
    |__ \  / __ \  |__ \  |__ \
    __/ / / / / /  __/ /  __/ /
   / __/ / /_/ /  / __/  / __/
  /____/ \____/  /____/ /____/

arch = x86_64
build_mode = release
log_level = info
......
```
