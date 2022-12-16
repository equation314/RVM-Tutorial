# RVM-Tutorial

Let's write an x86 hypervisor in Rust from scratch!

## Features

* Lightweight enough, only 3K+ LoC
* Supported guest OS: [NimbOS](https://github.com/equation314/nimbos)
* Guest/host memory isolation with nested paging
* Device emulation:
    + serial port I/O
    + APIC timer
* Currently, only supports single core single vCPU and single guest

## Install Build Dependencies

Install [cargo-binutils](https://github.com/rust-embedded/cargo-binutils) to use `rust-objcopy` and `rust-objdump` tools:

```console
$ cargo install cargo-binutils
```

Your also need to install [musl-gcc](http://musl.cc/x86_64-linux-musl-cross.tgz) to build guest user applications.

## Build Guest OS

```console
$ git submodule init && git submodule update
$ cd guest/nimbos/kernel
$ make user
$ make GUEST=on
```

## Build Guest BIOS

```console
$ cd guest/bios
$ make
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
Running guest...

NN   NN  iii               bb        OOOOO    SSSSS
NNN  NN       mm mm mmmm   bb       OO   OO  SS
NN N NN  iii  mmm  mm  mm  bbbbbb   OO   OO   SSSSS
NN  NNN  iii  mmm  mm  mm  bb   bb  OO   OO       SS
NN   NN  iii  mmm  mm  mm  bbbbbb    OOOO0    SSSSS
              ___    ____    ___    ___
             |__ \  / __ \  |__ \  |__ \
             __/ / / / / /  __/ /  __/ /
            / __/ / /_/ /  / __/  / __/
           /____/ \____/  /____/ /____/

arch = x86_64
platform = rvm-guest-x86_64
build_mode = release
log_level = warn
......
```

## Documents

* [in Chinese](https://github.com/equation314/RVM-Tutorial/wiki)
