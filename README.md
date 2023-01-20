# Web Assembly SHell

Copyright (c) 2022 [Antmicro](https://www.antmicro.com)

This repository contains a custom shell implementation that supports `wasm32-wasi` target with extended syscall set implemented with the [wasi_ext_lib](https://github.com/antmicro/wasi_ext_lib).

## Build for wasi target
You will need a custom Rust nightly toolchain that builds [`wasi_ext_lib`](https://github.com/antmicro/wasi_ext_lib) project. Get the custom Rust compiler by following the intructions in [`build`](https://github.com/antmicro/wasi_ext_lib#build) and [`Rust library`](https://github.com/antmicro/wasi_ext_lib#rust-library) sections. It is required to define [`WASI_SDK_PATH`](https://github.com/antmicro/wasi_ext_lib#build) environment variable.

After completing previous steps, you can build `wash` with command:

```
cargo +stage2 build --target wasm32-wasi --release
```