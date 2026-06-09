# Web Assembly SHell

Copyright (c) 2022-2025 [Antmicro](https://www.antmicro.com)

This repository contains a custom shell implementation that supports the `wasm32-wasip1` target; with an extended set of system calls implemented by [wasi_ext_lib](https://github.com/antmicro/wasi_ext_lib).

## Build for wasi target
You will need a custom Rust nightly toolchain that builds [`wasi_ext_lib`](https://github.com/antmicro/wasi_ext_lib) project. Get the custom Rust compiler by following the intructions in [`build`](https://github.com/antmicro/wasi_ext_lib#build) and [`Rust library`](https://github.com/antmicro/wasi_ext_lib#rust-library) sections. It is required to define [`WASI_SDK_PATH`](https://github.com/antmicro/wasi_ext_lib#build) environment variable.

After completing the previous steps, with the following command you can build `wash`:

```
cargo +wasi_extended build --target wasm32-wasip1 --release
```

If you want to compile for `wasm32-wasip1-threads` instead, you need to add required flags:
```
RUSTFLAGS="-C target-feature=-crt-static,+atomics,+bulk-memory,+mutable-globals -C link-arg=--max-memory=4294967296" cargo +wasi_extended build --target wasm32-wasip1-threads --release
```