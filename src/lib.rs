/*
 * Copyright (c) 2022-2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pub mod cli;
pub mod internals;
pub mod interpreter;
pub mod output_device;
pub mod saved_fd;
pub mod shell_base;

pub use shell_base::spawn;
pub use shell_base::Shell;
