/*
 * Copyright (c) 2022-2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::VecDeque;
use std::env;
use std::io;
use std::io::Read;
use std::os::raw::c_int;
use std::path::PathBuf;
use std::process;

use clap::{Arg, Command};

use wash::Shell;

#[cfg(not(target_os = "wasi"))]
extern "C" {
    fn isatty(fd: c_int) -> c_int;
}

const STDIN: c_int = 0;

fn is_fd_tty(fd: i32) -> Result<bool, i32> {
    #[cfg(not(target_os = "wasi"))]
    return Ok(unsafe { isatty(fd) } == 1);
    #[cfg(target_os = "wasi")]
    return wasi_ext_lib::isatty(fd);
}

fn main() {
    let name = {
        let mut path = PathBuf::from(
            env::args()
                .next()
                .unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string()),
        );
        path.set_extension("");
        path.file_name().unwrap().to_str().unwrap().to_string()
    };
    let version_short = &*format!(
        "{}-{} ({})\nCopyright (c) 2021-{} Antmicro <www.antmicro.com>",
        env!("CARGO_PKG_VERSION"),
        env!("SHELL_COMMIT_HASH"),
        env!("SHELL_TARGET"),
        env!("SHELL_COMMIT_DATE").split('-').collect::<Vec<&str>>()[0],
    );
    let matches = Command::new(name)
        .version(version_short)
        .long_version(&*format!(
            "{}\nCommit date: {}\nBuild date: {}",
            version_short,
            env!("SHELL_COMMIT_DATE"),
            env!("SHELL_COMPILE_DATE")
        ))
        .author("Antmicro <www.antmicro.com>")
        .help_template(
            "{before-help}{bin} {version}\n\
            {about-with-newline}\n\
            {usage-heading}\n\t{usage}\n\
            {all-args}{after-help}",
        )
        // FILE - first value is the script path, other values are CLI args
        .arg(
            Arg::new("FILE")
                .help("Execute commands from file")
                .multiple_values(true)
                .index(1),
        )
        .arg(
            Arg::new("command")
                .help("Execute provided command")
                .short('c')
                .long("command")
                .value_name("COMMAND")
                .takes_value(true),
        )
        .get_matches();

    let pwd;
    let should_echo;

    #[cfg(target_os = "wasi")]
    {
        let _ = wasi_ext_lib::chdir(match wasi_ext_lib::getcwd() {
            Ok(p) => {
                pwd = p;
                &pwd
            }
            Err(e) => {
                eprintln!("Could not obtain current working dir path (error {e})");
                pwd = String::from("/");
                &pwd
            }
        });
        should_echo = true;
    }
    #[cfg(not(target_os = "wasi"))]
    {
        if let Ok(cwd) = env::current_dir() {
            pwd = cwd.display().to_string();
        } else {
            pwd = String::from("/");
        }
        should_echo = false;
    }

    if env::var("PWD").is_err() {
        env::set_var("PWD", &pwd);
    }
    if env::var("HOME").is_err() {
        env::set_var("HOME", "/");
    }

    let script: String;
    let len: usize;
    let mut shell = Shell::new(
        should_echo,
        &pwd,
        if let Some(args) = matches.values_of("FILE") {
            len = args.len();
            let collected = args.map(String::from).collect::<VecDeque<String>>();
            script = collected[0].clone();
            collected
        } else {
            len = 0;
            script = String::from("");
            VecDeque::new()
        },
    );

    let result = if let Some(command) = matches.value_of("command") {
        shell.run_command(command)
    } else if len != 0 {
        shell.run_script(PathBuf::from(script))
    } else {
        match is_fd_tty(STDIN) {
            Err(_) => {
                // is_fd_tty will fail in WASI runtimes (wasmtime/wasmer/wasiwasm),
                // just run interpreter then without registreing sigint
                shell.run_interpreter()
            }
            Ok(true) => {
                #[cfg(target_os = "wasi")]
                shell
                    .register_sigint()
                    .expect("Cannot register InternalEventSource object!");
                shell.run_interpreter()
            }
            Ok(false) => {
                let mut input = String::new();
                let stdin = io::stdin();
                stdin.lock().read_to_string(&mut input).unwrap();
                shell.run_command(&input)
            }
        }
    };

    let exit_code = match result {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("{}: error occurred: {}", env!("CARGO_PKG_NAME"), e);
            2
        }
    };

    process::exit(exit_code);
}
