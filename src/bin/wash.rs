/*
 * Copyright (c) 2022-2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process;

use clap::{Arg, ArgAction, Command};

use wash::shell_base::{is_fd_tty, Fd};
use wash::Shell;

const STDIN: Fd = 0;

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
    let version_short = format!(
        "{}-{} ({})\nCopyright (c) 2021-{} Antmicro <www.antmicro.com>",
        env!("CARGO_PKG_VERSION"),
        env!("SHELL_COMMIT_HASH"),
        env!("SHELL_TARGET"),
        env!("SHELL_COMMIT_DATE").split('-').collect::<Vec<&str>>()[0],
    );

    let version_long = format!(
        "{}\nCommit date: {}\nBuild date: {}",
        version_short,
        env!("SHELL_COMMIT_DATE"),
        env!("SHELL_COMPILE_DATE")
    );

    let cli = Command::new(name)
        .version(version_short)
        .long_version(version_long)
        .author("Antmicro <www.antmicro.com>")
        .help_template(
            "{before-help}{bin} {version}\n\
        {about-with-newline}\n\
        {usage-heading}\n\t{usage}\n\
        {all-args}{after-help}",
        )
        // FILE - it is only for wash help printer
        .arg(
            Arg::new("FILE")
                .help("Execute commands from file")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("command")
                .help("Execute provided command")
                .short('c')
                .long("command")
                .value_name("COMMAND")
                .action(ArgAction::Set),
        );

    // Run CLI parser to find script argument only
    let pre_matches = cli
        .clone()
        .ignore_errors(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .get_matches();

    // split CLI args to wash arguments and script arguments
    let all_args: Vec<String> = env::args().collect();
    let (wash_args, script_args) = if let Some(script_idx) = pre_matches.index_of("FILE") {
        (&all_args[..script_idx], &all_args[script_idx..])
    } else {
        (&all_args[..], &[] as &[String])
    };

    let matches = cli.get_matches_from(wash_args);

    let pwd;
    let should_echo = true;

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
    }
    #[cfg(not(target_os = "wasi"))]
    {
        if let Ok(cwd) = env::current_dir() {
            pwd = cwd.display().to_string();
        } else {
            pwd = String::from("/");
        }
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
        if !script_args.is_empty() {
            let script_args: VecDeque<String> = script_args.iter().map(String::from).collect();
            len = script_args.len();
            script = script_args[0].clone();
            script_args
        } else {
            len = 0;
            script = String::from("");
            VecDeque::new()
        },
    );

    let result = if let Some(command) = matches.get_one::<String>("command") {
        shell.run_command(command)
    } else if len != 0 {
        shell.run_commands(io::BufReader::new(File::open(script).unwrap()))
    } else {
        match is_fd_tty(STDIN) {
            Err(_) => {
                // is_fd_tty will fail in WASI runtimes (wasmtime/wasmer/wasiwasm),
                // just run interpreter then without registreing sigint
                shell.run_interpreter()
            }
            Ok(true) => {
                shell
                    .enable_interpreter_mode()
                    .expect("Cannot set STDIN termios flags!");
                #[cfg(target_os = "wasi")]
                {
                    shell
                        .register_sigint()
                        .expect("Cannot register InternalEventSource object!");
                }

                let result = shell.run_interpreter();

                shell
                    .restore_default_mode()
                    .expect("Cannot set STDIN termios flags!");

                result
            }
            Ok(false) => shell.run_commands(io::stdin()),
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
