/*
 * Copyright (c) 2022-2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use color_eyre::Report;
use lazy_static::lazy_static;

use crate::output_device::OutputDevice;
use crate::shell_base::path_exists;
use crate::shell_base::Shell;
use crate::shell_base::{CLEAR_ESCAPE_CODE, EXIT_FAILURE, EXIT_SUCCESS};

type Internal = fn(&mut Shell, &mut [String], &mut OutputDevice) -> Result<i32, Report>;

fn clear(
    _shell: &mut Shell,
    _args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    output_device.print(CLEAR_ESCAPE_CODE);
    Ok(EXIT_SUCCESS)
}

fn exit(
    _shell: &mut Shell,
    args: &mut [String],
    _output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    let exit_code: i32 = {
        if args.is_empty() {
            EXIT_SUCCESS
        } else {
            args[0].parse().unwrap()
        }
    };
    std::process::exit(exit_code);
}

fn pwd(
    _shell: &mut Shell,
    _args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    output_device.println(&env::current_dir().unwrap().display().to_string());
    Ok(EXIT_SUCCESS)
}

fn cd(
    shell: &mut Shell,
    args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    let path = if args.is_empty() {
        PathBuf::from(env::var("HOME").unwrap())
    } else if args[0] == "-" {
        PathBuf::from(env::var("OLDPWD").unwrap())
    } else if args[0].starts_with('/') {
        PathBuf::from(&args[0])
    } else {
        PathBuf::from(&shell.pwd).join(&args[0])
    };

    if !path_exists(path.to_str().unwrap())? {
        output_device.eprintln(&format!(
            "cd: {}: No such file or directory",
            path.display()
        ));
        Ok(EXIT_FAILURE)
    } else {
        let metadata = fs::metadata(&path).unwrap();
        if metadata.is_file() {
            output_device.eprintln(&format!("cd: {}: Not a directory", path.display()));
            Ok(EXIT_FAILURE)
        } else {
            // TODO: for both targets, chain the commands and exit early if previous
            // step fails
            #[cfg(target_os = "wasi")]
            {
                wasi_ext_lib::set_env(
                    "OLDPWD",
                    Some(env::current_dir().unwrap().to_str().unwrap()),
                )
                .unwrap();
                shell.pwd = fs::canonicalize(&path).unwrap();
                wasi_ext_lib::set_env("PWD", Some(shell.pwd.to_str().unwrap())).unwrap();
                wasi_ext_lib::chdir(shell.pwd.to_str().unwrap()).unwrap();
            }
            #[cfg(not(target_os = "wasi"))]
            {
                env::set_var("OLDPWD", env::current_dir().unwrap().to_str().unwrap());
                shell.pwd = fs::canonicalize(path).unwrap();
                env::set_var("PWD", &shell.pwd);
                env::set_current_dir(&shell.pwd).unwrap();
            }
            Ok(EXIT_SUCCESS)
        }
    }
}

fn history(
    shell: &mut Shell,
    _args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    for (i, history_entry) in shell.cli.history.iter().enumerate() {
        output_device.println(&format!(
            "{}: {}",
            i + 1,
            history_entry.iter().collect::<String>()
        ));
    }
    Ok(EXIT_SUCCESS)
}

fn unset(
    shell: &mut Shell,
    args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    if args.is_empty() {
        output_device.eprintln("unset: help: unset <VAR> [<VAR>] ...");
        Ok(EXIT_FAILURE)
    } else {
        for arg in args {
            if arg == "PWD" || arg == "HOME" {
                output_device.println(&format!("unset: cannot unset {}", &arg));
            } else {
                shell.vars.remove(arg);
                if env::var(&arg).is_ok() {
                    env::remove_var(&arg);
                    #[cfg(target_os = "wasi")]
                    wasi_ext_lib::set_env(arg, None).unwrap();
                }
            }
        }
        Ok(EXIT_SUCCESS)
    }
}

fn declare(
    shell: &mut Shell,
    args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    if args.is_empty() {
        // TODO: we should join and sort the variables!
        for (key, value) in shell.vars.iter() {
            output_device.println(&format!("{key}={value}"));
        }
        for (key, value) in env::vars() {
            output_device.println(&format!("{key}={value}"));
        }
    } else if args[0] == "-x" || args[0] == "+x" {
        // if -x is provided declare works as export
        // if +x then makes global var local
        for arg in args.iter().skip(1) {
            if args[0] == "-x" {
                if let Some((key, value)) = arg.split_once('=') {
                    #[cfg(target_os = "wasi")]
                    wasi_ext_lib::set_env(key, Some(value)).unwrap();
                    #[cfg(not(target_os = "wasi"))]
                    env::set_var(key, value);
                }
            } else if let Some((key, value)) = arg.split_once('=') {
                #[cfg(target_os = "wasi")]
                wasi_ext_lib::set_env(key, None).unwrap();
                shell.vars.insert(key.to_string(), value.to_string());
            } else {
                let value = env::var(arg).unwrap();
                #[cfg(target_os = "wasi")]
                wasi_ext_lib::set_env(arg, None).unwrap();
                shell.vars.insert(arg.clone(), value.clone());
            }
        }
    } else {
        for arg in args {
            if let Some((key, value)) = arg.split_once('=') {
                shell.vars.insert(key.to_string(), value.to_string());
            }
        }
    }
    Ok(EXIT_SUCCESS)
}

fn export(
    shell: &mut Shell,
    args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    // export creates an env value if A=B notation is used,
    // or just copies a local var to env if "=" is not used.
    // Export on nonexisting local var exports empty variable.
    if args.is_empty() {
        output_device.eprintln("export: help: export <VAR>[=<VALUE>] [<VAR>[=<VALUE>]] ...");
        Ok(EXIT_FAILURE)
    } else {
        for arg in args {
            if let Some((key, value)) = arg.split_once('=') {
                shell.vars.remove(key);
                #[cfg(not(target_os = "wasi"))]
                env::set_var(key, value);
                #[cfg(target_os = "wasi")]
                wasi_ext_lib::set_env(key, Some(value)).unwrap();
            } else if let Some(value) = shell.vars.remove(arg) {
                #[cfg(not(target_os = "wasi"))]
                env::set_var(arg, value);
                #[cfg(target_os = "wasi")]
                wasi_ext_lib::set_env(arg, Some(&value)).unwrap();
            } else {
                #[cfg(not(target_os = "wasi"))]
                env::set_var(arg, "");
                #[cfg(target_os = "wasi")]
                wasi_ext_lib::set_env(arg, Some("")).unwrap();
            }
        }
        Ok(EXIT_SUCCESS)
    }
}

fn source(
    shell: &mut Shell,
    args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    if let Some(filename) = args.first() {
        shell.run_script(filename).unwrap();
        Ok(EXIT_SUCCESS)
    } else {
        output_device.eprintln("source: help: source <filename>");
        Ok(EXIT_FAILURE)
    }
}

fn write(
    _shell: &mut Shell,
    args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    if args.len() < 2 {
        output_device.eprintln("write: help: write <filename> <contents>");
        Ok(EXIT_FAILURE)
    } else {
        let filename = &args[1];
        let content = args.join(" ");
        match fs::write(filename, content) {
            Ok(_) => Ok(EXIT_SUCCESS),
            Err(error) => {
                output_device.eprintln(&format!(
                    "write: failed to write to file '{filename}': {error}"
                ));
                Ok(EXIT_FAILURE)
            }
        }
    }
}

fn shift(
    shell: &mut Shell,
    args: &mut [String],
    output_device: &mut OutputDevice,
) -> Result<i32, Report> {
    if args.len() > 1 {
        output_device.eprintln("shift: too many arguments");
        Ok(EXIT_FAILURE)
    } else if let Some(n) = &args.first() {
        if let Ok(m) = n.parse::<i32>() {
            if m < 0 {
                output_device.eprintln(&format!("shift: {m}: shift count out of range"));
                Ok(EXIT_FAILURE)
            } else if m as usize <= shell.args.len() {
                _ = shell.args.drain(0..m as usize);
                Ok(EXIT_SUCCESS)
            } else {
                Ok(EXIT_FAILURE)
            }
        } else {
            output_device.eprintln(&format!("shift: {n}: numeric argument required"));
            Ok(EXIT_FAILURE)
        }
    } else {
        _ = shell.args.pop_front();
        Ok(EXIT_SUCCESS)
    }
}

lazy_static! {
    pub static ref INTERNALS_MAP: HashMap<&'static str, Internal> = {
        let mut m: HashMap<&'static str, Internal> = HashMap::new();
        m.insert("clear", clear);
        m.insert("shift", shift);
        m.insert("exit", exit);
        m.insert("pwd", pwd);
        m.insert("cd", cd);
        m.insert("history", history);
        m.insert("unset", unset);
        m.insert("declare", declare);
        m.insert("export", export);
        m.insert("source", source);
        m.insert("write", write);
        m.insert("shift", shift);
        m
    };
}
