/*
 * Copyright (c) 2022-2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::HashMap;
use std::env;
#[cfg(target_os = "wasi")]
use std::fs;
#[cfg(not(target_os = "wasi"))]
use std::os::unix::prelude::RawFd;
use std::path::PathBuf;

use conch_parser::ast;
use glob::Pattern;

use crate::shell_base::{Redirect, Shell, EXIT_FAILURE, EXIT_SUCCESS, STDIN, STDOUT};

pub fn interpret(shell: &mut Shell, cmd: &ast::TopLevelCommand<String>) -> i32 {
    handle_top_level_command(shell, cmd)
}

fn handle_top_level_command(
    shell: &mut Shell,
    top_level_command: &ast::TopLevelCommand<String>,
) -> i32 {
    // println!("{:#?}", cmd);
    match &top_level_command.0 {
        ast::Command::Job(list) => handle_listable_command(shell, list, true),
        ast::Command::List(list) => handle_listable_command(shell, list, false),
    }
}

fn handle_listable_command(
    shell: &mut Shell,
    list: &ast::DefaultAndOrList,
    background: bool,
) -> i32 {
    let mut status_code = match &list.first {
        ast::ListableCommand::Single(cmd) => {
            handle_pipeable_command(shell, cmd, background, &mut Vec::new())
        }
        ast::ListableCommand::Pipe(negate, cmds) => handle_pipe(shell, *negate, cmds, background),
    };

    for next_cmd in &list.rest {
        match (status_code, next_cmd) {
            (EXIT_SUCCESS, ast::AndOr::And(cmd)) => {
                status_code = match &cmd {
                    ast::ListableCommand::Single(cmd) => {
                        handle_pipeable_command(shell, cmd, background, &mut Vec::new())
                    }
                    ast::ListableCommand::Pipe(negate, cmds) => {
                        handle_pipe(shell, *negate, cmds, background)
                    }
                }
            }
            (x, ast::AndOr::Or(cmd)) if x != EXIT_SUCCESS => {
                status_code = match &cmd {
                    ast::ListableCommand::Single(cmd) => {
                        handle_pipeable_command(shell, cmd, background, &mut Vec::new())
                    }
                    ast::ListableCommand::Pipe(negate, cmds) => {
                        handle_pipe(shell, *negate, cmds, background)
                    }
                }
            }
            (_, _) => {
                // either (fail, And) or (success, Or)
            }
        }
    }

    status_code
}

fn handle_pipe(
    shell: &mut Shell,
    negate: bool,
    cmds: &[ast::DefaultPipeableCommand],
    background: bool,
) -> i32 {
    #[cfg(target_os = "wasi")]
    let exit_status = {
        handle_pipeable_command(
            shell,
            &cmds[0],
            background,
            // TODO: name of the virtual file should be uniquely generated
            // TODO: add virtual mode that won't create files but in-memory strings
            &mut vec![Redirect::Write((STDOUT, "/proc/pipe0.txt".to_string()))],
        );

        for (i, cmd) in cmds.iter().enumerate().skip(1).take(cmds.len() - 2) {
            handle_pipeable_command(
                shell,
                cmd,
                background,
                &mut vec![
                    Redirect::Read((STDIN, format!("/proc/pipe{}.txt", i - 1))),
                    Redirect::Write((STDOUT, format!("/proc/pipe{}.txt", i))),
                ],
            );
        }

        let exit_status = handle_pipeable_command(
            shell,
            cmds.last().unwrap(),
            background,
            &mut vec![Redirect::Read((
                STDIN,
                format!("/proc/pipe{}.txt", cmds.len() - 2),
            ))],
        );

        // TODO: temporary solution before in-memory files get implemented
        for i in 0..cmds.len() - 1 {
            fs::remove_file(format!("/proc/pipe{}.txt", i)).unwrap();
        }
        exit_status
    };

    #[cfg(not(target_os = "wasi"))]
    let exit_status = {
        let (mut reader, mut writer) = os_pipe::pipe().unwrap();
        handle_pipeable_command(
            shell,
            &cmds[0],
            background,
            &mut vec![Redirect::PipeOut(Some(writer))],
        );

        for cmd in cmds.iter().skip(1).take(cmds.len() - 2) {
            let prev_reader = reader;
            (reader, writer) = os_pipe::pipe().unwrap();
            handle_pipeable_command(
                shell,
                cmd,
                background,
                &mut vec![
                    Redirect::PipeIn(Some(prev_reader)),
                    Redirect::PipeOut(Some(writer)),
                ],
            );
        }

        let exit_status = handle_pipeable_command(
            shell,
            cmds.last().unwrap(),
            background,
            &mut vec![Redirect::PipeIn(Some(reader))],
        );

        exit_status
    };

    // if ! was present at the beginning of the pipe, return logical negation of last command status
    if negate {
        (exit_status != EXIT_SUCCESS) as i32
    } else {
        exit_status
    }
}

fn handle_pipeable_command(
    shell: &mut Shell,
    cmd: &ast::DefaultPipeableCommand,
    background: bool,
    redirects: &mut Vec<Redirect>,
) -> i32 {
    match cmd {
        ast::PipeableCommand::Simple(cmd) => {
            handle_simple_command(shell, cmd, background, redirects)
        }
        ast::PipeableCommand::Compound(cmd) => {
            handle_compound_command(shell, cmd, background, redirects)
        }
        ast::PipeableCommand::FunctionDef(_name, _cmds) => {
            eprintln!("FunctionDef not yet handled (but it would be cool)");
            EXIT_FAILURE
        }
    }
}

fn handle_compound_command(
    shell: &mut Shell,
    cmd: &ast::DefaultCompoundCommand,
    _background: bool,
    _redirects: &mut [Redirect],
) -> i32 {
    let ast::CompoundCommand { kind, io: _ } = cmd;
    match kind {
        ast::CompoundCommandKind::Subshell(subshell_cmds) => {
            // TODO: this should actually spawn a subshell
            let mut exit_status = EXIT_SUCCESS;
            for subshell_cmd in subshell_cmds {
                exit_status = handle_top_level_command(shell, subshell_cmd)
            }
            exit_status
        }
        ast::CompoundCommandKind::For{ var, words, body } => {
            let mut exit_status = EXIT_SUCCESS;
            if let Some(w) = words {
                for word in w {
                    env::set_var(var, handle_top_level_word(shell, word).unwrap());
                    for command in body {
                        exit_status = handle_top_level_command(shell, command);
                    }
                }
            }
            exit_status
        },
        ast::CompoundCommandKind::If{ conditionals, else_branch } => {
            let mut exit_status = EXIT_SUCCESS;
            let mut guard_exit = EXIT_FAILURE;
            for guard_body in conditionals {
                for command in &guard_body.guard {
                    guard_exit = handle_top_level_command(shell, command);
                }
                if guard_exit == EXIT_SUCCESS {
                    for command in &guard_body.body {
                        exit_status = handle_top_level_command(shell, command);
                    }
                    break;
                }
            }
            if guard_exit != EXIT_SUCCESS {
                if let Some(els) = else_branch { for command in els {
                    exit_status = handle_top_level_command(shell, command);
                }
            }};
            exit_status
        },
        ast::CompoundCommandKind::While(guard_body) => {
            let mut exit_status = EXIT_SUCCESS;
            while guard_body.guard.iter().fold(EXIT_SUCCESS, |_, x| { handle_top_level_command(shell, x) }) == EXIT_SUCCESS {
                exit_status = guard_body.body.iter().fold(EXIT_SUCCESS, |_, x| { handle_top_level_command(shell, x) })
            }
            exit_status
        }
        ast::CompoundCommandKind::Case{ word, arms } => {
            let mut exit_status = EXIT_SUCCESS;
            if let Some(handled_word) = handle_top_level_word(shell, word) {
                for arm in arms {
                    if arm.patterns.iter().any(|pattern| {
                        if let Some(handled_pattern) = handle_top_level_word(shell, pattern) {
                            if let Ok(pat) = Pattern::new(&handled_pattern) {
                                pat.matches(&handled_word)
                            } else {
                                // if the pattern contains invalid wildcard, match against literal pattern
                                // TODO: if there are multiple valid wildcards in the pattern and at least
                                // one invalid, the pattern will be taken as literal.
                                // e.g. '[a*' won't match with [abbb
                                handled_pattern == handled_word
                            }
                        } else { false }
                    }) {
                        exit_status = arm.body.iter().fold(
                            EXIT_SUCCESS,
                            |_, x| { handle_top_level_command(shell, x) }
                        );
                        break;
                    }
                }
            } else {
                // if the word could not be matched, exit with failure
                exit_status = EXIT_FAILURE;
            }
            exit_status
        }
        any => {
            eprintln!("CompoundCommandKind not yet handled: {:#?}", any);
            EXIT_FAILURE
        }
    }
}

fn handle_simple_command(
    shell: &mut Shell,
    cmd: &ast::DefaultSimpleCommand,
    background: bool,
    redirects: &mut Vec<Redirect>,
) -> i32 {
    let env = cmd
        .redirects_or_env_vars
        .iter()
        .filter_map(|redirect_or_env_var| match redirect_or_env_var {
            ast::RedirectOrEnvVar::EnvVar(key, value) => {
                let value = match value {
                    None => Some("".to_string()),
                    Some(top_level_word) => handle_top_level_word(shell, top_level_word),
                };
                value.map(|value| (key.clone(), value))
            }
            _ => None,
        })
        .collect::<HashMap<_, _>>();

    let mut args = Vec::new();
    for redirect_or_cmd_word in &cmd.redirects_or_cmd_words {
        match redirect_or_cmd_word {
            ast::RedirectOrCmdWord::Redirect(redirect_type) => {
                if let Some(redirect) = handle_redirect_type(shell, redirect_type) {
                    redirects.push(redirect);
                }
            }
            ast::RedirectOrCmdWord::CmdWord(cmd_word) => {
                if let Some(arg) = handle_top_level_word(shell, &cmd_word.0) {
                    if let Ok(paths) = glob::glob_with(&arg, glob::MatchOptions {
                        case_sensitive: true,
                        require_literal_leading_dot: true,
                        require_literal_separator: true,
                    }) {
                        let mut globbed = paths.map(|s| {
                            if arg.starts_with("./") {
                                // glob crate strips ./ prefix, if it is a bug, maybe we could fix it and submit a PR
                                format!("./{}", s.unwrap().display())
                            } else {
                                s.unwrap().into_os_string().into_string().unwrap()
                            }
                        }).peekable();
                        if globbed.peek().is_none() {
                            args.push(arg);
                        } else {
                            args.extend(globbed);
                        }
                    } else { args.push(arg); }
                }
            }
        }
    }

    if !args.is_empty() {
        match shell.execute_command(&args.remove(0), &mut args, &env, background, redirects) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("{} error: {:?}", env!("CARGO_PKG_NAME"), error);
                EXIT_FAILURE
            }
        }
    } else {
        for (key, value) in env.iter() {
            // if it's a global update env, if shell variable update only vars
            if env::var(key).is_ok() {
                env::set_var(key, value);
                #[cfg(target_os = "wasi")]
                let _ = wasi_ext_lib::set_env(key, Some(value));
            } else {
                shell.vars.insert(key.clone(), value.clone());
            }
        }
        EXIT_SUCCESS
    }
}

fn handle_redirect_type(
    shell: &Shell,
    redirect_type: &ast::Redirect<ast::TopLevelWord<String>>,
) -> Option<Redirect> {
    let get_absolute_path = |filename: String| {
        if !filename.starts_with('/') {
            PathBuf::from(&shell.pwd)
                .join(&filename)
                .display()
                .to_string()
        } else {
            filename
        }
    };

    match redirect_type {
        ast::Redirect::Write(file_descriptor, top_level_word) => {
            // TODO: check noclobber option is set
            let file_descriptor = file_descriptor.unwrap_or(STDOUT);
            if let Some(mut filename) = handle_top_level_word(shell, top_level_word) {
                filename = get_absolute_path(filename);
                #[cfg(not(target_os = "wasi"))]
                let file_descriptor = file_descriptor as RawFd;
                Some(Redirect::Write((file_descriptor, filename)))
            } else {
                None
            }
        },
        ast::Redirect::Append(file_descriptor, top_level_word) => {
            let file_descriptor = file_descriptor.unwrap_or(STDOUT);
            if let Some(mut filename) = handle_top_level_word(shell, top_level_word) {
                filename = get_absolute_path(filename);
                #[cfg(not(target_os = "wasi"))]
                let file_descriptor = file_descriptor as RawFd;
                Some(Redirect::Append((file_descriptor, filename)))
            } else {
                None
            }
        },
        ast::Redirect::Read(file_descriptor, top_level_word) => {
            let file_descriptor = file_descriptor.unwrap_or(STDIN);
            if let Some(mut filename) = handle_top_level_word(shell, top_level_word) {
                filename = get_absolute_path(filename);
                #[cfg(not(target_os = "wasi"))]
                let file_descriptor = file_descriptor as RawFd;
                Some(Redirect::Read((file_descriptor, filename)))
            } else {
                None
            }
        },
        #[cfg(not(target_os = "wasi"))]
        ast::Redirect::ReadWrite(file_descriptor, top_level_word) => {
            let file_descriptor = file_descriptor.unwrap_or(STDIN);
            if let Some(mut filename) = handle_top_level_word(shell, top_level_word) {
                filename = get_absolute_path(filename);
                Some(Redirect::ReadWrite((file_descriptor as RawFd, filename)))
            } else {
                None
            }
        },
        #[cfg(not(target_os = "wasi"))]
        ast::Redirect::Clobber(file_descriptor, top_level_word) => {
            let file_descriptor = file_descriptor.unwrap_or(STDOUT);
            if let Some(mut filename) = handle_top_level_word(shell, top_level_word) {
                filename = get_absolute_path(filename);
                Some(Redirect::Write((file_descriptor as RawFd, filename)))
            } else {
                None
            }
        },
        #[cfg(not(target_os = "wasi"))]
        ast::Redirect::DupRead(file_descriptor, top_level_word) => {
            let fd_dest = file_descriptor.unwrap_or(STDIN);
            if let Some(fd) = handle_top_level_word(shell, top_level_word) {
                match fd.as_str() {
                    "-" => Some(Redirect::Close(fd_dest as RawFd)),
                    fd => if let Ok(fd_source) = fd.parse::<u16>() {
                        Some(Redirect::Duplicate((fd_dest as RawFd, fd_source as RawFd)))
                    } else {
                        eprintln!("DupRead redirect top_level_word not parsed: {:?}", top_level_word);
                        None
                    }
                }
            } else {
                None
            }
        },
        #[cfg(not(target_os = "wasi"))]
        ast::Redirect::DupWrite(file_descriptor, top_level_word) => {
            let fd_dest = file_descriptor.unwrap_or(STDOUT);
            if let Some(fd) = handle_top_level_word(shell, top_level_word) {
                match fd.as_str() {
                    "-" => Some(Redirect::Close(fd_dest as RawFd)),
                    fd => if let Ok(fd_source) = fd.parse::<u16>() {
                        Some(Redirect::Duplicate((fd_dest as RawFd, fd_source as RawFd)))
                    } else {
                        eprintln!("DupWrite redirect top_level_word not parsed: {:?}", top_level_word);
                        None
                    }
                }
            } else {
                None
            }
        },
        // TODO: Heredoc (multiline command parsing) implementation
        any => {
            eprintln!("Redirect not yet handled: {:?}", any);
            None
        },
    }
}

fn handle_top_level_word<'a>(
    shell: &'a Shell,
    word: &'a ast::DefaultComplexWord,
) -> Option<String> {
    match word {
        ast::ComplexWord::Single(word) => handle_single(shell, word),
        ast::ComplexWord::Concat(words) => Some(
            words
                .iter()
                .filter_map(|w| handle_single(shell, w))
                .collect::<Vec<_>>()
                .join(""),
        ),
    }
}

fn handle_single<'a>(shell: &'a Shell, word: &'a ast::DefaultWord) -> Option<String> {
    match &word {
        ast::Word::SingleQuoted(w) => Some(w.clone()),
        ast::Word::Simple(w) => handle_simple_word(shell, w),
        ast::Word::DoubleQuoted(words) => Some(
            words
                .iter()
                .filter_map(|w| handle_simple_word(shell, w))
                .collect::<Vec<_>>()
                .join(" "),
        ),
    }
}

fn handle_simple_word<'a>(shell: &'a Shell, word: &'a ast::DefaultSimpleWord) -> Option<String> {
    match word {
        ast::SimpleWord::Literal(w) => Some(w.clone()),
        ast::SimpleWord::Colon => Some(":".to_string()),
        ast::SimpleWord::Tilde => Some(env::var("HOME").unwrap()),
        ast::SimpleWord::Param(p) => match p {
            ast::Parameter::Var(key) => {
                if let Some(variable) = shell.vars.get(key) {
                    Some(variable.clone())
                } else {
                    env::var(key).ok()
                }
            }
            ast::Parameter::Question => Some(shell.last_exit_status.to_string()),
            ast::Parameter::Dollar => {
                #[cfg(not(target_os = "wasi"))]
                {
                    use std::process;
                    Some(process::id().to_string())
                }
                #[cfg(target_os = "wasi")]
                Some(
                    wasi_ext_lib::getpid().unwrap().to_string()
                )
            }
            ast::Parameter::At => {
                if shell.args.is_empty() {
                    Some(shell.args.range(1..).cloned().collect::<Vec<String>>().join(" "))
                } else { Some(String::from(" ")) }
            },
            ast::Parameter::Pound => {
                Some(format!("{}", if shell.args.is_empty() {
                    shell.args.len() - 1
                } else { 0 }))
            },
            ast::Parameter::Positional(n) => { Some(String::from(if let Some(a) = &shell.args.get(*n as usize) { a } else { "" })) }
            any => Some(format!("parameter not yet handled: {:?}", any)),
        },
        ast::SimpleWord::Star => { Some("*".to_string()) }
        ast::SimpleWord::Question => { Some("?".to_string()) }
        ast::SimpleWord::SquareOpen => { Some("[".to_string()) }
        ast::SimpleWord::SquareClose => { Some("]".to_string()) }
        any => Some(format!("simple word not yet handled: {:?}", any)),
    }
}
