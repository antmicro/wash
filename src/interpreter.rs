/*
 * Copyright (c) 2022-2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::HashMap;
use std::env;
#[cfg(target_os = "wasi")]
use std::fs;
#[cfg(target_os = "wasi")]
use std::fs::OpenOptions;
#[cfg(target_os = "wasi")]
use std::io::Read;
#[cfg(target_os = "wasi")]
use std::os::fd::AsRawFd;
use std::os::fd::IntoRawFd;
#[cfg(target_os = "wasi")]
use std::path::Path;
use std::path::PathBuf;

use conch_parser::ast::{
    self, ComplexWord::Single, GuardBodyPair, PatternBodyPair, SimpleWord::Param, TopLevelCommand,
    TopLevelWord, Word::Simple,
};
use conch_parser::lexer::Lexer;
use conch_parser::parse::{DefaultParser, ParseError, SourcePos};

use glob::Pattern;

#[cfg(not(target_os = "wasi"))]
use nix;

use crate::shell_base::{
    preprocess_redirects, Fd, Redirect, Shell, EXIT_FAILURE, EXIT_INTERRUPTED, EXIT_SUCCESS, STDIN,
    STDOUT,
};

use crate::output_device::OutputDevice;

#[cfg(not(target_os = "wasi"))]
use crate::shell_base::{apply_redirects, wait_for_child};

use crate::saved_fd::SavedFd;

pub struct InputInterpreter<'a> {
    input: &'a str,
}

impl<'a> InputInterpreter<'a> {
    pub fn from_input(input: &str) -> InputInterpreter {
        InputInterpreter { input }
    }

    pub fn interpret(&mut self, shell: &mut Shell) -> i32 {
        let lex = Lexer::new(self.input.chars());
        let parser = DefaultParser::new(lex);
        let mut exit_status = EXIT_SUCCESS;

        for cmd in parser {
            exit_status = match cmd {
                Ok(cmd) => self.handle_top_level_command(shell, &cmd),
                Err(e) => {
                    let err_msg = match e {
                        /*
                        TODO: Most of these errors will never occur due to
                        unimplemented shell features so error messages are
                        kind of general.
                        */
                        ParseError::BadFd(pos_start, pos_end) => {
                            let idx_start = pos_start.byte;
                            let idx_end = pos_end.byte;
                            format!(
                                "{}: ambiguous redirect",
                                self.input[idx_start..idx_end].to_owned()
                            )
                        }
                        ParseError::BadIdent(_, _) => "bad idenftifier".to_string(),
                        ParseError::BadSubst(_, _) => "bad substitution".to_string(),
                        ParseError::Unmatched(_, _) => "unmached expression".to_string(),
                        ParseError::IncompleteCmd(_, _, _, _) => "incomplete command".to_string(),
                        ParseError::Unexpected(_, _) => "unexpected token".to_string(),
                        ParseError::UnexpectedEOF => "unexpected end of file".to_string(),
                        ParseError::Custom(t) => {
                            format!("custom AST error: {t:?}")
                        }
                    };
                    eprintln!("{}: {}", env!("CARGO_PKG_NAME"), err_msg);
                    shell.last_exit_status = EXIT_FAILURE;
                    EXIT_FAILURE
                }
            };
            if exit_status == EXIT_INTERRUPTED {
                break;
            }
        }
        // TODO: pass proper exit status code
        exit_status
    }

    fn handle_top_level_command(
        &self,
        shell: &mut Shell,
        top_level_command: &ast::TopLevelCommand<String>,
    ) -> i32 {
        match &top_level_command.0 {
            ast::Command::Job(list) => self.handle_listable_command(shell, list, true),
            ast::Command::List(list) => self.handle_listable_command(shell, list, false),
        }
    }

    fn handle_listable_command(
        &self,
        shell: &mut Shell,
        list: &ast::DefaultAndOrList,
        background: bool,
    ) -> i32 {
        let mut status_code = match &list.first {
            ast::ListableCommand::Single(cmd) => {
                self.handle_pipeable_command(shell, cmd, background, &mut Vec::new())
            }
            ast::ListableCommand::Pipe(negate, cmds) => {
                self.handle_pipe(shell, *negate, cmds, background)
            }
        };

        for next_cmd in &list.rest {
            match (status_code, next_cmd) {
                (EXIT_INTERRUPTED, _) => return status_code,
                (EXIT_SUCCESS, ast::AndOr::And(cmd)) => {
                    status_code = match &cmd {
                        ast::ListableCommand::Single(cmd) => {
                            self.handle_pipeable_command(shell, cmd, background, &mut Vec::new())
                        }
                        ast::ListableCommand::Pipe(negate, cmds) => {
                            self.handle_pipe(shell, *negate, cmds, background)
                        }
                    }
                }
                (x, ast::AndOr::Or(cmd)) if x != EXIT_SUCCESS => {
                    status_code = match &cmd {
                        ast::ListableCommand::Single(cmd) => {
                            self.handle_pipeable_command(shell, cmd, background, &mut Vec::new())
                        }
                        ast::ListableCommand::Pipe(negate, cmds) => {
                            self.handle_pipe(shell, *negate, cmds, background)
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
        &self,
        shell: &mut Shell,
        negate: bool,
        cmds: &[ast::DefaultPipeableCommand],
        background: bool,
    ) -> i32 {
        let exit_status = {
            #[cfg(target_os = "wasi")]
            // TODO: name of the virtual file should be uniquely generated
            // TODO: add virtual mode that won't create files but in-memory strings
            let fd_writer = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/tmp/pipe0.txt")
                .expect("Cannot create pipe")
                .into_raw_fd() as Fd;

            #[cfg(not(target_os = "wasi"))]
            let (fd_reader, fd_writer) = {
                let pipe = os_pipe::pipe().expect("Cannot create pipe.");
                (pipe.0.into_raw_fd() as Fd, pipe.1.into_raw_fd() as Fd)
            };

            let mut exit_code = self.handle_pipeable_command(
                shell,
                &cmds[0],
                background,
                &mut vec![Redirect::PipeOut(fd_writer)],
            );

            #[cfg(target_os = "wasi")]
            unsafe { wasi::fd_close(fd_writer) }.expect("Cannot close pipe write end!");

            #[cfg(not(target_os = "wasi"))]
            let mut saved_reader = fd_reader;
            #[cfg(not(target_os = "wasi"))]
            nix::unistd::close(fd_writer).expect("Cannot close pipe write end!");

            for (i, cmd) in cmds.iter().enumerate().skip(1).take(cmds.len() - 2) {
                if exit_code == EXIT_INTERRUPTED {
                    break;
                }

                let (fd_reader, fd_writer) = {
                    #[cfg(target_os = "wasi")]
                    {
                        let read_end = OpenOptions::new()
                            .read(true)
                            .open(format!("/tmp/pipe{}.txt", i - 1))
                            .expect("Cannot create pipe read end!");
                        let write_end = OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .open(format!("/tmp/pipe{i}.txt"))
                            .expect("Cannot create pipe write end!");

                        (read_end.into_raw_fd() as Fd, write_end.into_raw_fd() as Fd)
                    }

                    #[cfg(not(target_os = "wasi"))]
                    {
                        let _ = i;
                        let pipe = os_pipe::pipe().expect("Cannot create pipe.");
                        let fds = (saved_reader, pipe.1.into_raw_fd() as Fd);
                        saved_reader = pipe.0.into_raw_fd() as Fd;
                        fds
                    }
                };

                exit_code = self.handle_pipeable_command(
                    shell,
                    cmd,
                    background,
                    &mut vec![Redirect::PipeIn(fd_reader), Redirect::PipeOut(fd_writer)],
                );

                // Close reader and writer
                #[cfg(target_os = "wasi")]
                unsafe {
                    wasi::fd_close(fd_reader).expect("Cannot close pipe read end!");
                    wasi::fd_close(fd_writer).expect("Cannot close pipe write end!");
                }
                #[cfg(not(target_os = "wasi"))]
                {
                    nix::unistd::close(fd_reader).expect("Cannot close pipe read end!");
                    nix::unistd::close(fd_writer).expect("Cannot close pipe write end!");
                }
            }

            if exit_code != EXIT_INTERRUPTED {
                let fd_reader = {
                    #[cfg(target_os = "wasi")]
                    {
                        OpenOptions::new()
                            .read(true)
                            .open(format!("/tmp/pipe{}.txt", cmds.len() - 2))
                            .expect("Cannot create pipe")
                            .into_raw_fd() as Fd
                    }

                    #[cfg(not(target_os = "wasi"))]
                    saved_reader
                };

                exit_code = self.handle_pipeable_command(
                    shell,
                    cmds.last().unwrap(),
                    background,
                    &mut vec![Redirect::PipeIn(fd_reader)],
                );

                #[cfg(target_os = "wasi")]
                unsafe { wasi::fd_close(fd_reader) }.expect("Cannot close pipe read end!");
                #[cfg(not(target_os = "wasi"))]
                nix::unistd::close(fd_reader).expect("Cannot close pipe write end!");
            }

            // TODO: temporary solution before in-memory files get implemented
            #[cfg(target_os = "wasi")]
            for i in 0..cmds.len() - 1 {
                let pipe_name = format!("/tmp/pipe{i}.txt");
                if Path::new(pipe_name.as_str()).exists() {
                    fs::remove_file(pipe_name.as_str()).unwrap();
                }
            }
            exit_code
        };

        // if ! was present at the beginning of the pipe, return logical negation of last command status
        if negate {
            (exit_status != EXIT_SUCCESS) as i32
        } else {
            exit_status
        }
    }

    fn handle_pipeable_command(
        &self,
        shell: &mut Shell,
        cmd: &ast::DefaultPipeableCommand,
        background: bool,
        redirects: &mut Vec<Redirect>,
    ) -> i32 {
        match cmd {
            ast::PipeableCommand::Simple(cmd) => {
                self.handle_simple_command(shell, cmd, background, redirects)
            }
            ast::PipeableCommand::Compound(cmd) => {
                self.handle_compound_command(shell, cmd, background, redirects)
            }
            ast::PipeableCommand::FunctionDef(_name, _cmds) => {
                eprintln!("FunctionDef not handled");
                EXIT_FAILURE
            }
        }
    }

    fn handle_compound_command(
        &self,
        shell: &mut Shell,
        cmd: &ast::DefaultCompoundCommand,
        background: bool,
        redirects: &mut Vec<Redirect>,
    ) -> i32 {
        let ast::CompoundCommand { kind, io } = cmd;

        for redirect_type in io.iter() {
            if let Some(redirect) = self.handle_redirect_type(shell, redirect_type) {
                redirects.push(redirect);
            } else {
                eprintln!("{}: cannot handle redirect!", env!("CARGO_PKG_NAME"));
                return EXIT_FAILURE;
            };
        }

        let mut output_device = OutputDevice::new();
        if let Err(err) = preprocess_redirects(redirects, &mut output_device) {
            output_device.eprintln(format!("{}: {}", env!("CARGO_PKG_NAME"), err).as_str());
            if let Err(err) = output_device.flush() {
                eprintln!("Cannot flush output_device: {}", err)
            }
            return EXIT_FAILURE;
        }

        if let ast::CompoundCommandKind::Subshell {
            body,
            start_pos,
            end_pos,
        } = kind
        {
            return self
                .handle_compound_subshell(shell, body, start_pos, end_pos, background, redirects);
        }

        let mut fds_to_restore: Vec<SavedFd> = Vec::new();

        for redirect in redirects.iter() {
            if let Err(err) = SavedFd::process_redirect(redirect, &mut fds_to_restore) {
                eprintln!("{}: {}", env!("CARGO_PKG_NAME"), err);
                SavedFd::restore_fds(fds_to_restore);
                return EXIT_FAILURE;
            }
        }

        let exit_status = match kind {
            ast::CompoundCommandKind::Subshell {
                body: _,
                start_pos: _,
                end_pos: _,
            } => unreachable!(),
            ast::CompoundCommandKind::For { var, words, body } => match words {
                Some(words) => self.handle_compound_for(shell, var, words, body, background),
                None => EXIT_SUCCESS,
            },
            ast::CompoundCommandKind::If {
                conditionals,
                else_branch,
            } => self.handle_compound_if(shell, conditionals, else_branch, background),
            ast::CompoundCommandKind::While(guard_body) => {
                self.handle_compound_while(shell, guard_body, background)
            }
            ast::CompoundCommandKind::Case { word, arms } => {
                self.handle_compound_case(shell, word, arms, background)
            }
            any => {
                eprintln!("CompoundCommandKind not handled: {any:#?}");
                EXIT_FAILURE
            }
        };

        SavedFd::restore_fds(fds_to_restore);
        exit_status
    }

    #[cfg(target_os = "wasi")]
    fn handle_compound_subshell(
        &self,
        shell: &mut Shell,
        _body: &[TopLevelCommand<String>],
        start_pos: &SourcePos,
        end_pos: &SourcePos,
        background: bool,
        redirects: &[Redirect],
    ) -> i32 {
        let subshell_cmds = &self.input[(start_pos.byte + 1)..(end_pos.byte)];

        let mut args_vec = vec!["-c".to_string(), subshell_cmds.to_string()];

        match shell.execute_command(
            "wash",
            &mut args_vec,
            &HashMap::new(),
            background,
            redirects,
        ) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("{} error: {:?}", env!("CARGO_PKG_NAME"), error);
                EXIT_FAILURE
            }
        }
    }

    #[cfg(not(target_os = "wasi"))]
    fn handle_compound_subshell(
        &self,
        shell: &mut Shell,
        body: &Vec<TopLevelCommand<String>>,
        _start_pos: &SourcePos,
        _end_pos: &SourcePos,
        background: bool,
        redirects: &[Redirect],
    ) -> i32 {
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                if !background {
                    wait_for_child(child)
                } else {
                    EXIT_SUCCESS
                }
            }
            Ok(nix::unistd::ForkResult::Child) => {
                // Apply all redirects passed to subshell
                if let Err(err) = apply_redirects(redirects) {
                    eprintln!("{}: {}", env!("CARGO_PKG_NAME"), err);
                    std::process::exit(EXIT_FAILURE);
                }

                let mut exit_status = EXIT_SUCCESS;

                // Run subshell commands
                for subshell_cmd in body {
                    exit_status = self.handle_top_level_command(shell, subshell_cmd);
                    if exit_status == EXIT_INTERRUPTED {
                        break;
                    }
                }

                std::process::exit(exit_status);
            }
            Err(err) => {
                eprintln!(
                    "{} error: subshell fork failed: {}",
                    env!("CARGO_PKG_NAME"),
                    err
                );
                EXIT_FAILURE
            }
        }
    }

    fn handle_compound_for(
        &self,
        shell: &mut Shell,
        var: &String,
        word_list: &Vec<TopLevelWord<String>>,
        body: &Vec<TopLevelCommand<String>>,
        // TODO: implement background jobs in compounds
        _background: bool,
    ) -> i32 {
        let mut exit_status = EXIT_SUCCESS;
        let mut finall_list: Vec<String> = vec![];

        for word in word_list {
            match word {
                TopLevelWord(Single(Simple(Param(_)))) => {
                    if let TopLevelWord(Single(Simple(param_word))) = word {
                        if let Some(value) = self.handle_simple_word(shell, param_word) {
                            finall_list.append(
                                &mut value
                                    .split_whitespace()
                                    .map(String::from)
                                    .collect::<Vec<String>>(),
                            );
                        }
                    }
                }
                word => {
                    if let Some(w) = self.handle_top_level_word(shell, word) {
                        finall_list.push(w);
                    }
                }
            }
        }

        for word in finall_list {
            env::set_var(var, word);
            for command in body {
                exit_status = self.handle_top_level_command(shell, command);
                if exit_status == EXIT_INTERRUPTED {
                    return exit_status;
                }
            }
        }
        exit_status
    }

    fn handle_compound_if(
        &self,
        shell: &mut Shell,
        conditionals: &Vec<GuardBodyPair<TopLevelCommand<String>>>,
        else_branch: &Option<Vec<TopLevelCommand<String>>>,
        // TODO: implement background jobs in compounds
        _background: bool,
    ) -> i32 {
        let mut exit_status = EXIT_SUCCESS;
        let mut guard_status = EXIT_SUCCESS;
        for guard_body in conditionals {
            for command in &guard_body.guard {
                guard_status = self.handle_top_level_command(shell, command);
                if guard_status == EXIT_INTERRUPTED {
                    return guard_status;
                }
            }
            if guard_status == EXIT_SUCCESS {
                for command in &guard_body.body {
                    exit_status = self.handle_top_level_command(shell, command);
                    if exit_status == EXIT_INTERRUPTED {
                        return exit_status;
                    }
                }
                return exit_status;
            } else {
                shell.last_exit_status = EXIT_SUCCESS;
            }
        }
        if guard_status != EXIT_SUCCESS && guard_status != EXIT_INTERRUPTED {
            if let Some(els) = else_branch {
                for command in els {
                    exit_status = self.handle_top_level_command(shell, command);
                    if exit_status == EXIT_INTERRUPTED {
                        break;
                    }
                }
            }
        };
        exit_status
    }

    fn handle_compound_while(
        &self,
        shell: &mut Shell,
        guard_body: &GuardBodyPair<TopLevelCommand<String>>,
        // TODO: implement background jobs in compounds
        _background: bool,
    ) -> i32 {
        let mut exit_status = EXIT_SUCCESS;
        loop {
            for cmd in guard_body.guard.iter() {
                exit_status = self.handle_top_level_command(shell, cmd);
                if exit_status == EXIT_INTERRUPTED {
                    return exit_status;
                }
            }

            if exit_status != EXIT_SUCCESS {
                exit_status = EXIT_SUCCESS;
                shell.last_exit_status = EXIT_SUCCESS;
                break;
            }

            for cmd in guard_body.body.iter() {
                exit_status = self.handle_top_level_command(shell, cmd);
                if exit_status == EXIT_INTERRUPTED {
                    return exit_status;
                }
            }
        }
        exit_status
    }

    fn handle_compound_case(
        &self,
        shell: &mut Shell,
        word: &TopLevelWord<String>,
        arms: &Vec<PatternBodyPair<TopLevelWord<String>, TopLevelCommand<String>>>,
        // TODO: implement background jobs in compounds
        _background: bool,
    ) -> i32 {
        let mut exit_status = EXIT_SUCCESS;
        let handled_word = self
            .handle_top_level_word(shell, word)
            .unwrap_or("".to_string());
        for arm in arms {
            if arm.patterns.iter().any(|pattern| {
                // TODO: Ctrl-C is not handled during processing pattern because `Subst`
                // is not handled and we cannot execute any command in pattern
                if let Some(handled_pattern) = self.handle_top_level_word(shell, pattern) {
                    if let Ok(pat) = Pattern::new(&handled_pattern) {
                        pat.matches(&handled_word)
                    } else {
                        // if the pattern contains invalid wildcard, match against literal pattern
                        // TODO: if there are multiple valid wildcards in the pattern and at least
                        // one invalid, the pattern will be taken as literal.
                        // e.g. '[a*' won't match with [abbb
                        handled_pattern == handled_word
                    }
                } else {
                    // When command fails then bash try to match handled_word with empty string
                    handled_word.is_empty()
                }
            }) {
                for command in arm.body.iter() {
                    exit_status = self.handle_top_level_command(shell, command);
                    if exit_status == EXIT_INTERRUPTED {
                        break;
                    }
                }
                break;
            }
        }
        exit_status
    }

    fn handle_simple_command(
        &self,
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
                        Some(top_level_word) => self.handle_top_level_word(shell, top_level_word),
                    };
                    value.map(|value| (key.clone(), value))
                }
                ast::RedirectOrEnvVar::Redirect(redirect_type) => {
                    // TODO: in case of None break execution?
                    if let Some(redirect) = self.handle_redirect_type(shell, redirect_type) {
                        redirects.push(redirect);
                    }
                    None
                }
            })
            .collect::<HashMap<_, _>>();

        let mut args = Vec::new();
        for redirect_or_cmd_word in &cmd.redirects_or_cmd_words {
            match redirect_or_cmd_word {
                ast::RedirectOrCmdWord::Redirect(redirect_type) => {
                    // TODO: in case of None break execution?
                    if let Some(redirect) = self.handle_redirect_type(shell, redirect_type) {
                        redirects.push(redirect);
                    }
                }
                ast::RedirectOrCmdWord::CmdWord(cmd_word) => {
                    if let Some(arg) = self.handle_top_level_word(shell, &cmd_word.0) {
                        if let Ok(paths) = glob::glob_with(
                            &arg,
                            glob::MatchOptions {
                                case_sensitive: true,
                                require_literal_leading_dot: true,
                                require_literal_separator: true,
                            },
                        ) {
                            let mut globbed = paths
                                .map(|s| {
                                    if arg.starts_with("./") {
                                        // glob crate strips ./ prefix, if it is a bug, maybe we could fix it and submit a PR
                                        format!("./{}", s.unwrap().display())
                                    } else {
                                        s.unwrap().into_os_string().into_string().unwrap()
                                    }
                                })
                                .peekable();
                            if globbed.peek().is_none() {
                                args.push(arg);
                            } else {
                                args.extend(globbed);
                            }
                        } else {
                            args.push(arg);
                        }
                    }
                }
            }
        }

        if !args.is_empty() {
            match shell.execute_command(&args.remove(0), &mut args, &env, background, redirects) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("{}: {:?}", env!("CARGO_PKG_NAME"), error);
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
        &self,
        shell: &mut Shell,
        redirect_type: &ast::Redirect<ast::TopLevelWord<String>>,
    ) -> Option<Redirect> {
        let get_absolute_path = |filename: String, sh: &Shell| {
            if !filename.starts_with('/') {
                PathBuf::from(&sh.pwd).join(&filename).display().to_string()
            } else {
                filename
            }
        };

        match redirect_type {
            ast::Redirect::Write(file_descriptor, top_level_word) => {
                // TODO: check noclobber option is set
                let file_descriptor = file_descriptor.map_or_else(|| STDOUT, |fd| fd as Fd);
                if let Some(mut filename) = self.handle_top_level_word(shell, top_level_word) {
                    filename = get_absolute_path(filename, shell);
                    Some(Redirect::Write(file_descriptor, filename))
                } else {
                    None
                }
            }
            ast::Redirect::Append(file_descriptor, top_level_word) => {
                let file_descriptor = file_descriptor.map_or_else(|| STDOUT, |fd| fd as Fd);
                if let Some(mut filename) = self.handle_top_level_word(shell, top_level_word) {
                    filename = get_absolute_path(filename, shell);
                    Some(Redirect::Append(file_descriptor, filename))
                } else {
                    None
                }
            }
            ast::Redirect::Read(file_descriptor, top_level_word) => {
                let file_descriptor = file_descriptor.map_or_else(|| STDIN, |fd| fd as Fd);
                if let Some(mut filename) = self.handle_top_level_word(shell, top_level_word) {
                    filename = get_absolute_path(filename, shell);
                    Some(Redirect::Read(file_descriptor, filename))
                } else {
                    None
                }
            }
            ast::Redirect::ReadWrite(file_descriptor, top_level_word) => {
                let file_descriptor = file_descriptor.map_or_else(|| STDIN, |fd| fd as Fd);
                if let Some(mut filename) = self.handle_top_level_word(shell, top_level_word) {
                    filename = get_absolute_path(filename, shell);
                    Some(Redirect::ReadWrite(file_descriptor, filename))
                } else {
                    None
                }
            }
            ast::Redirect::Clobber(file_descriptor, top_level_word) => {
                let file_descriptor = file_descriptor.map_or_else(|| STDOUT, |fd| fd as Fd);
                if let Some(mut filename) = self.handle_top_level_word(shell, top_level_word) {
                    filename = get_absolute_path(filename, shell);
                    Some(Redirect::Write(file_descriptor, filename))
                } else {
                    None
                }
            }
            ast::Redirect::DupRead(file_descriptor, top_level_word) => {
                let fd_dst = file_descriptor.map_or_else(|| STDIN, |fd| fd as Fd);
                if let Some(fd) = self.handle_top_level_word(shell, top_level_word) {
                    match fd.as_str() {
                        "-" => Some(Redirect::Close(fd_dst as Fd)),
                        fd => {
                            if let Ok(fd_src) = fd.parse::<Fd>() {
                                Some(Redirect::Duplicate { fd_src, fd_dst })
                            } else {
                                eprintln!("DupRead redirect cannot be parsed: {top_level_word:?}");
                                None
                            }
                        }
                    }
                } else {
                    None
                }
            }
            ast::Redirect::DupWrite(file_descriptor, top_level_word) => {
                let fd_dst = file_descriptor.map_or_else(|| STDOUT, |fd| fd as Fd);
                if let Some(fd) = self.handle_top_level_word(shell, top_level_word) {
                    match fd.as_str() {
                        "-" => Some(Redirect::Close(fd_dst as Fd)),
                        fd => {
                            if let Ok(fd_src) = fd.parse::<Fd>() {
                                Some(Redirect::Duplicate { fd_src, fd_dst })
                            } else {
                                eprintln!("DupWrite redirect cannot be parsed: {top_level_word:?}");
                                None
                            }
                        }
                    }
                } else {
                    None
                }
            }
            // TODO: Heredoc (multiline command parsing) implementation
            any => {
                eprintln!("Redirect not handled: {any:?}");
                None
            }
        }
    }

    fn handle_top_level_word(
        &self,
        shell: &mut Shell,
        word: &ast::DefaultComplexWord,
    ) -> Option<String> {
        match word {
            ast::ComplexWord::Single(word) => self.handle_single(shell, word),
            ast::ComplexWord::Concat(words) => Some(
                words
                    .iter()
                    .filter_map(|w| self.handle_single(shell, w))
                    .collect::<Vec<_>>()
                    .join(""),
            ),
        }
    }

    fn handle_single(&self, shell: &mut Shell, word: &ast::DefaultWord) -> Option<String> {
        match &word {
            ast::Word::SingleQuoted(w) => Some(w.clone()),
            ast::Word::Simple(w) => self.handle_simple_word(shell, w),
            ast::Word::DoubleQuoted(words) => Some(
                words
                    .iter()
                    .filter_map(|w| self.handle_simple_word(shell, w))
                    .collect::<Vec<_>>()
                    .join(""),
            ),
        }
    }

    fn handle_simple_word(
        &self,
        shell: &mut Shell,
        word: &ast::DefaultSimpleWord,
    ) -> Option<String> {
        match word {
            ast::SimpleWord::Literal(w) => Some(w.clone()),
            ast::SimpleWord::Colon => Some(":".to_string()),
            ast::SimpleWord::Tilde => Some(env::var("HOME").unwrap()),
            #[cfg(target_os = "wasi")]
            ast::SimpleWord::Subst(c) => match (*c).as_ref() {
                ast::ParameterSubstitution::Command(cmd, (start, end)) => {
                    let subshell_pipe_path =
                        format!("/dev/subshell_pipe.{}", wasi_ext_lib::getpid().unwrap_or(0));
                    wasi_ext_lib::mknod(&subshell_pipe_path, -1).unwrap();

                    let mut one = 1;
                    let mut subshell_pipe = fs::OpenOptions::new()
                        .read(true)
                        .open(&subshell_pipe_path)
                        .unwrap();
                    wasi_ext_lib::ioctl(
                        subshell_pipe.as_raw_fd(),
                        wasi_ext_lib::FIFOSCLOSERM,
                        Some(&mut one),
                    )
                    .unwrap();

                    self.handle_compound_subshell(
                        shell,
                        cmd,
                        start,
                        end,
                        false,
                        &[Redirect::Write(1, subshell_pipe_path.to_string())],
                    );

                    let mut data = String::new();
                    subshell_pipe.read_to_string(&mut data).unwrap();
                    if data.ends_with('\n') {
                        data.pop();
                    }

                    Some(data)
                }
                _ => todo!(),
            },
            ast::SimpleWord::Escaped(w) => Some(w.replace('\\', "")),
            ast::SimpleWord::Param(p) => match p {
                ast::Parameter::Bang => shell.last_job_pid.map(|pid| pid.to_string()),
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
                    Some(wasi_ext_lib::getpid().unwrap().to_string())
                }
                ast::Parameter::At => {
                    if !shell.args.is_empty() {
                        Some(
                            shell
                                .args
                                .range(1..)
                                .cloned()
                                .collect::<Vec<String>>()
                                .join(" "),
                        )
                    } else {
                        Some(String::from(" "))
                    }
                }
                ast::Parameter::Pound => Some(format!(
                    "{}",
                    if !shell.args.is_empty() {
                        shell.args.len() - 1
                    } else {
                        0
                    }
                )),
                ast::Parameter::Positional(n) => Some(String::from(
                    if let Some(a) = &shell.args.get(*n as usize) {
                        a
                    } else {
                        ""
                    },
                )),
                any => {
                    eprintln!("parameter not handled: {any:?}");
                    None
                }
            },
            ast::SimpleWord::Star => Some("*".to_string()),
            ast::SimpleWord::Question => Some("?".to_string()),
            ast::SimpleWord::SquareOpen => Some("[".to_string()),
            ast::SimpleWord::SquareClose => Some("]".to_string()),
            #[cfg(not(target_os = "wasi"))]
            any => {
                eprintln!("simple word not handled: {any:?}");
                None
            }
        }
    }
}
