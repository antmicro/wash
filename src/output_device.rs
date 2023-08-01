/*
 * Copyright (c) 2022-2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// #[cfg(target_os = "wasi")]
use crate::shell_base::{Fd, Redirect, STDOUT, STDERR};

use color_eyre::Report;
use std::fs::{File, OpenOptions};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::io::Write;

#[derive(Debug)]
/// Wrapper for stdout/stderr operations from shell builtins so that they are redirects-aware
pub struct OutputDevice<'a> {
    stdout_redirect: Option<&'a Redirect>,
    stderr_redirect: Option<&'a Redirect>,
    stdout_data: String,
    stderr_data: String,
}

impl<'a> OutputDevice<'a> {
    pub fn new() -> Self {
        OutputDevice {
            stdout_redirect: None,
            stderr_redirect: None,
            stdout_data: String::new(),
            stderr_data: String::new(),
        }
    }

    pub fn set_redirect_out(&mut self, redirect: &'a Redirect) {
        self.stdout_redirect = Some(redirect);
    }

    pub fn set_redirect_err(&mut self, redirect: &'a Redirect) {
        self.stderr_redirect = Some(redirect);
    }

    // TODO: ensure this gets called, maybe move it to custom Drop implementation
    pub fn flush(&mut self) -> Result<(), Report> {
        if !self.stdout_data.is_empty() {
            self.flush_fd(STDOUT, &self.stdout_data)?;
        }
        if !self.stderr_data.is_empty() {
            self.flush_fd(STDERR, &self.stderr_data)?;
        }
        Ok(())
    }

    fn flush_fd(&self, to_fd: Fd, output: &str) -> Result<(), Report> {
        let redirect = if to_fd == STDOUT {
            self.stdout_redirect
        } else {
            self.stderr_redirect
        };

        let mut finall_file = match redirect {
            None => unsafe { File::from_raw_fd(to_fd as RawFd) },
            Some(Redirect::Write(_, path))  => {
                OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(path)?
                
            }
            Some(Redirect::Append(_, path)) => {
                OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open(path)?
            }
            Some(Redirect::ReadWrite(_, path)) => {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(path)?
            }
            Some(Redirect::PipeOut(fd)) => {
                unsafe { File::from_raw_fd(*fd as RawFd) }
            }
            Some(Redirect::Duplicate { fd_src, fd_dst: _ }) => {
                unsafe { File::from_raw_fd(*fd_src as RawFd) }
            }
            Some(Redirect::Read(_, _)) |
            Some(Redirect::PipeIn(_)) |
            Some(Redirect::Close(_)) => {
                return Err(Report::msg(
                format!(
                        "Wrong redirection type '{:?}' for writing.",
                        redirect.unwrap()
                    )
                ));
            }
        };

        let res = write!(finall_file, "{}", output);
        finall_file.flush().unwrap();
        match redirect {
            Some(Redirect::Write(_, _)) |
            Some(Redirect::Append(_, _)) |
            Some(Redirect::ReadWrite(_, _)) => {
                // Close opened file;
                drop(finall_file);
            }
            None |
            Some(Redirect::PipeOut(_)) | 
            Some(Redirect::Duplicate { fd_src: _, fd_dst: _ }) => {
                // Leave fd opened
                let _ = finall_file.into_raw_fd();
            }
            _ => unreachable!()
        }

        if let Err(err) = res {
            Err(Report::msg(format!("Cannot write to file descriptor in output device: {}", err)))
        } else {
            Ok(())
        }
    }

    pub fn print(&mut self, output: &str) {
        self.stdout_data.push_str(output);
    }

    pub fn println(&mut self, output: &str) {
        self.stdout_data.push_str(output);
        self.stdout_data.push('\n');
    }

    pub fn eprint(&mut self, output: &str) {
        self.stderr_data.push_str(output);
    }

    pub fn eprintln(&mut self, output: &str) {
        self.stderr_data.push_str(output);
        self.stderr_data.push('\n');
    }
}
