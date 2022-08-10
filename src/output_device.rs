#[cfg(not(target_os = "wasi"))]
use std::collections::HashMap;
#[cfg(target_os = "wasi")]
use std::fs::{OpenOptions, self};
use std::io::Write;
#[cfg(not(target_os = "wasi"))]
use std::os::unix::prelude::RawFd;
#[cfg(target_os = "wasi")]
use std::path::Path;
use color_eyre::Report;
#[cfg(target_os = "wasi")]
use crate::shell_base::{STDERR, STDOUT, Redirect};
#[cfg(not(target_os = "wasi"))]
use crate::shell_base::{STDERR, STDOUT, OpenedFd};

/// Wrapper for stdout/stderr operations from shell builtins so that they are redirects-aware

#[cfg(target_os = "wasi")]
pub struct OutputDevice<'a> {
    redirects: &'a [Redirect],
    stdout: String,
    stderr: String,
}

#[cfg(target_os = "wasi")]
impl<'a> OutputDevice<'a> {
    pub fn new(redirects: &'a [Redirect]) -> Result<Self, String> {
        for i in redirects.iter() {
            match i {
                Redirect::Write((_, path)) | Redirect::Read((_, path)) | Redirect::Append((_, path)) =>{
                    if Path::new(path).is_dir() { return Err(format!("{}: Is a directory", path)) }
                },
            }
        }
        Ok(OutputDevice {
            redirects,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    // TODO: ensure this gets called, maybe move it to custom Drop implementation
    pub fn flush(&self) -> Result<(), Report> {
        if !self.stdout.is_empty() {
            self.flush_fd(STDOUT, &self.stdout)?;
        }
        if !self.stderr.is_empty() {
            self.flush_fd(STDERR, &self.stderr)?;
        }
        Ok(())
    }

    fn flush_fd(&self, to_fd: u16, output: &str) -> Result<(), Report> {
        let mut is_redirected = false;
        for redirect in self.redirects {
            match redirect {
                Redirect::Write((fd, file)) => {
                    if *fd == to_fd {
                        fs::write(file, output)?;
                        is_redirected = true;
                    }
                }
                Redirect::Append((fd, file)) => {
                    if *fd == to_fd {
                        let mut file = OpenOptions::new().write(true).append(true).open(file)?;
                        write!(file, "{}", output)?;
                        is_redirected = true;
                    }
                }
                _ => {}
            }
        }

        if !is_redirected {
            if to_fd == STDOUT {
                print!("{}", output);
            } else {
                eprint!("{}", output);
            }
        }

        Ok(())
    }

    pub fn print(&mut self, output: &str) {
        self.stdout.push_str(output);
    }

    pub fn println(&mut self, output: &str) {
        self.stdout.push_str(output);
        self.stdout.push('\n');
    }

    pub fn eprint(&mut self, output: &str) {
        self.stderr.push_str(output);
    }

    pub fn eprintln(&mut self, output: &str) {
        self.stderr.push_str(output);
        self.stderr.push('\n');
    }
}

#[cfg(not(target_os = "wasi"))]
pub struct OutputDevice {
    redirects: HashMap<RawFd, OpenedFd>,
    stdout: String,
    stderr: String,
}

#[cfg(not(target_os = "wasi"))]
impl OutputDevice {
    pub fn new(redirects: &HashMap<RawFd, OpenedFd>) -> Result<Self, String> {
        let redirects = redirects.iter().filter_map(|(fd, obj)| {
            match obj {
                OpenedFd::StdIn | OpenedFd::PipeReader(_) => None,
                OpenedFd::File{file, writable} => {
                    if *writable {
                        let file = file.try_clone().unwrap();
                        Some((*fd, OpenedFd::File { file, writable: true }))
                    } else {
                        None
                    }
                },
                OpenedFd::PipeWriter(pipe) => {
                    let pipe = pipe.try_clone().unwrap();
                    Some((*fd, OpenedFd::PipeWriter(pipe)))
                },
                OpenedFd::StdOut => Some((*fd, OpenedFd::StdOut)),
                OpenedFd::StdErr => Some((*fd, OpenedFd::StdErr))
            }
        }).collect::<HashMap<RawFd, OpenedFd>>();
        Ok(OutputDevice {
            redirects,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    // TODO: ensure this gets called, maybe move it to custom Drop implementation
    pub fn flush(&mut self) -> Result<(), Report> {
        // TODO: Due to file/pipe writer self object needs to be mutable
        // TODO: Also we must clone stdout/stderr caused with that mutability
        if !self.stdout.is_empty() {
            if let Err(rep) = self.flush_fd(STDOUT, &self.stdout.clone()) {
                self.eprintln(format!("{}: {}", env!("CARGO_PKG_NAME"), rep).as_str());
            }
        }
        if !self.stderr.is_empty() {
            self.flush_fd(STDERR, &self.stderr.clone())?;
        }
        Ok(())
    }

    fn flush_fd(&mut self, to_fd: u16, output: &str) -> Result<(), Report> {
        let out_obj = match self.redirects.get_mut(&(to_fd as RawFd)) {
            Some(o) => o,
            None => return Err(Report::new(
                std::io::Error::from_raw_os_error(
                    libc::EBADF
                ))),
        };
        match out_obj {
            OpenedFd::File{file, writable: true} => {
                write!(file, "{}", output)?;
            },
            OpenedFd::PipeWriter(pipe) => {
                write!(pipe, "{}", output)?;
            },
            OpenedFd::StdOut => print!("{}", output),
            OpenedFd::StdErr => eprint!("{}", output),
            _ => panic!("OutputDevice: received input object"),
        }
        Ok(())
    }

    pub fn print(&mut self, output: &str) {
        self.stdout.push_str(output);
    }

    pub fn println(&mut self, output: &str) {
        self.stdout.push_str(output);
        self.stdout.push('\n');
    }

    pub fn eprint(&mut self, output: &str) {
        self.stderr.push_str(output);
    }

    pub fn eprintln(&mut self, output: &str) {
        self.stderr.push_str(output);
        self.stderr.push('\n');
    }
}