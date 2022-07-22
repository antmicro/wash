use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(target_os = "wasi")]
use std::path::Path;

use color_eyre::Report;

use crate::shell_base::{Redirect, STDERR, STDOUT};

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
    redirects: Vec<Redirect>,
    stdout: String,
    stderr: String,
}

#[cfg(not(target_os = "wasi"))]
impl OutputDevice {
    pub fn new(redirects: &Vec<Redirect>) -> Result<Self, String> {
        let redirects = redirects.iter().filter_map(|red| {
            match red {
                Redirect::Write((fd, path)) => {
                    Some(Redirect::Write((*fd, path.clone())))
                },
                Redirect::Append((fd, path)) => {
                    Some(Redirect::Append((*fd, path.clone())))
                },
                Redirect::PipeOut(pipe) => {
                    Some(Redirect::PipeOut(pipe.try_clone().unwrap()))
                }
                _ => None
            }
        }).collect::<Vec<Redirect>>();
        Ok(OutputDevice {
            redirects,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    // TODO: ensure this gets called, maybe move it to custom Drop implementation
    pub fn flush(&mut self) -> Result<(), Report> {
        // TODO: Due to pipe writer self object needs to be mutable
        // TODO: Also we must clone stdout/stderr caused with that mutability
        if !self.stdout.is_empty() {
            self.flush_fd(STDOUT, &self.stdout.clone())?;
        }
        if !self.stderr.is_empty() {
            self.flush_fd(STDERR, &self.stderr.clone())?;
        }
        Ok(())
    }

    fn flush_fd(&mut self, to_fd: u16, output: &str) -> Result<(), Report> {
        let mut is_redirected = false;
        for redirect in self.redirects.iter_mut() {
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
                Redirect::PipeOut(pipe) => {
                    if to_fd == STDOUT {
                        pipe.write(format!("{}", output).as_bytes()).unwrap();
                        is_redirected = true;
                    }
                }
                // TODO: stderr case

                // TODO: Control must not enter here, maybe panic? 
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