use std::fs::OpenOptions;
use std::os::fd::IntoRawFd;

use color_eyre::Report;

use crate::shell_base::{Fd, Redirect, STDIN, STDOUT};

pub enum SavedFd {
    Move {
        fd_src: Fd,
        fd_dst: Fd,
        fd_flags: nix::fcntl::FdFlag,
    },
    Close {
        fd: Fd,
    },
}

impl SavedFd {
    fn save_fd(fd: Fd) -> Result<Self, Report> {
        let saved_fd = match nix::fcntl::fcntl(fd, nix::fcntl::F_DUPFD(10)) {
            Ok(saved_fd) => saved_fd as Fd,
            Err(err) => {
                return Err(Report::msg(format!(
                    "fcntl: cannot duplicate fd {}, errno: {}",
                    fd, err,
                )))
            }
        };

        let flags = match nix::fcntl::fcntl(saved_fd, nix::fcntl::F_GETFD) {
            Ok(flags) => nix::fcntl::FdFlag::from_bits(flags).unwrap(),
            Err(err) => {
                return Err(Report::msg(format!(
                    "fcntl: cannot get flags of fd {}, errno: {}",
                    fd, err,
                )))
            }
        };

        if let Err(err) = nix::fcntl::fcntl(
            saved_fd,
            nix::fcntl::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        ) {
            return Err(Report::msg(format!(
                "fcntl: cannot set flags of fd {}, errno: {}",
                fd, err,
            )));
        }

        Ok(Self::Move {
            fd_src: saved_fd,
            fd_dst: fd,
            fd_flags: flags,
        })
    }

    pub fn process_redirect(
        redirect: &Redirect,
        saved_fds_vec: &mut Vec<Self>,
    ) -> Result<(), Report> {
        let (fd_src, fd_dst, close_src): (Fd, Fd, bool) = match redirect {
            Redirect::Read(fd, path)
            | Redirect::Write(fd, path)
            | Redirect::Append(fd, path)
            | Redirect::ReadWrite(fd, path) => {
                let mut open_options = OpenOptions::new();
                match redirect {
                    Redirect::Read(_, _) => {
                        open_options.read(true);
                    }
                    Redirect::Write(_, _) => {
                        open_options.write(true).truncate(true).create(true);
                    }
                    Redirect::Append(_, _) => {
                        open_options.write(true).append(true).create(true);
                    }
                    Redirect::ReadWrite(_, _) => {
                        open_options.read(true).write(true).create(true);
                    }
                    _ => unreachable!(),
                };

                let opened_fd = match open_options.open(path) {
                    Ok(file) => {
                        // After this line, user is responsible for closing fd
                        file.into_raw_fd() as Fd
                    }
                    Err(err) => {
                        return Err(Report::msg(format!("{}: {}", path, err)));
                    }
                };

                (opened_fd, *fd, true)
            }
            Redirect::PipeIn(fd) => (*fd, STDIN, false),
            Redirect::PipeOut(fd) => (*fd, STDOUT, false),
            Redirect::Duplicate { fd_src, fd_dst } => (*fd_src, *fd_dst, false),
            Redirect::Close(fd) => {
                return match Self::save_fd(*fd) {
                    Ok(saved_fd) => {
                        saved_fds_vec.push(saved_fd);
                        return Ok(());
                    }
                    Err(err) => Err(Report::msg(format!("Cannot store fd, errno: {}", err))),
                }
            }
        };

        let fd_flags_res = nix::fcntl::fcntl(fd_dst, nix::fcntl::F_GETFD);

        match fd_flags_res {
            Ok(_) if fd_dst != fd_src => {
                // Make copy of fd
                match Self::save_fd(fd_dst) {
                    Ok(saved_fd) => saved_fds_vec.push(saved_fd),
                    Err(err) => return Err(err),
                }
            }
            Ok(_) => {
                // Case when file is already opened on dst_fd, skip fd_renumber
                saved_fds_vec.push(Self::Close { fd: fd_dst });
                return Ok(());
            }
            #[cfg(not(target_os = "wasi"))]
            Err(nix::errno::Errno::EBADF) => {
                // We can make redirect without saving fd
                saved_fds_vec.push(Self::Close { fd: fd_dst });
            }
            Err(err) => {
                return Err(Report::msg(format!(
                    "fcntl: cannot get flags of fd {}, errno: {}",
                    fd_dst, err
                )));
            }
        }

        #[cfg(not(target_os = "wasi"))]
        if let Err(err) = nix::unistd::dup2(fd_src, fd_dst) {
            return Err(Report::msg(format!("dup2: {}", err)));
        } else if close_src {
            if let Err(err) = nix::unistd::close(fd_src) {
                return Err(Report::msg(format!("close: {}", err)));
            }
        }

        Ok(())
    }

    pub fn restore_fds(fds: Vec<Self>) {
        for saved_fd in fds.into_iter().rev() {
            match saved_fd {
                Self::Move {
                    fd_src,
                    fd_dst,
                    fd_flags,
                } => {
                    if let Err(err) = nix::unistd::dup2(fd_src, fd_dst) {
                        panic!("{}: dup2: {}", env!("CARGO_PKG_NAME"), err);
                    } else if let Err(err) = nix::unistd::close(fd_src) {
                        panic!("{}: close: {}", env!("CARGO_PKG_NAME"), err);
                    } else if let Err(err) =
                        nix::fcntl::fcntl(fd_dst, nix::fcntl::F_SETFD(fd_flags))
                    {
                        panic!("{}: fcntl: {}", env!("CARGO_PKG_NAME"), err);
                    }
                }
                Self::Close { fd } => {
                    if let Err(err) = nix::unistd::close(fd) {
                        panic!("{}: close: {}", env!("CARGO_PKG_NAME"), err);
                    }
                }
            }
        }
    }
}
