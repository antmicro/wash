
use color_eyre::Report;

use crate::shell_base::Fd;

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
    pub fn save_fd(fd: Fd) -> Result<Self, Report> {
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

        Ok(SavedFd::Move {
            fd_src: saved_fd,
            fd_dst: fd,
            fd_flags: flags,
        })
    }

    pub fn restore_fds(fds: Vec<SavedFd>) {
        for saved_fd in fds.into_iter().rev() {
            match saved_fd {
                SavedFd::Move {
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
                SavedFd::Close { fd } => {
                    if let Err(err) = nix::unistd::close(fd) {
                        panic!("{}: close: {}", env!("CARGO_PKG_NAME"), err);
                    }
                }
            }
        }
    }
}