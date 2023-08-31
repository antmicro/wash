use color_eyre::Report;

use crate::shell_base::Fd;

pub enum SavedFd {
    Move {
        fd_src: Fd,
        fd_dst: Fd,
        fd_flags: wasi::Fdflags,
    },
    Close {
        fd: Fd,
    },
}

impl SavedFd {
    pub fn save_fd(fd: Fd) -> Result<Self, Report> {
        let saved_fd =
            match wasi_ext_lib::fcntl(fd, wasi_ext_lib::FcntlCommand::F_MVFD { min_fd_num: 10 }) {
                Ok(saved_fd) => saved_fd as wasi::Fd,
                Err(err) => {
                    return Err(Report::msg(format!(
                        "fcntl: cannot move fd {}, errno: {}",
                        fd, err,
                    )))
                }
            };

        let flags = match wasi_ext_lib::fcntl(saved_fd, wasi_ext_lib::FcntlCommand::F_GETFD) {
            Ok(flags) => flags as wasi::Fdflags,
            Err(err) => {
                return Err(Report::msg(format!(
                    "fcntl: cannot get flags of fd {}, errno: {}",
                    fd, err,
                )))
            }
        };

        if let Err(err) = wasi_ext_lib::fcntl(
            saved_fd,
            wasi_ext_lib::FcntlCommand::F_SETFD {
                flags: wasi_ext_lib::WASI_EXT_FDFLAG_CLOEXEC,
            },
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
                    if let Err(err) = unsafe { wasi::fd_renumber(fd_src, fd_dst) } {
                        panic!("{}: fd_renumber: {}", env!("CARGO_PKG_NAME"), err);
                    } else if let Err(err) = unsafe { wasi::fd_close(fd_src) } {
                        panic!("{}: fd_close: {}", env!("CARGO_PKG_NAME"), err);
                    } else if let Err(err) = wasi_ext_lib::fcntl(
                        fd_dst,
                        wasi_ext_lib::FcntlCommand::F_SETFD { flags: fd_flags },
                    ) {
                        panic!("{}: fcntl: {}", env!("CARGO_PKG_NAME"), err);
                    }
                }
                SavedFd::Close { fd } => {
                    if let Err(err) = unsafe { wasi::fd_close(fd as Fd) } {
                        panic!("{}: fd_close: {}", env!("CARGO_PKG_NAME"), err);
                    }
                }
            }
        }
    }
}