use crate::shell_base::STDIN;
use color_eyre::Report;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::wasi::io::{AsRawFd, FromRawFd, RawFd};
use wasi;

use super::StdinEvent;

const TTY_TOKEN: u64 = 1;
const SIGINT_TOKEN: u64 = 2;

pub struct InternalEventSource {
    subs: [wasi::Subscription; 2],
    events: [wasi::Event; 2],
    tty_input: File,
    event_src: File,
}

impl AsRawFd for InternalEventSource {
    fn as_raw_fd(&self) -> RawFd {
        self.event_src.as_raw_fd()
    }
}

impl Iterator for InternalEventSource {
    type Item = Result<StdinEvent<u8>, Report>;

    fn next(&mut self) -> Option<Self::Item> {
        // subscribe and wait
        let mut byte: [u8; 1] = [0];
        let result = unsafe {
            wasi::poll_oneoff(
                self.subs.as_ptr(),
                self.events.as_mut_ptr(),
                self.subs.len(),
            )
        };

        let events_count = match result {
            Ok(n) => n,
            Err(e) => {
                return Some(Err(Report::msg(format!(
                    "Poll_oneoff returned non zero code = {e}!"
                ))));
            }
        };

        for event in self.events[0..events_count].iter() {
            let errno = event.error.raw();
            if errno > 0 {
                return Some(Err(Report::msg(
                    "Poll_oneoff returned non zero code for event!",
                )));
            }
        }

        for event in self.events[0..events_count].iter() {
            match (event.userdata, event.type_) {
                (TTY_TOKEN, wasi::EVENTTYPE_FD_READ) => {
                    if let Err(e) = self.tty_input.read_exact(&mut byte) {
                        return Some(Err(e.into()));
                    }
                }
                (SIGINT_TOKEN, wasi::EVENTTYPE_FD_READ) => {
                    let mut read_buff: [u8; wasi_ext_lib::WASI_EVENTS_MASK_SIZE] =
                        [0u8; wasi_ext_lib::WASI_EVENTS_MASK_SIZE];

                    if let Err(e) = self.event_src.read_exact(&mut read_buff) {
                        return Some(Err(e.into()));
                    }

                    if u32::from_le_bytes(read_buff) as wasi_ext_lib::WasiEvents
                        & wasi_ext_lib::WASI_EVENT_SIGINT
                        != 0
                    {
                        return Some(Ok(StdinEvent::SigInt));
                    } else {
                        unreachable!();
                    }
                }
                _ => unreachable!(),
            }
        }

        Some(Ok(StdinEvent::Data(byte[0])))
    }
}

impl Default for InternalEventSource {
    fn default() -> Self {
        let input_fd = STDIN as i32;

        if !wasi_ext_lib::isatty(input_fd).unwrap() {
            panic!("Input is not TTY!");
        }

        let event_source_fd = match wasi_ext_lib::event_source_fd(wasi_ext_lib::WASI_EVENT_SIGINT) {
            Ok(fd) => fd,
            Err(err) => {
                panic!("Cannot obtain event_source_fd, error code: {}", err);
            }
        };

        InternalEventSource {
            subs: [
                wasi::Subscription {
                    userdata: TTY_TOKEN,
                    u: wasi::SubscriptionU {
                        tag: wasi::EVENTTYPE_FD_READ.raw(),
                        u: wasi::SubscriptionUU {
                            fd_read: wasi::SubscriptionFdReadwrite {
                                file_descriptor: input_fd as u32,
                            },
                        },
                    },
                },
                wasi::Subscription {
                    userdata: SIGINT_TOKEN,
                    u: wasi::SubscriptionU {
                        tag: wasi::EVENTTYPE_FD_READ.raw(),
                        u: wasi::SubscriptionUU {
                            fd_read: wasi::SubscriptionFdReadwrite {
                                file_descriptor: event_source_fd as u32,
                            },
                        },
                    },
                },
            ],
            events: unsafe { mem::zeroed() },
            tty_input: unsafe { File::from_raw_fd(input_fd) },
            event_src: unsafe { File::from_raw_fd(event_source_fd) },
        }
    }
}
