#[cfg(target_os = "wasi")]
use crate::cli::event_source::InternalEventSource;
use crate::cli::StdinEvent;
use color_eyre::eyre::Report;
use std::io::{self, Read};

pub enum InternalReader {
    #[cfg(target_os = "wasi")]
    StdinWithSigInt(InternalEventSource),
    OnlyStdin,
}

impl Iterator for InternalReader {
    type Item = Result<StdinEvent<u8>, Report>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            #[cfg(target_os = "wasi")]
            InternalReader::StdinWithSigInt(reader) => reader.next(),
            InternalReader::OnlyStdin => {
                let mut buffer: [u8; 1] = [0];
                if let Err(e) = io::stdin().read_exact(&mut buffer) {
                    Some(Err(e.into()))
                } else {
                    Some(Ok(StdinEvent::Data(buffer[0])))
                }
            }
        }
    }
}
