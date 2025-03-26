/*
 * Copyright (c) 2022-2024 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#[cfg(target_os = "wasi")]
pub mod event_source;
mod internal_reader;

use lazy_static::lazy_static;
use regex::Regex;

pub(crate) use internal_reader::InternalReader;

use std::collections::VecDeque;
use std::io::Write;
use std::{fmt, io};

use std::cell::RefCell;
use std::rc::Rc;

use color_eyre::eyre::Report;
use vte::{Params, Parser, Perform};

lazy_static! {
    static ref NUMBER_RE: Regex = Regex::new(r"(?:^|[^\[])!(-?\d+)").unwrap();
}

pub enum StdinEvent<T> {
    Data(T),
    SigInt,
}

pub(crate) enum HistoryExpansion {
    Expanded(String),
    Unchanged(String),
}

#[derive(Debug)]
pub(crate) enum HistoryExpansionError {
    EventNotFound(String),
}
impl std::error::Error for HistoryExpansionError {}
impl fmt::Display for HistoryExpansionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HistoryExpansionError::EventNotFound(ev) => write!(f, "{}: event not found", ev),
        }
    }
}

pub(crate) type HistoryExpansionResult = Result<HistoryExpansion, HistoryExpansionError>;

pub struct Cli {
    pub history: Vec<Vec<char>>,
    pub should_echo: bool,
    pub cursor_position: usize,
    pub input: Vec<char>,

    pub(crate) internal_reader: InternalReader,

    history_entry_to_display: i32,
    input_ready: bool,
    input_stash: Vec<char>,
    insert_mode: bool,
}

impl Cli {
    pub fn new(should_echo: bool, internal_reader: InternalReader) -> Self {
        Cli {
            cursor_position: 0,
            history: Vec::new(),
            history_entry_to_display: -1,
            input: Vec::new(),
            internal_reader,
            input_ready: false,
            input_stash: Vec::new(),
            insert_mode: true,
            should_echo,
        }
    }

    pub fn is_input_ready(&self) -> bool {
        self.input_ready
    }

    pub fn reset(&mut self) {
        self.cursor_position = 0;
        self.history_entry_to_display = -1;
        self.input.clear();
        self.input_ready = false;
        self.input_stash.clear();

        if !self.insert_mode {
            self.insert_mode = true;
        }
    }

    fn echo(&self, output: &str) {
        if self.should_echo {
            // TODO: should this maybe use OutputDevice too?
            print!("{output}");
        } else if output.contains('\n') {
            println!();
        }
    }

    fn get_cursor_to_beginning(&mut self) {
        if self.cursor_position > 0 {
            // bring cursor to the beggining with `ESC[nD` escape sequence
            self.echo(&format!("\x1b[{}D", self.cursor_position));
        }
        self.cursor_position = 0;
    }

    fn get_cursor_to_end(&mut self) {
        let to_end = self.input.len() - self.cursor_position;
        if self.input.len() - self.cursor_position > 0 {
            // bring cursor to the end with `ESC[nC` escape sequence
            self.echo(&format!("\x1b[{}C", to_end));
        }
        self.cursor_position = self.input.len();
    }

    fn erase_input(&mut self) {
        // bring cursor to the beginning and clear line to the right with `ESC[0K`
        self.get_cursor_to_beginning();
        self.echo("\x1b[0K");
    }

    /// Expands input line with history expansion.
    fn history_expansion(&mut self, input: &str) -> HistoryExpansionResult {
        let mut processed = input.to_string();
        if let Some(last_command) = self.history.last() {
            processed = processed.replace("!!", &last_command.iter().collect::<String>());
        }
        // for eg. "!12", "!-2"
        // for each match
        for captures in NUMBER_RE.captures_iter(input) {
            // get matched number
            let full_match = captures.get(0).unwrap().as_str();
            let group_match = captures.get(1).unwrap().as_str();
            let history_number = group_match.parse::<i32>().unwrap();
            let history_number = if history_number < 0 {
                (self.history.len() as i32 + history_number) as usize
            } else {
                (history_number - 1) as usize
            };
            // get that entry from history (if it exists)
            if let Some(history_cmd) = self.history.get(history_number) {
                // replace the match with the entry from history
                processed = processed.replace(full_match, &history_cmd.iter().collect::<String>());
            } else {
                return Err(HistoryExpansionError::EventNotFound(full_match.into()));
            }
        }

        // $ for eg. "!ls"
        lazy_static! {
            static ref STRING_RE: Regex = Regex::new(r"(?:^|[^\[])!(\w+)").unwrap();
        }
        // for each match
        // TODO: Clippy warns about redundant clone here, removing it produces errors
        // find out if there is a better solution that would satisfy Clippy
        #[allow(clippy::redundant_clone)]
        for captures in STRING_RE.captures_iter(&processed.clone()) {
            let full_match = captures.get(0).unwrap().as_str();
            let group_match = captures.get(1).unwrap().as_str();

            // find history entry starting with the match
            if let Some(history_cmd) = self
                .history
                .iter()
                .rev()
                .find(|entry| entry.starts_with(&group_match.chars().collect::<Vec<char>>()))
            {
                // replace the match with the entry from history
                processed = processed.replace(full_match, &history_cmd.iter().collect::<String>());
            } else {
                return Err(HistoryExpansionError::EventNotFound(full_match.into()));
            }
        }

        if input == processed {
            Ok(HistoryExpansion::Unchanged(processed))
        } else {
            Ok(HistoryExpansion::Expanded(processed))
        }
    }
}

impl Perform for Cli {
    fn print(&mut self, c: char) {
        let byte = c as u16;
        match byte {
            // backspace
            0x7f => {
                if !self.input.is_empty() && self.cursor_position > 0 {
                    self.echo("\x1b[D\x1b[P");
                    self.input.remove(self.cursor_position - 1);
                    self.cursor_position -= 1;
                }
            }
            // regular characters
            _ => {
                if self.cursor_position == self.input.len() {
                    self.input.push(c);
                    self.echo(&c.to_string());
                } else if self.insert_mode {
                    // in insert mode, when cursor is in the middle, new character expand CLI
                    // instead of replacing character under cursor

                    self.input.insert(self.cursor_position, c);
                    self.echo(&format!("\x1b[@{}", c));
                } else {
                    self.input[self.cursor_position] = c;
                    self.echo(&c.to_string());
                }

                self.cursor_position += 1;
            }
        }

        io::stdout().flush().unwrap();
    }

    fn execute(&mut self, byte: u8) {
        // C0 and C1 control functions
        match byte {
            // enter
            0xa | 0xd => {
                self.echo("\n");
                self.cursor_position = 0;
                self.input_ready = true;
            }
            _ => { /* ignore for now */ }
        }
        io::stdout().flush().unwrap();
    }

    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _c: char) {
        /* ignore for now */
    }

    fn put(&mut self, _byte: u8) {
        /* ignore for now */
    }

    fn unhook(&mut self) {
        /* ignore for now */
    }

    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {
        /* ignore for now */
    }

    fn csi_dispatch(&mut self, params: &Params, _intermediates: &[u8], _ignore: bool, c: char) {
        if params.len() == 1 {
            let param = params.iter().next().unwrap();
            match (param[0], c) {
                // UpArrow
                (_, 'A') => {
                    if !self.history.is_empty() && self.history_entry_to_display != 0 {
                        if self.history_entry_to_display == -1 {
                            self.history_entry_to_display = (self.history.len() - 1) as i32;
                            self.input_stash = self.input.clone();
                        } else if self.history_entry_to_display > 0 {
                            self.history_entry_to_display -= 1;
                        }

                        self.erase_input();
                        self.input = self.history[self.history_entry_to_display as usize].clone();
                        self.cursor_position = self.input.len();
                        self.echo(&self.input.iter().collect::<String>());
                    }
                }
                // DownArrow
                (_, 'B') => {
                    if self.history_entry_to_display != -1 {
                        self.erase_input();
                        if self.history.len() - 1 > (self.history_entry_to_display as usize) {
                            self.history_entry_to_display += 1;
                            self.input =
                                self.history[self.history_entry_to_display as usize].clone();
                        } else {
                            self.input = self.input_stash.clone();
                            self.history_entry_to_display = -1;
                        }
                        self.cursor_position = self.input.len();
                        self.echo(&self.input.iter().collect::<String>());
                    }
                }
                // RightArrow
                (_, 'C') => {
                    if self.cursor_position < self.input.len() {
                        // move cursor right with `ESC[C`
                        self.echo("\x1b[C");
                        self.cursor_position += 1;
                    }
                }
                // LeftArrow
                (_, 'D') => {
                    if self.cursor_position > 0 {
                        // move cursor left with `ESC[D`
                        self.echo("\x1b[D");
                        self.cursor_position -= 1;
                    }
                }
                // End
                (_, 'F') => {
                    self.get_cursor_to_end();
                }
                // Home
                (_, 'H') => {
                    self.get_cursor_to_beginning();
                }
                // Insert
                (2, '~') => {
                    self.insert_mode = !self.insert_mode;
                }
                // Del
                (3, '~') => {
                    if self.input.len() - self.cursor_position > 0 {
                        self.echo("\x1b[P");
                        self.input.remove(self.cursor_position);
                    }
                }
                // PageUp
                (5, '~') => {
                    if !self.history.is_empty() && self.history_entry_to_display != 0 {
                        if self.history_entry_to_display == -1 {
                            self.input_stash = self.input.clone();
                        }
                        self.history_entry_to_display = 0;
                        self.erase_input();
                        self.input = self.history[0].clone();
                        self.cursor_position = self.input.len();
                        self.echo(&self.input.iter().collect::<String>());
                    }
                }
                // PageDown
                (6, '~') => {
                    if self.history_entry_to_display != -1 {
                        self.erase_input();
                        self.input = self.input_stash.clone();
                        self.history_entry_to_display = -1;
                        self.cursor_position = self.input.len();
                        self.echo(&self.input.iter().collect::<String>());
                    }
                }
                (_, _) => { /* ignore for now */ }
            }
        } else {
            /* ignore for now */
        }
        io::stdout().flush().unwrap();
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {
        /* ignore for now */
    }
}

impl Iterator for Cli {
    type Item = Result<StdinEvent<String>, Report>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut vt_parser = Parser::new();
        self.reset();

        while !self.is_input_ready() {
            match self.internal_reader.next() {
                Some(ev) => {
                    if let Err(e) = ev {
                        return Some(Err(e));
                    }
                    match ev.unwrap() {
                        StdinEvent::Data(byte) => vt_parser.advance(self, byte),
                        StdinEvent::SigInt => return Some(Ok(StdinEvent::SigInt)),
                    }
                }
                None => return None,
            }
        }
        Some(Ok(StdinEvent::Data(
            match self.history_expansion(self.input.iter().collect::<String>().trim()) {
                Ok(HistoryExpansion::Unchanged(s) | HistoryExpansion::Expanded(s)) => s,
                Err(e) => {
                    return Some(Err(e.into()));
                }
            },
        )))
    }
}

#[derive(Default)]
pub(crate) struct CommonState {
    stopped: bool,
    pub last_event: Option<Result<StdinEvent<String>, Report>>,
}

impl CommonState {
    pub fn stop(&mut self) {
        self.stopped = true;
    }
}

pub(crate) struct CliChars<'a> {
    cli: &'a mut Cli,
    last_line: VecDeque<char>,
    common_state: Rc<RefCell<CommonState>>,
    print_ps2: bool,
    ps2_prompt: &'a str,
}

impl<'a> CliChars<'a> {
    pub fn new(cli: &'a mut Cli, ps2_prompt: &'a str) -> Self {
        Self {
            cli,
            common_state: Rc::new(RefCell::new(CommonState::default())),
            last_line: VecDeque::new(),
            print_ps2: false,
            ps2_prompt,
        }
    }

    pub fn get_common_state(&self) -> Rc<RefCell<CommonState>> {
        self.common_state.clone()
    }
}

impl<'a> Iterator for CliChars<'a> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(chr) = self.last_line.pop_front() {
            if chr != '\n' && self.last_line.is_empty() {
                self.last_line.push_back('\n');
            }
            return Some(chr);
        } else if self.common_state.borrow().stopped {
            return None;
        }

        if self.print_ps2 {
            eprint!("{}", self.ps2_prompt);
        }
        self.common_state.borrow_mut().last_event = if let Some(ev) = self.cli.next() {
            self.print_ps2 = true;
            Some(ev)
        } else {
            return None;
        };

        if let Some(Ok(StdinEvent::Data(s))) = &self.common_state.borrow().last_event {
            self.last_line = s.chars().collect::<VecDeque<char>>();
        } else {
            return None;
        }

        self.last_line.pop_front()
    }
}
