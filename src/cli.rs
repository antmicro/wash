/*
 * Copyright (c) 2022-2024 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::io;
use std::io::Write;

use vte::{Params, Perform};

pub struct Cli {
    pub history: Vec<Vec<char>>,
    pub should_echo: bool,
    pub cursor_position: usize,
    pub input: Vec<char>,

    history_entry_to_display: i32,
    input_ready: bool,
    input_stash: Vec<char>,
    insert_mode: bool,
}

impl Cli {
    pub fn new(should_echo: bool) -> Self {
        Cli {
            cursor_position: 0,
            history: Vec::new(),
            history_entry_to_display: -1,
            input: Vec::new(),
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

                    // for wasi target, we assume that hterm has enabled insert mode
                    #[cfg(target_os = "wasi")]
                    self.echo(&c.to_string());

                    #[cfg(not(target_os = "wasi"))]
                    self.echo(&format!("\x1b[@{}", c));
                } else {
                    self.input[self.cursor_position] = c;

                    #[cfg(target_os = "wasi")]
                    self.echo(&format!("\x1b[P{}", c));

                    #[cfg(not(target_os = "wasi"))]
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
