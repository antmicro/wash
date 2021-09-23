use conch_parser::ast;

#[derive(Debug)]
pub enum Action {
    Command {
        name: String,
        args: Vec<String>,
        background: bool,
    },
    SetEnv {
        key: String,
        value: String,
    },
}

pub fn interpret(cmd: &ast::TopLevelCommand<String>) -> Action {
    match &cmd.0 {
        ast::Command::Job(list) => handle_listable_command(list, true),
        ast::Command::List(list) => handle_listable_command(list, false)
    }
}

fn handle_listable_command(list: &ast::DefaultAndOrList, background: bool) -> Action {
    match &list.first {
        ast::ListableCommand::Single(cmd) => {
            match cmd {
                ast::PipeableCommand::Simple(cmd) => {
                    let mut words = cmd
                        .redirects_or_cmd_words
                        .iter()
                        .filter_map(|redirect_or_cmd_word| match redirect_or_cmd_word {
                            ast::RedirectOrCmdWord::Redirect(_) => None, // TODO: handle redirects
                            ast::RedirectOrCmdWord::CmdWord(cmd_word) => {
                                match &cmd_word.0 {
                                    ast::ComplexWord::Single(word) => match &word {
                                        ast::Word::SingleQuoted(w) => Some(w.clone()),
                                        ast::Word::Simple(w) => {
                                            get_simple_word_as_string(w)
                                        }
                                        ast::Word::DoubleQuoted(words) => Some(
                                            words
                                                .iter()
                                                .filter_map(|w| {
                                                    get_simple_word_as_string(w)
                                                })
                                                .collect::<Vec<_>>()
                                                .join(" "),
                                        ),
                                    },
                                    ast::ComplexWord::Concat(_) => None, // TODO: handle concat (just join together?)
                                }
                            }
                        })
                        .collect::<Vec<String>>();
                    return Action::Command {
                        name: words.remove(0),
                        args: words,
                        background,
                    }
                }
                _ => unimplemented!(),
            };
        }
        ast::ListableCommand::Pipe(_, cmds) => unimplemented!(),
    }

    // TODO: handle list.rest
}


fn get_simple_word_as_string(word: &ast::DefaultSimpleWord) -> Option<String> {
    match word {
        ast::SimpleWord::Literal(w) => Some(w.clone()),
        _ => None, // Ignoring substitutions and others for simplicity here
    }
}