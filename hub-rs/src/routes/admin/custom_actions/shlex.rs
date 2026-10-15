//! Shell-ish command-line parsing for custom actions: `shlex`-compatible
//! splitting/quoting and the command-list validation
//! (`services/custom_actions.py`).

use super::super::py_repr;

// ---------------------------------------------------------------------------
// shlex (services/custom_actions.py tokenization — never a shell)
// ---------------------------------------------------------------------------

/// `shlex.split` (POSIX mode, `comments=False`): quoting is honoured (`echo "a
/// b"` → two tokens) but nothing is ever executed through a shell.
///
/// Ported state machine for `shlex.shlex.read_token` with `whitespace_split`:
/// outside quotes a backslash escapes any character (dropping the backslash);
/// inside `'…'` everything is literal; inside `"…"` only `\"` and `\\` are
/// escapes — any other `\x` keeps the backslash, exactly like CPython.
pub fn shlex_split(input: &str) -> Result<Vec<String>, String> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Space,
        Word,
        SingleQuote,
        DoubleQuote,
        /// Backslash escape: `return` is the state to resume after it.
        Escape {
            in_double_quotes: bool,
        },
    }

    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut state = State::Space;
    let mut chars = input.chars();

    loop {
        let next = chars.next();
        match state {
            State::Escape { in_double_quotes } => {
                let Some(c) = next else {
                    return Err("No escaped character".to_owned());
                };
                if in_double_quotes && c != '\\' && c != '"' {
                    // "only the quote itself or the escape character may be
                    // escaped within quotes" — the backslash stays.
                    token.push('\\');
                }
                token.push(c);
                state = if in_double_quotes {
                    State::DoubleQuote
                } else {
                    State::Word
                };
            }
            State::SingleQuote | State::DoubleQuote => {
                let quote = if state == State::SingleQuote {
                    '\''
                } else {
                    '"'
                };
                let Some(c) = next else {
                    return Err("No closing quotation".to_owned());
                };
                if c == quote {
                    state = State::Word;
                } else if c == '\\' && quote == '"' {
                    state = State::Escape {
                        in_double_quotes: true,
                    };
                } else {
                    token.push(c);
                }
            }
            State::Space => match next {
                None => break,
                Some(c) if c.is_whitespace() => continue,
                Some('\'') => {
                    quoted = true;
                    state = State::SingleQuote;
                }
                Some('"') => {
                    quoted = true;
                    state = State::DoubleQuote;
                }
                Some('\\') => {
                    state = State::Escape {
                        in_double_quotes: false,
                    }
                }
                Some(c) => {
                    token.push(c);
                    state = State::Word;
                }
            },
            State::Word => match next {
                None => break,
                Some(c) if c.is_whitespace() => {
                    tokens.push(std::mem::take(&mut token));
                    quoted = false;
                    state = State::Space;
                }
                Some('\'') => {
                    quoted = true;
                    state = State::SingleQuote;
                }
                Some('"') => {
                    quoted = true;
                    state = State::DoubleQuote;
                }
                Some('\\') => {
                    state = State::Escape {
                        in_double_quotes: false,
                    }
                }
                Some(c) => token.push(c),
            },
        }
    }

    // `echo ""` emits an empty token (quoted=True); a trailing word break does
    // not emit a spurious empty one.
    if !token.is_empty() || quoted {
        tokens.push(token);
    }
    Ok(tokens)
}

/// `shlex.quote` — the safe character set of CPython's `_find_unsafe`
/// (`[^\w@%+=:,./-]`, ASCII) decides between verbatim and `'…'`.
pub fn shlex_quote(value: &str) -> String {
    let unsafe_ = value.chars().any(|c| {
        !(c.is_ascii_alphanumeric()
            || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-'))
    });
    if !value.is_empty() && !unsafe_ {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// `shlex.join` — the canonical display form of an argv vector.
pub fn shlex_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Command-line parsing (services/custom_actions.py)
// ---------------------------------------------------------------------------

const MAX_COMMANDS: usize = 32;
const MAX_ARGV: usize = 64;
const MAX_ELEM: usize = 1024;

/// `custom_actions.parse_command_lines` — parse command lines into argv
/// vectors (shlex tokenization, no shell). Each non-blank line becomes one
/// argv vector. Raises the exact Python `ValueError` messages otherwise.
pub fn parse_command_lines(lines: &[String]) -> Result<Vec<Vec<String>>, String> {
    let mut commands: Vec<Vec<String>> = Vec::new();
    for raw in lines {
        if raw.trim().is_empty() {
            continue; // skip blank lines
        }
        let argv = shlex_split(raw)
            .map_err(|e| format!("could not parse command {}: {}", py_repr(raw), e))?;
        if argv.is_empty() {
            continue;
        }
        if argv.len() > MAX_ARGV {
            return Err(format!("command has too many tokens (max {MAX_ARGV})"));
        }
        for elem in &argv {
            if elem.contains('\0') || elem.chars().count() > MAX_ELEM {
                return Err("command token contains a null byte or is too long".to_owned());
            }
        }
        commands.push(argv);
    }
    if commands.is_empty() {
        return Err("at least one command is required".to_owned());
    }
    if commands.len() > MAX_COMMANDS {
        return Err(format!("too many commands (max {MAX_COMMANDS})"));
    }
    Ok(commands)
}

/// `custom_actions.lines_of` — stored argv vectors back to canonical command
/// lines (for display).
pub fn lines_of(commands: &[Vec<String>]) -> Vec<String> {
    commands.iter().map(|argv| shlex_join(argv)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shlex_split_matches_cpython() {
        assert_eq!(shlex_split(r#"echo "a b""#).unwrap(), ["echo", "a b"]);
        assert_eq!(shlex_split(r"echo a\ b").unwrap(), ["echo", "a b"]);
        assert_eq!(shlex_split("echo 'it is'").unwrap(), ["echo", "it is"]);
        assert_eq!(shlex_split(r#"echo "a\tb""#).unwrap(), ["echo", r"a\tb"]);
        assert_eq!(shlex_split(r#"echo a\"b"#).unwrap(), ["echo", "a\"b"]);
        assert_eq!(shlex_split("echo ''").unwrap(), ["echo", ""]);
        assert_eq!(
            shlex_split("echo  spaced   out ").unwrap(),
            ["echo", "spaced", "out"]
        );
        assert_eq!(shlex_split("a\"b c\"d").unwrap(), ["ab cd"]);
        assert_eq!(
            shlex_split(r#"echo "back\\slash""#).unwrap(),
            ["echo", r"back\slash"]
        );
        assert!(shlex_split("").unwrap().is_empty());
        assert!(shlex_split("   ").unwrap().is_empty());

        assert_eq!(
            shlex_split("echo 'unbal").unwrap_err(),
            "No closing quotation"
        );
        assert_eq!(
            shlex_split("echo \"unbal").unwrap_err(),
            "No closing quotation"
        );
        assert_eq!(
            shlex_split("echo tail\\").unwrap_err(),
            "No escaped character"
        );
    }

    #[test]
    fn shlex_quote_and_join_match_cpython() {
        assert_eq!(shlex_quote("plain"), "plain");
        assert_eq!(shlex_quote("under_score"), "under_score");
        assert_eq!(shlex_quote("a-b_c.d,e/f@g%h+i=j"), "a-b_c.d,e/f@g%h+i=j");
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("a b"), "'a b'");
        assert_eq!(shlex_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shlex_quote("a\"b"), "'a\"b'");
        assert_eq!(
            shlex_join(&["echo".into(), "a b".into(), "it's".into()]),
            "echo 'a b' 'it'\"'\"'s'"
        );
    }

    #[test]
    fn parse_command_lines_matches_the_python_service() {
        let lines = vec![
            "systemctl restart nginx".to_owned(),
            "echo \"a b\"".to_owned(),
        ];
        assert_eq!(
            parse_command_lines(&lines).unwrap(),
            vec![vec!["systemctl", "restart", "nginx"], vec!["echo", "a b"]]
        );
        // Blank lines are skipped.
        assert_eq!(
            parse_command_lines(&["  ".to_owned(), "uptime".to_owned()]).unwrap(),
            vec![vec!["uptime"]]
        );
        // Errors carry the exact Python messages.
        assert_eq!(
            parse_command_lines(&["echo 'oops".to_owned()]).unwrap_err(),
            "could not parse command \"echo 'oops\": No closing quotation"
        );
        assert_eq!(
            parse_command_lines(&["".to_owned()]).unwrap_err(),
            "at least one command is required"
        );
        let too_many = vec!["true".to_owned(); 33];
        assert_eq!(
            parse_command_lines(&too_many).unwrap_err(),
            "too many commands (max 32)"
        );
        let huge_line = vec![format!("echo {}", "x".repeat(1025))];
        assert_eq!(
            parse_command_lines(&huge_line).unwrap_err(),
            "command token contains a null byte or is too long"
        );
        // lines_of round-trips the display form.
        let commands = parse_command_lines(&["echo \"a b\"".to_owned()]).unwrap();
        assert_eq!(lines_of(&commands), vec!["echo 'a b'"]);
    }
}
