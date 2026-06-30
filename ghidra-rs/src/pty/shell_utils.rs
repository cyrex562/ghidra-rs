use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    Normal,
    NormalEscape,
    Dquote,
    DquoteEscape,
    Squote,
    SquoteEscape,
}

/// Parses a shell command line into individual argument tokens.
///
/// Handles backslash escapes and single/double-quoted substrings. A space
/// always delimits arguments (even inside an escape sequence or quote, once
/// the quote/escape is resolved). Multiple consecutive spaces produce empty
/// tokens between them, matching the Java reference implementation.
///
/// # Errors
///
/// Returns `Err` if the input contains an unterminated quoted string or an
/// incomplete backslash escape at end-of-input.
pub fn parse_args(args: &str) -> Result<Vec<String>, String> {
    let mut args_list: Vec<String> = Vec::new();
    let mut cur_arg = String::new();
    let mut state = State::Normal;

    for c in args.chars() {
        match state {
            State::Normal => match c {
                '\\' => state = State::NormalEscape,
                '"' => state = State::Dquote,
                '\'' => state = State::Squote,
                ' ' => {
                    args_list.push(cur_arg.clone());
                    cur_arg.clear();
                }
                _ => cur_arg.push(c),
            },
            State::NormalEscape => {
                cur_arg.push(c);
                state = State::Normal;
            }
            State::Dquote => match c {
                '\\' => state = State::DquoteEscape,
                '"' => state = State::Normal,
                _ => cur_arg.push(c),
            },
            State::DquoteEscape => {
                cur_arg.push(c);
                state = State::Dquote;
            }
            State::Squote => match c {
                '\\' => state = State::SquoteEscape,
                '\'' => state = State::Normal,
                _ => cur_arg.push(c),
            },
            State::SquoteEscape => {
                cur_arg.push(c);
                state = State::Squote;
            }
        }
    }

    match state {
        State::Normal => {
            if !cur_arg.is_empty() {
                args_list.push(cur_arg);
            }
        }
        State::Dquote | State::Squote => {
            return Err("Unterminated string".to_string());
        }
        State::NormalEscape | State::DquoteEscape | State::SquoteEscape => {
            return Err("Incomplete escaped character".to_string());
        }
    }

    Ok(args_list)
}

/// Returns the filename component of an executable path, stripping any
/// leading directory components.
pub fn remove_path(exec: &str) -> String {
    Path::new(exec)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| exec.to_string())
}

/// Returns a copy of `args` with the directory path stripped from the first
/// element (the executable).  Returns an empty `Vec` when `args` is empty.
pub fn remove_path_from_args(args: &[String]) -> Vec<String> {
    if args.is_empty() {
        return Vec::new();
    }
    let mut copy = args.to_vec();
    copy[0] = remove_path(&args[0]);
    copy
}

/// Joins `args` into a shell command line, quoting each argument that
/// contains spaces via [`generate_argument`].
pub fn generate_line(args: &[String]) -> String {
    if args.is_empty() {
        return String::new();
    }
    let mut line = generate_argument(&args[0]);
    for a in &args[1..] {
        line.push(' ');
        line.push_str(&generate_argument(a));
    }
    line
}

/// Returns a shell-safe representation of the argument `a`.
///
/// - No spaces → returned as-is.
/// - Contains spaces but no `"` → wrapped in double quotes.
/// - Contains spaces and `"` but no `'` → wrapped in single quotes.
/// - Contains spaces, `"`, and `'` → double-quoted with embedded `"` escaped
///   as `\"`.
pub fn generate_argument(a: &str) -> String {
    if a.contains(' ') {
        if a.contains('"') {
            if a.contains('\'') {
                return format!("\"{}\"", a.replace('"', "\\\""));
            }
            return format!("'{}'", a);
        }
        return format!("\"{}\"", a);
    }
    a.to_string()
}

/// Builds an environment block from `env` as a concatenation of
/// `KEY=VALUE\0` entries.
///
/// The caller is responsible for appending the final NUL terminator required
/// by the OS (matching the Java/JNA convention where JNA appends it).
pub fn generate_env_block(env: &HashMap<String, String>) -> String {
    env.iter()
        .map(|(k, v)| format!("{}={}\0", k, v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // parse_args

    #[test]
    fn parse_args_empty_input() {
        assert_eq!(parse_args("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn parse_args_single_word() {
        assert_eq!(parse_args("foo").unwrap(), vec!["foo"]);
    }

    #[test]
    fn parse_args_multiple_words() {
        assert_eq!(parse_args("foo bar baz").unwrap(), vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn parse_args_double_quoted_with_space() {
        assert_eq!(parse_args("\"hello world\"").unwrap(), vec!["hello world"]);
    }

    #[test]
    fn parse_args_single_quoted_with_space() {
        assert_eq!(parse_args("'hello world'").unwrap(), vec!["hello world"]);
    }

    #[test]
    fn parse_args_normal_backslash_escape() {
        assert_eq!(parse_args(r"foo\ bar").unwrap(), vec!["foo bar"]);
    }

    #[test]
    fn parse_args_dquote_backslash_escape() {
        assert_eq!(parse_args("\"a\\\"b\"").unwrap(), vec!["a\"b"]);
    }

    #[test]
    fn parse_args_squote_backslash_escape() {
        assert_eq!(parse_args("'a\\'b'").unwrap(), vec!["a'b"]);
    }

    #[test]
    fn parse_args_mixed_quotes() {
        assert_eq!(
            parse_args("foo \"bar baz\" 'qux quux'").unwrap(),
            vec!["foo", "bar baz", "qux quux"]
        );
    }

    #[test]
    fn parse_args_consecutive_spaces_produce_empty_token() {
        assert_eq!(parse_args("foo  bar").unwrap(), vec!["foo", "", "bar"]);
    }

    #[test]
    fn parse_args_unterminated_dquote_is_error() {
        assert!(parse_args("\"unterminated").is_err());
    }

    #[test]
    fn parse_args_unterminated_squote_is_error() {
        assert!(parse_args("'unterminated").is_err());
    }

    #[test]
    fn parse_args_incomplete_escape_is_error() {
        assert!(parse_args("foo\\").is_err());
    }

    // remove_path

    #[test]
    fn remove_path_strips_directory_components() {
        assert_eq!(remove_path("/usr/bin/bash"), "bash");
    }

    #[test]
    fn remove_path_bare_name_unchanged() {
        assert_eq!(remove_path("bash"), "bash");
    }

    #[test]
    fn remove_path_relative_path() {
        assert_eq!(remove_path("some/dir/tool"), "tool");
    }

    // remove_path_from_args

    #[test]
    fn remove_path_from_args_empty_slice() {
        assert_eq!(remove_path_from_args(&[]), Vec::<String>::new());
    }

    #[test]
    fn remove_path_from_args_strips_only_first_element() {
        let args = vec![
            "/usr/bin/bash".to_string(),
            "-c".to_string(),
            "echo hi".to_string(),
        ];
        let result = remove_path_from_args(&args);
        assert_eq!(result, vec!["bash", "-c", "echo hi"]);
    }

    #[test]
    fn remove_path_from_args_single_element() {
        let args = vec!["/bin/ls".to_string()];
        assert_eq!(remove_path_from_args(&args), vec!["ls"]);
    }

    // generate_argument

    #[test]
    fn generate_argument_no_spaces_unchanged() {
        assert_eq!(generate_argument("foo"), "foo");
    }

    #[test]
    fn generate_argument_space_wrapped_in_dquote() {
        assert_eq!(generate_argument("foo bar"), "\"foo bar\"");
    }

    #[test]
    fn generate_argument_space_and_dquote_wrapped_in_squote() {
        assert_eq!(generate_argument("foo \"bar\""), "'foo \"bar\"'");
    }

    #[test]
    fn generate_argument_space_dquote_squote_escapes_dquote() {
        let result = generate_argument("a \"b\" 'c'");
        assert_eq!(result, "\"a \\\"b\\\" 'c'\"");
    }

    // generate_line

    #[test]
    fn generate_line_empty_args() {
        assert_eq!(generate_line(&[]), "");
    }

    #[test]
    fn generate_line_single_arg() {
        assert_eq!(generate_line(&["foo".to_string()]), "foo");
    }

    #[test]
    fn generate_line_multiple_plain_args() {
        let args = vec!["ls".to_string(), "-la".to_string(), "/tmp".to_string()];
        assert_eq!(generate_line(&args), "ls -la /tmp");
    }

    #[test]
    fn generate_line_arg_with_space_is_quoted() {
        let args = vec!["echo".to_string(), "hello world".to_string()];
        assert_eq!(generate_line(&args), "echo \"hello world\"");
    }

    // generate_env_block

    #[test]
    fn generate_env_block_empty_map() {
        assert_eq!(generate_env_block(&HashMap::new()), "");
    }

    #[test]
    fn generate_env_block_single_entry() {
        let mut env = HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        assert_eq!(generate_env_block(&env), "FOO=bar\0");
    }

    #[test]
    fn generate_env_block_multiple_entries() {
        let mut env = HashMap::new();
        env.insert("A".to_string(), "1".to_string());
        env.insert("B".to_string(), "2".to_string());
        let block = generate_env_block(&env);
        assert!(block.contains("A=1\0"));
        assert!(block.contains("B=2\0"));
        assert_eq!(block.len(), "A=1\0".len() + "B=2\0".len());
    }
}
