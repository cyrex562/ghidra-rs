/// Utilities for parsing grouped theme value strings.
///
/// Mirrors `generic.theme.ThemeValueUtils` from Ghidra.

use thiserror::Error;

/// Error returned when [`parse_groupings`] encounters an invalid grouping structure.
#[derive(Debug, Error)]
#[error("Error parsing groupings for {input} at offset {offset}")]
pub struct ParseGroupingsError {
    pub input: String,
    pub offset: usize,
}

/// Parses `source` into a list of top-level group contents.
///
/// Each group is delimited by `start_char` and `end_char`. Whitespace between
/// groups is skipped. The returned strings contain the content *inside* the
/// outer delimiters (exclusive).
///
/// # Errors
///
/// Returns [`ParseGroupingsError`] if the next non-whitespace character is not
/// `start_char`, or if a group's matching `end_char` is not found.
pub fn parse_groupings(
    source: &str,
    start_char: char,
    end_char: char,
) -> Result<Vec<String>, ParseGroupingsError> {
    let chars: Vec<char> = source.chars().collect();
    let mut results = Vec::new();
    let mut index = 0usize;

    while index < chars.len() {
        let group_start = match find_next_non_whitespace(&chars, index) {
            Some(i) => i,
            None => break,
        };
        if chars[group_start] != start_char {
            return Err(ParseGroupingsError { input: source.to_string(), offset: index });
        }
        let group_end = match find_matching_end(&chars, group_start + 1, start_char, end_char) {
            Some(i) => i,
            None => return Err(ParseGroupingsError { input: source.to_string(), offset: index }),
        };
        results.push(chars[group_start + 1..group_end].iter().collect());
        index = group_end + 1;
    }
    Ok(results)
}

fn find_matching_end(
    chars: &[char],
    mut index: usize,
    start_char: char,
    end_char: char,
) -> Option<usize> {
    let mut level = 0i32;
    while index < chars.len() {
        let c = chars[index];
        if c == start_char {
            level += 1;
        } else if c == end_char {
            if level == 0 {
                return Some(index);
            }
            level -= 1;
        }
        index += 1;
    }
    None
}

fn find_next_non_whitespace(chars: &[char], mut index: usize) -> Option<usize> {
    while index < chars.len() {
        if !chars[index].is_whitespace() {
            return Some(index);
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_groupings() {
        let source = "(ab (cd))(ef)(( gh))";
        let results = parse_groupings(source, '(', ')').unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], "ab (cd)");
        assert_eq!(results[1], "ef");
        assert_eq!(results[2], "( gh)");
    }

    #[test]
    fn test_parse_groupings_unbalanced() {
        assert!(parse_groupings("(ab (cd))(ef)( gh))", '(', ')').is_err());
    }

    #[test]
    fn test_parse_groupings_invalid_start() {
        assert!(parse_groupings("  xx", '(', ')').is_err());
    }

    #[test]
    fn test_parse_groupings_empty() {
        assert!(parse_groupings("", '(', ')').unwrap().is_empty());
    }

    #[test]
    fn test_parse_groupings_whitespace_only() {
        assert!(parse_groupings("   ", '(', ')').unwrap().is_empty());
    }

    #[test]
    fn test_parse_groupings_single_group() {
        let result = parse_groupings("(hello)", '(', ')').unwrap();
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn test_parse_groupings_nested() {
        let result = parse_groupings("((inner))", '(', ')').unwrap();
        assert_eq!(result, vec!["(inner)"]);
    }

    #[test]
    fn test_parse_groupings_different_delimiters() {
        let result = parse_groupings("[a][b][c]", '[', ']').unwrap();
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_groupings_missing_end() {
        assert!(parse_groupings("(no end", '(', ')').is_err());
    }

    #[test]
    fn test_error_contains_input() {
        let err = parse_groupings("bad input", '(', ')').unwrap_err();
        assert!(err.to_string().contains("bad input"));
    }
}
