/// Maximum word length before forcing a hard split at the line limit.
pub const MAX_WORD_LENGTH: usize = 10;

/// Splits text into lines, wrapping at `max_line_length` (0 = no wrapping).
/// Leading whitespace is discarded at line breaks.
pub fn split(text: &str, max_line_length: usize) -> Vec<String> {
    split_with_spacing(text, max_line_length, false)
}

/// Splits text into lines, wrapping at `max_line_length` (0 = no wrapping).
/// When `retain_spacing` is true, whitespace at line breaks is preserved.
pub fn split_with_spacing(text: &str, max_line_length: usize, retain_spacing: bool) -> Vec<String> {
    let newlines: Vec<&str> = text.split('\n').collect();

    if max_line_length == 0 {
        return newlines.into_iter().map(|s| s.to_string()).collect();
    }

    let mut lines = Vec::new();
    for line in &newlines {
        if line.is_empty() {
            lines.push(String::new());
            continue;
        }
        lines.extend(wrap(line, max_line_length, retain_spacing));
    }
    lines
}

fn count_spaces_from(chars: &[char], offset: usize) -> usize {
    chars[offset..].iter().take_while(|c| c.is_whitespace()).count()
}

fn last_index_of_space(chars: &[char]) -> Option<usize> {
    chars.iter().rposition(|&c| c == ' ' || c == '\t')
}

fn wrap(text: &str, max_line_length: usize, retain_spacing: bool) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let length = chars.len();
    let mut lines: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut size = 0usize;
    let mut break_needed = false;
    let mut has_forced_break = false;

    let mut i = 0usize;
    while i < length {
        let c = chars[i];
        size += if c == '\t' { 4 } else { 1 };

        let hit_max_length = size >= max_line_length;
        let is_whitespace = c.is_whitespace();

        if break_needed {
            if is_whitespace {
                let line: String = chars[start..i].iter().collect();
                lines.push(line);

                let skip = if retain_spacing { 0 } else { count_spaces_from(&chars, i) };
                i += skip;
                start = i;
                size = 0;
                break_needed = false;
            } else if size.saturating_sub(max_line_length) >= MAX_WORD_LENGTH {
                has_forced_break = true;
                break_needed = false;
                let end = start + max_line_length;
                let line: String = chars[start..end].iter().collect();
                lines.push(line);
                start = end;
                size = i - start;
            }
        } else if hit_max_length {
            let sub: &[char] = &chars[start..i];

            let line_chars: &[char] = if !is_whitespace {
                match last_index_of_space(sub) {
                    None => {
                        break_needed = true;
                        i += 1;
                        continue;
                    }
                    Some(end) => &sub[..end + 1],
                }
            } else {
                sub
            };

            let raw: String = line_chars.iter().collect();
            let trimmed = if retain_spacing { raw } else { line_chars.iter().collect::<String>().trim().to_string() };
            let line_len = line_chars.len();
            lines.push(trimmed);

            start += line_len;
            let skip = if retain_spacing { 0 } else { count_spaces_from(&chars, start) };
            start += skip;
            if i < start {
                i = start;
            }
            size = i - start;
        }

        i += 1;
    }

    // Handle trailing text; force-split only if a hard break was required earlier.
    let trailing: String = chars[start..length].iter().collect();
    let trailing = if retain_spacing {
        trailing
    } else {
        trailing.trim().to_string()
    };
    let split_on = if has_forced_break { Some(max_line_length) } else { None };
    lines.extend(force_split_on(&trailing, split_on));

    lines
}

fn force_split_on(s: &str, size: Option<usize>) -> Vec<String> {
    match size {
        None => {
            if s.is_empty() {
                vec![]
            } else {
                vec![s.to_string()]
            }
        }
        Some(chunk) => {
            let mut lines = Vec::new();
            let mut buf = String::new();
            for c in s.chars() {
                buf.push(c);
                if buf.chars().count() == chunk {
                    lines.push(buf.clone());
                    buf.clear();
                }
            }
            if !buf.is_empty() {
                lines.push(buf);
            }
            lines
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_with_max_retain_leading_spaces_with_spaces_at_front() {
        let text = "              Heeey mom!  Look, no hands";
        let lines = split_with_spacing(text, 21, true);
        assert_eq!(2, lines.len());
        assert_eq!("              Heeey ", lines[0]);
        assert_eq!("mom!  Look, no hands", lines[1]);
    }

    #[test]
    fn test_split_with_max_retain_leading_spaces_with_spaces_in_middle() {
        let text = "Heeey mom!                Look, no hands";
        let lines = split_with_spacing(text, 21, true);
        assert_eq!(2, lines.len());
        assert_eq!("Heeey mom!          ", lines[0]);
        assert_eq!("      Look, no hands", lines[1]);
    }

    #[test]
    fn test_split_no_max_with_newlines() {
        let lines = split("abc\ndef", 0);
        assert_eq!(2, lines.len());
        assert_eq!("abc", lines[0]);
        assert_eq!("def", lines[1]);
    }

    #[test]
    fn test_split_no_max_with_contiguous_newlines_in_middle() {
        let lines = split("abc\n\ndef", 0);
        assert_eq!(3, lines.len());
        assert_eq!("abc", lines[0]);
        assert_eq!("", lines[1]);
        assert_eq!("def", lines[2]);

        let lines = split("abc\n\n\ndef", 0);
        assert_eq!(4, lines.len());
        assert_eq!("abc", lines[0]);
        assert_eq!("", lines[1]);
        assert_eq!("", lines[2]);
        assert_eq!("def", lines[3]);
    }

    #[test]
    fn test_split_no_max_with_contiguous_newlines_at_end() {
        let lines = split("abcdef\n\n", 0);
        assert_eq!(3, lines.len());
        assert_eq!("abcdef", lines[0]);
        assert_eq!("", lines[1]);
        assert_eq!("", lines[2]);

        let lines = split("abcdef\n\n\n", 0);
        assert_eq!(4, lines.len());
        assert_eq!("abcdef", lines[0]);
        assert_eq!("", lines[1]);
        assert_eq!("", lines[2]);
        assert_eq!("", lines[3]);
    }

    #[test]
    fn test_split_no_max_without_newlines() {
        let lines = split("abcdef", 0);
        assert_eq!(1, lines.len());
        assert_eq!("abcdef", lines[0]);
    }

    #[test]
    fn test_split_with_max_with_newlines() {
        // length below max
        let lines = split("abc\ndef", 100);
        assert_eq!(2, lines.len());
        assert_eq!("abc", lines[0]);
        assert_eq!("def", lines[1]);

        // past max; newlines less than max
        let lines = split("abc\ndef", 5);
        assert_eq!(2, lines.len());
        assert_eq!("abc", lines[0]);
        assert_eq!("def", lines[1]);

        // past max; newlines larger than max (splits on newlines only; no other whitespace)
        let lines = split("abcdefg\nh", 5);
        assert_eq!(2, lines.len());
        assert_eq!("abcdefg", lines[0]);
        assert_eq!("h", lines[1]);
    }

    #[test]
    fn test_split_with_max_without_newlines() {
        // single string -- no whitespace or newlines upon which to split
        let lines = split("abcdefghi", 3);
        assert_eq!(1, lines.len());
        assert_eq!("abcdefghi", lines[0]);
    }

    #[test]
    fn test_split_with_max_with_space_at_end() {
        let lines = split("abcdefghijklm ", 3);
        assert_eq!(2, lines.len());
        assert_eq!("abc", lines[0]);
        assert_eq!("defghijklm", lines[1]);
    }

    #[test]
    fn test_split_with_max_at_max_with_spaces_at_end() {
        let lines = split("abc        ", 3);
        assert_eq!(1, lines.len());
        assert_eq!("abc", lines[0]);
    }

    #[test]
    fn test_split_with_max_whitespace_as_part_of_max_with_space_at_end() {
        let lines = split("ab   c     ", 6);
        assert_eq!(2, lines.len());
        assert_eq!("ab", lines[0]);
        assert_eq!("c", lines[1]);
    }

    #[test]
    fn test_split_without_max_newline_at_beginning_and_end_only() {
        let lines = split("\nabcdefghi\n", 0);
        assert_eq!(3, lines.len());
        assert_eq!("", lines[0]);
        assert_eq!("abcdefghi", lines[1]);
        assert_eq!("", lines[2]);
    }

    #[test]
    fn test_split_with_max_newline_at_beginning_and_end_only() {
        let lines = split("\nabcdefghi\n", 4);
        assert_eq!(3, lines.len());
        assert_eq!("", lines[0]);
        assert_eq!("abcdefghi", lines[1]);
        assert_eq!("", lines[2]);
    }

    #[test]
    fn test_split_with_max_newline_at_beginning_and_middle_and_end_only() {
        let lines = split("\nabcd\nefghi\n", 6);
        assert_eq!(4, lines.len());
        assert_eq!("", lines[0]);
        assert_eq!("abcd", lines[1]);
        assert_eq!("efghi", lines[2]);
        assert_eq!("", lines[3]);
    }

    #[test]
    fn test_split_with_multiple_trailing_newlines() {
        let lines = split("\naa\n\nbb\n\n\n", 100);
        assert_eq!(7, lines.len());
        assert_eq!("", lines[0]);
        assert_eq!("aa", lines[1]);
        assert_eq!("", lines[2]);
        assert_eq!("bb", lines[3]);
        assert_eq!("", lines[4]);
        assert_eq!("", lines[5]);
        assert_eq!("", lines[6]);
    }

    #[test]
    fn test_split_with_multiple_trailing_newlines2() {
        let lines = split("\naa\n\n", 100);
        assert_eq!(4, lines.len());
        assert_eq!("", lines[0]);
        assert_eq!("aa", lines[1]);
        assert_eq!("", lines[2]);
        assert_eq!("", lines[3]);
    }

    #[test]
    fn test_split_with_no_max_with_multiple_newlines_only() {
        let lines = split("\n\n\n", 100);
        assert_eq!(4, lines.len());
    }

    #[test]
    fn test_split_with_max_with_spaces_less_than_max() {
        let lines = split("abcd efghijklmnopq", 8);
        assert_eq!(2, lines.len());
        assert_eq!("abcd", lines[0]);
        assert_eq!("efghijklmnopq", lines[1]);
    }

    #[test]
    fn test_split_with_max_with_spaces_greater_than_max() {
        let lines = split("abcdefg hijklmnopq", 3);
        assert_eq!(2, lines.len());
        assert_eq!("abcdefg", lines[0]);
        assert_eq!("hijklmnopq", lines[1]);
    }

    #[test]
    fn test_split_with_max_with_spaces_far_away_from_max() {
        let lines = split("abcdefg hijklmnopq", 3);
        assert_eq!(2, lines.len());
        assert_eq!("abcdefg", lines[0]);
        assert_eq!("hijklmnopq", lines[1]);
    }

    #[test]
    fn test_split_with_max_retain_blank_lines() {
        let lines = split("abcd\n\nefgh", 3);
        assert_eq!(3, lines.len(), "Wrong number of lines - {:?}", lines);
        assert_eq!("abcd", lines[0]);
        assert_eq!("", lines[1]);
        assert_eq!("efgh", lines[2]);
    }

    #[test]
    fn test_split_with_max_without_spaces_greater_than_max_word_length() {
        assert_eq!(10, MAX_WORD_LENGTH, "Update test for new MAX_WORD_LENGTH");

        let lines = split("abcdefghijklmnopqrstuvwxyz", 3);
        assert_eq!(9, lines.len());
        assert_eq!("abc", lines[0]);
        assert_eq!("def", lines[1]);
        assert_eq!("ghi", lines[2]);
        assert_eq!("jkl", lines[3]);
        assert_eq!("mno", lines[4]);
        assert_eq!("pqr", lines[5]);
        assert_eq!("stu", lines[6]);
        assert_eq!("vwx", lines[7]);
        assert_eq!("yz", lines[8]);
    }

    #[test]
    fn test_split_at_space() {
        let lines = split("split split", 5);
        assert_eq!(2, lines.len(), "Wrong number of lines - {:?}", lines);
        assert_eq!("split", lines[0]);
        assert_eq!("split", lines[1]);
    }

    #[test]
    fn test_split_at_space_preserve_whitespace() {
        let lines = split_with_spacing("split split", 5, true);
        assert_eq!(3, lines.len(), "Wrong number of lines - {:?}", lines);
        assert_eq!("split", lines[0]);
        assert_eq!(" ", lines[1]);
        assert_eq!("split", lines[2]);
    }
}
