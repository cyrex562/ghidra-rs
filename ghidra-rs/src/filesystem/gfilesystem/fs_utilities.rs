pub const SEPARATOR_CHARS: &str = "/\\:";
pub const SEPARATOR: char = '/';

/// Characters that are escaped even though they fall in the printable ASCII range, because
/// they are used as FSRL portion separators (`%` for the escape marker itself, `?` for the
/// parameter separator, `|` for the FSRL-part separator).
const ESCAPE_CHARS: &str = "%?|";

/// Returns a copy of `s` with FSRL-problematic characters escaped as `%nn` sequences, where
/// `nn` are hexdigits specifying the byte value (UTF-8 encoded for non-ASCII characters).
///
/// Mirrors `FSUtilities.escapeEncode(String)`. The inverse (`escapeDecode`) is not ported here;
/// nothing in the current port needs to parse FSRL strings back into structured values yet.
pub fn escape_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cv = c as u32;
        if !(32..=126).contains(&cv) || ESCAPE_CHARS.contains(c) {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).as_bytes() {
                out.push('%');
                out.push_str(&format!("{:02x}", b));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Concatenates path strings, ensuring correct separators between parts.
///
/// Handles both forward and back slashes in input but only inserts a forward slash
/// when a separator is needed.
///
/// Returns `None` if all provided paths are `None` or the slice is empty.
pub fn append_path(paths: &[Option<&str>]) -> Option<String> {
    if paths.iter().all(|p| p.is_none()) {
        return None;
    }

    let mut buffer = String::new();
    for path_opt in paths {
        let path = match path_opt {
            None => continue,
            Some(p) if p.is_empty() => continue,
            Some(p) => *p,
        };

        let empty_buffer = buffer.is_empty();
        let buffer_ends_with_slash =
            !empty_buffer && matches!(buffer.as_bytes().last(), Some(b'/') | Some(b'\\'));
        let path_starts_with_slash =
            matches!(path.as_bytes().first(), Some(b'/') | Some(b'\\'));

        if !buffer_ends_with_slash && !path_starts_with_slash && !empty_buffer {
            buffer.push('/');
            buffer.push_str(path);
        } else if path_starts_with_slash && buffer_ends_with_slash {
            buffer.push_str(&path[1..]);
        } else {
            buffer.push_str(path);
        }
    }

    Some(buffer)
}

/// Converts a native OS path (which may use `\` separators) into an absolute unix-style path.
///
/// Mirrors `FSUtilities.normalizeNativePath(String)`, which is
/// `appendPath("/", FilenameUtils.separatorsToUnix(path))`.
pub fn normalize_native_path(path: &str) -> String {
    let unix_path = path.replace('\\', "/");
    append_path(&[Some("/"), Some(&unix_path)]).unwrap_or_else(|| "/".to_string())
}

/// Returns the file extension of `path` at the given extension depth.
///
/// - `ext_level = 1` returns the last `.ext` suffix.
/// - `ext_level = 2` returns the last two `.ext1.ext2` suffix.
/// - Returns `None` if the path contains fewer than `ext_level` dot-separated
///   extensions in the filename portion (i.e., before any separator character).
///
/// # Panics
/// Panics if `ext_level` is 0.
pub fn get_extension(path: &str, ext_level: usize) -> Option<&str> {
    assert!(ext_level >= 1, "Bad extension level: {}", ext_level);

    let mut level = ext_level;
    let bytes = path.as_bytes();

    for i in (0..path.len()).rev() {
        let c = bytes[i] as char;
        if SEPARATOR_CHARS.contains(c) {
            return None;
        }
        if c == '.' {
            level -= 1;
            if level == 0 {
                return Some(&path[i..]);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- append_path ----------------------------------------------------------

    #[test]
    fn append_path_no_args_returns_none() {
        assert_eq!(append_path(&[]).as_deref(), None);
    }

    #[test]
    fn append_path_all_null_returns_none() {
        assert_eq!(append_path(&[None, None]).as_deref(), None);
        assert_eq!(append_path(&[None, None, None]).as_deref(), None);
    }

    #[test]
    fn append_path_empty_strings() {
        assert_eq!(append_path(&[Some(""), Some("")]).as_deref(), Some(""));
        assert_eq!(append_path(&[Some("")]).as_deref(), Some(""));
        assert_eq!(append_path(&[Some(""), Some(""), Some("")]).as_deref(), Some(""));
    }

    #[test]
    fn append_path_whitespace() {
        assert_eq!(append_path(&[Some("    ")]).as_deref(), Some("    "));
        assert_eq!(append_path(&[Some("    "), Some("\t")]).as_deref(), Some("    /\t"));
    }

    #[test]
    fn append_path_leading_slash_with_empty_or_null() {
        assert_eq!(append_path(&[Some("/"), Some("")]).as_deref(), Some("/"));
        assert_eq!(append_path(&[Some("/"), None]).as_deref(), Some("/"));
        assert_eq!(append_path(&[Some("/"), None, Some("")]).as_deref(), Some("/"));
        assert_eq!(append_path(&[Some("/"), None, None]).as_deref(), Some("/"));
    }

    #[test]
    fn append_path_slash_from_empties() {
        assert_eq!(append_path(&[Some(""), None, Some("/")]).as_deref(), Some("/"));
    }

    #[test]
    fn append_path_simple_segments() {
        assert_eq!(append_path(&[Some(""), Some("blah")]).as_deref(), Some("blah"));
        assert_eq!(append_path(&[Some(""), None, Some("/blah")]).as_deref(), Some("/blah"));
        assert_eq!(append_path(&[Some(""), None, Some("blah")]).as_deref(), Some("blah"));
    }

    #[test]
    fn append_path_strips_duplicate_leading_slash() {
        assert_eq!(
            append_path(&[Some("/blah/"), Some("/leading")]).as_deref(),
            Some("/blah/leading")
        );
        assert_eq!(
            append_path(&[Some("/blah/"), Some("/leading"), Some("dir")]).as_deref(),
            Some("/blah/leading/dir")
        );
    }

    #[test]
    fn append_path_basic_join() {
        assert_eq!(append_path(&[Some("blah")]).as_deref(), Some("blah"));
        assert_eq!(append_path(&[Some("blah"), Some("sub")]).as_deref(), Some("blah/sub"));
        assert_eq!(append_path(&[Some("blah/"), Some("sub")]).as_deref(), Some("blah/sub"));
    }

    #[test]
    fn append_path_backslash_separator() {
        assert_eq!(
            append_path(&[Some("blah\\"), Some("sub")]).as_deref(),
            Some("blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("blah"), Some("/sub")]).as_deref(),
            Some("blah/sub")
        );
        assert_eq!(
            append_path(&[Some("blah"), Some("\\sub")]).as_deref(),
            Some("blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("/blah/blah"), Some("\\sub")]).as_deref(),
            Some("/blah/blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("\\blah\\blah"), Some("\\sub")]).as_deref(),
            Some("\\blah\\blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("\\blah\\blah\\"), Some("\\sub")]).as_deref(),
            Some("\\blah\\blah\\sub")
        );
    }

    // -- append_path multiple separators --------------------------------------

    #[test]
    fn append_path_multiple_separators() {
        assert_eq!(
            append_path(&[Some("/blah"), Some("////")]).as_deref(),
            Some("/blah////")
        );
        assert_eq!(
            append_path(&[Some("/blah/"), Some("////leading")]).as_deref(),
            Some("/blah////leading")
        );
        assert_eq!(
            append_path(&[Some("//"), Some("//")]).as_deref(),
            Some("///")
        );
        assert_eq!(
            append_path(&[Some("\\\\"), Some("\\\\")]).as_deref(),
            Some("\\\\\\")
        );
    }

    // -- escape_encode ----------------------------------------------------------

    #[test]
    fn escape_encode_leaves_normal_ascii_untouched() {
        assert_eq!(escape_encode("dir/example.zip"), "dir/example.zip");
    }

    #[test]
    fn escape_encode_escapes_separator_characters() {
        assert_eq!(escape_encode("a%b?c|d"), "a%25b%3fc%7cd");
    }

    #[test]
    fn escape_encode_escapes_control_characters() {
        assert_eq!(escape_encode("a\tb"), "a%09b");
    }

    #[test]
    fn escape_encode_escapes_non_ascii_as_utf8_bytes() {
        // '\u{e9}' (LATIN SMALL LETTER E WITH ACUTE) encodes to 2 UTF-8 bytes: 0xC3 0xA9.
        assert_eq!(escape_encode("caf\u{e9}"), "caf%c3%a9");
    }

    // -- get_extension --------------------------------------------------------

    #[test]
    fn get_extension_level_1() {
        assert_eq!(get_extension("blah.ext", 1), Some(".ext"));
        assert_eq!(get_extension("blah.xyz.ext", 1), Some(".ext"));
        assert_eq!(get_extension("blah.", 1), Some("."));
        assert_eq!(get_extension("blah", 1), None);
        assert_eq!(get_extension("blah.ext/filename", 1), None);
    }

    #[test]
    fn get_extension_level_2() {
        assert_eq!(get_extension("blah.xyz.ext", 2), Some(".xyz.ext"));
        assert_eq!(get_extension("blah.ext", 2), None);
    }

    #[test]
    #[should_panic(expected = "Bad extension level")]
    fn get_extension_zero_level_panics() {
        get_extension("hi", 0);
    }
}
