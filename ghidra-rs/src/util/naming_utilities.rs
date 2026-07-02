use std::collections::HashSet;
use std::sync::OnceLock;

const MANGLE_CHAR: char = '_';

/// Returns the set of valid non-alphanumeric ASCII characters allowed in Ghidra
/// project file names and path elements.
pub fn valid_name_charset() -> &'static HashSet<char> {
    static CHARSET: OnceLock<HashSet<char>> = OnceLock::new();
    CHARSET.get_or_init(|| {
        ['.', '-', '=', '@', ' ', '_', '(', ')', '[', ']', '~']
            .into_iter()
            .collect()
    })
}

/// Static utility methods for validating project file names or constrained file
/// path elements.
pub struct NamingUtilities;

impl NamingUtilities {
    /// Returns `true` if the given string is a valid project name.
    ///
    /// Rules:
    /// - Name may not be blank (no characters or all whitespace).
    /// - Name may not start with a period.
    /// - All characters must be a letter, digit, or within the allowed set:
    ///   `'.'`, `'-'`, `'='`, `'@'`, `' '`, `'_'`, `'('`, `')'`, `'['`, `']'`, `'~'`.
    pub fn is_valid_project_name(name: &str) -> bool {
        Self::check_project_name(name).is_ok()
    }

    /// Checks the specified project name for character restrictions.
    ///
    /// # Errors
    /// Returns an error message if name restrictions are violated.
    pub fn check_project_name(name: &str) -> Result<(), String> {
        Self::check_name(name, Some("Project name"))
    }

    /// Checks the specified project or file path element name for character restrictions.
    ///
    /// The path element must exclude path separators and must not include any
    /// Windows drive specification (e.g., `C:`). If this restriction needs to apply
    /// to an entire path, invoke this method on each element separately.
    ///
    /// # Parameters
    /// - `path_element`: the name component to validate.
    /// - `element_type`: descriptive label used in error messages; defaults to
    ///   `"Path element"` when `None` or blank.
    ///
    /// # Errors
    /// Returns an error message if name restrictions are violated.
    pub fn check_name(path_element: &str, element_type: Option<&str>) -> Result<(), String> {
        let type_str = match element_type {
            Some(t) if !t.trim().is_empty() => t.to_string(),
            _ => "Path element".to_string(),
        };

        if path_element.trim().is_empty() {
            return Err(format!("A blank {} is not allowed", type_str));
        }
        if path_element.starts_with('.') {
            return Err(format!("{} starting with '.' is not permitted", type_str));
        }
        if let Some(invalid) = Self::find_invalid_char(path_element) {
            return Err(format!(
                "{} contains invalid character: '{}'",
                type_str, invalid
            ));
        }
        Ok(())
    }

    /// Identifies the first invalid character found in the given name string.
    ///
    /// Applies to project names and individual path name elements only.
    ///
    /// Returns `Some(ch)` with the offending character rendered as a `String`, or
    /// `None` if every character is valid.
    pub fn find_invalid_char(name: &str) -> Option<String> {
        let charset = valid_name_charset();
        for c in name.chars() {
            if c.is_alphanumeric() {
                continue;
            }
            // Allow only ASCII symbols from the whitelist
            if (c as u32) <= 0x7F && charset.contains(&c) {
                continue;
            }
            return Some(c.to_string());
        }
        None
    }

    /// Returns a mangled copy of `name` in which every uppercase letter is replaced
    /// by `MANGLE_CHAR` followed by the lowercase version of that letter, and every
    /// existing `MANGLE_CHAR` is doubled.
    ///
    /// This allows case-sensitive Ghidra names to survive on case-insensitive
    /// filesystems: `"Foo.exe"` → `"_foo.exe"`.
    pub fn mangle(name: &str) -> String {
        let mut buf = String::with_capacity(2 * name.len());
        for c in name.chars() {
            if c == MANGLE_CHAR {
                buf.push(MANGLE_CHAR);
                buf.push(MANGLE_CHAR);
            } else if c.is_uppercase() {
                buf.push(MANGLE_CHAR);
                for lc in c.to_lowercase() {
                    buf.push(lc);
                }
            } else {
                buf.push(c);
            }
        }
        buf
    }

    /// Reverses [`NamingUtilities::mangle`]: characters following `MANGLE_CHAR` are
    /// converted to uppercase, and two consecutive `MANGLE_CHAR`s are collapsed into
    /// one.
    pub fn demangle(mangled_name: &str) -> String {
        let mut buf = String::with_capacity(mangled_name.len());
        let mut found_mangle = false;
        for c in mangled_name.chars() {
            if found_mangle {
                found_mangle = false;
                if c == MANGLE_CHAR {
                    buf.push(c);
                } else {
                    for uc in c.to_uppercase() {
                        buf.push(uc);
                    }
                }
            } else if c == MANGLE_CHAR {
                found_mangle = true;
            } else {
                buf.push(c);
            }
        }
        buf
    }

    /// Returns `true` if the name contains no uppercase letters and can therefore be
    /// successfully demangled.
    pub fn is_valid_mangled_name(name: &str) -> bool {
        !name.chars().any(|c| c.is_uppercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_valid_project_name / check_name ---

    #[test]
    fn test_valid_project_name_simple() {
        assert!(NamingUtilities::is_valid_project_name("hello"));
        assert!(NamingUtilities::is_valid_project_name("my-project"));
        assert!(NamingUtilities::is_valid_project_name("project.1"));
        assert!(NamingUtilities::is_valid_project_name("test (1)"));
        assert!(NamingUtilities::is_valid_project_name("name_v2"));
        assert!(NamingUtilities::is_valid_project_name("abc~def"));
        assert!(NamingUtilities::is_valid_project_name("[arch]"));
        assert!(NamingUtilities::is_valid_project_name("user@host"));
        assert!(NamingUtilities::is_valid_project_name("a=b"));
    }

    #[test]
    fn test_invalid_project_name_blank() {
        assert!(!NamingUtilities::is_valid_project_name(""));
        assert!(!NamingUtilities::is_valid_project_name("   "));
    }

    #[test]
    fn test_invalid_project_name_starts_with_dot() {
        assert!(!NamingUtilities::is_valid_project_name(".hidden"));
        assert!(!NamingUtilities::is_valid_project_name("."));
        assert!(!NamingUtilities::is_valid_project_name(".."));
    }

    #[test]
    fn test_invalid_project_name_bad_chars() {
        assert!(!NamingUtilities::is_valid_project_name("file/name"));
        assert!(!NamingUtilities::is_valid_project_name("file\\name"));
        assert!(!NamingUtilities::is_valid_project_name("file:name"));
        assert!(!NamingUtilities::is_valid_project_name("file*name"));
        assert!(!NamingUtilities::is_valid_project_name("file?name"));
        assert!(!NamingUtilities::is_valid_project_name("file\tname"));
        // Non-ASCII letters are accepted: Java uses Character.isLetterOrDigit,
        // which treats accented letters like 'ï' as letters, so "naïve" is valid.
        assert!(NamingUtilities::is_valid_project_name("naïve"));
    }

    #[test]
    fn test_check_name_error_messages() {
        let err = NamingUtilities::check_name("", Some("Project name")).unwrap_err();
        assert!(err.contains("blank"), "expected blank error, got: {}", err);

        let err = NamingUtilities::check_name(".secret", Some("Project name")).unwrap_err();
        assert!(err.contains("'.'"), "expected dot error, got: {}", err);

        let err = NamingUtilities::check_name("bad/char", Some("Project name")).unwrap_err();
        assert!(err.contains("invalid character"), "expected invalid char error, got: {}", err);
    }

    #[test]
    fn test_check_name_default_element_type() {
        let err = NamingUtilities::check_name("", None).unwrap_err();
        assert!(err.starts_with("A blank Path element"), "{}", err);
    }

    // --- find_invalid_char ---

    #[test]
    fn test_find_invalid_char_none_for_valid() {
        assert_eq!(NamingUtilities::find_invalid_char("hello"), None);
        assert_eq!(NamingUtilities::find_invalid_char("my-file.txt"), None);
        assert_eq!(NamingUtilities::find_invalid_char("val_ue"), None);
        assert_eq!(NamingUtilities::find_invalid_char("(ok)"), None);
    }

    #[test]
    fn test_find_invalid_char_returns_bad_char() {
        assert_eq!(
            NamingUtilities::find_invalid_char("bad/path"),
            Some("/".to_string())
        );
        assert_eq!(
            NamingUtilities::find_invalid_char("tab\there"),
            Some("\t".to_string())
        );
    }

    // --- mangle ---

    #[test]
    fn test_mangle_uppercase() {
        assert_eq!(NamingUtilities::mangle("Foo.exe"), "_foo.exe");
        assert_eq!(NamingUtilities::mangle("FOO"), "_f_o_o");
        assert_eq!(NamingUtilities::mangle("lowercase"), "lowercase");
    }

    #[test]
    fn test_mangle_underscore_doubled() {
        assert_eq!(NamingUtilities::mangle("my_file"), "my__file");
        assert_eq!(NamingUtilities::mangle("_"), "__");
        assert_eq!(NamingUtilities::mangle("__"), "____");
    }

    #[test]
    fn test_mangle_empty() {
        assert_eq!(NamingUtilities::mangle(""), "");
    }

    // --- demangle ---

    #[test]
    fn test_demangle_basic() {
        assert_eq!(NamingUtilities::demangle("_foo.exe"), "Foo.exe");
        assert_eq!(NamingUtilities::demangle("_f_o_o"), "FOO");
        assert_eq!(NamingUtilities::demangle("lowercase"), "lowercase");
    }

    #[test]
    fn test_demangle_escaped_underscore() {
        assert_eq!(NamingUtilities::demangle("my__file"), "my_file");
        assert_eq!(NamingUtilities::demangle("__"), "_");
    }

    #[test]
    fn test_demangle_empty() {
        assert_eq!(NamingUtilities::demangle(""), "");
    }

    // --- round-trip ---

    #[test]
    fn test_mangle_demangle_roundtrip() {
        let cases = ["Hello", "World", "Foo_Bar", "ABC_xyz", "test123", "MixedCase"];
        for s in &cases {
            assert_eq!(
                NamingUtilities::demangle(&NamingUtilities::mangle(s)),
                *s,
                "round-trip failed for {:?}",
                s
            );
        }
    }

    // --- is_valid_mangled_name ---

    #[test]
    fn test_is_valid_mangled_name() {
        assert!(NamingUtilities::is_valid_mangled_name("_foo.exe"));
        assert!(NamingUtilities::is_valid_mangled_name("all_lower_case"));
        assert!(NamingUtilities::is_valid_mangled_name(""));
        assert!(!NamingUtilities::is_valid_mangled_name("HasUpper"));
        assert!(!NamingUtilities::is_valid_mangled_name("A"));
    }
}
