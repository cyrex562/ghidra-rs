/// Demangles Rust legacy-format mangled symbols.
///
/// Maps to `ghidra.app.plugin.core.analysis.rust.demangler.RustDemanglerLegacy`.

/// Demangles a Rust legacy-mangled symbol.
///
/// Accepts symbols prefixed with `_ZN` (standard), `ZN` (Windows, dbghelp strips the
/// leading underscore), or `__ZN` (macOS extra underscore). Returns `None` for
/// unrecognised or malformed input.
///
/// The demangled form strips the trailing 16-digit hex hash suffix (`h[0-9a-f]{16}`)
/// if present, expands `$XX$`-encoded characters, converts `..` to `::`, and joins
/// the path elements with `::`.
pub fn demangle(symbol: &str) -> Option<String> {
    let symbol = if symbol.starts_with("__ZN") {
        &symbol[4..]
    } else if symbol.starts_with("_ZN") {
        &symbol[3..]
    } else if symbol.starts_with("ZN") {
        &symbol[2..]
    } else {
        return None;
    };

    if !symbol.is_ascii() {
        return None;
    }

    let bytes = symbol.as_bytes();
    let length = bytes.len();
    let mut elements: Vec<String> = Vec::new();
    let mut i = 0;

    while i < length && bytes[i] != b'E' {
        if !bytes[i].is_ascii_digit() {
            return None;
        }

        let start = i;
        while i < length && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i >= length {
            return None;
        }

        let element_length: usize = symbol[start..i].parse().ok()?;

        if i + element_length > length {
            return None;
        }

        let raw = &symbol[i..i + element_length];
        // A leading `_$` is a legacy escaping artefact; strip the underscore so that
        // the `$` is processed normally in the escape-expansion pass below.
        let element = if raw.starts_with("_$") {
            raw[1..].to_string()
        } else {
            raw.to_string()
        };

        elements.push(element);
        i += element_length;
    }

    if i >= length || bytes[i] != b'E' {
        return None;
    }

    for element in &mut elements {
        *element = element.replace("$SP$", "@");
        *element = element.replace("$BP$", "*");
        *element = element.replace("$RF$", "&");
        *element = element.replace("$LT$", "<");
        *element = element.replace("$GT$", ">");
        *element = element.replace("$LP$", "(");
        *element = element.replace("$RP$", ")");
        *element = element.replace("$C$", ",");
        *element = element.replace("..", "::");
        unescape_unicode(element);
    }

    if elements.len() > 1 {
        if is_uid(elements.last().unwrap()) {
            elements.pop();
        }
    }

    Some(elements.join("::"))
}

/// Expands `$uXXXX$` numeric-escape sequences in-place.
///
/// Called after the named `$XX$` replacements so the only remaining `$...$` tokens
/// should be `$u<hex>$` forms.  Unrecognised `$...$` tokens are left untouched.
fn unescape_unicode(s: &mut String) {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if let Some(rel_end) = bytes[i + 1..].iter().position(|&b| b == b'$') {
                let end = i + 1 + rel_end;
                let inner = &s[i..end + 1];
                if inner.starts_with("$u") {
                    let hex_str = &s[i + 2..end];
                    if let Ok(num) = u32::from_str_radix(hex_str, 16) {
                        if let Some(new_char) = char::from_u32(num) {
                            result.push(new_char);
                            i = end + 1;
                            continue;
                        }
                    }
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    *s = result;
}

/// Returns `true` if `s` matches the legacy Rust hash-id pattern `h[0-9a-f]{16}`.
fn is_uid(s: &str) -> bool {
    let s = s.trim();
    s.len() == 17
        && s.starts_with('h')
        && s[1..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── basic prefix stripping ────────────────────────────────────────────────

    #[test]
    fn zn_prefix_standard() {
        assert_eq!(demangle("_ZN3foo3barE"), Some("foo::bar".into()));
    }

    #[test]
    fn zn_prefix_windows() {
        assert_eq!(demangle("ZN3foo3barE"), Some("foo::bar".into()));
    }

    #[test]
    fn zn_prefix_macos() {
        assert_eq!(demangle("__ZN3foo3barE"), Some("foo::bar".into()));
    }

    #[test]
    fn no_valid_prefix_returns_none() {
        assert_eq!(demangle("foo::bar"), None);
    }

    #[test]
    fn empty_string_returns_none() {
        assert_eq!(demangle(""), None);
    }

    // ── hash-id stripping ─────────────────────────────────────────────────────

    #[test]
    fn trailing_hash_removed() {
        // sample from Java doc: std::io::Read::read_to_end::hb85a0f6802e14499
        let mangled = "_ZN3std2io4Read11read_to_end17hb85a0f6802e14499E";
        assert_eq!(demangle(mangled), Some("std::io::Read::read_to_end".into()));
    }

    #[test]
    fn hash_not_removed_when_only_element() {
        // Single-element symbols whose element happens to match the hash pattern
        // should NOT be stripped (elements.len() > 1 guard).
        assert_eq!(
            demangle("_ZN17hb85a0f6802e14499E"),
            Some("hb85a0f6802e14499".into())
        );
    }

    #[test]
    fn non_hash_last_element_kept() {
        assert_eq!(demangle("_ZN3foo3barE"), Some("foo::bar".into()));
    }

    // ── escape sequences ──────────────────────────────────────────────────────

    #[test]
    fn dot_dot_becomes_double_colon() {
        // "foo..bar" is a length-8 element
        assert_eq!(demangle("_ZN8foo..barE"), Some("foo::bar".into()));
    }

    #[test]
    fn lt_gt_escapes_expanded() {
        // Element "$LT$i32$GT$" (11 chars)
        assert_eq!(demangle("_ZN11$LT$i32$GT$E"), Some("<i32>".into()));
    }

    #[test]
    fn sp_escape_expanded() {
        // "$SP$" is 4 chars → "@"
        assert_eq!(demangle("_ZN3foo4$SP$E"), Some("foo::@".into()));
    }

    #[test]
    fn c_escape_expanded() {
        assert_eq!(demangle("_ZN3foo3$C$E"), Some("foo::,".into()));
    }

    #[test]
    fn rf_escape_expanded() {
        assert_eq!(demangle("_ZN3foo4$RF$E"), Some("foo::&".into()));
    }

    #[test]
    fn unicode_escape_expanded() {
        // "$u7b$" encodes '{' (U+007B)
        assert_eq!(demangle("_ZN3foo5$u7b$E"), Some("foo::{".into()));
    }

    // ── malformed input ───────────────────────────────────────────────────────

    #[test]
    fn non_ascii_returns_none() {
        assert_eq!(demangle("_ZN3foé3barE"), None);
    }

    #[test]
    fn missing_e_terminator_returns_none() {
        assert_eq!(demangle("_ZN3foo3bar"), None);
    }

    #[test]
    fn element_length_overflows_returns_none() {
        // Length prefix 9 but only 3 chars remain before E
        assert_eq!(demangle("_ZN9fooE"), None);
    }

    #[test]
    fn non_digit_where_digit_expected_returns_none() {
        // After stripping prefix, first char must be a digit
        assert_eq!(demangle("_ZNfooE"), None);
    }

    // ── is_uid ────────────────────────────────────────────────────────────────

    #[test]
    fn is_uid_valid() {
        assert!(is_uid("hb85a0f6802e14499"));
    }

    #[test]
    fn is_uid_with_whitespace() {
        assert!(is_uid("  hb85a0f6802e14499  "));
    }

    #[test]
    fn is_uid_wrong_length() {
        assert!(!is_uid("hb85a0f6802e144")); // only 15 hex digits
    }

    #[test]
    fn is_uid_uppercase_rejected() {
        assert!(!is_uid("hB85A0F6802E14499")); // uppercase hex
    }

    #[test]
    fn is_uid_wrong_prefix() {
        assert!(!is_uid("ab85a0f6802e14499")); // doesn't start with 'h'
    }
}
