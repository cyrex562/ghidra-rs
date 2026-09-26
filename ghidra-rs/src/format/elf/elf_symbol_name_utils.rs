//! Port of `ghidra.app.util.bin.format.elf.ElfSymbolNameUtils`.
//!
//! Fixes up ELF symbol name strings that contain "bad" (invisible/unprintable/whitespace)
//! characters, formatting control characters the way `readelf` does (`^@`..`^_` for C0 controls,
//! `^?` for DEL) and collapsing spaces to underscores.
//!
//! # Departure from the Java class
//!
//! Java's `replaceInvalidChars(String)` delegates to
//! `SymbolUtilities.replaceInvalidChars(String, BadCharFixupFunc)`, whose bad-code-point test
//! (`SymbolUtilities.isInvalidCodePoint`) matches ten full Unicode *general categories*
//! (`CONTROL`, `FORMAT`, `SURROGATE`, `UNASSIGNED`, `PRIVATE_USE`, ...), not just ASCII control
//! characters. This port only ever needs to distinguish the three ranges
//! [`get_bad_elf_symbol_string_code_point_replacement`] itself branches on -- C0 controls
//! (`0x00`-`0x1F`), DEL (`0x7F`), and space (`0x20`) -- so [`is_invalid_code_point`] tests exactly
//! those three ranges rather than pulling in full Unicode category tables. This mirrors the same
//! simplification already made by this crate's
//! [`SymbolUtilities::is_invalid_char`](crate::program::model::symbol::symbol_utilities::SymbolUtilities::is_invalid_char)
//! (`c < ' ' || c == ' '`), extended here to also flag DEL since this class's own callback has a
//! dedicated branch for it.

/// [`get_bad_elf_symbol_string_code_point_replacement`]'s notion of "bad": C0 control characters,
/// DEL, and space. See the [module docs](self) for why this is narrower than Java's general
/// `SymbolUtilities.isInvalidCodePoint`.
fn is_invalid_code_point(cp: u32) -> bool {
    cp < 0x20 || cp == 0x7F || cp == 0x20
}

/// `ElfSymbolNameUtils.getBadElfSymbolStringCodePointReplacement(int, int)`.
///
/// Returns a replacement value for any bad code points found in an Elf symbol string.
///
/// * A C0 control character (`0x00`-`0x1F`) is rendered `^@`..`^_`, matching `readelf`.
/// * DEL (`0x7F`) is rendered `^?`.
/// * A space is rendered `_`.
/// * Any other bad code point -- unreachable when driven through [`replace_invalid_chars`],
///   since [`is_invalid_code_point`] only ever flags the three cases above, but kept for
///   signature fidelity with the Java method's own fallthrough -- is omitted (`None`).
///
/// `index` is accepted (and ignored), matching the Java method's own unused `index` parameter.
pub fn get_bad_elf_symbol_string_code_point_replacement(index: usize, cp: u32) -> Option<String> {
    let _ = index;
    if cp < 0x20 {
        // Format as ^Control character for consistency with readelf: ^@ (0x00) .. ^_ (0x1F).
        let marker = (b'@' + cp as u8) as char;
        Some(format!("^{marker}"))
    } else if cp == 0x7F {
        // Format as ^? character for consistency with readelf.
        Some("^?".to_string())
    } else if cp == ' ' as u32 {
        Some("_".to_string())
    } else {
        // Omit the bad codepoint that caused this callback to be invoked.
        None
    }
}

/// `ElfSymbolNameUtils.replaceInvalidChars(String)`.
///
/// Converts a string with possible invalid characters into a valid symbol string. `None` in,
/// `None` out, matching Java's `null`-tolerant contract.
pub fn replace_invalid_chars_nullable(str_: Option<&str>) -> Option<String> {
    str_.map(replace_invalid_chars)
}

/// `ElfSymbolNameUtils.replaceInvalidChars(String)`, non-nullable form: every call site in this
/// port already holds an `Option<String>` and unwraps before calling in (see
/// [`AbstractElfRelocationHandlerBase`](crate::format::elf::relocation::abstract_elf_relocation_handler::AbstractElfRelocationHandlerBase)).
pub fn replace_invalid_chars(str_: &str) -> String {
    let mut result: Option<String> = None;
    for (byte_idx, cp) in str_.char_indices() {
        let cp_u32 = cp as u32;
        if is_invalid_code_point(cp_u32) {
            if result.is_none() {
                result = Some(str_[..byte_idx].to_string());
            }
            if let Some(replacement) =
                get_bad_elf_symbol_string_code_point_replacement(byte_idx, cp_u32)
            {
                result.as_mut().expect("just set to Some above").push_str(&replacement);
            }
        } else if let Some(buf) = result.as_mut() {
            buf.push(cp);
        }
    }
    result.unwrap_or_else(|| str_.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_valid_string_is_returned_unchanged() {
        assert_eq!(replace_invalid_chars("main"), "main");
        assert_eq!(replace_invalid_chars(""), "");
    }

    #[test]
    fn control_characters_are_rendered_readelf_style() {
        // '\n' is 0x0A -> ^J ('@' + 0x0A = 'J').
        assert_eq!(replace_invalid_chars("bad\nname"), "bad^Jname");
        // NUL (0x00) -> ^@.
        assert_eq!(replace_invalid_chars("a\u{0}b"), "a^@b");
        // 0x1F (last C0 control) -> ^_.
        assert_eq!(replace_invalid_chars("a\u{1f}b"), "a^_b");
    }

    #[test]
    fn del_is_rendered_as_caret_question_mark() {
        assert_eq!(replace_invalid_chars("a\u{7f}b"), "a^?b");
    }

    #[test]
    fn space_is_rendered_as_underscore() {
        assert_eq!(replace_invalid_chars("bad name"), "bad_name");
        assert_eq!(replace_invalid_chars("a  b"), "a__b");
    }

    #[test]
    fn combination_of_bad_characters() {
        assert_eq!(replace_invalid_chars("bad name\n"), "bad_name^J");
    }

    #[test]
    fn nullable_wrapper_matches_java_null_contract() {
        assert_eq!(replace_invalid_chars_nullable(None), None);
        assert_eq!(replace_invalid_chars_nullable(Some("bad name")), Some("bad_name".to_string()));
    }

    #[test]
    fn code_point_replacement_boundaries() {
        assert_eq!(get_bad_elf_symbol_string_code_point_replacement(0, 0x00), Some("^@".to_string()));
        assert_eq!(get_bad_elf_symbol_string_code_point_replacement(0, 0x1F), Some("^_".to_string()));
        assert_eq!(get_bad_elf_symbol_string_code_point_replacement(0, 0x7F), Some("^?".to_string()));
        assert_eq!(get_bad_elf_symbol_string_code_point_replacement(0, 0x20), Some("_".to_string()));
        // A code point this port's narrower `is_invalid_code_point` never flags as bad, but the
        // fixup function itself still has a defined (omitting) answer for, matching Java's
        // fallthrough `else { return null; }`.
        assert_eq!(get_bad_elf_symbol_string_code_point_replacement(0, 'A' as u32), None);
    }

    #[test]
    fn multibyte_utf8_characters_are_preserved() {
        // Non-ASCII, non-control code points are valid and must survive unescaped once the
        // buffer path has been triggered by an earlier bad character.
        assert_eq!(replace_invalid_chars("caf\u{e9} \u{4e2d}"), "caf\u{e9}_\u{4e2d}");
    }
}
