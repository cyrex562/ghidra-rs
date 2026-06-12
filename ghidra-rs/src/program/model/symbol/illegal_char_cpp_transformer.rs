use crate::program::model::symbol::NameTransformer;
use std::borrow::Cow;

const AFTER_FIRST_CHAR: u8 = 1;
const TEMPLATE: u8 = 2;
const OPERATOR: u8 = 4;
const FIRST_CHAR: u8 = 8;

/// Replaces illegal C++ symbol-name characters with `_`.
///
/// This mirrors Ghidra's `IllegalCharCppTransformer`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IllegalCharCppTransformer;

impl NameTransformer for IllegalCharCppTransformer {
    fn simplify<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let chars: Vec<char> = input.chars().collect();
        let mut template_depth = 0i32;
        let mut transformed: Option<Vec<char>> = None;

        for (index, &ch) in chars.iter().enumerate() {
            if ch.is_alphabetic() {
                continue;
            }
            if ch == '<' {
                template_depth += 1;
                continue;
            }
            if ch == '>' {
                template_depth -= 1;
                if template_depth < 0 {
                    template_depth = 0;
                }
                continue;
            }

            if is_legal_non_letter(input, ch, index, template_depth) {
                continue;
            }

            let transformed = transformed.get_or_insert_with(|| chars.clone());
            transformed[index] = '_';
        }

        match transformed {
            Some(chars) => Cow::Owned(chars.into_iter().collect()),
            None => Cow::Borrowed(input),
        }
    }
}

fn is_legal_non_letter(input: &str, ch: char, index: usize, template_depth: i32) -> bool {
    let flags = legal_flags(ch);
    if flags == 0 {
        return false;
    }
    if flags & AFTER_FIRST_CHAR != 0 && index > 0 {
        return true;
    }
    if flags & FIRST_CHAR != 0 && index == 0 {
        return true;
    }
    if flags & TEMPLATE != 0 && template_depth > 0 {
        return true;
    }
    flags & OPERATOR != 0 && (8..=10).contains(&index) && input.starts_with("operator")
}

fn legal_flags(ch: char) -> u8 {
    match ch {
        '_' => AFTER_FIRST_CHAR | TEMPLATE | OPERATOR | FIRST_CHAR,
        '0'..='9' => AFTER_FIRST_CHAR | TEMPLATE | OPERATOR,
        '*' | '(' | ')' | '[' | ']' | '&' => TEMPLATE | OPERATOR,
        ':' | ',' => TEMPLATE,
        '+' | '-' | '|' | '=' | '!' | '/' | '%' | '^' => OPERATOR,
        '~' => TEMPLATE | OPERATOR | FIRST_CHAR,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_legal_cpp_names_borrowed() {
        let transformer = IllegalCharCppTransformer;
        let simplified = transformer.simplify("_validName123");

        assert!(matches!(simplified, Cow::Borrowed(_)));
        assert_eq!(simplified.as_ref(), "_validName123");
    }

    #[test]
    fn replaces_illegal_first_digit_and_space() {
        let transformer = IllegalCharCppTransformer;

        assert_eq!(transformer.simplify("1 bad").as_ref(), "__bad");
    }

    #[test]
    fn allows_template_parameter_characters_inside_templates() {
        let transformer = IllegalCharCppTransformer;

        assert_eq!(
            transformer.simplify("Vector<int*,ns::Type&>").as_ref(),
            "Vector<int*,ns::Type&>"
        );
    }

    #[test]
    fn replaces_template_only_characters_outside_templates() {
        let transformer = IllegalCharCppTransformer;

        assert_eq!(transformer.simplify("ns::Type").as_ref(), "ns__Type");
    }

    #[test]
    fn allows_operator_punctuation_after_operator_keyword() {
        let transformer = IllegalCharCppTransformer;

        assert_eq!(transformer.simplify("operator++").as_ref(), "operator++");
        assert_eq!(transformer.simplify("operator$").as_ref(), "operator_");
    }

    #[test]
    fn allows_tilde_at_first_character() {
        let transformer = IllegalCharCppTransformer;

        assert_eq!(transformer.simplify("~Destructor").as_ref(), "~Destructor");
        assert_eq!(transformer.simplify("Name~Part").as_ref(), "Name_Part");
    }
}
