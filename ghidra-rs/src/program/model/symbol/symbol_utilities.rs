use crate::program::model::address::{Address, AddressFactory, AddressSpace};
use std::sync::Arc;

/// Maximum allowed symbol name length, matching Ghidra's Java SymbolUtilities.
pub const MAX_SYMBOL_NAME_LENGTH: usize = 2000;

/// Prefix used for ordinal symbol names.
pub const ORDINAL_PREFIX: &str = "Ordinal_";

/// Default prefix for subroutine labels.
pub const DEFAULT_SUBROUTINE_PREFIX: &str = "SUB_";
/// Default prefix for flow labels that are not calls.
pub const DEFAULT_SYMBOL_PREFIX: &str = "LAB_";
/// Default prefix for data labels.
pub const DEFAULT_DATA_PREFIX: &str = "DAT_";
/// Default prefix for unknown labels.
pub const DEFAULT_UNKNOWN_PREFIX: &str = "UNK_";
/// Default prefix for external entry labels.
pub const DEFAULT_EXTERNAL_ENTRY_PREFIX: &str = "EXT_";
/// Default prefix for function labels.
pub const DEFAULT_FUNCTION_PREFIX: &str = "FUN_";
/// Default prefix for offcut reference labels.
pub const DEFAULT_INTERNAL_REF_PREFIX: &str = "OFF_";

/// Reference level for unknown dynamic labels.
pub const UNK_LEVEL: usize = 0;
/// Reference level for data dynamic labels.
pub const DAT_LEVEL: usize = 1;
/// Reference level for label dynamic labels.
pub const LAB_LEVEL: usize = 2;
/// Reference level for subroutine dynamic labels.
pub const SUB_LEVEL: usize = 3;
/// Reference level for external dynamic labels.
pub const EXT_LEVEL: usize = 5;
/// Reference level for function dynamic labels.
pub const FUN_LEVEL: usize = 6;

const UNDERSCORE: &str = "_";
const MIN_LABEL_ADDRESS_DIGITS: usize = 4;
const DYNAMIC_PREFIX_ARRAY: [&str; 7] = [
    DEFAULT_UNKNOWN_PREFIX,
    DEFAULT_DATA_PREFIX,
    DEFAULT_SYMBOL_PREFIX,
    DEFAULT_SUBROUTINE_PREFIX,
    DEFAULT_UNKNOWN_PREFIX,
    DEFAULT_EXTERNAL_ENTRY_PREFIX,
    DEFAULT_FUNCTION_PREFIX,
];

/// Returns the ordinal value encoded in a symbol name or -1 if it is not an ordinal name.
pub fn get_ordinal_value(symbol_name: Option<&str>) -> i32 {
    let Some(symbol_name) = symbol_name else {
        return -1;
    };
    let Some(ordinal_text) = symbol_name.strip_prefix(ORDINAL_PREFIX) else {
        return -1;
    };
    ordinal_text.parse::<i32>().unwrap_or(-1)
}

/// Returns true if the string contains an invalid symbol-name character.
pub fn contains_invalid_chars(str: &str) -> bool {
    str.chars().any(is_invalid_char)
}

/// Generates Ghidra's default function name for an address.
pub fn get_default_function_name(addr: &Address) -> String {
    format!("{}{}", DEFAULT_FUNCTION_PREFIX, get_address_string(addr))
}

/// Returns true if the name is a reserved default external symbol name.
pub fn is_reserved_external_default_name(name: &str, factory: &dyn AddressFactory) -> bool {
    name.starts_with(DEFAULT_EXTERNAL_ENTRY_PREFIX) && parse_dynamic_name(factory, name).is_some()
}

/// Generates Ghidra's default external function name for an address.
pub fn get_default_external_function_name(addr: &Address) -> String {
    format!(
        "{}{}{}",
        DEFAULT_EXTERNAL_ENTRY_PREFIX,
        DEFAULT_FUNCTION_PREFIX,
        get_address_string(addr)
    )
}

/// Generates Ghidra's default external name for an address and optional data-type prefix.
pub fn get_default_external_name(addr: &Address, data_type_prefix: Option<&str>) -> String {
    match data_type_prefix {
        Some(prefix) if !prefix.is_empty() => format!(
            "{}{}{}{}",
            DEFAULT_EXTERNAL_ENTRY_PREFIX,
            prefix,
            UNDERSCORE,
            get_address_string(addr)
        ),
        _ => format!(
            "{}{}",
            DEFAULT_EXTERNAL_ENTRY_PREFIX,
            get_address_string(addr)
        ),
    }
}

/// Returns true if the name parses as a reserved dynamic label name for this address factory.
pub fn is_reserved_dynamic_label_name(name: &str, factory: &dyn AddressFactory) -> bool {
    let Some(prefix) = find_dynamic_prefix(name) else {
        return false;
    };
    name.len() >= prefix.len() + 1 && parse_dynamic_name(factory, name).is_some()
}

/// Validates a symbol name against Ghidra's basic Java SymbolUtilities checks.
pub fn validate_name(name: Option<&str>) -> Result<(), String> {
    let Some(name) = name else {
        return Err("Symbol name can't be null".to_string());
    };
    if name.is_empty() {
        return Err("Symbol name can't be empty string".to_string());
    }
    if name.len() > MAX_SYMBOL_NAME_LENGTH {
        return Err(format!(
            "Symbol name exceeds maximum length of {}, length={}",
            MAX_SYMBOL_NAME_LENGTH,
            name.len()
        ));
    }
    if contains_invalid_chars(name) {
        return Err(format!("Symbol name contains invalid characters: {}", name));
    }
    Ok(())
}

/// Returns true if the name starts with one of Ghidra's default dynamic prefixes.
pub fn starts_with_default_dynamic_prefix(name: &str) -> bool {
    find_dynamic_prefix(name).is_some()
}

/// Returns true if the name has a plausible dynamic symbol shape.
pub fn is_dynamic_symbol_pattern(name: &str, case_sensitive: bool) -> bool {
    let normalized;
    let name = if case_sensitive {
        name
    } else {
        normalized = name.to_uppercase();
        normalized.as_str()
    };

    if starts_with_default_dynamic_prefix(name) {
        return true;
    }

    let Some(last_index) = name.rfind('_') else {
        return false;
    };
    if last_index == 0 {
        return false;
    }
    let suffix = &name[last_index + 1..];
    (3..=16).contains(&suffix.len()) && suffix.chars().all(is_hex_digit)
}

/// Returns true if the character is invalid inside a symbol name.
pub fn is_invalid_char(c: char) -> bool {
    c < ' ' || c == ' '
}

/// Removes invalid characters or replaces them with underscores.
pub fn replace_invalid_chars(str: Option<&str>, replace_with_underscore: bool) -> Option<String> {
    str.map(|str| {
        let mut result = String::with_capacity(str.len());
        for c in str.chars() {
            if is_invalid_char(c) {
                if replace_with_underscore {
                    result.push('_');
                }
            } else {
                result.push(c);
            }
        }
        result
    })
}

/// Creates a dynamic label name for an offcut reference.
pub fn get_dynamic_offcut_name(addr: Option<&Address>) -> Option<String> {
    addr.map(|addr| {
        format!(
            "{}{}",
            DEFAULT_INTERNAL_REF_PREFIX,
            get_address_string(addr)
        )
    })
}

/// Creates a dynamic symbol name for a reference level and address.
pub fn get_dynamic_name(reference_level: usize, addr: Option<&Address>) -> Option<String> {
    let addr = addr?;
    DYNAMIC_PREFIX_ARRAY
        .get(reference_level)
        .map(|prefix| format!("{}{}", prefix, get_address_string(addr)))
}

/// Formats an offcut difference the same way as Java SymbolUtilities.
pub fn get_diff_string(diff: i64) -> String {
    if diff < 10 {
        diff.to_string()
    } else {
        format!("0x{:x}", diff)
    }
}

/// Parses a dynamic name into an address using the supplied address factory.
pub fn parse_dynamic_name(factory: &dyn AddressFactory, name: &str) -> Option<Address> {
    if name.starts_with(UNDERSCORE) {
        return None;
    }

    let pieces: Vec<&str> = name.split(UNDERSCORE).collect();
    if pieces.len() < 2 {
        return None;
    }

    let address_offset_string = pieces[pieces.len() - 1];
    if address_offset_string.len() < MIN_LABEL_ADDRESS_DIGITS {
        return None;
    }

    let space = find_address_space(factory, &pieces)?;
    space
        .parse_address(address_offset_string, true)
        .ok()
        .flatten()
}

/// Returns the Ghidra dynamic-label address string for an address.
pub fn get_address_string(addr: &Address) -> String {
    addr.to_string().replace(':', "_")
}

/// Appends an address to a base name using Ghidra's dynamic-label address formatting.
pub fn get_address_appended_name(name: &str, addr: &Address) -> String {
    format!("{}_{}", name, get_address_string(addr))
}

/// Replaces invalid symbol-name characters, preserving other characters.
pub fn get_clean_symbol_name(name: &str) -> String {
    replace_invalid_chars(Some(name), true).unwrap_or_default()
}

fn find_dynamic_prefix(name: &str) -> Option<&'static str> {
    DYNAMIC_PREFIX_ARRAY
        .iter()
        .copied()
        .find(|prefix| name.starts_with(prefix))
}

fn find_address_space(factory: &dyn AddressFactory, pieces: &[&str]) -> Option<Arc<AddressSpace>> {
    if pieces.len() > 2 {
        let mut start = 1;
        let mut end = pieces.len() - 2;
        if pieces[end].is_empty() {
            if end == 0 {
                return factory.get_default_address_space();
            }
            end -= 1;
        }

        while start <= end {
            let space_name = pieces[start..=end].join(UNDERSCORE);
            if let Some(space) = factory.get_address_space_by_name(&space_name) {
                return Some(space);
            }
            start += 1;
        }
    }
    factory.get_default_address_space()
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};

    fn fixture() -> (Arc<AddressSpace>, DefaultAddressFactory) {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let code = AddressSpace::new("program_mem", 32, 1, AddressSpaceType::Code, 2);
        let factory =
            DefaultAddressFactory::with_default_space(vec![ram.clone(), code], Some(ram.clone()));
        (ram, factory)
    }

    #[test]
    fn ordinal_names_parse_like_java() {
        assert_eq!(get_ordinal_value(Some("Ordinal_7")), 7);
        assert_eq!(get_ordinal_value(Some("Ordinal_-1")), -1);
        assert_eq!(get_ordinal_value(Some("Ordinal_bad")), -1);
        assert_eq!(get_ordinal_value(Some("Name_7")), -1);
        assert_eq!(get_ordinal_value(None), -1);
    }

    #[test]
    fn invalid_character_checks_match_java_rules() {
        assert!(is_invalid_char(' '));
        assert!(is_invalid_char('\n'));
        assert!(!is_invalid_char(':'));
        assert!(contains_invalid_chars("bad name"));
        assert_eq!(
            replace_invalid_chars(Some("bad name\n"), true),
            Some("bad_name_".to_string())
        );
        assert_eq!(
            replace_invalid_chars(Some("bad name\n"), false),
            Some("badname".to_string())
        );
        assert_eq!(replace_invalid_chars(None, true), None);
    }

    #[test]
    fn name_validation_rejects_java_invalid_inputs() {
        assert!(validate_name(Some("valid_name")).is_ok());
        assert!(validate_name(None).unwrap_err().contains("can't be null"));
        assert!(validate_name(Some("")).unwrap_err().contains("empty"));
        assert!(validate_name(Some("bad name"))
            .unwrap_err()
            .contains("invalid"));

        let long_name = "a".repeat(MAX_SYMBOL_NAME_LENGTH + 1);
        assert!(validate_name(Some(&long_name))
            .unwrap_err()
            .contains("exceeds"));
    }

    #[test]
    fn default_names_use_address_strings() {
        let (ram, _) = fixture();
        let addr = ram.address(0x1234);

        assert_eq!(get_address_string(&addr), "ram_0x1234");
        assert_eq!(get_default_function_name(&addr), "FUN_ram_0x1234");
        assert_eq!(
            get_default_external_function_name(&addr),
            "EXT_FUN_ram_0x1234"
        );
        assert_eq!(get_default_external_name(&addr, None), "EXT_ram_0x1234");
        assert_eq!(
            get_default_external_name(&addr, Some("char")),
            "EXT_char_ram_0x1234"
        );
        assert_eq!(
            get_dynamic_offcut_name(Some(&addr)),
            Some("OFF_ram_0x1234".to_string())
        );
        assert_eq!(get_dynamic_offcut_name(None), None);
        assert_eq!(
            get_dynamic_name(FUN_LEVEL, Some(&addr)),
            Some("FUN_ram_0x1234".to_string())
        );
        assert_eq!(get_dynamic_name(99, Some(&addr)), None);
        assert_eq!(get_address_appended_name("base", &addr), "base_ram_0x1234");
    }

    #[test]
    fn dynamic_pattern_detection_matches_default_prefix_and_suffix_rules() {
        assert!(starts_with_default_dynamic_prefix("FUN_ram_0x1234"));
        assert!(!starts_with_default_dynamic_prefix("custom_1234"));
        assert!(is_dynamic_symbol_pattern("FUN_ram_0x1234", true));
        assert!(!is_dynamic_symbol_pattern("fun_ram_0x1234", true));
        assert!(is_dynamic_symbol_pattern("fun_ram_0x1234", false));
        assert!(is_dynamic_symbol_pattern("custom_abc", true));
        assert!(!is_dynamic_symbol_pattern("custom_ab", true));
        assert!(!is_dynamic_symbol_pattern("custom_nothex", true));
    }

    #[test]
    fn dynamic_names_parse_addresses_with_space_names() {
        let (ram, factory) = fixture();
        assert_eq!(
            parse_dynamic_name(&factory, "FUN_ram_0x1234"),
            Some(ram.address(0x1234))
        );
        assert_eq!(
            parse_dynamic_name(&factory, "LAB_program_mem_0x20"),
            Some(
                factory
                    .get_address_space_by_name("program_mem")
                    .unwrap()
                    .address(0x20)
            )
        );
        assert_eq!(parse_dynamic_name(&factory, "_FUN_ram_0x1234"), None);
        assert_eq!(parse_dynamic_name(&factory, "FUN_ram_123"), None);
        assert_eq!(parse_dynamic_name(&factory, "plain"), None);
    }

    #[test]
    fn reserved_dynamic_name_checks_require_parseable_addresses() {
        let (_, factory) = fixture();
        assert!(is_reserved_dynamic_label_name("FUN_ram_0x1234", &factory));
        assert!(is_reserved_external_default_name(
            "EXT_ram_0x1234",
            &factory
        ));
        assert!(!is_reserved_external_default_name(
            "FUN_ram_0x1234",
            &factory
        ));
        assert!(!is_reserved_dynamic_label_name("custom_0x1234", &factory));
    }

    #[test]
    fn diff_and_clean_name_helpers_match_java_behavior() {
        assert_eq!(get_diff_string(9), "9");
        assert_eq!(get_diff_string(10), "0xa");
        assert_eq!(get_diff_string(-2), "-2");
        assert_eq!(get_clean_symbol_name("bad name\nok"), "bad_name_ok");
    }
}
