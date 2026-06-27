/// Match a `secondary_key` decimal integer string against a binary or hex formatted constraint.
///
/// The constraint must be patterned as:
/// - Binary: `"0b1110_0001 111..."` (spaces and `_` ignored, dots are wildcards)
/// - Hex:    `"0xaabb_ccdd"` (hex digits, spaces and `_` ignored)
///
/// Returns `true` if `secondary_key` matches the constraint; `false` if it doesn't match,
/// if the constraint isn't a binary or hex constraint, or if `secondary_key` isn't an integer.
pub fn secondary_attribute_matches(secondary_key: &str, constraint: &str) -> bool {
    let secondary_key_int: i32 = match secondary_key.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };

    let constraint: String = constraint
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .collect::<String>()
        .to_lowercase();

    if constraint.starts_with("0x") {
        match u32::from_str_radix(&constraint[2..], 16) {
            Ok(hex_val) => secondary_key_int == hex_val as i32,
            Err(_) => false,
        }
    } else if constraint.starts_with("0b") {
        let secondary_bits = format!("{:032b}", secondary_key_int as u32);
        let constraint_suffix = &constraint[2..];
        // Left-pad with '0' to 32 chars (mirrors Java StringUtils.leftPad)
        let constraint_bits = if constraint_suffix.len() < 32 {
            format!("{:0>32}", constraint_suffix)
        } else {
            constraint_suffix.to_string()
        };
        // Compare only the first 32 positions (mirrors Java for loop i < 32)
        for (s, c) in secondary_bits.chars().zip(constraint_bits.chars()).take(32) {
            if c == '.' {
                continue;
            }
            if s != c {
                return false;
            }
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values taken from MIPS.opinion:
    ///   00110000111100000011000100001111
    ///   00010000000011110001010000000000
    ///   00000000101001010001000100000101
    #[test]
    fn test_secondary_attribute_matches() {
        let attribute = "0b 00.. ..00 .... .... 00.1 0.0. 0000 ....";

        assert!(!secondary_attribute_matches("111", attribute));
        assert!(secondary_attribute_matches("821047567", attribute));
        assert!(secondary_attribute_matches("821047567", attribute));
        assert!(secondary_attribute_matches("269423616", attribute));
        assert!(secondary_attribute_matches("10817797", attribute));
    }

    #[test]
    fn test_hex_constraint() {
        assert!(secondary_attribute_matches("85", "0x55"));
        assert!(secondary_attribute_matches("-1", "0xff ff_ff ff"));
    }

    #[test]
    fn test_not_binary_or_hex_constraint() {
        assert!(!secondary_attribute_matches("1", "not_a_valid_constraint"));
        assert!(!secondary_attribute_matches("1", "0b1x"));
        assert!(!secondary_attribute_matches("1", ""));
    }

    #[test]
    fn test_not_integer_key() {
        assert!(!secondary_attribute_matches("abc", "0x1"));
        assert!(!secondary_attribute_matches("", "0b...."));
    }
}
