/// Returns the decimal string representation of a PE machine type value.
///
/// The `i16` variant mirrors Java's `MachineName.getName(short)`, which interprets
/// the signed short as an unsigned value before formatting.
pub fn get_name_i16(machine: i16) -> String {
    get_name(machine as u16 as u32)
}

/// Returns the decimal string representation of a PE machine type value.
///
/// Mirrors Java's `MachineName.getName(int)`.
pub fn get_name(machine: u32) -> String {
    machine.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_name_zero() {
        assert_eq!(get_name(0), "0");
    }

    #[test]
    fn get_name_known_value() {
        // IMAGE_FILE_MACHINE_AMD64 = 0x8664 = 34404
        assert_eq!(get_name(0x8664), "34404");
    }

    #[test]
    fn get_name_i16_positive() {
        // Positive short — same as unsigned
        assert_eq!(get_name_i16(0x014c), "332");
    }

    #[test]
    fn get_name_i16_negative_treated_as_unsigned() {
        // i16::MIN = -32768 → as u16 = 32768 → as u32 = 32768
        assert_eq!(get_name_i16(i16::MIN), "32768");
    }

    #[test]
    fn get_name_i16_minus_one_is_65535() {
        // -1 as u16 = 65535 (Java Short.toUnsignedInt behavior)
        assert_eq!(get_name_i16(-1), "65535");
    }

    #[test]
    fn get_name_large_value() {
        assert_eq!(get_name(u32::MAX), "4294967295");
    }
}
