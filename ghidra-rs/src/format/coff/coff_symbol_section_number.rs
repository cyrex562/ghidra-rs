/// Special symbolic debugging symbol.
pub const N_DEBUG: i16 = -2;

/// Absolute symbol (not relocatable).
pub const N_ABS: i16 = -1;

/// Undefined external symbol.
pub const N_UNDEF: i16 = 0;

/// `.text` section symbol.
pub const N_TEXT: i16 = 1;

/// `.data` section symbol.
pub const N_DATA: i16 = 2;

/// `.bss` section symbol.
pub const N_BSS: i16 = 3;

// Section numbers 4 through 32767 are reserved for user-defined named sections,
// in the order in which each section is defined.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values_match_java_source() {
        assert_eq!(N_DEBUG, -2);
        assert_eq!(N_ABS,   -1);
        assert_eq!(N_UNDEF,  0);
        assert_eq!(N_TEXT,   1);
        assert_eq!(N_DATA,   2);
        assert_eq!(N_BSS,    3);
    }

    #[test]
    fn ordering() {
        assert!(N_DEBUG < N_ABS);
        assert!(N_ABS < N_UNDEF);
        assert!(N_UNDEF < N_TEXT);
        assert!(N_TEXT < N_DATA);
        assert!(N_DATA < N_BSS);
    }

    #[test]
    fn special_values_are_negative_or_zero() {
        assert!(N_DEBUG < 0);
        assert!(N_ABS < 0);
        assert_eq!(N_UNDEF, 0);
    }

    #[test]
    fn section_constants_are_positive() {
        assert!(N_TEXT > 0);
        assert!(N_DATA > 0);
        assert!(N_BSS > 0);
    }
}
