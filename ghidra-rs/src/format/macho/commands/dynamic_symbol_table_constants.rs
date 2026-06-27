/// Sentinel value indicating an indirect symbol entry refers to a local symbol.
pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;

/// Sentinel value indicating an indirect symbol entry refers to an absolute symbol.
pub const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indirect_symbol_local_value() {
        assert_eq!(INDIRECT_SYMBOL_LOCAL, 0x80000000);
    }

    #[test]
    fn indirect_symbol_abs_value() {
        assert_eq!(INDIRECT_SYMBOL_ABS, 0x40000000);
    }

    #[test]
    fn flags_are_distinct_bits() {
        assert_eq!(INDIRECT_SYMBOL_LOCAL & INDIRECT_SYMBOL_ABS, 0);
    }
}
