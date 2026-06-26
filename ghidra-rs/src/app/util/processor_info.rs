/// Miscellaneous address space defines for language providers.
/// Provides recommended default address space names and IDs.

/// The default address space in a program.
pub const DEFAULT_SPACE: &str = "MEM";
/// The code space in a program.
pub const CODE_SPACE: &str = "CODE";
/// The internal memory space in a program.
pub const INTMEM_SPACE: &str = "INTMEM";
/// The bit space in a program.
pub const BIT_SPACE: &str = "BITS";
/// The external memory space in a program.
pub const EXTMEM_SPACE: &str = "EXTMEM";
/// The Special Function Registers space in a program.
pub const SFR_SPACE: &str = "SFR";

/// ID for the CODE_SPACE.
pub const CODE_SPACE_ID: i32 = 0;
/// ID for the INTMEM_SPACE.
pub const INTMEM_SPACE_ID: i32 = 3;
/// ID for the SFR_SPACE.
pub const SFR_SPACE_ID: i32 = 4;
/// ID for the EXTMEM_SPACE.
pub const EXTMEM_SPACE_ID: i32 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_space_names() {
        assert_eq!(DEFAULT_SPACE, "MEM");
        assert_eq!(CODE_SPACE, "CODE");
        assert_eq!(INTMEM_SPACE, "INTMEM");
        assert_eq!(BIT_SPACE, "BITS");
        assert_eq!(EXTMEM_SPACE, "EXTMEM");
        assert_eq!(SFR_SPACE, "SFR");
    }

    #[test]
    fn test_space_ids() {
        assert_eq!(CODE_SPACE_ID, 0);
        assert_eq!(INTMEM_SPACE_ID, 3);
        assert_eq!(SFR_SPACE_ID, 4);
        assert_eq!(EXTMEM_SPACE_ID, 8);
    }

    #[test]
    fn test_space_ids_are_distinct() {
        let ids = [CODE_SPACE_ID, INTMEM_SPACE_ID, SFR_SPACE_ID, EXTMEM_SPACE_ID];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j]);
            }
        }
    }
}
