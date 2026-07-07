/// DWARF unit type codes (DWARF5 section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DWARFUnitType {
    Compile = 0x01,
    Type = 0x02,
    Partial = 0x03,
    Skeleton = 0x04,
    SplitCompile = 0x05,
    SplitType = 0x06,
}

/// Inclusive lower bound of the vendor-defined unit-type range.
pub const DW_UT_LO_USER: u8 = 0x80;
/// Inclusive upper bound of the vendor-defined unit-type range.
pub const DW_UT_HI_USER: u8 = 0xff;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminant_values() {
        assert_eq!(DWARFUnitType::Compile as u8, 0x01);
        assert_eq!(DWARFUnitType::Type as u8, 0x02);
        assert_eq!(DWARFUnitType::Partial as u8, 0x03);
        assert_eq!(DWARFUnitType::Skeleton as u8, 0x04);
        assert_eq!(DWARFUnitType::SplitCompile as u8, 0x05);
        assert_eq!(DWARFUnitType::SplitType as u8, 0x06);
    }

    #[test]
    fn user_range_bounds() {
        assert_eq!(DW_UT_LO_USER, 0x80);
        assert_eq!(DW_UT_HI_USER, 0xff);
        assert!(DW_UT_LO_USER < DW_UT_HI_USER);
    }
}
