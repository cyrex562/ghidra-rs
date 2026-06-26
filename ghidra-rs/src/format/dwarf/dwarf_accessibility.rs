/// DWARF accessibility constants from www.dwarfstd.org/doc/DWARF4.pdf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFAccessibility {
    Public = 0x1,
    Protected = 0x2,
    Private = 0x3,
}

impl DWARFAccessibility {
    /// Returns the integer value of this accessibility.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFAccessibility` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known accessibility value.
    pub fn find(key: u32) -> Result<Self, u32> {
        match key {
            0x1 => Ok(Self::Public),
            0x2 => Ok(Self::Protected),
            0x3 => Ok(Self::Private),
            _ => Err(key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFAccessibility::Public.value(),    0x1);
        assert_eq!(DWARFAccessibility::Protected.value(), 0x2);
        assert_eq!(DWARFAccessibility::Private.value(),   0x3);
    }

    #[test]
    fn find_returns_correct_variant() {
        assert_eq!(DWARFAccessibility::find(0x1), Ok(DWARFAccessibility::Public));
        assert_eq!(DWARFAccessibility::find(0x2), Ok(DWARFAccessibility::Protected));
        assert_eq!(DWARFAccessibility::find(0x3), Ok(DWARFAccessibility::Private));
    }

    #[test]
    fn find_rejects_invalid_key() {
        assert_eq!(DWARFAccessibility::find(0),   Err(0));
        assert_eq!(DWARFAccessibility::find(4),   Err(4));
        assert_eq!(DWARFAccessibility::find(255), Err(255));
    }

    #[test]
    fn roundtrip_value_then_find() {
        for variant in [
            DWARFAccessibility::Public,
            DWARFAccessibility::Protected,
            DWARFAccessibility::Private,
        ] {
            assert_eq!(DWARFAccessibility::find(variant.value()), Ok(variant));
        }
    }
}
