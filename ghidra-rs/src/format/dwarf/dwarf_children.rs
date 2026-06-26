/// DWARF child determination constants from www.dwarfstd.org/doc/DWARF4.pdf.
///
/// Equivalent to a boolean in effect, but defined explicitly in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFChildren {
    No = 0,
    Yes = 1,
}

impl DWARFChildren {
    /// Returns the integer value of this children flag.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFChildren` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known value.
    pub fn find(key: u32) -> Result<Self, u32> {
        match key {
            0 => Ok(Self::No),
            1 => Ok(Self::Yes),
            _ => Err(key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFChildren::No.value(), 0);
        assert_eq!(DWARFChildren::Yes.value(), 1);
    }

    #[test]
    fn find_returns_correct_variant() {
        assert_eq!(DWARFChildren::find(0), Ok(DWARFChildren::No));
        assert_eq!(DWARFChildren::find(1), Ok(DWARFChildren::Yes));
    }

    #[test]
    fn find_rejects_invalid_key() {
        assert_eq!(DWARFChildren::find(2), Err(2));
        assert_eq!(DWARFChildren::find(255), Err(255));
    }

    #[test]
    fn roundtrip_value_then_find() {
        for variant in [DWARFChildren::No, DWARFChildren::Yes] {
            assert_eq!(DWARFChildren::find(variant.value()), Ok(variant));
        }
    }
}
