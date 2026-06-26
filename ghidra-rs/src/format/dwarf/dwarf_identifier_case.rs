/// DWARF identifier case constants from www.dwarfstd.org/doc/DWARF4.pdf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFIdentifierCase {
    CaseSensitive = 0x0,
    UpCase = 0x1,
    DownCase = 0x2,
    CaseInsensitive = 0x3,
}

impl DWARFIdentifierCase {
    /// Returns the integer value of this identifier case.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFIdentifierCase` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known identifier case value.
    pub fn find(key: u64) -> Result<Self, u64> {
        match key as u32 {
            0x0 => Ok(Self::CaseSensitive),
            0x1 => Ok(Self::UpCase),
            0x2 => Ok(Self::DownCase),
            0x3 => Ok(Self::CaseInsensitive),
            _ => Err(key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFIdentifierCase::CaseSensitive.value(), 0x0);
        assert_eq!(DWARFIdentifierCase::UpCase.value(), 0x1);
        assert_eq!(DWARFIdentifierCase::DownCase.value(), 0x2);
        assert_eq!(DWARFIdentifierCase::CaseInsensitive.value(), 0x3);
    }

    #[test]
    fn find_returns_correct_variants() {
        assert_eq!(DWARFIdentifierCase::find(0x0), Ok(DWARFIdentifierCase::CaseSensitive));
        assert_eq!(DWARFIdentifierCase::find(0x1), Ok(DWARFIdentifierCase::UpCase));
        assert_eq!(DWARFIdentifierCase::find(0x2), Ok(DWARFIdentifierCase::DownCase));
        assert_eq!(DWARFIdentifierCase::find(0x3), Ok(DWARFIdentifierCase::CaseInsensitive));
    }

    #[test]
    fn find_rejects_invalid_keys() {
        assert_eq!(DWARFIdentifierCase::find(0x4), Err(0x4));
        assert_eq!(DWARFIdentifierCase::find(0xff), Err(0xff));
        assert_eq!(DWARFIdentifierCase::find(0x100), Err(0x100));
    }

    #[test]
    fn roundtrip_value_then_find() {
        let variants = [
            DWARFIdentifierCase::CaseSensitive,
            DWARFIdentifierCase::UpCase,
            DWARFIdentifierCase::DownCase,
            DWARFIdentifierCase::CaseInsensitive,
        ];
        for variant in variants {
            assert_eq!(DWARFIdentifierCase::find(variant.value() as u64), Ok(variant));
        }
    }
}
