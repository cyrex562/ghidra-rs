/// DWARF inline encodings from www.dwarfstd.org/doc/DWARF4.pdf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFInline {
    NotInlined = 0x0,
    Inlined = 0x1,
    DeclaredNotInlined = 0x2,
    DeclaredInlined = 0x3,
}

impl DWARFInline {
    /// Returns the integer value of this inline encoding.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFInline` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known inline encoding value.
    pub fn find(key: u64) -> Result<Self, u64> {
        match key as u32 {
            0x0 => Ok(Self::NotInlined),
            0x1 => Ok(Self::Inlined),
            0x2 => Ok(Self::DeclaredNotInlined),
            0x3 => Ok(Self::DeclaredInlined),
            _ => Err(key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFInline::NotInlined.value(), 0x0);
        assert_eq!(DWARFInline::Inlined.value(), 0x1);
        assert_eq!(DWARFInline::DeclaredNotInlined.value(), 0x2);
        assert_eq!(DWARFInline::DeclaredInlined.value(), 0x3);
    }

    #[test]
    fn find_returns_correct_variants() {
        assert_eq!(DWARFInline::find(0x0), Ok(DWARFInline::NotInlined));
        assert_eq!(DWARFInline::find(0x1), Ok(DWARFInline::Inlined));
        assert_eq!(DWARFInline::find(0x2), Ok(DWARFInline::DeclaredNotInlined));
        assert_eq!(DWARFInline::find(0x3), Ok(DWARFInline::DeclaredInlined));
    }

    #[test]
    fn find_rejects_invalid_keys() {
        assert_eq!(DWARFInline::find(0x4), Err(0x4));
        assert_eq!(DWARFInline::find(0xff), Err(0xff));
        assert_eq!(DWARFInline::find(0x100), Err(0x100));
    }

    #[test]
    fn roundtrip_value_then_find() {
        let variants = [
            DWARFInline::NotInlined,
            DWARFInline::Inlined,
            DWARFInline::DeclaredNotInlined,
            DWARFInline::DeclaredInlined,
        ];
        for variant in variants {
            assert_eq!(DWARFInline::find(variant.value() as u64), Ok(variant));
        }
    }
}
