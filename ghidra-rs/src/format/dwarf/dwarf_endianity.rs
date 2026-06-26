/// DWARF endianity constants from www.dwarfstd.org/doc/DWARF4.pdf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFEndianity {
    Default = 0x00,
    Big = 0x01,
    Little = 0x02,
    LoUser = 0x40,
    HiUser = 0xff,
}

impl DWARFEndianity {
    /// Returns the integer value of this endianity constant.
    pub fn value(self) -> u64 {
        self as u64
    }

    /// Returns the `DWARFEndianity` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known constant.
    pub fn find(key: u64) -> Result<Self, u64> {
        match key {
            0x00 => Ok(Self::Default),
            0x01 => Ok(Self::Big),
            0x02 => Ok(Self::Little),
            0x40 => Ok(Self::LoUser),
            0xff => Ok(Self::HiUser),
            _ => Err(key),
        }
    }

    /// Returns whether the given endianity value represents big-endian byte order.
    ///
    /// `default_is_big_endian` is used when the value is [`DWARFEndianity::Default`].
    ///
    /// # Errors
    /// Returns `Err(endian)` if `endian` is not a handled endianity value.
    pub fn get_endianity(endian: u64, default_is_big_endian: bool) -> Result<bool, u64> {
        match endian as u32 {
            0x00 => Ok(default_is_big_endian),
            0x01 => Ok(true),
            0x02 => Ok(false),
            _ => Err(endian),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFEndianity::Default.value(), 0x00);
        assert_eq!(DWARFEndianity::Big.value(), 0x01);
        assert_eq!(DWARFEndianity::Little.value(), 0x02);
        assert_eq!(DWARFEndianity::LoUser.value(), 0x40);
        assert_eq!(DWARFEndianity::HiUser.value(), 0xff);
    }

    #[test]
    fn find_returns_correct_variants() {
        assert_eq!(DWARFEndianity::find(0x00), Ok(DWARFEndianity::Default));
        assert_eq!(DWARFEndianity::find(0x01), Ok(DWARFEndianity::Big));
        assert_eq!(DWARFEndianity::find(0x02), Ok(DWARFEndianity::Little));
        assert_eq!(DWARFEndianity::find(0x40), Ok(DWARFEndianity::LoUser));
        assert_eq!(DWARFEndianity::find(0xff), Ok(DWARFEndianity::HiUser));
    }

    #[test]
    fn find_rejects_invalid_keys() {
        assert_eq!(DWARFEndianity::find(0x03), Err(0x03));
        assert_eq!(DWARFEndianity::find(0x3f), Err(0x3f));
        assert_eq!(DWARFEndianity::find(0x41), Err(0x41));
        assert_eq!(DWARFEndianity::find(0xfe), Err(0xfe));
    }

    #[test]
    fn get_endianity_big_explicit() {
        assert_eq!(DWARFEndianity::get_endianity(0x01, false), Ok(true));
        assert_eq!(DWARFEndianity::get_endianity(0x01, true), Ok(true));
    }

    #[test]
    fn get_endianity_little_explicit() {
        assert_eq!(DWARFEndianity::get_endianity(0x02, true), Ok(false));
        assert_eq!(DWARFEndianity::get_endianity(0x02, false), Ok(false));
    }

    #[test]
    fn get_endianity_default_follows_argument() {
        assert_eq!(DWARFEndianity::get_endianity(0x00, true), Ok(true));
        assert_eq!(DWARFEndianity::get_endianity(0x00, false), Ok(false));
    }

    #[test]
    fn get_endianity_rejects_unhandled_values() {
        assert_eq!(DWARFEndianity::get_endianity(0x03, true), Err(0x03));
        assert_eq!(DWARFEndianity::get_endianity(0x40, false), Err(0x40));
        assert_eq!(DWARFEndianity::get_endianity(0xff, true), Err(0xff));
    }

    #[test]
    fn roundtrip_value_then_find() {
        for variant in [
            DWARFEndianity::Default,
            DWARFEndianity::Big,
            DWARFEndianity::Little,
            DWARFEndianity::LoUser,
            DWARFEndianity::HiUser,
        ] {
            assert_eq!(DWARFEndianity::find(variant.value()), Ok(variant));
        }
    }
}
