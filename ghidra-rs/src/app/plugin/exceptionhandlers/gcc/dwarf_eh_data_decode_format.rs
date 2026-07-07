/// Exception handling data decoding formats.
///
/// See the [Linux Standard Base DWARF extensions specification](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html) for details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DwarfEhDataDecodeFormat {
    AbsPtr,
    Uleb128,
    Udata2,
    Udata4,
    Udata8,
    Signed,
    Sleb128,
    Sdata2,
    Sdata4,
    Sdata8,
    Omit,
}

impl DwarfEhDataDecodeFormat {
    /// Returns the code value for this decode format.
    pub fn code(self) -> u8 {
        match self {
            DwarfEhDataDecodeFormat::AbsPtr => 0x00,
            DwarfEhDataDecodeFormat::Uleb128 => 0x01,
            DwarfEhDataDecodeFormat::Udata2 => 0x02,
            DwarfEhDataDecodeFormat::Udata4 => 0x03,
            DwarfEhDataDecodeFormat::Udata8 => 0x04,
            DwarfEhDataDecodeFormat::Signed => 0x08,
            DwarfEhDataDecodeFormat::Sleb128 => 0x09,
            DwarfEhDataDecodeFormat::Sdata2 => 0x0a,
            DwarfEhDataDecodeFormat::Sdata4 => 0x0b,
            DwarfEhDataDecodeFormat::Sdata8 => 0x0c,
            DwarfEhDataDecodeFormat::Omit => 0x0f,
        }
    }

    /// Returns the decode format for the indicated code, or `None` if the code is invalid.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(DwarfEhDataDecodeFormat::AbsPtr),
            0x01 => Some(DwarfEhDataDecodeFormat::Uleb128),
            0x02 => Some(DwarfEhDataDecodeFormat::Udata2),
            0x03 => Some(DwarfEhDataDecodeFormat::Udata4),
            0x04 => Some(DwarfEhDataDecodeFormat::Udata8),
            0x08 => Some(DwarfEhDataDecodeFormat::Signed),
            0x09 => Some(DwarfEhDataDecodeFormat::Sleb128),
            0x0a => Some(DwarfEhDataDecodeFormat::Sdata2),
            0x0b => Some(DwarfEhDataDecodeFormat::Sdata4),
            0x0c => Some(DwarfEhDataDecodeFormat::Sdata8),
            0x0f => Some(DwarfEhDataDecodeFormat::Omit),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_codes() {
        assert_eq!(DwarfEhDataDecodeFormat::AbsPtr.code(), 0x00);
        assert_eq!(DwarfEhDataDecodeFormat::Uleb128.code(), 0x01);
        assert_eq!(DwarfEhDataDecodeFormat::Udata2.code(), 0x02);
        assert_eq!(DwarfEhDataDecodeFormat::Udata4.code(), 0x03);
        assert_eq!(DwarfEhDataDecodeFormat::Udata8.code(), 0x04);
        assert_eq!(DwarfEhDataDecodeFormat::Signed.code(), 0x08);
        assert_eq!(DwarfEhDataDecodeFormat::Sleb128.code(), 0x09);
        assert_eq!(DwarfEhDataDecodeFormat::Sdata2.code(), 0x0a);
        assert_eq!(DwarfEhDataDecodeFormat::Sdata4.code(), 0x0b);
        assert_eq!(DwarfEhDataDecodeFormat::Sdata8.code(), 0x0c);
        assert_eq!(DwarfEhDataDecodeFormat::Omit.code(), 0x0f);
    }

    #[test]
    fn test_from_code_valid() {
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x00),
            Some(DwarfEhDataDecodeFormat::AbsPtr)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x01),
            Some(DwarfEhDataDecodeFormat::Uleb128)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x02),
            Some(DwarfEhDataDecodeFormat::Udata2)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x03),
            Some(DwarfEhDataDecodeFormat::Udata4)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x04),
            Some(DwarfEhDataDecodeFormat::Udata8)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x08),
            Some(DwarfEhDataDecodeFormat::Signed)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x09),
            Some(DwarfEhDataDecodeFormat::Sleb128)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x0a),
            Some(DwarfEhDataDecodeFormat::Sdata2)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x0b),
            Some(DwarfEhDataDecodeFormat::Sdata4)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x0c),
            Some(DwarfEhDataDecodeFormat::Sdata8)
        );
        assert_eq!(
            DwarfEhDataDecodeFormat::from_code(0x0f),
            Some(DwarfEhDataDecodeFormat::Omit)
        );
    }

    #[test]
    fn test_from_code_invalid() {
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0x05), None);
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0x06), None);
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0x07), None);
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0x0d), None);
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0x0e), None);
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0x10), None);
        assert_eq!(DwarfEhDataDecodeFormat::from_code(0xff), None);
    }

    #[test]
    fn test_roundtrip() {
        let formats = vec![
            DwarfEhDataDecodeFormat::AbsPtr,
            DwarfEhDataDecodeFormat::Uleb128,
            DwarfEhDataDecodeFormat::Udata2,
            DwarfEhDataDecodeFormat::Udata4,
            DwarfEhDataDecodeFormat::Udata8,
            DwarfEhDataDecodeFormat::Signed,
            DwarfEhDataDecodeFormat::Sleb128,
            DwarfEhDataDecodeFormat::Sdata2,
            DwarfEhDataDecodeFormat::Sdata4,
            DwarfEhDataDecodeFormat::Sdata8,
            DwarfEhDataDecodeFormat::Omit,
        ];
        for format in formats {
            assert_eq!(
                DwarfEhDataDecodeFormat::from_code(format.code()),
                Some(format)
            );
        }
    }

    #[test]
    fn test_clone_copy() {
        let format = DwarfEhDataDecodeFormat::Uleb128;
        let format2 = format;
        assert_eq!(format, format2);
    }

    #[test]
    fn test_debug() {
        let format = DwarfEhDataDecodeFormat::Uleb128;
        let debug_str = format!("{:?}", format);
        assert!(debug_str.contains("Uleb128"));
    }
}
