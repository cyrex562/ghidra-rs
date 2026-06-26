/// DWARF attribute encoding constants from www.dwarfstd.org/doc/DWARF4.pdf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFEncoding {
    Void = 0x00,
    Address = 0x01,
    Boolean = 0x02,
    ComplexFloat = 0x03,
    Float = 0x04,
    Signed = 0x05,
    SignedChar = 0x06,
    Unsigned = 0x07,
    UnsignedChar = 0x08,
    ImaginaryFloat = 0x09,
    PackedDecimal = 0x0a,
    NumericString = 0x0b,
    Edited = 0x0c,
    SignedFixed = 0x0d,
    UnsignedFixed = 0x0e,
    DecimalFloat = 0x0f,
    Utf = 0x10,
    LoUser = 0x80,
    HiUser = 0xff,
}

impl DWARFEncoding {
    /// Returns the integer value of this encoding.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFEncoding` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known encoding value.
    pub fn find(key: u32) -> Result<Self, u32> {
        match key {
            0x00 => Ok(Self::Void),
            0x01 => Ok(Self::Address),
            0x02 => Ok(Self::Boolean),
            0x03 => Ok(Self::ComplexFloat),
            0x04 => Ok(Self::Float),
            0x05 => Ok(Self::Signed),
            0x06 => Ok(Self::SignedChar),
            0x07 => Ok(Self::Unsigned),
            0x08 => Ok(Self::UnsignedChar),
            0x09 => Ok(Self::ImaginaryFloat),
            0x0a => Ok(Self::PackedDecimal),
            0x0b => Ok(Self::NumericString),
            0x0c => Ok(Self::Edited),
            0x0d => Ok(Self::SignedFixed),
            0x0e => Ok(Self::UnsignedFixed),
            0x0f => Ok(Self::DecimalFloat),
            0x10 => Ok(Self::Utf),
            0x80 => Ok(Self::LoUser),
            0xff => Ok(Self::HiUser),
            _ => Err(key),
        }
    }

    /// Returns the short type name for this encoding (the part after `DW_ATE_`).
    pub fn type_name(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Address => "address",
            Self::Boolean => "boolean",
            Self::ComplexFloat => "complex_float",
            Self::Float => "float",
            Self::Signed => "signed",
            Self::SignedChar => "signed_char",
            Self::Unsigned => "unsigned",
            Self::UnsignedChar => "unsigned_char",
            Self::ImaginaryFloat => "imaginary_float",
            Self::PackedDecimal => "packed_decimal",
            Self::NumericString => "numeric_string",
            Self::Edited => "edited",
            Self::SignedFixed => "signed_fixed",
            Self::UnsignedFixed => "unsigned_fixed",
            Self::DecimalFloat => "decimal_float",
            Self::Utf => "UTF",
            Self::LoUser => "lo_user",
            Self::HiUser => "hi_user",
        }
    }

    /// Returns the type name for a raw encoding value.
    ///
    /// Equivalent to Java's `DWARFEncoding.getTypeName(int)`: strips the `DW_ATE_` prefix
    /// and returns the short name, or `"unknown_type_encoding"` for unrecognised values.
    pub fn get_type_name(encoding: u32) -> &'static str {
        match Self::find(encoding) {
            Ok(enc) => enc.type_name(),
            Err(_) => "unknown_type_encoding",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFEncoding::Void.value(), 0x00);
        assert_eq!(DWARFEncoding::Address.value(), 0x01);
        assert_eq!(DWARFEncoding::Boolean.value(), 0x02);
        assert_eq!(DWARFEncoding::ComplexFloat.value(), 0x03);
        assert_eq!(DWARFEncoding::Float.value(), 0x04);
        assert_eq!(DWARFEncoding::Signed.value(), 0x05);
        assert_eq!(DWARFEncoding::SignedChar.value(), 0x06);
        assert_eq!(DWARFEncoding::Unsigned.value(), 0x07);
        assert_eq!(DWARFEncoding::UnsignedChar.value(), 0x08);
        assert_eq!(DWARFEncoding::ImaginaryFloat.value(), 0x09);
        assert_eq!(DWARFEncoding::PackedDecimal.value(), 0x0a);
        assert_eq!(DWARFEncoding::NumericString.value(), 0x0b);
        assert_eq!(DWARFEncoding::Edited.value(), 0x0c);
        assert_eq!(DWARFEncoding::SignedFixed.value(), 0x0d);
        assert_eq!(DWARFEncoding::UnsignedFixed.value(), 0x0e);
        assert_eq!(DWARFEncoding::DecimalFloat.value(), 0x0f);
        assert_eq!(DWARFEncoding::Utf.value(), 0x10);
        assert_eq!(DWARFEncoding::LoUser.value(), 0x80);
        assert_eq!(DWARFEncoding::HiUser.value(), 0xff);
    }

    #[test]
    fn find_returns_correct_variants() {
        assert_eq!(DWARFEncoding::find(0x00), Ok(DWARFEncoding::Void));
        assert_eq!(DWARFEncoding::find(0x05), Ok(DWARFEncoding::Signed));
        assert_eq!(DWARFEncoding::find(0x10), Ok(DWARFEncoding::Utf));
        assert_eq!(DWARFEncoding::find(0x80), Ok(DWARFEncoding::LoUser));
        assert_eq!(DWARFEncoding::find(0xff), Ok(DWARFEncoding::HiUser));
    }

    #[test]
    fn find_rejects_invalid_keys() {
        assert_eq!(DWARFEncoding::find(0x11), Err(0x11));
        assert_eq!(DWARFEncoding::find(0x7f), Err(0x7f));
        assert_eq!(DWARFEncoding::find(0x81), Err(0x81));
        assert_eq!(DWARFEncoding::find(0xfe), Err(0xfe));
    }

    #[test]
    fn type_name_strips_prefix() {
        assert_eq!(DWARFEncoding::Void.type_name(), "void");
        assert_eq!(DWARFEncoding::Signed.type_name(), "signed");
        assert_eq!(DWARFEncoding::ComplexFloat.type_name(), "complex_float");
        assert_eq!(DWARFEncoding::Utf.type_name(), "UTF");
        assert_eq!(DWARFEncoding::LoUser.type_name(), "lo_user");
        assert_eq!(DWARFEncoding::HiUser.type_name(), "hi_user");
    }

    #[test]
    fn get_type_name_known() {
        assert_eq!(DWARFEncoding::get_type_name(0x01), "address");
        assert_eq!(DWARFEncoding::get_type_name(0x04), "float");
        assert_eq!(DWARFEncoding::get_type_name(0x10), "UTF");
    }

    #[test]
    fn get_type_name_unknown() {
        assert_eq!(DWARFEncoding::get_type_name(0x11), "unknown_type_encoding");
        assert_eq!(DWARFEncoding::get_type_name(0x81), "unknown_type_encoding");
    }

    #[test]
    fn roundtrip_value_then_find() {
        let variants = [
            DWARFEncoding::Void,
            DWARFEncoding::Address,
            DWARFEncoding::Boolean,
            DWARFEncoding::ComplexFloat,
            DWARFEncoding::Float,
            DWARFEncoding::Signed,
            DWARFEncoding::SignedChar,
            DWARFEncoding::Unsigned,
            DWARFEncoding::UnsignedChar,
            DWARFEncoding::ImaginaryFloat,
            DWARFEncoding::PackedDecimal,
            DWARFEncoding::NumericString,
            DWARFEncoding::Edited,
            DWARFEncoding::SignedFixed,
            DWARFEncoding::UnsignedFixed,
            DWARFEncoding::DecimalFloat,
            DWARFEncoding::Utf,
            DWARFEncoding::LoUser,
            DWARFEncoding::HiUser,
        ];
        for variant in variants {
            assert_eq!(DWARFEncoding::find(variant.value()), Ok(variant));
        }
    }
}
