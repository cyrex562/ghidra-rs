/// Imported and exported symbol classes in a PEF binary.
///
/// Mirrors `ghidra.app.util.bin.format.pef.SymbolClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolClass {
    /// A code address.
    Code,
    /// A data address.
    Data,
    /// A standard procedure pointer.
    TVect,
    /// A direct data area (table of contents) symbol.
    TOC,
    /// A linker-inserted glue symbol.
    Glue,
    /// An undefined symbol.
    Undefined,
}

impl SymbolClass {
    /// Returns the numeric value used in the binary format.
    pub fn value(self) -> u8 {
        match self {
            SymbolClass::Code => 0x00,
            SymbolClass::Data => 0x01,
            SymbolClass::TVect => 0x02,
            SymbolClass::TOC => 0x03,
            SymbolClass::Glue => 0x04,
            SymbolClass::Undefined => 0x0f,
        }
    }

    /// Returns the `SymbolClass` corresponding to the given raw value, or `None`
    /// if the value does not match any known class.
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(SymbolClass::Code),
            0x01 => Some(SymbolClass::Data),
            0x02 => Some(SymbolClass::TVect),
            0x03 => Some(SymbolClass::TOC),
            0x04 => Some(SymbolClass::Glue),
            0x0f => Some(SymbolClass::Undefined),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(SymbolClass::Code.value(), 0x00);
        assert_eq!(SymbolClass::Data.value(), 0x01);
        assert_eq!(SymbolClass::TVect.value(), 0x02);
        assert_eq!(SymbolClass::TOC.value(), 0x03);
        assert_eq!(SymbolClass::Glue.value(), 0x04);
        assert_eq!(SymbolClass::Undefined.value(), 0x0f);
    }

    #[test]
    fn from_value_round_trips_all_variants() {
        for &v in &[0x00u8, 0x01, 0x02, 0x03, 0x04, 0x0f] {
            let sc = SymbolClass::from_value(v).expect("known value");
            assert_eq!(sc.value(), v);
        }
    }

    #[test]
    fn from_value_returns_none_for_unknown() {
        assert!(SymbolClass::from_value(0x05).is_none());
        assert!(SymbolClass::from_value(0x0e).is_none());
        assert!(SymbolClass::from_value(0xff).is_none());
    }
}
