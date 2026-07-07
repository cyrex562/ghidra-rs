/// Represents a single entry in the UNIX a.out symbol table.
///
/// Mirrors `ghidra.app.util.bin.format.unixaout.UnixAoutSymbol`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixAoutSymbol {
    pub name_string_offset: u64,
    pub name: Option<String>,
    pub symbol_type: SymbolType,
    pub kind: SymbolKind,
    pub other_byte: u8,
    pub desc: i16,
    pub value: u64,
    pub is_ext: bool,
}

/// Symbol section/type classification for UNIX a.out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    /// Undefined / unresolved
    NUndf,
    /// Absolute
    NAbs,
    /// Text section
    NText,
    /// Data section
    NData,
    /// BSS section
    NBss,
    /// Indirect
    NIndr,
    /// File name (stab)
    NFn,
    /// Stab debug entry (type byte >= 0x20)
    NStab,
    Unknown,
}

/// Auxiliary kind classification derived from the `other` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    AuxFunc,
    AuxObject,
    AuxLabel,
    Unknown,
}

impl UnixAoutSymbol {
    /// Decode a raw symbol table entry.
    ///
    /// `type_byte` is the raw `n_type` field; `other_byte` is `n_other`;
    /// `desc` is `n_desc`; `value` is `n_value`.
    pub fn new(name_string_offset: u64, type_byte: u8, other_byte: u8, desc: i16, value: u64) -> Self {
        let is_ext = (type_byte & 1) == 1;

        let symbol_type = match type_byte & 0xfe {
            0 => SymbolType::NUndf,
            2 => SymbolType::NAbs,
            4 => SymbolType::NText,
            6 => SymbolType::NData,
            8 => SymbolType::NBss,
            10 => SymbolType::NIndr,
            masked => {
                if masked >= 0x20 {
                    SymbolType::NStab
                } else {
                    SymbolType::Unknown
                }
            }
        };

        let kind = match other_byte & 0x0f {
            1 => SymbolKind::AuxObject,
            2 => SymbolKind::AuxFunc,
            3 => SymbolKind::AuxLabel,
            _ => SymbolKind::Unknown,
        };

        Self {
            name_string_offset,
            name: None,
            symbol_type,
            kind,
            other_byte,
            desc,
            value,
            is_ext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_flag_from_lsb() {
        let ext = UnixAoutSymbol::new(0, 0x01, 0, 0, 0);
        assert!(ext.is_ext);
        assert_eq!(ext.symbol_type, SymbolType::NUndf);

        let not_ext = UnixAoutSymbol::new(0, 0x00, 0, 0, 0);
        assert!(!not_ext.is_ext);
    }

    #[test]
    fn symbol_types_decoded() {
        let cases: &[(u8, SymbolType)] = &[
            (0x00, SymbolType::NUndf),
            (0x02, SymbolType::NAbs),
            (0x04, SymbolType::NText),
            (0x06, SymbolType::NData),
            (0x08, SymbolType::NBss),
            (0x0a, SymbolType::NIndr),
            (0x20, SymbolType::NStab),
            (0xfe, SymbolType::NStab),
            (0x0c, SymbolType::Unknown),
            (0x0e, SymbolType::Unknown),
        ];
        for &(byte, expected) in cases {
            let sym = UnixAoutSymbol::new(0, byte, 0, 0, 0);
            assert_eq!(sym.symbol_type, expected, "type_byte=0x{byte:02x}");
        }
    }

    #[test]
    fn ext_bit_does_not_affect_type() {
        // N_TEXT with ext bit set
        let sym = UnixAoutSymbol::new(0, 0x05, 0, 0, 0);
        assert!(sym.is_ext);
        assert_eq!(sym.symbol_type, SymbolType::NText);
    }

    #[test]
    fn symbol_kinds_decoded() {
        let cases: &[(u8, SymbolKind)] = &[
            (0x01, SymbolKind::AuxObject),
            (0x02, SymbolKind::AuxFunc),
            (0x03, SymbolKind::AuxLabel),
            (0x00, SymbolKind::Unknown),
            (0x04, SymbolKind::Unknown),
            (0xff, SymbolKind::Unknown),
        ];
        for &(byte, expected) in cases {
            let sym = UnixAoutSymbol::new(0, 0, byte, 0, 0);
            assert_eq!(sym.kind, expected, "other_byte=0x{byte:02x}");
        }
    }

    #[test]
    fn kind_only_uses_low_nibble() {
        // High nibble should not affect kind
        let sym_low = UnixAoutSymbol::new(0, 0, 0x02, 0, 0);
        let sym_high = UnixAoutSymbol::new(0, 0, 0xf2, 0, 0);
        assert_eq!(sym_low.kind, sym_high.kind);
        assert_eq!(sym_high.kind, SymbolKind::AuxFunc);
    }

    #[test]
    fn fields_stored_verbatim() {
        let sym = UnixAoutSymbol::new(42, 0x04, 0x02, -5, 0xdeadbeef);
        assert_eq!(sym.name_string_offset, 42);
        assert_eq!(sym.other_byte, 0x02);
        assert_eq!(sym.desc, -5);
        assert_eq!(sym.value, 0xdeadbeef);
        assert!(sym.name.is_none());
    }

    #[test]
    fn stab_boundary_at_0x20() {
        let just_below = UnixAoutSymbol::new(0, 0x1e, 0, 0, 0); // 0x1e = 30, masked = 30 < 32
        assert_eq!(just_below.symbol_type, SymbolType::Unknown);

        let at_boundary = UnixAoutSymbol::new(0, 0x20, 0, 0, 0); // masked = 0x20 = 32
        assert_eq!(at_boundary.symbol_type, SymbolType::NStab);
    }
}
