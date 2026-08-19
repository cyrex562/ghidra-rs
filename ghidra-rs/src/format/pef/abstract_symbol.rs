use super::symbol_class::SymbolClass;
use std::fmt;

/// Weak symbol mask for PEF imports.
///
/// Mirrors `ghidra.app.util.bin.format.pef.AbstractSymbol.kPEFWeakImportSymMask`.
pub const PEF_WEAK_IMPORT_SYM_MASK: u8 = 0x80;

/// Abstract base trait for PEF symbols (imported and exported).
///
/// Mirrors `ghidra.app.util.bin.format.pef.AbstractSymbol`.
pub trait AbstractSymbol: fmt::Debug {
    /// Returns the symbol's name.
    fn name(&self) -> &str;

    /// Returns the symbol's class.
    fn symbol_class(&self) -> SymbolClass;
}

impl fmt::Display for dyn AbstractSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:?}", self.name(), self.symbol_class())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSymbol {
        name: String,
        class: SymbolClass,
    }

    impl fmt::Debug for TestSymbol {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TestSymbol")
                .field("name", &self.name)
                .field("class", &self.class)
                .finish()
        }
    }

    impl AbstractSymbol for TestSymbol {
        fn name(&self) -> &str {
            &self.name
        }

        fn symbol_class(&self) -> SymbolClass {
            self.class
        }
    }

    #[test]
    fn weak_import_mask_matches_java_source() {
        assert_eq!(PEF_WEAK_IMPORT_SYM_MASK, 0x80);
    }

    #[test]
    fn display_combines_name_and_class() {
        let symbol = TestSymbol {
            name: "test_symbol".to_string(),
            class: SymbolClass::Code,
        };
        let display_str = (&symbol as &dyn AbstractSymbol).to_string();
        assert!(display_str.contains("test_symbol"));
        assert!(display_str.contains("Code"));
    }

    #[test]
    fn display_works_with_different_symbol_classes() {
        let classes = [
            SymbolClass::Code,
            SymbolClass::Data,
            SymbolClass::TVect,
            SymbolClass::TOC,
            SymbolClass::Glue,
            SymbolClass::Undefined,
        ];

        for class in classes {
            let symbol = TestSymbol {
                name: "sym".to_string(),
                class,
            };
            let display_str = (&symbol as &dyn AbstractSymbol).to_string();
            assert!(display_str.contains("sym"));
        }
    }
}
