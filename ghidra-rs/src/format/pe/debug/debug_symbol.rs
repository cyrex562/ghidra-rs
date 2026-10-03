/// Trait representing a base Object Module Format (OMF) symbol.
///
/// Mirrors the abstract `DebugSymbol` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
pub trait DebugSymbol {
    /// Returns the length of the symbol.
    fn length(&self) -> i16;

    /// Returns the type of the symbol.
    fn symbol_type(&self) -> i16;

    /// Returns the name of the symbol.
    fn name(&self) -> &str;

    /// Returns the section number.
    fn section(&self) -> i16;

    /// Returns the offset.
    fn offset(&self) -> i32;
}

/// Common fields shared by all OMF debug symbols.
///
/// Concrete symbol types embed this struct and implement [`DebugSymbol`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DebugSymbolBase {
    pub length: i16,
    /// The symbol type identifier (`type` is a reserved keyword in Rust).
    pub symbol_type: i16,
    pub name: String,
    pub section: i16,
    pub offset: i32,
}

impl DebugSymbolBase {
    /// Initializes the base header fields, mirroring `processDebugSymbol`.
    pub fn process_debug_symbol(&mut self, length: i16, symbol_type: i16) {
        self.length = length;
        self.symbol_type = symbol_type;
    }
}

impl DebugSymbol for DebugSymbolBase {
    fn length(&self) -> i16 {
        self.length
    }

    fn symbol_type(&self) -> i16 {
        self.symbol_type
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn section(&self) -> i16 {
        self.section
    }

    fn offset(&self) -> i32 {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fields_are_zero() {
        let sym = DebugSymbolBase::default();
        assert_eq!(sym.length(), 0);
        assert_eq!(sym.symbol_type(), 0);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn process_debug_symbol_sets_length_and_type() {
        let mut sym = DebugSymbolBase::default();
        sym.process_debug_symbol(42, 7);
        assert_eq!(sym.length(), 42);
        assert_eq!(sym.symbol_type(), 7);
        // Other fields remain at their defaults.
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn field_assignment_and_getters() {
        let sym = DebugSymbolBase {
            length: 16,
            symbol_type: 3,
            name: "MySymbol".to_string(),
            section: 2,
            offset: 0x1000,
        };
        assert_eq!(sym.length(), 16);
        assert_eq!(sym.symbol_type(), 3);
        assert_eq!(sym.name(), "MySymbol");
        assert_eq!(sym.section(), 2);
        assert_eq!(sym.offset(), 0x1000);
    }

    #[test]
    fn trait_object_dispatch() {
        let sym: Box<dyn DebugSymbol> = Box::new(DebugSymbolBase {
            length: 8,
            symbol_type: 1,
            name: "func".to_string(),
            section: 1,
            offset: 0x200,
        });
        assert_eq!(sym.length(), 8);
        assert_eq!(sym.symbol_type(), 1);
        assert_eq!(sym.name(), "func");
        assert_eq!(sym.section(), 1);
        assert_eq!(sym.offset(), 0x200);
    }

    #[test]
    fn negative_values_preserved() {
        let sym = DebugSymbolBase {
            length: -1,
            symbol_type: -2,
            name: String::new(),
            section: -3,
            offset: -4,
        };
        assert_eq!(sym.length(), -1);
        assert_eq!(sym.symbol_type(), -2);
        assert_eq!(sym.section(), -3);
        assert_eq!(sym.offset(), -4);
    }

    #[test]
    fn clone_equality() {
        let sym = DebugSymbolBase {
            length: 10,
            symbol_type: 5,
            name: "clone_test".to_string(),
            section: 3,
            offset: 0x400,
        };
        let cloned = sym.clone();
        assert_eq!(sym, cloned);
    }
}
