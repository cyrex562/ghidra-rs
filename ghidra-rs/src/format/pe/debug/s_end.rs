use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Mirrors the `S_END` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// An end symbol (type `0x0006`) that marks the end of a scope or compilation unit.
/// It always has a fixed name "END", offset 0, and section 0.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SEnd {
    base: DebugSymbolBase,
}

impl SEnd {
    /// Creates a new `SEnd` and initializes it with the given header fields,
    /// mirroring the Java constructor `S_END(short length, short type, BinaryReader reader, int ptr)`.
    ///
    /// The BinaryReader and pointer parameters from the Java version are consumed
    /// for potential debug logging but do not affect the symbol's state.
    pub fn new(length: i16, symbol_type: i16) -> Self {
        let mut s = SEnd::default();
        s.base.process_debug_symbol(length, symbol_type);
        s.base.name = "END".to_string();
        s.base.offset = 0;
        s.base.section = 0;
        s
    }
}

impl DebugSymbol for SEnd {
    fn length(&self) -> i16 {
        self.base.length()
    }

    fn symbol_type(&self) -> i16 {
        self.base.symbol_type()
    }

    fn name(&self) -> &str {
        self.base.name()
    }

    fn section(&self) -> i16 {
        self.base.section()
    }

    fn offset(&self) -> i32 {
        self.base.offset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_length_and_type() {
        let sym = SEnd::new(4, 0x0006);
        assert_eq!(sym.length(), 4);
        assert_eq!(sym.symbol_type(), 0x0006);
    }

    #[test]
    fn new_sets_name_to_end() {
        let sym = SEnd::new(4, 0x0006);
        assert_eq!(sym.name(), "END");
    }

    #[test]
    fn new_sets_offset_to_zero() {
        let sym = SEnd::new(4, 0x0006);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn new_sets_section_to_zero() {
        let sym = SEnd::new(4, 0x0006);
        assert_eq!(sym.section(), 0);
    }

    #[test]
    fn default_fields_are_zero() {
        let sym = SEnd::default();
        assert_eq!(sym.length(), 0);
        assert_eq!(sym.symbol_type(), 0);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn all_fixed_fields() {
        let sym = SEnd::new(8, 0x0006);
        assert_eq!(sym.length(), 8);
        assert_eq!(sym.symbol_type(), 0x0006);
        assert_eq!(sym.name(), "END");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn trait_object_dispatch() {
        let sym: Box<dyn DebugSymbol> = Box::new(SEnd::new(4, 0x0006));
        assert_eq!(sym.length(), 4);
        assert_eq!(sym.symbol_type(), 0x0006);
        assert_eq!(sym.name(), "END");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn clone_equality() {
        let sym = SEnd::new(6, 0x0006);
        let cloned = sym.clone();
        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let sym = SEnd::new(-1, 0x0006);
        assert_eq!(sym.length(), -1);
        assert_eq!(sym.name(), "END");
    }
}
