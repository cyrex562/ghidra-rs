use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Mirrors the `S_BLOCK32` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// A block-start symbol (type `0x0207`) that carries only the base header
/// fields defined by [`DebugSymbol`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SBlock32 {
    base: DebugSymbolBase,
}

impl SBlock32 {
    /// Creates a new `SBlock32` and initializes it with the given header fields,
    /// mirroring the Java constructor `S_BLOCK32(short length, short type)`.
    pub fn new(length: i16, symbol_type: i16) -> Self {
        let mut s = SBlock32::default();
        s.base.process_debug_symbol(length, symbol_type);
        s
    }
}

impl DebugSymbol for SBlock32 {
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
        let sym = SBlock32::new(20, 0x0207);
        assert_eq!(sym.length(), 20);
        assert_eq!(sym.symbol_type(), 0x0207);
    }

    #[test]
    fn default_fields_are_zero() {
        let sym = SBlock32::default();
        assert_eq!(sym.length(), 0);
        assert_eq!(sym.symbol_type(), 0);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn trait_object_dispatch() {
        let sym: Box<dyn DebugSymbol> = Box::new(SBlock32::new(8, 0x0207));
        assert_eq!(sym.length(), 8);
        assert_eq!(sym.symbol_type(), 0x0207);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn clone_equality() {
        let sym = SBlock32::new(12, 0x0207);
        let cloned = sym.clone();
        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let sym = SBlock32::new(-1, 0x0207);
        assert_eq!(sym.length(), -1);
    }
}
