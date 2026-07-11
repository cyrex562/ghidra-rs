use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Mirrors the `S_COMPILE` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// A compile-flags symbol (type `0x0001`) that carries only the base header
/// fields defined by [`DebugSymbol`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SCompile {
    base: DebugSymbolBase,
}

impl SCompile {
    /// Creates a new `SCompile` and initializes it with the given header fields,
    /// mirroring the Java constructor `S_COMPILE(short length, short type)`.
    pub fn new(length: i16, symbol_type: i16) -> Self {
        let mut s = SCompile::default();
        s.base.process_debug_symbol(length, symbol_type);
        s
    }
}

impl DebugSymbol for SCompile {
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
        let sym = SCompile::new(20, 0x0001);
        assert_eq!(sym.length(), 20);
        assert_eq!(sym.symbol_type(), 0x0001);
    }

    #[test]
    fn default_fields_are_zero() {
        let sym = SCompile::default();
        assert_eq!(sym.length(), 0);
        assert_eq!(sym.symbol_type(), 0);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn trait_object_dispatch() {
        let sym: Box<dyn DebugSymbol> = Box::new(SCompile::new(8, 0x0001));
        assert_eq!(sym.length(), 8);
        assert_eq!(sym.symbol_type(), 0x0001);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn clone_equality() {
        let sym = SCompile::new(12, 0x0001);
        let cloned = sym.clone();
        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let sym = SCompile::new(-1, 0x0001);
        assert_eq!(sym.length(), -1);
    }
}
