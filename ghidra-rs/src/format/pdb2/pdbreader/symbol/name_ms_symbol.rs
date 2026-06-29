/// Implemented by symbols that carry a symbol name.
///
/// Corresponds to the Java interface
/// `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.NameMsSymbol`.
pub trait NameMsSymbol {
    /// Returns the name of the symbol.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSymbol {
        name: String,
    }

    impl NameMsSymbol for MockSymbol {
        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn name_returned_correctly() {
        let sym = MockSymbol { name: "foo".to_string() };
        assert_eq!(sym.name(), "foo");
    }

    #[test]
    fn empty_name() {
        let sym = MockSymbol { name: String::new() };
        assert_eq!(sym.name(), "");
    }

    #[test]
    fn name_with_special_characters() {
        let sym = MockSymbol { name: "my::symbol<int>".to_string() };
        assert_eq!(sym.name(), "my::symbol<int>");
    }
}
