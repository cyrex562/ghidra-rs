use crate::decompiler::slghsymbol::SleighSymbol;

/// Provides the ability to find a symbol by name.
///
/// Models `ghidra.pcodeCPort.sleighbase.NamedSymbolProvider`.
pub trait NamedSymbolProvider {
    fn find_symbol(&self, nm: &str) -> Option<&SleighSymbol>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::location::Location;

    struct TestProvider {
        symbol: SleighSymbol,
    }

    impl NamedSymbolProvider for TestProvider {
        fn find_symbol(&self, nm: &str) -> Option<&SleighSymbol> {
            if nm == self.symbol.name() {
                Some(&self.symbol)
            } else {
                None
            }
        }
    }

    #[test]
    fn find_symbol_returns_matching_symbol() {
        let loc = Location::new("test.sla", 1);
        let provider = TestProvider {
            symbol: SleighSymbol::with_name(loc, "test_symbol"),
        };

        let result = provider.find_symbol("test_symbol");
        assert!(result.is_some());
    }

    #[test]
    fn find_symbol_returns_none_for_nonmatching() {
        let loc = Location::new("test.sla", 1);
        let provider = TestProvider {
            symbol: SleighSymbol::with_name(loc, "test_symbol"),
        };

        let result = provider.find_symbol("other_symbol");
        assert!(result.is_none());
    }
}
