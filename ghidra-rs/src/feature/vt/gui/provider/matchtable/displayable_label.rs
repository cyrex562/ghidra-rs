use std::cmp::Ordering;
use std::sync::Arc;

use crate::docking::widgets::table::DisplayStringProvider;
use crate::program::model::symbol::Symbol;

/// A displayable label based on a symbol.
///
/// Mirrors `DisplayableLabel` from the Java source.
/// Implements DisplayStringProvider and Comparable semantics.
#[derive(Clone)]
pub struct DisplayableLabel {
    symbol: Option<Arc<dyn Symbol>>,
}

impl DisplayableLabel {
    /// Creates a new DisplayableLabel wrapping the given symbol.
    pub fn new(symbol: Option<Arc<dyn Symbol>>) -> Self {
        Self { symbol }
    }

    /// Returns the underlying symbol, or None if not set.
    pub fn symbol(&self) -> Option<&Arc<dyn Symbol>> {
        self.symbol.as_ref()
    }
}

impl DisplayStringProvider for DisplayableLabel {
    fn display_string(&self) -> String {
        match &self.symbol {
            Some(sym) => sym.get_name().to_string(),
            None => "<No Symbol>".to_string(),
        }
    }
}

impl Ord for DisplayableLabel {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.symbol, &other.symbol) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(s), Some(o)) => {
                s.get_name().to_lowercase().cmp(&o.get_name().to_lowercase())
            }
        }
    }
}

impl PartialOrd for DisplayableLabel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for DisplayableLabel {}

impl PartialEq for DisplayableLabel {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SourceType, SymbolType};

    struct MockSymbol {
        name: String,
    }

    impl MockSymbol {
        fn new(name: &str) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                name: name.to_string(),
            })
        }
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            0
        }

        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    #[test]
    fn display_string_with_symbol() {
        let label = DisplayableLabel::new(Some(MockSymbol::new("myLabel")));
        assert_eq!(label.display_string(), "myLabel");
    }

    #[test]
    fn display_string_without_symbol() {
        let label: DisplayableLabel = DisplayableLabel::new(None);
        assert_eq!(label.display_string(), "<No Symbol>");
    }


    #[test]
    fn compare_both_none() {
        let label1 = DisplayableLabel::new(None);
        let label2 = DisplayableLabel::new(None);
        assert_eq!(label1.cmp(&label2), Ordering::Equal);
    }

    #[test]
    fn compare_first_none() {
        let label1 = DisplayableLabel::new(None);
        let label2 = DisplayableLabel::new(Some(MockSymbol::new("abc")));
        assert_eq!(label1.cmp(&label2), Ordering::Less);
    }

    #[test]
    fn compare_second_none() {
        let label1 = DisplayableLabel::new(Some(MockSymbol::new("abc")));
        let label2 = DisplayableLabel::new(None);
        assert_eq!(label1.cmp(&label2), Ordering::Greater);
    }

    #[test]
    fn compare_case_insensitive() {
        let label1 = DisplayableLabel::new(Some(MockSymbol::new("ABC")));
        let label2 = DisplayableLabel::new(Some(MockSymbol::new("abc")));
        assert_eq!(label1.cmp(&label2), Ordering::Equal);
    }

    #[test]
    fn compare_different_names_case_insensitive() {
        let label1 = DisplayableLabel::new(Some(MockSymbol::new("Alice")));
        let label2 = DisplayableLabel::new(Some(MockSymbol::new("BOB")));
        assert_eq!(label1.cmp(&label2), Ordering::Less);
    }

    #[test]
    fn compare_reverse_order() {
        let label1 = DisplayableLabel::new(Some(MockSymbol::new("Zebra")));
        let label2 = DisplayableLabel::new(Some(MockSymbol::new("Apple")));
        assert_eq!(label1.cmp(&label2), Ordering::Greater);
    }

    #[test]
    fn equality_both_none() {
        let label1 = DisplayableLabel::new(None);
        let label2 = DisplayableLabel::new(None);
        assert!(label1 == label2);
    }

    #[test]
    fn equality_case_insensitive() {
        let label1 = DisplayableLabel::new(Some(MockSymbol::new("Test")));
        let label2 = DisplayableLabel::new(Some(MockSymbol::new("test")));
        assert!(label1 == label2);
    }

    #[test]
    fn inequality_different_symbols() {
        let label1 = DisplayableLabel::new(Some(MockSymbol::new("first")));
        let label2 = DisplayableLabel::new(Some(MockSymbol::new("second")));
        assert!(label1 != label2);
    }

    #[test]
    fn partial_ord_consistency() {
        let label1 = DisplayableLabel::new(Some(MockSymbol::new("foo")));
        let label2 = DisplayableLabel::new(Some(MockSymbol::new("bar")));
        assert_eq!(label1.partial_cmp(&label2), Some(label1.cmp(&label2)));
    }

    #[test]
    fn ordering_is_transitive() {
        let a = DisplayableLabel::new(Some(MockSymbol::new("apple")));
        let b = DisplayableLabel::new(Some(MockSymbol::new("banana")));
        let c = DisplayableLabel::new(Some(MockSymbol::new("cherry")));

        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(b.cmp(&c), Ordering::Less);
        assert_eq!(a.cmp(&c), Ordering::Less);
    }

    #[test]
    fn get_symbol() {
        let sym = MockSymbol::new("test");
        let label = DisplayableLabel::new(Some(sym.clone()));
        assert!(label.symbol().is_some());
        assert_eq!(label.symbol().unwrap().get_name(), "test");
    }

    #[test]
    fn get_symbol_none() {
        let label: DisplayableLabel = DisplayableLabel::new(None);
        assert!(label.symbol().is_none());
    }
}
