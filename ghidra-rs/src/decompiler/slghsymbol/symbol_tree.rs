//! Models `ghidra.pcodeCPort.slghsymbol.SymbolTree` (and its private `SymbolCompare`).

use std::collections::BTreeMap;

use crate::decompiler::slghsymbol::sleigh_symbol::SleighSymbol;

/// A set of [`SleighSymbol`]s ordered and deduplicated by name.
///
/// Models `ghidra.pcodeCPort.slghsymbol.SymbolTree`, a `SetSTL<SleighSymbol>` ordered by the
/// private `SymbolCompare` (`o1.getName().compareTo(o2.getName())`). A `BTreeMap<String,
/// SleighSymbol>` keyed by name gives the same ordered-by-name, unique-by-name semantics
/// directly, without needing to port `SetSTL`'s generic comparator machinery for what is, in
/// practice, always a name ordering.
#[derive(Default, Clone)]
pub struct SymbolTree {
    symbols: BTreeMap<String, SleighSymbol>,
}

impl SymbolTree {
    /// An empty symbol tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `symbol`, keyed by its name. Returns `(the symbol now in the tree under that
    /// name, true)` if `symbol` was newly inserted, or `(the existing symbol, false)` if a
    /// symbol with that name was already present (mirroring `SetSTL::insert`'s
    /// `Pair<Iterator, Boolean>` -- insertion never overwrites an existing entry).
    pub fn insert(&mut self, symbol: SleighSymbol) -> (SleighSymbol, bool) {
        if let Some(existing) = self.symbols.get(symbol.name()) {
            return (existing.clone(), false);
        }
        let name = symbol.name().to_string();
        self.symbols.insert(name.clone(), symbol);
        (self.symbols[&name].clone(), true)
    }

    /// Removes the symbol named `symbol.name()`, if present.
    pub fn erase(&mut self, symbol: &SleighSymbol) {
        self.symbols.remove(symbol.name());
    }

    /// Finds the symbol named `name`, if present.
    pub fn find(&self, name: &str) -> Option<&SleighSymbol> {
        self.symbols.get(name)
    }

    /// Iterates over every symbol in name order.
    pub fn iter(&self) -> impl Iterator<Item = &SleighSymbol> {
        self.symbols.values()
    }

    /// The number of symbols in the tree.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the tree has no symbols.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

impl std::fmt::Display for SymbolTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (i, sym) in self.symbols.values().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", sym)?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::Location;

    fn sym(name: &str) -> SleighSymbol {
        SleighSymbol::with_name(Location::new("test.sleigh", 1), name)
    }

    #[test]
    fn new_is_empty() {
        let tree = SymbolTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn insert_adds_a_new_symbol() {
        let mut tree = SymbolTree::new();
        let (inserted, was_new) = tree.insert(sym("foo"));
        assert!(was_new);
        assert_eq!(inserted.name(), "foo");
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn insert_does_not_overwrite_existing_name() {
        let mut tree = SymbolTree::new();
        let mut first = sym("foo");
        first.id = 1;
        tree.insert(first);

        let mut second = sym("foo");
        second.id = 2;
        let (existing, was_new) = tree.insert(second);

        assert!(!was_new);
        assert_eq!(existing.id, 1, "the original symbol should still be the one in the tree");
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn find_locates_by_name() {
        let mut tree = SymbolTree::new();
        tree.insert(sym("foo"));
        tree.insert(sym("bar"));

        assert!(tree.find("foo").is_some());
        assert!(tree.find("bar").is_some());
        assert!(tree.find("baz").is_none());
    }

    #[test]
    fn erase_removes_by_name() {
        let mut tree = SymbolTree::new();
        tree.insert(sym("foo"));
        tree.erase(&sym("foo"));
        assert!(tree.find("foo").is_none());
        assert!(tree.is_empty());
    }

    #[test]
    fn erase_missing_symbol_is_a_no_op() {
        let mut tree = SymbolTree::new();
        tree.insert(sym("foo"));
        tree.erase(&sym("missing"));
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn iter_yields_symbols_in_name_order() {
        let mut tree = SymbolTree::new();
        tree.insert(sym("charlie"));
        tree.insert(sym("alpha"));
        tree.insert(sym("bravo"));

        let names: Vec<&str> = tree.iter().map(|s| s.name()).collect();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn display_lists_every_symbol() {
        let mut tree = SymbolTree::new();
        tree.insert(sym("alpha"));
        tree.insert(sym("bravo"));
        let text = tree.to_string();
        assert!(text.starts_with('['));
        assert!(text.ends_with(']'));
        assert!(text.contains("alpha"));
        assert!(text.contains("bravo"));
    }
}
