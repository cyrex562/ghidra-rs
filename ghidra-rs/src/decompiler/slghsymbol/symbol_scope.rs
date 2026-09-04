//! Models `ghidra.pcodeCPort.slghsymbol.SymbolScope`.

use crate::decompiler::slghsymbol::sleigh_symbol::SleighSymbol;
use crate::decompiler::slghsymbol::symbol_tree::SymbolTree;

/// One lexical scope of SLEIGH symbols (e.g. a constructor's local operand names), holding its
/// own name-keyed symbol set and a link to its enclosing scope.
///
/// Models `ghidra.pcodeCPort.slghsymbol.SymbolScope`. Java's `parent` field is a direct
/// reference to the enclosing `SymbolScope` object; scopes here instead reference their parent
/// by [`id`](SymbolScope::id) (`parent_id`), matching how `scope_id` already identifies a
/// symbol's scope on [`SleighSymbol`] -- the owning scope tree (Java's `SymbolTable`, not yet
/// ported) is what actually resolves an id back to a `SymbolScope`, the same way it would
/// resolve any other cross-scope reference.
pub struct SymbolScope {
    parent_id: Option<i32>,
    tree: SymbolTree,
    id: i32,
}

impl SymbolScope {
    /// Creates a new scope with id `id`, whose parent scope has id `parent_id` (or `None` for
    /// the root scope).
    pub fn new(parent_id: Option<i32>, id: i32) -> Self {
        Self {
            parent_id,
            tree: SymbolTree::new(),
            id,
        }
    }

    /// The enclosing scope's id, or `None` if this is the root scope.
    pub fn parent_id(&self) -> Option<i32> {
        self.parent_id
    }

    /// This scope's own id.
    pub fn id(&self) -> i32 {
        self.id
    }

    /// Iterates over every symbol in this scope, in name order.
    pub fn iter(&self) -> impl Iterator<Item = &SleighSymbol> {
        self.tree.iter()
    }

    /// Removes `a` from this scope.
    pub fn remove_symbol(&mut self, a: &SleighSymbol) {
        self.tree.erase(a);
    }

    /// Adds `a` to this scope, returning the symbol now registered under that name: `a` itself
    /// if the name was not already taken, or the pre-existing symbol of that name otherwise
    /// (this scope is left unchanged in that case -- mirrors Java's
    /// `"Symbol already exists in this table"` short-circuit).
    pub fn add_symbol(&mut self, a: SleighSymbol) -> SleighSymbol {
        self.tree.insert(a).0
    }

    /// Finds the symbol named `name` in this scope, if any.
    pub fn find_symbol(&self, name: &str) -> Option<&SleighSymbol> {
        self.tree.find(name)
    }
}

impl std::fmt::Display for SymbolScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ {}: {} ]", self.id, self.tree)
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
    fn new_root_scope_has_no_parent() {
        let scope = SymbolScope::new(None, 0);
        assert_eq!(scope.parent_id(), None);
        assert_eq!(scope.id(), 0);
    }

    #[test]
    fn new_child_scope_tracks_parent_id() {
        let scope = SymbolScope::new(Some(0), 1);
        assert_eq!(scope.parent_id(), Some(0));
        assert_eq!(scope.id(), 1);
    }

    #[test]
    fn add_symbol_registers_a_new_name() {
        let mut scope = SymbolScope::new(None, 0);
        let added = scope.add_symbol(sym("rs1"));
        assert_eq!(added.name(), "rs1");
        assert!(scope.find_symbol("rs1").is_some());
    }

    #[test]
    fn add_symbol_returns_existing_entry_on_name_collision() {
        let mut scope = SymbolScope::new(None, 0);
        let mut first = sym("rs1");
        first.id = 10;
        scope.add_symbol(first);

        let mut second = sym("rs1");
        second.id = 20;
        let result = scope.add_symbol(second);

        assert_eq!(result.id, 10, "the original symbol should win on a name collision");
        assert_eq!(scope.iter().count(), 1);
    }

    #[test]
    fn remove_symbol_drops_it_from_the_scope() {
        let mut scope = SymbolScope::new(None, 0);
        scope.add_symbol(sym("rs1"));
        scope.remove_symbol(&sym("rs1"));
        assert!(scope.find_symbol("rs1").is_none());
    }

    #[test]
    fn find_symbol_is_none_for_unregistered_names() {
        let scope = SymbolScope::new(None, 0);
        assert!(scope.find_symbol("missing").is_none());
    }

    #[test]
    fn iter_yields_every_symbol_in_name_order() {
        let mut scope = SymbolScope::new(None, 0);
        scope.add_symbol(sym("zeta"));
        scope.add_symbol(sym("alpha"));
        let names: Vec<&str> = scope.iter().map(|s| s.name()).collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn display_shows_id_and_tree() {
        let mut scope = SymbolScope::new(None, 7);
        scope.add_symbol(sym("rs1"));
        let text = scope.to_string();
        assert!(text.starts_with("[ 7: "));
        assert!(text.contains("rs1"));
        assert!(text.ends_with(" ]"));
    }
}
