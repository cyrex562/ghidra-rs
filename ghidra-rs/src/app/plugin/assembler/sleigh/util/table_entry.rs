//! Mirrors `ghidra.app.plugin.assembler.sleigh.util.TableEntry`.

use std::sync::Arc;

use crate::app::seam_stubs::AssemblySymbol;

use super::table_entry_key::TableEntryKey;

/// An entry in a (sparse) LR(0) transition table or LALR(1) action/goto table.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.util.TableEntry<T>`, which `extends
/// TableEntryKey` to attach a `value` to the `(state, sym)` key. Since [`TableEntryKey`] was
/// already ported as a trait (implementors own the `(state, sym)` pair however they like, rather
/// than inheriting shared fields from a base class), `TableEntry` composes naturally: it owns
/// `state`/`sym`/`value` directly and implements [`TableEntryKey`] over its own fields, in place
/// of the Java `extends`.
pub struct TableEntry<T> {
    state: i32,
    sym: Arc<dyn AssemblySymbol>,
    value: T,
}

impl<T> TableEntry<T> {
    /// Create a new table entry with the given value at the given state and symbol.
    ///
    /// Mirrors `TableEntry(int state, AssemblySymbol sym, T value)`.
    pub fn new(state: i32, sym: Arc<dyn AssemblySymbol>, value: T) -> Self {
        TableEntry { state, sym, value }
    }

    /// Get the value of the entry.
    ///
    /// Mirrors `TableEntry.getValue()`.
    pub fn get_value(&self) -> &T {
        &self.value
    }
}

impl<T> TableEntryKey for TableEntry<T> {
    fn state(&self) -> i32 {
        self.state
    }

    fn sym(&self) -> Arc<dyn AssemblySymbol> {
        self.sym.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSymbol(&'static str);

    impl std::fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    fn sym(name: &'static str) -> Arc<dyn AssemblySymbol> {
        Arc::new(MockSymbol(name))
    }

    #[test]
    fn get_value_returns_constructed_value() {
        let entry = TableEntry::new(3, sym("insn"), "shift-action".to_string());
        assert_eq!(entry.get_value(), "shift-action");
    }

    #[test]
    fn state_and_sym_are_exposed_via_table_entry_key() {
        let entry = TableEntry::new(7, sym("reg"), 42i32);
        assert_eq!(entry.state(), 7);
        assert_eq!(entry.sym().terminal_tag(), "reg");
        assert_eq!(*entry.get_value(), 42);
    }

    #[test]
    fn compare_to_delegates_to_table_entry_key_default() {
        let a = TableEntry::new(1, sym("a"), "x".to_string());
        let b = TableEntry::new(2, sym("a"), "y".to_string());
        assert_eq!(a.compare_to(&b), std::cmp::Ordering::Less);
    }

    #[test]
    fn works_as_trait_object() {
        let entry: Box<dyn TableEntryKey> = Box::new(TableEntry::new(5, sym("z"), 9i32));
        assert_eq!(entry.state(), 5);
        assert_eq!(entry.sym().terminal_tag(), "z");
    }

    #[test]
    fn different_value_types_are_supported() {
        let str_entry = TableEntry::new(0, sym("s"), "hello".to_string());
        let vec_entry = TableEntry::new(0, sym("v"), vec![1, 2, 3]);
        assert_eq!(str_entry.get_value(), "hello");
        assert_eq!(vec_entry.get_value(), &vec![1, 2, 3]);
    }
}
