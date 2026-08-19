//! Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseTransitionTable`.

use std::sync::Arc;

use crate::app::seam_stubs::AssemblySymbol;

/// One entry from an [`AssemblyParseTransitionTable`], as yielded by
/// [`AssemblyParseTransitionTable::for_each`].
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.util.TableEntry<Integer>` combined with its
/// `TableEntryKey` superclass -- `AssemblyParseTransitionTable` only ever instantiates
/// `TableEntry<Integer>`, and `TableEntryKey`/`TableEntry` aren't ported as their own types yet,
/// so rather than stub out the generic Java hierarchy this models the one concrete shape actually
/// needed: `TableEntryKey.getState()`/`getSym()` plus `TableEntry.getValue()`.
pub struct TableEntry {
    /// Mirrors `TableEntryKey.getState()`.
    pub state: i32,
    /// Mirrors `TableEntryKey.getSym()`.
    pub sym: Arc<dyn AssemblySymbol>,
    /// Mirrors `TableEntry.getValue()`.
    pub value: i32,
}

/// The transition table defining an LR(0) parsing machine.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseTransitionTable`, a concrete
/// class backed by a `Map<TableEntryKey, Integer>`. That class was chosen as the cut-point for a
/// dependency cycle running through the parser and its grammar/symbol types, so it is ported here
/// as a trait: implementors own the underlying sparse map however they like (a `TreeMap` keyed on
/// `(state, AssemblySymbol)` in Java), and this trait exposes only `put`/`get`/`for_each`, the
/// class's public surface.
///
/// [`AssemblySymbol`]'s equality/ordering are LAZILY defined in terms of its `Display`
/// implementation (see that trait's docs), which is why `get` takes `&dyn AssemblySymbol` rather
/// than requiring `Eq`/`Ord` directly -- implementors key their map off of `to_string()` (or the
/// `terminal_tag()` stand-in), the same convention used elsewhere in this crate.
pub trait AssemblyParseTransitionTable {
    /// Put an entry into the state machine.
    ///
    /// **NOTE:** Generally, if this returns `Some`, something is probably wrong with your LR(0)
    /// machine generator.
    ///
    /// Mirrors `AssemblyParseTransitionTable.put(int, AssemblySymbol, int)`.
    fn put(
        &mut self,
        from_state: i32,
        next: Arc<dyn AssemblySymbol>,
        new_state: i32,
    ) -> Option<i32>;

    /// Get an entry from the state machine.
    ///
    /// Mirrors `AssemblyParseTransitionTable.get(int, AssemblySymbol)`.
    fn get(&self, from_state: i32, next: &dyn AssemblySymbol) -> Option<i32>;

    /// Traverse every entry in the table, invoking `consumer` on each.
    ///
    /// Mirrors `AssemblyParseTransitionTable.forEach(Consumer<TableEntry<Integer>>)`.
    fn for_each(&self, consumer: &mut dyn FnMut(TableEntry));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
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

    /// Stands in for `AssemblyParseTransitionTable`'s private `TreeMap<TableEntryKey, Integer>`.
    #[derive(Default)]
    struct MockTransitionTable {
        map: BTreeMap<(i32, String), (Arc<dyn AssemblySymbol>, i32)>,
    }

    impl AssemblyParseTransitionTable for MockTransitionTable {
        fn put(
            &mut self,
            from_state: i32,
            next: Arc<dyn AssemblySymbol>,
            new_state: i32,
        ) -> Option<i32> {
            let key = (from_state, next.terminal_tag().to_string());
            self.map.insert(key, (next, new_state)).map(|(_, v)| v)
        }

        fn get(&self, from_state: i32, next: &dyn AssemblySymbol) -> Option<i32> {
            let key = (from_state, next.terminal_tag().to_string());
            self.map.get(&key).map(|(_, v)| *v)
        }

        fn for_each(&self, consumer: &mut dyn FnMut(TableEntry)) {
            for (&(state, _), (sym, value)) in self.map.iter() {
                consumer(TableEntry { state, sym: sym.clone(), value: *value });
            }
        }
    }

    #[test]
    fn put_then_get_round_trips() {
        let mut table = MockTransitionTable::default();
        let sym: Arc<dyn AssemblySymbol> = Arc::new(MockSymbol("insn"));

        assert_eq!(table.put(0, sym.clone(), 1), None);
        assert_eq!(table.get(0, sym.as_ref()), Some(1));
        assert_eq!(table.get(1, sym.as_ref()), None);
    }

    #[test]
    fn put_returns_previous_value_for_same_cell() {
        let mut table = MockTransitionTable::default();
        let sym: Arc<dyn AssemblySymbol> = Arc::new(MockSymbol("reg"));

        assert_eq!(table.put(3, sym.clone(), 7), None);
        assert_eq!(table.put(3, sym.clone(), 9), Some(7));
        assert_eq!(table.get(3, sym.as_ref()), Some(9));
    }

    #[test]
    fn for_each_visits_every_entry() {
        let mut table = MockTransitionTable::default();
        table.put(0, Arc::new(MockSymbol("a")), 1);
        table.put(0, Arc::new(MockSymbol("b")), 2);
        table.put(5, Arc::new(MockSymbol("a")), 6);

        let mut seen = Vec::new();
        table.for_each(&mut |ent| {
            seen.push((ent.state, ent.sym.terminal_tag().to_string(), ent.value));
        });
        seen.sort();

        assert_eq!(
            seen,
            vec![
                (0, "a".to_string(), 1),
                (0, "b".to_string(), 2),
                (5, "a".to_string(), 6),
            ]
        );
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let mut table: Box<dyn AssemblyParseTransitionTable> =
            Box::new(MockTransitionTable::default());
        let sym: Arc<dyn AssemblySymbol> = Arc::new(MockSymbol("x"));
        table.put(0, sym.clone(), 42);
        assert_eq!(table.get(0, sym.as_ref()), Some(42));
    }
}
