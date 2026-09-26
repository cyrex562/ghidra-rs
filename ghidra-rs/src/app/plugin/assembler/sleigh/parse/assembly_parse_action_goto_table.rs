//! Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseActionGotoTable`.

use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal;
use crate::app::seam_stubs::{AssemblyNonTerminal, AssemblyProduction, AssemblySymbol};

/// An entry in the Action/Goto table.
///
/// Mirrors `AssemblyParseActionGotoTable.Action` and its four concrete subclasses
/// (`ShiftAction`, `ReduceAction`, `GotoAction`, `AcceptAction`), collapsed into a single enum:
/// Java's hierarchy is a closed set of otherwise-data-only variants distinguished only by their
/// `toString()` (`"S<n>"`, `"R<n>"`, `"G<n>"`, `"acc"`), which is also all `Action.equals`,
/// `Action.hashCode`, and `Action.compareTo` key off of (the same LAZY, `toString()`-based
/// convention used throughout this crate's port of this package, e.g.
/// [`TableEntryKey`](crate::app::plugin::assembler::sleigh::util::TableEntryKey)). `Eq`/`Ord`
/// here are hand-implemented against [`Display`](fmt::Display) rather than derived, to reproduce
/// that. `ReduceAction.prod` is kept as an actual
/// [`AssemblyProduction`](crate::app::seam_stubs::AssemblyProduction) (not just its index) since
/// downstream consumers (`AssemblyParseMachine`, `AssemblyParser`) read `((ReduceAction)
/// a).prod` directly, not just its formatted index.
#[derive(Clone)]
pub enum Action {
    /// A SHIFT (S*n*) entry. Mirrors `ShiftAction`.
    Shift {
        /// Mirrors `ShiftAction.newStateNum`.
        new_state_num: i32,
    },
    /// A REDUCE (R*n*) entry. Mirrors `ReduceAction`.
    Reduce {
        /// Mirrors `ReduceAction.prod`.
        prod: Arc<dyn AssemblyProduction>,
    },
    /// A GOTO (G*n*) entry. Mirrors `GotoAction`.
    Goto {
        /// Mirrors `GotoAction.newStateNum`.
        new_state_num: i32,
    },
    /// An ACCEPT (acc) entry. Mirrors `AcceptAction`, whose only instance is the `ACCEPT`
    /// singleton -- reproduced here as a unit variant rather than a lazily-constructed constant,
    /// since Rust has no direct equivalent of a `static final` instance of an enum variant.
    Accept,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Shift { new_state_num } => write!(f, "S{new_state_num}"),
            Action::Reduce { prod } => write!(f, "R{}", prod.index()),
            Action::Goto { new_state_num } => write!(f, "G{new_state_num}"),
            Action::Accept => write!(f, "acc"),
        }
    }
}

// `dyn AssemblyProduction` doesn't implement `Debug`, so this is hand-written (in terms of the
// same `toString()`-equivalent formatting as `Display`) rather than derived.
impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Action({self})")
    }
}

impl PartialEq for Action {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for Action {}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

/// The Action/Goto table for a LALR(1) parser.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseActionGotoTable`, a concrete
/// class backed by a `MultiValuedMap<TableEntryKey, Action>` (the sparse table itself) plus a
/// second `MultiValuedMap<Integer, AssemblyTerminal>` (`possibleTerms`, an index of populated
/// terminal columns per state, used by [`get_expected`](Self::get_expected)). This table is
/// unconventional in that a single cell may hold more than one action: rather than presuming to
/// control the grammar (which is automatically derived from another source), the parsing
/// algorithm branches and tries every action in a cell.
///
/// This class was chosen as the cut-point for a dependency cycle running through the parser and
/// its grammar/symbol types, so it is ported here as a trait: implementors own the underlying
/// `(state, symbol) -> [Action]` sparse map and the `possibleTerms` index however they like (a
/// pair of `TreeSetValuedTreeMap`s, keyed by
/// [`TableEntryKey`](crate::app::plugin::assembler::sleigh::util::TableEntryKey), in Java).
///
/// Every `put*` convenience method (`putShift`, `putReduce`, `putGoto`, `putAccept`) is a
/// *required* trait method rather than a default built atop [`put`](Self::put), unlike the
/// sibling
/// [`AssemblyParseTransitionTable`](crate::app::plugin::assembler::sleigh::parse::AssemblyParseTransitionTable)
/// trait's single `put`. That's because Java's `put(int, AssemblySymbol, Action)` performs an
/// `instanceof AssemblyTerminal` check to decide whether to also index `next` into
/// `possibleTerms` -- information a caller of `putShift`/`putReduce` (both always given an
/// `AssemblyTerminal`) has but a generic `Arc<dyn AssemblySymbol>` parameter to `put` would have
/// erased. Rather than require implementors to recover that information via a downcast, each
/// `put*` variant is its own required method, with the erased [`put`](Self::put) still available
/// for the fully-generic case Java's overload resolution can't distinguish anyway (used
/// internally by [`putAccept`](Self::put_accept) in Java, and exposed here for callers that
/// already hold an `Arc<dyn AssemblySymbol>`).
///
/// [`put_accept`](Self::put_accept) additionally takes the end-of-input terminal as an explicit
/// `eoi` parameter rather than reaching for the `AssemblyEOI.EOI` singleton Java hardcodes:
/// `AssemblyEOI` (a concrete subclass of the already-ported
/// [`AssemblyTerminal`](crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal) that
/// adds no new methods of its own, only overriding inherited ones) isn't ported yet, and since
/// its only role here is *being* an `AssemblyTerminal` instance -- a trait this crate already has
/// -- there's nothing left to stub; the caller supplies whichever `AssemblyTerminal` represents
/// EOI in their grammar.
pub trait AssemblyParseActionGotoTable {
    /// Add an action entry to the given cell.
    ///
    /// Mirrors `AssemblyParseActionGotoTable.put(int, AssemblySymbol, Action)`.
    ///
    /// Returns `true` if the given entry was not already present.
    fn put(&mut self, from_state: i32, next: Arc<dyn AssemblySymbol>, action: Action) -> bool;

    /// Add a SHIFT (S*n*) entry to the given cell.
    ///
    /// Mirrors `AssemblyParseActionGotoTable.putShift(int, AssemblyTerminal, int)`.
    ///
    /// Returns `true` if the given entry was not already present.
    fn put_shift(&mut self, from_state: i32, next: Arc<dyn AssemblyTerminal>, new_state: i32)
        -> bool;

    /// Add a REDUCE (R*n*) entry to the given cell.
    ///
    /// Mirrors `AssemblyParseActionGotoTable.putReduce(int, AssemblyTerminal,
    /// AssemblyProduction)`.
    ///
    /// Returns `true` if the given entry was not already present.
    fn put_reduce(
        &mut self,
        from_state: i32,
        next: Arc<dyn AssemblyTerminal>,
        prod: Arc<dyn AssemblyProduction>,
    ) -> bool;

    /// Add a GOTO entry to the given cell.
    ///
    /// Mirrors `AssemblyParseActionGotoTable.putGoto(int, AssemblyNonTerminal, int)`.
    ///
    /// Returns `true` if the given entry was not already present.
    fn put_goto(&mut self, from_state: i32, next: Arc<dyn AssemblyNonTerminal>, new_state: i32)
        -> bool;

    /// Add an ACCEPT entry for the given state at the end of input.
    ///
    /// Mirrors `AssemblyParseActionGotoTable.putAccept(int)`. `eoi` stands in for the
    /// `AssemblyEOI.EOI` singleton Java hardcodes; see the trait-level docs for why.
    ///
    /// Returns `true` if the state does not already accept on end of input.
    fn put_accept(&mut self, from_state: i32, eoi: Arc<dyn AssemblyTerminal>) -> bool;

    /// Get the terminals that are expected, i.e., have entries for the given state.
    ///
    /// Mirrors `AssemblyParseActionGotoTable.getExpected(int)`.
    fn get_expected(&self, from_state: i32) -> Vec<Arc<dyn AssemblyTerminal>>;

    /// Get all entries in a given cell.
    ///
    /// Mirrors `AssemblyParseActionGotoTable.get(int, AssemblySymbol)`.
    fn get(&self, from_state: i32, next: &dyn AssemblySymbol) -> Vec<Action>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction;
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct MockSymbol(&'static str);

    impl fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    struct MockProduction {
        index: i32,
    }

    impl AbstractAssemblyProduction for MockProduction {
        fn index(&self) -> i32 {
            self.index
        }

        fn set_index(&mut self, _index: i32) {}

        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            unimplemented!("not exercised by this smoke test")
        }

        fn rhs(
            &self,
        ) -> Arc<dyn crate::app::plugin::assembler::sleigh::grammars::AssemblySentential> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl AssemblyProduction for MockProduction {}

    /// Stands in for `AssemblyParseActionGotoTable`'s private `MultiValuedMap<TableEntryKey,
    /// Action>` plus its `possibleTerms` index, both keyed loosely on `(state, symbol tag)`
    /// strings the same way sibling mock tables in this crate do (e.g.
    /// `AssemblyParseTransitionTable`'s test module).
    #[derive(Default)]
    struct MockActionGotoTable {
        cells: BTreeMap<(i32, String), Vec<Action>>,
        possible_terms: BTreeMap<i32, Vec<Arc<dyn AssemblyTerminal>>>,
    }

    impl MockActionGotoTable {
        fn insert(&mut self, from_state: i32, next: &dyn AssemblySymbol, action: Action) -> bool {
            let key = (from_state, next.terminal_tag().to_string());
            let cell = self.cells.entry(key).or_default();
            if cell.contains(&action) {
                return false;
            }
            cell.push(action);
            true
        }
    }

    impl AssemblyParseActionGotoTable for MockActionGotoTable {
        fn put(&mut self, from_state: i32, next: Arc<dyn AssemblySymbol>, action: Action) -> bool {
            self.insert(from_state, next.as_ref(), action)
        }

        fn put_shift(
            &mut self,
            from_state: i32,
            next: Arc<dyn AssemblyTerminal>,
            new_state: i32,
        ) -> bool {
            self.possible_terms.entry(from_state).or_default().push(next.clone());
            self.insert(from_state, next.as_ref(), Action::Shift { new_state_num: new_state })
        }

        fn put_reduce(
            &mut self,
            from_state: i32,
            next: Arc<dyn AssemblyTerminal>,
            prod: Arc<dyn AssemblyProduction>,
        ) -> bool {
            self.possible_terms.entry(from_state).or_default().push(next.clone());
            self.insert(from_state, next.as_ref(), Action::Reduce { prod })
        }

        fn put_goto(
            &mut self,
            from_state: i32,
            _next: Arc<dyn AssemblyNonTerminal>,
            new_state: i32,
        ) -> bool {
            // `AssemblyNonTerminal` isn't ported yet and its stub doesn't carry a stable tag,
            // so this mock keys GOTO entries under the fixed empty-string column -- fine for a
            // single-nonterminal smoke test.
            self.insert(from_state, &MockSymbol(""), Action::Goto { new_state_num: new_state })
        }

        fn put_accept(&mut self, from_state: i32, eoi: Arc<dyn AssemblyTerminal>) -> bool {
            self.possible_terms.entry(from_state).or_default().push(eoi.clone());
            self.insert(from_state, eoi.as_ref(), Action::Accept)
        }

        fn get_expected(&self, from_state: i32) -> Vec<Arc<dyn AssemblyTerminal>> {
            self.possible_terms.get(&from_state).cloned().unwrap_or_default()
        }

        fn get(&self, from_state: i32, next: &dyn AssemblySymbol) -> Vec<Action> {
            let key = (from_state, next.terminal_tag().to_string());
            self.cells.get(&key).cloned().unwrap_or_default()
        }
    }

    struct MockTerminal(&'static str);

    impl fmt::Display for MockTerminal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockTerminal {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    impl AssemblyTerminal for MockTerminal {
        fn r#match(
            &self,
            _buffer: &str,
            _pos: usize,
            _grammar: &dyn crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar,
            _symbols: &dyn crate::app::seam_stubs::AssemblyNumericSymbols,
        ) -> Vec<Arc<dyn crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken>> {
            Vec::new()
        }

        fn get_suggestions(
            &self,
            _got: &str,
            _symbols: &dyn crate::app::seam_stubs::AssemblyNumericSymbols,
        ) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn action_display_and_ordering_matches_java_tostring() {
        let prod: Arc<dyn AssemblyProduction> = Arc::new(MockProduction { index: 3 });
        assert_eq!(Action::Shift { new_state_num: 5 }.to_string(), "S5");
        assert_eq!(Action::Reduce { prod: prod.clone() }.to_string(), "R3");
        assert_eq!(Action::Goto { new_state_num: 7 }.to_string(), "G7");
        assert_eq!(Action::Accept.to_string(), "acc");

        // Lexical ordering of the `toString()` forms: 'G' < 'R' < 'S' < 'a' in ASCII, so GOTO <
        // REDUCE < SHIFT < ACCEPT -- not, say, alphabetical-by-action-name order.
        assert!(Action::Goto { new_state_num: 0 } < Action::Reduce { prod: prod.clone() });
        assert!(Action::Reduce { prod } < Action::Shift { new_state_num: 0 });
        assert!(Action::Shift { new_state_num: 0 } < Action::Accept);
    }

    #[test]
    fn action_eq_is_lazy_on_display_not_prod_identity() {
        let a: Arc<dyn AssemblyProduction> = Arc::new(MockProduction { index: 9 });
        let b: Arc<dyn AssemblyProduction> = Arc::new(MockProduction { index: 9 });
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(Action::Reduce { prod: a }, Action::Reduce { prod: b });
    }

    #[test]
    fn put_shift_populates_cell_and_expected_terminals() {
        let mut table = MockActionGotoTable::default();
        let shift: Arc<dyn AssemblyTerminal> = Arc::new(MockTerminal("insn"));

        assert!(table.put_shift(0, shift.clone(), 1));
        assert_eq!(table.get(0, shift.as_ref()), vec![Action::Shift { new_state_num: 1 }]);
        assert_eq!(table.get_expected(0).len(), 1);
        assert_eq!(table.get_expected(0)[0].terminal_tag(), "insn");
    }

    #[test]
    fn cell_may_hold_multiple_actions_shift_reduce_conflict() {
        let mut table = MockActionGotoTable::default();
        let term: Arc<dyn AssemblyTerminal> = Arc::new(MockTerminal("amb"));
        let prod: Arc<dyn AssemblyProduction> = Arc::new(MockProduction { index: 2 });

        assert!(table.put_shift(0, term.clone(), 4));
        assert!(table.put_reduce(0, term.clone(), prod));
        // Re-adding the identical SHIFT is a no-op, matching `put`'s "already present" contract.
        assert!(!table.put_shift(0, term.clone(), 4));

        let entries = table.get(0, term.as_ref());
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&Action::Shift { new_state_num: 4 }));
        assert!(entries.contains(&Action::Reduce { prod: Arc::new(MockProduction { index: 2 }) }));
    }

    #[test]
    fn put_accept_uses_supplied_eoi_terminal() {
        let mut table = MockActionGotoTable::default();
        let eoi: Arc<dyn AssemblyTerminal> = Arc::new(MockTerminal("$"));

        assert!(table.put_accept(3, eoi.clone()));
        assert_eq!(table.get(3, eoi.as_ref()), vec![Action::Accept]);
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let mut table: Box<dyn AssemblyParseActionGotoTable> =
            Box::new(MockActionGotoTable::default());
        let sym: Arc<dyn AssemblySymbol> = Arc::new(MockSymbol("x"));
        table.put(0, sym.clone(), Action::Goto { new_state_num: 2 });
        assert_eq!(table.get(0, sym.as_ref()), vec![Action::Goto { new_state_num: 2 }]);
    }
}
