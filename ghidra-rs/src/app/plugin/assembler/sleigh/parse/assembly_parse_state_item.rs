//! Port of `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseStateItem`.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyGrammar;
use crate::app::plugin::assembler::sleigh::grammars::abstract_assembly_production::AbstractAssemblyProduction;
use crate::app::seam_stubs::AssemblySymbol;

/// An item in the state of an LR(0) parser.
///
/// An item is a production with a dot indicating a position while parsing.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseStateItem`, a concrete class
/// `implements Comparable<AssemblyParseStateItem>` whose `prod` field is declared as the concrete
/// `AssemblyProduction` type but is only ever used through its inherited
/// `AbstractAssemblyProduction` surface (`getRHS()`, `getLHS()`, `getIndex()`) -- this class never
/// calls `AssemblyProduction`'s own `isConstructor()`. This port therefore stores
/// [`Arc<dyn AbstractAssemblyProduction>`](AbstractAssemblyProduction) rather than the more
/// specific [`AssemblyProduction`](crate::app::plugin::assembler::sleigh::grammars::AssemblyProduction),
/// and [`get_closure`](Self::get_closure) takes `&dyn` [`AbstractAssemblyGrammar`] rather than the
/// more specific
/// [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar) -- the
/// concrete `AssemblyGrammar` class's own `productionsOf` is inherited unchanged from
/// `AbstractAssemblyGrammar`, and the already-ported `AssemblyGrammar` trait in this crate does
/// not (yet) extend the also-already-ported `AbstractAssemblyGrammar` trait (see that trait's own
/// docs), so this is the most decoupled, currently-usable pairing that still exposes exactly what
/// this class needs.
#[derive(Clone)]
pub struct AssemblyParseStateItem {
    prod: Arc<dyn AbstractAssemblyProduction>,
    pos: usize,
}

// `prod` is a `Arc<dyn AbstractAssemblyProduction>` trait object with no `Debug` supertrait, so
// `#[derive(Debug)]` isn't available; this manual impl reports `pos` and a placeholder for `prod`.
impl std::fmt::Debug for AssemblyParseStateItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssemblyParseStateItem")
            .field("prod", &"<dyn AbstractAssemblyProduction>")
            .field("pos", &self.pos)
            .finish()
    }
}

impl AssemblyParseStateItem {
    /// Construct a new item starting immediately before the symbol at the given position in the
    /// given production.
    ///
    /// Port of `AssemblyParseStateItem(AssemblyProduction, int)`.
    ///
    /// # Panics
    /// Panics if `pos` is beyond the end of the production's right-hand side, mirroring Java's
    /// `throw new AssertionError("INTERNAL: Attempt to advance beyond end of RHS")`.
    pub fn new(prod: Arc<dyn AbstractAssemblyProduction>, pos: usize) -> Self {
        assert!(
            pos <= prod.rhs().size(),
            "INTERNAL: Attempt to advance beyond end of RHS"
        );
        AssemblyParseStateItem { prod, pos }
    }

    /// Construct a new item starting at the far left of the given production.
    ///
    /// Port of the convenience constructor `AssemblyParseStateItem(AssemblyProduction)`, which
    /// delegates to `this(prod, 0)`.
    pub fn at_start(prod: Arc<dyn AbstractAssemblyProduction>) -> Self {
        Self::new(prod, 0)
    }

    /// Advance the dot by one position, producing a new item.
    ///
    /// Port of `read()`.
    pub fn read(&self) -> AssemblyParseStateItem {
        AssemblyParseStateItem::new(self.prod.clone(), self.pos + 1)
    }

    /// Get the symbol immediately to the right of the dot.
    ///
    /// This is the symbol which must be matched to advance the dot. Returns `None` if the item is
    /// completed, i.e., the dot is at the far right.
    ///
    /// Port of `getNext()`.
    pub fn get_next(&self) -> Option<Arc<dyn AssemblySymbol>> {
        if self.completed() {
            return None;
        }
        Some(self.prod.rhs().get_symbol(self.pos))
    }

    /// "Fill" one step out to close a state containing this item.
    ///
    /// To compute the full closure, you must continue stepping out until no new items are
    /// generated.
    ///
    /// * `grammar` - the grammar containing the production.
    ///
    /// Returns a subset of items in the closure of a state containing this item.
    ///
    /// Port of `getClosure(AssemblyGrammar)`. See the struct's own docs for why this takes `&dyn`
    /// [`AbstractAssemblyGrammar`] rather than the more specific `AssemblyGrammar`, and
    /// [`AssemblySymbol::as_non_terminal`] for how Java's `next instanceof AssemblyNonTerminal`
    /// check is reproduced.
    pub fn get_closure(
        &self,
        grammar: &dyn AbstractAssemblyGrammar,
    ) -> BTreeSet<AssemblyParseStateItem> {
        let Some(next) = self.get_next() else {
            return BTreeSet::new();
        };
        let Some(nt) = next.as_non_terminal() else {
            return BTreeSet::new();
        };
        grammar
            .productions_of_non_terminal(nt)
            .into_iter()
            .map(|subst| AssemblyParseStateItem::at_start(subst))
            .collect()
    }

    /// Check if this item is completed.
    ///
    /// The item is completed if all symbols have been matched, i.e., the dot is at the far right
    /// of the production.
    ///
    /// Port of `completed()`.
    pub fn completed(&self) -> bool {
        self.pos == self.prod.rhs().size()
    }

    /// Get the position of the dot.
    ///
    /// The position is the number of symbols to the left of the dot.
    ///
    /// Port of `getPos()`.
    pub fn get_pos(&self) -> usize {
        self.pos
    }

    /// Get the production associated with this item.
    ///
    /// Port of `getProduction()`.
    pub fn get_production(&self) -> Arc<dyn AbstractAssemblyProduction> {
        self.prod.clone()
    }
}

impl fmt::Display for AssemblyParseStateItem {
    /// Port of `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rhs = self.prod.rhs();
        let prec = rhs.sub(0, self.pos);
        let proc = rhs.sub(self.pos, rhs.size());
        write!(f, "{}. {} => ", self.prod.index(), self.prod.lhs())?;
        if prec.size() != 0 {
            write!(f, "{} ", prec.display_string())?;
        }
        write!(f, "*")?;
        if proc.size() != 0 {
            write!(f, " {}", proc.display_string())?;
        }
        Ok(())
    }
}

impl PartialEq for AssemblyParseStateItem {
    /// Port of `equals(Object)`.
    fn eq(&self, other: &Self) -> bool {
        self.prod.index() == other.prod.index() && self.pos == other.pos
    }
}

impl Eq for AssemblyParseStateItem {}

impl PartialOrd for AssemblyParseStateItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssemblyParseStateItem {
    /// Port of `compareTo(AssemblyParseStateItem)`.
    fn cmp(&self, other: &Self) -> Ordering {
        self.prod.index().cmp(&other.prod.index()).then(self.pos.cmp(&other.pos))
    }
}

impl Hash for AssemblyParseStateItem {
    /// Port of `hashCode()`: `result = prod.getIndex(); result *= 31; result += pos;`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        let result: i64 = (self.prod.index() as i64) * 31 + self.pos as i64;
        result.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::AssemblySentential;
    use crate::app::seam_stubs::AssemblyNonTerminal;

    #[derive(Clone)]
    struct MockNonTerminal(&'static str);

    impl fmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for MockNonTerminal {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    #[derive(Clone)]
    struct MockTerminalSymbol(&'static str);

    impl fmt::Display for MockTerminalSymbol {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockTerminalSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    /// A symbol that *is* a non-terminal, wrapping a [`MockNonTerminal`] and exposing it via
    /// [`AssemblySymbol::as_non_terminal`] -- standing in for Java's `AssemblyNonTerminal extends
    /// AssemblySymbol` relationship (see this crate's own docs on why that relationship isn't
    /// structural for these two placeholder traits).
    #[derive(Clone)]
    struct MockNonTerminalSymbol(MockNonTerminal);

    impl fmt::Display for MockNonTerminalSymbol {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockNonTerminalSymbol {
        fn terminal_tag(&self) -> &str {
            "<non-terminal>"
        }
        fn as_non_terminal(&self) -> Option<&dyn AssemblyNonTerminal> {
            Some(&self.0)
        }
    }

    #[derive(Default, Clone)]
    struct MockSentential {
        symbols: Vec<Arc<dyn AssemblySymbol>>,
    }

    impl AssemblySentential for MockSentential {
        fn add_symbol(&mut self, symbol: Arc<dyn AssemblySymbol>) -> bool {
            self.symbols.push(symbol);
            true
        }
        fn get_symbols(&self) -> Vec<Arc<dyn AssemblySymbol>> {
            self.symbols.clone()
        }
        fn finish(&mut self) {}
        fn sub(&self, from_index: usize, to_index: usize) -> Box<dyn AssemblySentential> {
            Box::new(MockSentential { symbols: self.symbols[from_index..to_index].to_vec() })
        }
        fn white_space_symbol(&self) -> Arc<dyn AssemblySymbol> {
            unimplemented!("not exercised by these tests")
        }
        fn make_string_terminal(&self, _str: &str) -> Arc<dyn AssemblySymbol> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockProduction {
        idx: i32,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    }

    impl AbstractAssemblyProduction for MockProduction {
        fn index(&self) -> i32 {
            self.idx
        }
        fn set_index(&mut self, idx: i32) {
            self.idx = idx;
        }
        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.lhs.clone()
        }
        fn rhs(&self) -> Arc<dyn AssemblySentential> {
            self.rhs.clone()
        }
    }

    fn terminal(name: &'static str) -> Arc<dyn AssemblySymbol> {
        Arc::new(MockTerminalSymbol(name))
    }

    fn non_terminal_symbol(name: &'static str) -> Arc<dyn AssemblySymbol> {
        Arc::new(MockNonTerminalSymbol(MockNonTerminal(name)))
    }

    /// Builds a production `idx. [lhs] => <symbols...>`.
    fn production(
        idx: i32,
        lhs: &'static str,
        symbols: Vec<Arc<dyn AssemblySymbol>>,
    ) -> Arc<dyn AbstractAssemblyProduction> {
        let mut rhs = MockSentential::default();
        for s in symbols {
            rhs.add_symbol(s);
        }
        Arc::new(MockProduction { idx, lhs: Arc::new(MockNonTerminal(lhs)), rhs: Arc::new(rhs) })
    }

    #[test]
    fn at_start_begins_at_position_zero() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item = AssemblyParseStateItem::at_start(prod);
        assert_eq!(item.get_pos(), 0);
        assert!(!item.completed());
    }

    #[test]
    fn new_panics_when_pos_exceeds_rhs_length() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AssemblyParseStateItem::new(prod, 2)
        }));
        assert!(result.is_err(), "constructing past the end of the RHS must panic");
    }

    #[test]
    fn new_allows_pos_exactly_at_rhs_length() {
        let prod = production(0, "insn", vec![terminal("a")]);
        // pos == rhs.size() is the "completed" position, not "past the end".
        let item = AssemblyParseStateItem::new(prod, 1);
        assert!(item.completed());
    }

    #[test]
    fn read_advances_the_dot_by_one() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item = AssemblyParseStateItem::at_start(prod);
        let advanced = item.read();
        assert_eq!(advanced.get_pos(), 1);
        assert!(!advanced.completed());
    }

    #[test]
    fn get_next_returns_the_symbol_after_the_dot() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item = AssemblyParseStateItem::at_start(prod);
        let next = item.get_next().expect("not completed");
        assert_eq!(next.to_string(), "a");
    }

    #[test]
    fn get_next_returns_none_when_completed() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let item = AssemblyParseStateItem::new(prod, 1);
        assert!(item.get_next().is_none());
    }

    #[test]
    fn completed_is_true_only_at_the_far_right() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let at_start = AssemblyParseStateItem::at_start(prod.clone());
        let at_end = AssemblyParseStateItem::new(prod, 1);
        assert!(!at_start.completed());
        assert!(at_end.completed());
    }

    #[test]
    fn equals_compares_by_production_index_and_pos_only() {
        // Two different productions that happen to share the same index compare equal --
        // mirroring Java's equals(), which never inspects lhs/rhs content, only `prod.getIndex()`.
        let a = production(5, "a", vec![terminal("x")]);
        let b = production(5, "b", vec![terminal("y"), terminal("z")]);
        let item_a = AssemblyParseStateItem::at_start(a);
        let item_b = AssemblyParseStateItem::at_start(b);
        assert_eq!(item_a, item_b);
    }

    #[test]
    fn equals_is_false_for_different_index_or_pos() {
        let prod = production(1, "insn", vec![terminal("a"), terminal("b")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod.clone(), 1);
        assert_ne!(item0, item1);

        let other_prod = production(2, "insn", vec![terminal("a"), terminal("b")]);
        let other_item0 = AssemblyParseStateItem::new(other_prod, 0);
        assert_ne!(item0, other_item0);
    }

    #[test]
    fn compare_to_orders_by_index_then_pos() {
        let prod1 = production(1, "a", vec![terminal("x"), terminal("y")]);
        let prod2 = production(2, "b", vec![terminal("x")]);
        let low_index = AssemblyParseStateItem::new(prod1.clone(), 1);
        let high_index = AssemblyParseStateItem::at_start(prod2);
        assert_eq!(low_index.cmp(&high_index), Ordering::Less);

        let pos0 = AssemblyParseStateItem::new(prod1.clone(), 0);
        let pos1 = AssemblyParseStateItem::new(prod1, 1);
        assert_eq!(pos0.cmp(&pos1), Ordering::Less);
    }

    #[test]
    fn hash_matches_for_equal_items() {
        use std::collections::hash_map::DefaultHasher;
        let a = production(3, "a", vec![terminal("x")]);
        let b = production(3, "b", vec![terminal("y")]);
        let item_a = AssemblyParseStateItem::at_start(a);
        let item_b = AssemblyParseStateItem::at_start(b);
        assert_eq!(item_a, item_b);

        let mut h1 = DefaultHasher::new();
        item_a.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        item_b.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn to_string_matches_java_format_with_dot_in_the_middle() {
        let prod = production(4, "insn", vec![terminal("a"), terminal("b"), terminal("c")]);
        let item = AssemblyParseStateItem::new(prod, 1);
        assert_eq!(item.to_string(), "4. [insn] => a * b c");
    }

    #[test]
    fn to_string_at_start_has_no_leading_symbols() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item = AssemblyParseStateItem::at_start(prod);
        assert_eq!(item.to_string(), "0. [insn] => * a b");
    }

    #[test]
    fn to_string_at_end_has_no_trailing_symbols() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item = AssemblyParseStateItem::new(prod, 2);
        assert_eq!(item.to_string(), "0. [insn] => a b *");
    }

    /// A `TestGrammar` recording which non-terminal `productions_of_non_terminal` was asked
    /// about, and returning a fixed set of substitute productions for it.
    struct TestGrammar {
        target_name: &'static str,
        substitutes: Vec<Arc<dyn AbstractAssemblyProduction>>,
    }

    impl crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyGrammar for TestGrammar {
        fn new_production(
            &self,
            _lhs: Arc<dyn AssemblyNonTerminal>,
            _rhs: Arc<dyn AssemblySentential>,
        ) -> Arc<dyn AbstractAssemblyProduction> {
            unimplemented!("not exercised by these tests")
        }
        fn add_production(&mut self, _prod: Arc<dyn AbstractAssemblyProduction>) {
            unimplemented!("not exercised by these tests")
        }
        fn set_start_name(&mut self, _start_name: Option<String>) {}
        fn get_start_name(&self) -> Option<String> {
            None
        }
        fn get_non_terminal(&self, _name: &str) -> Option<Arc<dyn AssemblyNonTerminal>> {
            None
        }
        fn get_terminal(
            &self,
            _name: &str,
        ) -> Option<Arc<dyn crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal>> {
            None
        }
        fn non_terminals(&self) -> Vec<Arc<dyn AssemblyNonTerminal>> {
            Vec::new()
        }
        fn terminals(
            &self,
        ) -> Vec<Arc<dyn crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal>> {
            Vec::new()
        }
        fn productions_of(&self, name: &str) -> Vec<Arc<dyn AbstractAssemblyProduction>> {
            if name == self.target_name {
                self.substitutes.clone()
            } else {
                Vec::new()
            }
        }
        fn iter_productions(&self) -> Vec<Arc<dyn AbstractAssemblyProduction>> {
            Vec::new()
        }
    }

    #[test]
    fn get_closure_is_empty_when_completed() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let item = AssemblyParseStateItem::new(prod, 1);
        let grammar = TestGrammar { target_name: "unused", substitutes: Vec::new() };
        assert!(item.get_closure(&grammar).is_empty());
    }

    #[test]
    fn get_closure_is_empty_when_next_symbol_is_a_terminal() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let item = AssemblyParseStateItem::at_start(prod);
        let grammar = TestGrammar { target_name: "unused", substitutes: Vec::new() };
        assert!(item.get_closure(&grammar).is_empty());
    }

    #[test]
    fn get_closure_expands_a_non_terminal_via_the_grammars_productions() {
        let prod = production(0, "insn", vec![non_terminal_symbol("expr")]);
        let item = AssemblyParseStateItem::at_start(prod);

        let substitute = production(1, "expr", vec![terminal("x")]);
        let grammar =
            TestGrammar { target_name: "expr", substitutes: vec![substitute.clone()] };

        let closure = item.get_closure(&grammar);
        assert_eq!(closure.len(), 1);
        let only = closure.iter().next().unwrap();
        assert_eq!(only.get_pos(), 0);
        assert_eq!(only.get_production().index(), 1);
    }

    #[test]
    fn get_closure_deduplicates_and_sorts_via_btreeset() {
        let prod = production(0, "insn", vec![non_terminal_symbol("expr")]);
        let item = AssemblyParseStateItem::at_start(prod);

        let sub_a = production(5, "expr", vec![terminal("x")]);
        let sub_b = production(2, "expr", vec![terminal("y")]);
        let grammar = TestGrammar {
            target_name: "expr",
            substitutes: vec![sub_a.clone(), sub_b.clone()],
        };

        let closure: Vec<AssemblyParseStateItem> = item.get_closure(&grammar).into_iter().collect();
        assert_eq!(closure.len(), 2);
        // BTreeSet orders by AssemblyParseStateItem's own Ord (index, then pos).
        assert_eq!(closure[0].get_production().index(), 2);
        assert_eq!(closure[1].get_production().index(), 5);
    }

    #[test]
    fn get_production_returns_the_stored_production() {
        let prod = production(7, "insn", vec![terminal("a")]);
        let item = AssemblyParseStateItem::at_start(prod);
        assert_eq!(item.get_production().index(), 7);
    }
}
