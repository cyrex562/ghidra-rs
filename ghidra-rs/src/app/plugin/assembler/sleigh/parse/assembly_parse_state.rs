//! Port of `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseState`.
//!
//! A state in an LR(0) parsing machine. Each state consists of a kernel and an implied closure.
//! Only the kernel is necessary to define the state, but the whole closure must be considered
//! when deriving new states.
//!
//! # `kernel`/`closure` as an insertion-ordered set
//!
//! Java's `kernel`/`closure` fields are both `Set<AssemblyParseStateItem>`, backed by
//! `LinkedHashSet` -- insertion-ordered, and mutated externally through the live reference
//! [`get_kernel`](AssemblyParseState::get_kernel) hands out (`getKernel().add(item)`, as
//! [`AssemblyParser`](super::assembly_parser::AssemblyParser)'s Java source does). Since
//! [`AssemblyParseStateItem`] has real value-based (not identity-based) equality, [`ItemSet`]
//! models this the same way
//! [`StackUnwindWarningSet`](crate::app::plugin::core::debug::stack::stack_unwind_warning_set::StackUnwindWarningSet)
//! models its own `LinkedHashSet` field -- a `Vec` with add-time dedup -- except using
//! [`AssemblyParseStateItem`]'s real `PartialEq` rather than pointer identity. `kernel`/`closure`
//! are wrapped in [`RefCell`] so [`get_kernel`](AssemblyParseState::get_kernel) can hand out a
//! live, mutable view from `&self` (mirroring Java's aliased-mutable-reference semantics) and so
//! [`get_closure`](AssemblyParseState::get_closure) can lazily compute-and-cache from `&self`,
//! exactly as `getClosure()` does: once computed, the cache is **never** invalidated by later
//! [`get_kernel`](AssemblyParseState::get_kernel)-mutations, matching Java's own
//! `if (closure != null) { return closure; }` early return.
//!
//! # Preserved quirk: `equals`/`hashCode` contract violation
//!
//! `equals()` delegates to `kernel.equals(...)`, i.e. `Set.equals` -- order-*independent* (two
//! sets are equal iff they contain the same elements, regardless of insertion order). But
//! `hashCode()` is a **custom**, order-*dependent* accumulation (`result = result * 31 +
//! item.hashCode()` for each item in iteration order) rather than delegating to
//! `kernel.hashCode()` (which, for `AbstractSet`, is order-independent -- a sum, not an
//! accumulation). This violates Java's own equals/hashCode contract: two `AssemblyParseState`s
//! with the same kernel items added in a different order are `.equals()` but can have different
//! `.hashCode()`s. This port preserves that exactly -- see
//! [`equal_kernels_in_different_insertion_order_are_equal_but_may_hash_differently`] below --
//! rather than "fixing" [`Hash`] to be order-independent.
//!
//! # Preserved quirk: `compareTo`'s stale "TreeSet" comment
//!
//! `compareTo`'s comment claims `// This only works because TreeSet presents the items in
//! order`, but `kernel`'s declared type is `LinkedHashSet`, not `TreeSet` -- so
//! [`AsmUtil::compareInOrder`](crate::app::plugin::assembler::sleigh::util::compare_in_order),
//! which compares two sequences positionally, actually walks `kernel` in **insertion** order, not
//! sorted order. The comparison is therefore only meaningful when callers happen to insert kernel
//! items in a consistent order across the states being compared; it is not the sorted-order
//! comparison the comment claims. This port's [`Ord`] impl reproduces that faithfully (comparing
//! [`ItemSet`]'s insertion order via [`ItemSet::as_slice`]) rather than actually sorting first --
//! see [`compare_to_depends_on_insertion_order_despite_the_stale_treeset_comment`] below.

use std::cell::{Ref, RefCell};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyGrammar;
use crate::app::plugin::assembler::sleigh::parse::assembly_parse_state_item::AssemblyParseStateItem;
use crate::app::plugin::assembler::sleigh::util::asm_util::compare_in_order;

/// An insertion-ordered, de-duplicated collection of [`AssemblyParseStateItem`]s. See the module
/// docs for why this (rather than `BTreeSet`) is needed to model Java's `LinkedHashSet` fields.
#[derive(Debug, Clone, Default)]
pub struct ItemSet {
    items: Vec<AssemblyParseStateItem>,
}

impl ItemSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors `Set.add(E)`: returns `true` if the item was not already present.
    pub fn add(&mut self, item: AssemblyParseStateItem) -> bool {
        if self.items.contains(&item) {
            return false;
        }
        self.items.push(item);
        true
    }

    /// Mirrors `Set.addAll(Collection)`: returns `true` if any item was newly added.
    pub fn add_all(&mut self, items: impl IntoIterator<Item = AssemblyParseStateItem>) -> bool {
        let mut changed = false;
        for item in items {
            if self.add(item) {
                changed = true;
            }
        }
        changed
    }

    /// Mirrors `Set.contains(Object)`.
    pub fn contains(&self, item: &AssemblyParseStateItem) -> bool {
        self.items.contains(item)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &AssemblyParseStateItem> {
        self.items.iter()
    }

    /// The items in insertion order, for positional (not set-based) comparisons -- see
    /// [`AssemblyParseState`]'s docs on `compareTo`'s stale "TreeSet" comment.
    pub fn as_slice(&self) -> &[AssemblyParseStateItem] {
        &self.items
    }
}

impl<'a> IntoIterator for &'a ItemSet {
    type Item = &'a AssemblyParseStateItem;
    type IntoIter = std::slice::Iter<'a, AssemblyParseStateItem>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

/// Mirrors `AssemblyParseStateItem.hashCode()`'s formula (`result = prod.getIndex(); result *=
/// 31; result += pos;`), read back out through its public accessors, so
/// [`AssemblyParseState`]'s own custom `hashCode()` accumulation can be reproduced exactly. See
/// that sibling file's own `Hash` impl for why plain (non-wrapping) `i64` arithmetic is used here
/// too, for consistency.
fn item_hash_code(item: &AssemblyParseStateItem) -> i64 {
    (item.get_production().index() as i64) * 31 + item.get_pos() as i64
}

/// A state in an LR(0) parsing machine.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseState`. See the module docs for
/// the `kernel`/`closure` representation and two preserved Java quirks.
pub struct AssemblyParseState {
    grammar: Arc<dyn AbstractAssemblyGrammar>,
    kernel: RefCell<ItemSet>,
    closure: RefCell<Option<ItemSet>>,
}

impl AssemblyParseState {
    /// Construct a new state associated with the given grammar.
    ///
    /// Port of `AssemblyParseState(AssemblyGrammar)`.
    pub fn new(grammar: Arc<dyn AbstractAssemblyGrammar>) -> Self {
        AssemblyParseState { grammar, kernel: RefCell::new(ItemSet::new()), closure: RefCell::new(None) }
    }

    /// Construct a new state associated with the given grammar, seeded with the given item.
    ///
    /// Port of `AssemblyParseState(AssemblyGrammar, AssemblyParseStateItem)`.
    pub fn with_item(grammar: Arc<dyn AbstractAssemblyGrammar>, item: AssemblyParseStateItem) -> Self {
        let state = Self::new(grammar);
        state.kernel.borrow_mut().add(item);
        state
    }

    /// Get the (mutable) kernel for this state.
    ///
    /// Port of `getKernel()`, which returns the live, mutable backing set; callers add to it via
    /// e.g. `state.get_kernel().add(item)`, mirroring Java's `state.getKernel().add(item)`. See
    /// the module docs for why this doesn't invalidate an already-computed
    /// [`get_closure`](Self::get_closure) cache -- neither does Java's.
    pub fn get_kernel(&self) -> std::cell::RefMut<'_, ItemSet> {
        self.kernel.borrow_mut()
    }

    /// Get the closure of this state, caching the result.
    ///
    /// Port of `getClosure()`.
    pub fn get_closure(&self) -> Ref<'_, ItemSet> {
        if self.closure.borrow().is_none() {
            let computed = self.compute_closure();
            *self.closure.borrow_mut() = Some(computed);
        }
        Ref::map(self.closure.borrow(), |c| c.as_ref().expect("just computed"))
    }

    fn compute_closure(&self) -> ItemSet {
        let mut closure = ItemSet::new();
        closure.add_all(self.kernel.borrow().iter().cloned());
        loop {
            let mut new_items = ItemSet::new();
            for item in closure.iter() {
                new_items.add_all(item.get_closure(self.grammar.as_ref()));
            }
            if !closure.add_all(new_items.iter().cloned()) {
                break;
            }
        }
        closure
    }
}

impl PartialEq for AssemblyParseState {
    /// Port of `equals(Object)`: `Set.equals` semantics on `kernel` (order-independent). See the
    /// module docs for why [`Hash`] below is, faithfully, *not* consistent with this.
    fn eq(&self, other: &Self) -> bool {
        let a = self.kernel.borrow();
        let b = other.kernel.borrow();
        a.len() == b.len() && a.iter().all(|item| b.contains(item))
    }
}

impl Eq for AssemblyParseState {}

impl Ord for AssemblyParseState {
    /// Port of `compareTo(AssemblyParseState)`. See the module docs for why this compares
    /// `kernel` in insertion order (not sorted order), despite the Java source's comment
    /// claiming otherwise.
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.kernel.borrow();
        let b = other.kernel.borrow();
        let by_size = a.len().cmp(&b.len());
        if by_size != Ordering::Equal {
            return by_size;
        }
        compare_in_order(a.as_slice(), b.as_slice())
    }
}

impl PartialOrd for AssemblyParseState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for AssemblyParseState {
    /// Port of `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kernel = self.kernel.borrow();
        let mut it = kernel.iter();
        let Some(first) = it.next() else {
            return Ok(());
        };
        write!(f, "\n\n{first}")?;
        for item in it {
            write!(f, "\n{item}")?;
        }
        Ok(())
    }
}

impl Hash for AssemblyParseState {
    /// Port of `hashCode()`. See the module docs: this is a **faithful reproduction of a Java
    /// equals/hashCode contract violation** -- order-dependent, unlike the order-independent
    /// [`PartialEq`] above.
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut result: i64 = 0;
        for item in self.kernel.borrow().iter() {
            result *= 31;
            result += item_hash_code(item);
        }
        result.hash(state);
    }
}

// `grammar` is an `Arc<dyn AbstractAssemblyGrammar>` trait object with no `Debug` supertrait, so
// `#[derive(Debug)]` isn't available; this manual impl reports the kernel/closure-cache state and
// a placeholder for `grammar`.
impl fmt::Debug for AssemblyParseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssemblyParseState")
            .field("grammar", &"<dyn AbstractAssemblyGrammar>")
            .field("kernel", &self.kernel.borrow().as_slice())
            .field("closure_cached", &self.closure.borrow().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::abstract_assembly_production::AbstractAssemblyProduction;
    use crate::app::plugin::assembler::sleigh::grammars::AssemblySentential;
    use crate::app::seam_stubs::{AssemblyNonTerminal, AssemblySymbol};
    use std::fmt as stdfmt;

    #[derive(Clone)]
    struct MockNonTerminal(&'static str);

    impl stdfmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut stdfmt::Formatter<'_>) -> stdfmt::Result {
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

    impl stdfmt::Display for MockTerminalSymbol {
        fn fmt(&self, f: &mut stdfmt::Formatter<'_>) -> stdfmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockTerminalSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    #[derive(Clone)]
    struct MockNonTerminalSymbol(MockNonTerminal);

    impl stdfmt::Display for MockNonTerminalSymbol {
        fn fmt(&self, f: &mut stdfmt::Formatter<'_>) -> stdfmt::Result {
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

    /// A `TestGrammar` returning fixed substitute productions for a given non-terminal name; used
    /// to drive [`AssemblyParseState::get_closure`]'s fixpoint expansion.
    struct TestGrammar {
        target_name: &'static str,
        substitutes: Vec<Arc<dyn AbstractAssemblyProduction>>,
    }

    impl AbstractAssemblyGrammar for TestGrammar {
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

    fn empty_grammar() -> Arc<dyn AbstractAssemblyGrammar> {
        Arc::new(TestGrammar { target_name: "unused", substitutes: Vec::new() })
    }

    #[test]
    fn new_state_has_empty_kernel() {
        let state = AssemblyParseState::new(empty_grammar());
        assert!(state.get_kernel().is_empty());
    }

    #[test]
    fn with_item_seeds_the_kernel() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let item = AssemblyParseStateItem::at_start(prod);
        let state = AssemblyParseState::with_item(empty_grammar(), item.clone());
        assert_eq!(state.get_kernel().len(), 1);
        assert!(state.get_kernel().contains(&item));
    }

    #[test]
    fn get_kernel_add_mutates_live_kernel() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod, 1);

        let state = AssemblyParseState::new(empty_grammar());
        state.get_kernel().add(item0.clone());
        state.get_kernel().add(item1.clone());

        assert_eq!(state.get_kernel().len(), 2);
        assert!(state.get_kernel().contains(&item0));
        assert!(state.get_kernel().contains(&item1));
    }

    #[test]
    fn get_kernel_add_dedups_equal_items() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let item = AssemblyParseStateItem::at_start(prod);

        let state = AssemblyParseState::new(empty_grammar());
        assert!(state.get_kernel().add(item.clone()));
        assert!(!state.get_kernel().add(item));
        assert_eq!(state.get_kernel().len(), 1);
    }

    #[test]
    fn get_closure_starts_from_the_kernel_when_no_non_terminals_follow() {
        let prod = production(0, "insn", vec![terminal("a")]);
        let item = AssemblyParseStateItem::at_start(prod);
        let state = AssemblyParseState::with_item(empty_grammar(), item.clone());

        let closure = state.get_closure();
        assert_eq!(closure.len(), 1);
        assert!(closure.contains(&item));
    }

    #[test]
    fn get_closure_expands_non_terminals_to_a_fixpoint() {
        // insn => *expr, expr => x, no further non-terminals: closure should contain both items.
        let insn_prod = production(0, "insn", vec![non_terminal_symbol("expr")]);
        let expr_prod = production(1, "expr", vec![terminal("x")]);
        let item = AssemblyParseStateItem::at_start(insn_prod);

        let grammar: Arc<dyn AbstractAssemblyGrammar> =
            Arc::new(TestGrammar { target_name: "expr", substitutes: vec![expr_prod.clone()] });
        let state = AssemblyParseState::with_item(grammar, item.clone());

        let closure = state.get_closure();
        assert_eq!(closure.len(), 2);
        assert!(closure.contains(&item));
        assert!(closure.contains(&AssemblyParseStateItem::at_start(expr_prod)));
    }

    #[test]
    fn get_closure_is_cached_and_not_invalidated_by_later_kernel_mutation() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod, 1);

        let state = AssemblyParseState::with_item(empty_grammar(), item0);
        // First call computes and caches the closure from the kernel as it exists right now.
        assert_eq!(state.get_closure().len(), 1);

        // Mutating the kernel afterward does NOT invalidate the cache -- matches Java's
        // `if (closure != null) { return closure; }` never being reset.
        state.get_kernel().add(item1);
        assert_eq!(state.get_kernel().len(), 2);
        assert_eq!(state.get_closure().len(), 1, "cached closure must not reflect the later kernel mutation");
    }

    #[test]
    fn to_string_is_empty_for_an_empty_kernel() {
        let state = AssemblyParseState::new(empty_grammar());
        assert_eq!(state.to_string(), "");
    }

    #[test]
    fn to_string_matches_java_format() {
        let prod = production(4, "insn", vec![terminal("a"), terminal("b")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod, 1);

        let state = AssemblyParseState::with_item(empty_grammar(), item0);
        state.get_kernel().add(item1);

        assert_eq!(state.to_string(), "\n\n4. [insn] => * a b\n4. [insn] => a * b");
    }

    #[test]
    fn equals_uses_set_semantics_regardless_of_insertion_order() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod, 1);

        let a = AssemblyParseState::with_item(empty_grammar(), item0.clone());
        a.get_kernel().add(item1.clone());

        let b = AssemblyParseState::with_item(empty_grammar(), item1);
        b.get_kernel().add(item0);

        assert_eq!(a, b, "Set.equals is order-independent");
    }

    #[test]
    fn equal_kernels_in_different_insertion_order_are_equal_but_may_hash_differently() {
        // Faithful reproduction of a real Java equals/hashCode contract violation: `equals()`
        // uses order-independent Set semantics, but `hashCode()` is a custom order-DEPENDENT
        // accumulation. See the module docs.
        use std::collections::hash_map::DefaultHasher;

        let prod = production(0, "insn", vec![terminal("a"), terminal("b"), terminal("c")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod.clone(), 1);
        let item2 = AssemblyParseStateItem::new(prod, 2);

        let a = AssemblyParseState::with_item(empty_grammar(), item0.clone());
        a.get_kernel().add(item1.clone());
        a.get_kernel().add(item2.clone());

        let b = AssemblyParseState::with_item(empty_grammar(), item2);
        b.get_kernel().add(item1);
        b.get_kernel().add(item0);

        assert_eq!(a, b, "same elements regardless of order => equal per Set semantics");

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_ne!(
            ha.finish(),
            hb.finish(),
            "order-dependent hashCode() diverges for equal-but-differently-ordered kernels, \
             exactly reproducing the Java equals/hashCode contract violation"
        );
    }

    #[test]
    fn not_equal_for_different_kernels() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod, 1);

        let a = AssemblyParseState::with_item(empty_grammar(), item0);
        let b = AssemblyParseState::with_item(empty_grammar(), item1);
        assert_ne!(a, b);
    }

    #[test]
    fn compare_to_orders_by_kernel_size_first() {
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let item0 = AssemblyParseStateItem::new(prod.clone(), 0);
        let item1 = AssemblyParseStateItem::new(prod, 1);

        let small = AssemblyParseState::with_item(empty_grammar(), item0.clone());
        let big = AssemblyParseState::with_item(empty_grammar(), item0);
        big.get_kernel().add(item1);

        assert_eq!(small.cmp(&big), Ordering::Less);
        assert_eq!(big.cmp(&small), Ordering::Greater);
    }

    #[test]
    fn compare_to_depends_on_insertion_order_despite_the_stale_treeset_comment() {
        // Same two kernel items, inserted in opposite order into two same-size states. Despite
        // the Java source's comment ("This only works because TreeSet presents the items in
        // order"), `kernel` is a LinkedHashSet, so compareTo actually walks insertion order --
        // producing a nonzero (order-dependent) result here rather than treating the two states
        // as equal-by-content the way a genuine sorted-order comparison would for a
        // set-equality-equal pair.
        let prod = production(0, "insn", vec![terminal("a"), terminal("b")]);
        let low = AssemblyParseStateItem::new(prod.clone(), 0);
        let high = AssemblyParseStateItem::new(prod, 1);

        let ordered_low_high = AssemblyParseState::with_item(empty_grammar(), low.clone());
        ordered_low_high.get_kernel().add(high.clone());

        let ordered_high_low = AssemblyParseState::with_item(empty_grammar(), high);
        ordered_high_low.get_kernel().add(low);

        // The two states are `.equals()` (same set of items)...
        assert_eq!(ordered_low_high, ordered_high_low);
        // ...but `compareTo` is insertion-order-sensitive, so it is NOT consistent with equals.
        assert_ne!(ordered_low_high.cmp(&ordered_high_low), Ordering::Equal);
    }

    #[test]
    fn debug_formatting_does_not_panic() {
        let state = AssemblyParseState::new(empty_grammar());
        let debug_str = format!("{:?}", state);
        assert!(debug_str.contains("AssemblyParseState"));
    }
}
