use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::decompiler::context::SleighError;
use crate::decompiler::seam_stubs::Constructor;
use crate::decompiler::slghpatexpress::{OperandValue, PatternExpression, PatternValue};
use crate::decompiler::slghsymbol::specific_symbol::SpecificSymbol;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::program::model::lang::sleigh::template::VarnodeTpl;
use crate::program::model::pcode::ids::{
    ATTRIB_BASE, ATTRIB_CODE, ATTRIB_ID, ATTRIB_INDEX, ATTRIB_MINLEN, ATTRIB_OFF, ATTRIB_SUBSYM,
    ELEM_OPERAND_SYM, ELEM_OPERAND_SYM_HEAD,
};
use crate::program::model::pcode::Encoder;
use crate::sleigh::grammar::location::Location;
use std::io;
use std::sync::Arc;

const CODE_ADDRESS_FLAG: u32 = 1;
const OFFSET_IRREL_FLAG: u32 = 2;
const VARIABLE_LEN_FLAG: u32 = 4;
const MARKED_FLAG: u32 = 8;

/// What this operand resolves to once defined: either a [`SpecificSymbol`] (delegates varnode
/// resolution to it directly), a zero-size family symbol, or any other [`TripleSymbol`].
///
/// Java's `OperandSymbol.getVarnode()` picks its varnode shape at call time via
/// `triple instanceof SpecificSymbol` and `triple.getType() == valuemap_symbol/name_symbol`
/// runtime checks; `Box<dyn TripleSymbol>` alone can't answer either question in Rust (`Any`
/// downcasting only recovers a *concrete* type, not "does this also implement trait X", and the
/// generic `TripleSymbol` trait doesn't carry a `symbol_type()` of its own for the second check).
/// This enum instead has the caller of [`OperandSymbol::define_operand_symbol`] make that choice
/// once, at definition time -- when the concrete type is still known -- rather than recovering it
/// later through runtime inspection.
pub enum OperandDefiningSymbol {
    /// A `SpecificSymbol` (`StartSymbol`, `EndSymbol`, `Next2Symbol`, `EpsilonSymbol`,
    /// `FlowRefSymbol`, `FlowDestSymbol`, another `OperandSymbol`, ...), plus its `SleighSymbol`
    /// id (Java's `TripleSymbol` extends `SleighSymbol` and so carries `getId()` directly; the
    /// Rust `TripleSymbol` trait doesn't expose one -- adding it would touch every implementor
    /// crate-wide -- so the id is captured here instead, by the caller who already has the
    /// concrete symbol's id in hand before boxing it).
    Specific(Box<dyn SpecificSymbol>, u64),
    /// A zero-size family symbol (`ValueMapSymbol`/`NameSymbol` in Java) -- both always print a
    /// fixed string/value with no varnode footprint of their own, so they resolve to a
    /// definite-constant handle the same way a defining expression does.
    ZeroSize(Box<dyn TripleSymbol>, u64),
    /// Any other triple symbol (e.g. `SubtableSymbol`, `ContextSymbol`, a plain `ValueSymbol`) --
    /// resolves to a possibly-dynamic handle.
    Other(Box<dyn TripleSymbol>, u64),
}

impl OperandDefiningSymbol {
    fn as_triple_symbol(&self) -> &dyn TripleSymbol {
        match self {
            OperandDefiningSymbol::Specific(s, _) => s.as_ref(),
            OperandDefiningSymbol::ZeroSize(t, _) => t.as_ref(),
            OperandDefiningSymbol::Other(t, _) => t.as_ref(),
        }
    }

    /// This defining symbol's `SleighSymbol` id (Java's `triple.getId()`).
    fn id(&self) -> u64 {
        match self {
            OperandDefiningSymbol::Specific(_, id) => *id,
            OperandDefiningSymbol::ZeroSize(_, id) => *id,
            OperandDefiningSymbol::Other(_, id) => *id,
        }
    }
}

/// Forwards every [`PatternExpression`]/[`PatternValue`] method to a shared [`OperandValue`],
/// letting [`OperandSymbol::get_pattern_expression`] return an owned `Box<dyn PatternExpression>`
/// that still refers to the *same* underlying value Java's `getPatternExpression() { return
/// localexp; }` would -- see the identical [`crate::decompiler::slghsymbol::value_symbol`]'s
/// `SharedPatternExpression` for why this indirection is needed (no generic
/// clone-and-recreate capability on an owned `OperandValue` field, since it in turn holds a
/// `Box<dyn Constructor>`).
struct SharedOperandExpression(Arc<OperandValue>);

impl PatternExpression for SharedOperandExpression {
    fn list_values<'a>(&'a self, list: &mut Vec<&'a dyn PatternValue>) {
        PatternExpression::list_values(self.0.as_ref(), list);
    }

    fn get_min_max(&self, minlist: &mut VectorStl<i64>, maxlist: &mut VectorStl<i64>) {
        PatternExpression::get_min_max(self.0.as_ref(), minlist, maxlist);
    }

    fn get_sub_value(&self, replace: &VectorStl<i64>, listpos: &mut MutableInt) -> i64 {
        PatternExpression::get_sub_value(self.0.as_ref(), replace, listpos)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        PatternExpression::encode(self.0.as_ref(), encoder)
    }
}

/// An operand symbol in SLEIGH: one placeholder within a constructor's print pieces and pattern
/// equation, resolved either to a defining pattern expression, a defining triple symbol
/// (subtable, context/value/name/valuemap symbol), or left as a bare handle reference into the
/// constructor that owns it.
///
/// Models `ghidra.pcodeCPort.slghsymbol.OperandSymbol`, which extends `SpecificSymbol`.
pub struct OperandSymbol {
    symbol: SleighSymbol,
    pub flags: u32,
    /// Relative offset (Java's `reloffset`).
    pub reloffset: i32,
    /// Base operand this offset is relative to, or `-1` for "relative to constructor start"
    /// (Java's `offsetbase`).
    pub offsetbase: i32,
    /// Minimum size of this operand within the instruction's tokens, in bytes (Java's
    /// `minimumlength`).
    pub minimumlength: i32,
    /// Handle index (Java's `hand`).
    hand: i32,
    /// This operand's own reference-by-index pattern value, present once this operand has been
    /// assigned an index within its constructor (Java's `localexp`, always non-null once
    /// constructed via the real 4-argument Java constructor).
    localexp: Option<Arc<OperandValue>>,
    /// What this operand is defined to resolve to, if anything (Java's `triple`/`defexp`
    /// unified: exactly one of "defined by a symbol" or "defined by an expression" can be set,
    /// same as Java's mutual-exclusion invariant enforced by `defineOperand`'s two overloads).
    defined_as: Option<OperandDefinition>,
}

enum OperandDefinition {
    Symbol(OperandDefiningSymbol),
    Expression(Box<dyn PatternExpression>),
}

impl OperandSymbol {
    /// Creates a new, otherwise-uninitialized operand symbol at the given location (Java's
    /// `OperandSymbol(Location location)`; note this leaves `hand`/`localexp` unset, matching
    /// Java -- a symbol constructed this way isn't usable as a pattern value until given an
    /// index some other way).
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
            flags: 0,
            reloffset: 0,
            offsetbase: 0,
            minimumlength: 0,
            hand: 0,
            localexp: None,
            defined_as: None,
        }
    }

    /// Creates a new, named-but-otherwise-uninitialized operand symbol (test/construction
    /// convenience predating the real 4-argument Java constructor's port; does not itself
    /// assign an index or a `localexp`, unlike [`OperandSymbol::with_operand_value`]).
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            flags: 0,
            reloffset: 0,
            offsetbase: 0,
            minimumlength: 0,
            hand: 0,
            localexp: None,
            defined_as: None,
        }
    }

    /// Creates a new operand symbol at index `index` within constructor `ct` (Java's
    /// `OperandSymbol(Location location, String nm, int index, Constructor ct)`).
    pub fn with_operand_value(
        location: Location,
        name: impl Into<String>,
        index: i32,
        ct: Box<dyn Constructor>,
    ) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location.clone(), name),
            flags: 0,
            reloffset: 0,
            offsetbase: 0,
            minimumlength: 0,
            hand: index,
            localexp: Some(Arc::new(OperandValue::with_operand(location, index, ct))),
            defined_as: None,
        }
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }

    /// Returns the symbol type for this operand.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::OperandSymbol
    }

    /// Marks this operand symbol.
    pub fn set_mark(&mut self) {
        self.flags |= MARKED_FLAG;
    }

    /// Clears the mark on this operand symbol.
    pub fn clear_mark(&mut self) {
        self.flags &= !MARKED_FLAG;
    }

    /// Returns whether this operand symbol is marked.
    pub fn is_marked(&self) -> bool {
        (self.flags & MARKED_FLAG) != 0
    }

    /// The relative offset (Java's `getRelativeOffset`).
    pub fn get_relative_offset(&self) -> i32 {
        self.reloffset
    }

    /// The base operand this offset is relative to (Java's `getOffsetBase`).
    pub fn get_offset_base(&self) -> i32 {
        self.offsetbase
    }

    /// The minimum size of this operand, in bytes (Java's `getMinimumLength`).
    pub fn get_minimum_length(&self) -> i32 {
        self.minimumlength
    }

    /// The handle index (Java's `getIndex`).
    pub fn get_index(&self) -> i32 {
        self.hand
    }

    pub fn set_code_address(&mut self) {
        self.flags |= CODE_ADDRESS_FLAG;
    }

    pub fn is_code_address(&self) -> bool {
        (self.flags & CODE_ADDRESS_FLAG) != 0
    }

    pub fn set_variable_length(&mut self) {
        self.flags |= VARIABLE_LEN_FLAG;
    }

    pub fn is_variable_length(&self) -> bool {
        (self.flags & VARIABLE_LEN_FLAG) != 0
    }

    pub fn set_offset_irrelevant(&mut self) {
        self.flags |= OFFSET_IRREL_FLAG;
    }

    /// Whether this operand's offset is irrelevant (e.g. it's a global/expression-defined
    /// operand whose position within the constructor doesn't matter for pattern matching).
    pub fn is_offset_irrelevant(&self) -> bool {
        (self.flags & OFFSET_IRREL_FLAG) != 0
    }

    /// The defining expression, if this operand was defined via
    /// [`OperandSymbol::define_operand_expression`] (Java's `getDefiningExpression`).
    pub fn get_defining_expression(&self) -> Option<&dyn PatternExpression> {
        match &self.defined_as {
            Some(OperandDefinition::Expression(pe)) => Some(pe.as_ref()),
            _ => None,
        }
    }

    /// The defining symbol, if this operand was defined via
    /// [`OperandSymbol::define_operand_symbol`] (Java's `getDefiningSymbol`).
    pub fn get_defining_symbol(&self) -> Option<&dyn TripleSymbol> {
        match &self.defined_as {
            Some(OperandDefinition::Symbol(sym)) => Some(sym.as_triple_symbol()),
            _ => None,
        }
    }

    /// The `SleighSymbol` id of this operand's defining symbol, if any (Java compares
    /// `sym == parent` by object identity in `Constructor.isRecursive`; this crate's
    /// `OperandDefiningSymbol` already captures each variant's id for
    /// [`crate::decompiler::slghsymbol::Constructor::encode`]'s `ATTRIB_SUBSYM`, so
    /// `Constructor::is_recursive` reuses it for the same comparison, by id instead of identity).
    pub fn defining_symbol_id(&self) -> Option<u64> {
        match &self.defined_as {
            Some(OperandDefinition::Symbol(sym)) => Some(sym.id()),
            _ => None,
        }
    }

    /// Reassigns this operand's handle index, used by
    /// [`crate::decompiler::slghsymbol::Constructor::order_operands`] to fix up indices after
    /// reordering (Java's `newops.get(i).hand = i`).
    pub fn set_hand(&mut self, hand: i32) {
        self.hand = hand;
    }

    /// Reassigns the index this operand's own `localexp` resolves to, matching
    /// [`OperandSymbol::set_hand`] (Java's `newops.get(i).localexp.changeIndex(i)`).
    ///
    /// # Panics
    /// Panics if this operand's `localexp` has already been shared out (e.g. via
    /// [`TripleSymbol::get_pattern_expression`]) to more than one owner -- `order_operands` is
    /// expected to run before a constructor's operands are exposed that way, matching Java's own
    /// call order (`orderOperands` runs near the end of `buildPattern`, which is what first makes
    /// a constructor's pattern -- and so its operands' pattern expressions -- externally visible).
    pub fn change_local_expression_index(&mut self, new_index: i32) {
        if let Some(localexp) = &mut self.localexp {
            std::sync::Arc::get_mut(localexp)
                .expect("OperandSymbol::change_local_expression_index called after localexp was shared out")
                .change_index(new_index);
        }
    }

    /// Defines this operand's pattern directly from `pe` (Java's `defineOperand(PatternExpression
    /// pe)`).
    ///
    /// # Panics
    /// Panics with a [`SleighError`] if this operand has already been defined, matching Java's
    /// `throw new SleighError("Redefining operand from " + pe.location, getLocation())`.
    pub fn define_operand_expression(&mut self, pe: Box<dyn PatternExpression>) {
        if self.defined_as.is_some() {
            panic!("{}", SleighError::new("Redefining operand", self.symbol.location().clone()));
        }
        self.defined_as = Some(OperandDefinition::Expression(pe));
    }

    /// Defines this operand to resolve to `tri` (Java's `defineOperand(TripleSymbol tri)`).
    ///
    /// # Panics
    /// Panics with a [`SleighError`] if this operand has already been defined, matching Java's
    /// `throw new SleighError("Redefining operand " + tri.getName() + " from " +
    /// tri.getLocation(), getLocation())`.
    pub fn define_operand_symbol(&mut self, tri: OperandDefiningSymbol) {
        if self.defined_as.is_some() {
            panic!("{}", SleighError::new("Redefining operand", self.symbol.location().clone()));
        }
        self.defined_as = Some(OperandDefinition::Symbol(tri));
    }

    /// The varnode template this operand resolves to (Java's `getVarnode`).
    ///
    /// # Panics
    /// Panics if this operand was never given an index (`localexp`/`hand` unset) -- mirrors
    /// Java, which would NPE on `getIndex()`'s use inside every branch below.
    pub fn get_varnode(&self) -> VarnodeTpl {
        if matches!(self.defined_as, Some(OperandDefinition::Expression(_))) {
            return VarnodeTpl::with_handle(self.hand, true); // Definite constant handle
        }
        match &self.defined_as {
            Some(OperandDefinition::Symbol(OperandDefiningSymbol::Specific(specific, _))) => {
                *specific.get_varnode()
            }
            Some(OperandDefinition::Symbol(OperandDefiningSymbol::ZeroSize(_, _))) => {
                VarnodeTpl::with_handle(self.hand, true) // Zero-size symbols
            }
            _ => VarnodeTpl::with_handle(self.hand, false), // Possible dynamic handle
        }
    }

    /// Encodes this operand symbol to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_OPERAND_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.symbol.id() as u64)?;
        if let Some(OperandDefinition::Symbol(sym)) = &self.defined_as {
            encoder.write_unsigned_integer(ATTRIB_SUBSYM, sym.id())?;
        }
        encoder.write_signed_integer(ATTRIB_OFF, self.reloffset as i64)?;
        encoder.write_signed_integer(ATTRIB_BASE, self.offsetbase as i64)?;
        encoder.write_signed_integer(ATTRIB_MINLEN, self.minimumlength as i64)?;
        if self.is_code_address() {
            encoder.write_bool(ATTRIB_CODE, true)?;
        }
        encoder.write_signed_integer(ATTRIB_INDEX, self.hand as i64)?;
        if let Some(localexp) = &self.localexp {
            PatternExpression::encode(localexp.as_ref(), encoder)?;
        }
        if let Some(OperandDefinition::Expression(defexp)) = &self.defined_as {
            defexp.encode(encoder)?;
        }
        encoder.close_element(ELEM_OPERAND_SYM)?;
        Ok(())
    }

    /// Encodes just the shared symbol header for this operand symbol.
    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_OPERAND_SYM_HEAD)?;
        self.symbol.encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_OPERAND_SYM_HEAD)?;
        Ok(())
    }
}

impl TripleSymbol for OperandSymbol {
    fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
        let localexp = self
            .localexp
            .clone()
            .expect("OperandSymbol::get_pattern_expression called before an index was assigned");
        Box::new(SharedOperandExpression(localexp))
    }

    fn get_size(&self) -> i32 {
        match &self.defined_as {
            Some(OperandDefinition::Symbol(sym)) => sym.as_triple_symbol().get_size(),
            _ => 0,
        }
    }

    fn collect_local_values(&self, results: &mut Vec<i64>) {
        if let Some(OperandDefinition::Symbol(sym)) = &self.defined_as {
            sym.as_triple_symbol().collect_local_values(results);
        }
    }
}

impl SpecificSymbol for OperandSymbol {
    fn get_varnode(&self) -> Box<VarnodeTpl> {
        Box::new(self.get_varnode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghsymbol::specific_symbol::SpecificSymbol as _;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    struct MockConstructor {
        location: Location,
    }
    impl Default for MockConstructor {
        fn default() -> Self {
            Self { location: loc() }
        }
    }
    impl Constructor for MockConstructor {
        fn location(&self) -> &Location {
            &self.location
        }
        fn get_operand(&self, _index: i32) -> &OperandSymbol {
            unimplemented!("not exercised by these tests")
        }
        fn get_operand_sub_value(&self, _index: i32, _replace: &[i64], _listpos: &mut MutableInt) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn parent_id(&self) -> u64 {
            0
        }
        fn id(&self) -> u64 {
            0
        }
        fn set_id(&mut self, _id: u64) {}
        fn collect_local_exports(&self, _results: &mut Vec<i64>) {}
        fn num_operands(&self) -> i32 {
            0
        }
        fn add_operand(&mut self, _sym: OperandSymbol) -> i32 {
            0
        }
        fn add_invisible_operand(&mut self, _sym: OperandSymbol) -> i32 {
            0
        }
        fn get_operand_mut(&mut self, _index: i32) -> &mut OperandSymbol {
            unimplemented!("not exercised by these tests")
        }
        fn set_source_file_index(&mut self, _index: i32) {}
        fn add_equation(&mut self, _pateq: Box<dyn crate::decompiler::slghpatexpress::PatternEquationOps>) {}
        fn remove_trailing_space(&mut self) {}
        fn add_context(&mut self, _contvec: Vec<Box<dyn crate::decompiler::slghsymbol::ContextChange>>) {}
        fn set_main_section(&mut self, _section: Option<crate::program::model::lang::sleigh::template::ConstructTpl>) {}
        fn set_named_section(&mut self, _section: crate::program::model::lang::sleigh::template::ConstructTpl, _index: i32) {}
    }

    struct FixedValue {
        min: i64,
        max: i64,
    }

    struct MockTokenPattern;
    impl crate::decompiler::slghpatexpress::TokenPattern for MockTokenPattern {
        fn location(&self) -> &Location {
            unimplemented!("not exercised by these tests")
        }
        fn get_pattern(&self) -> &dyn crate::decompiler::slghpattern::Pattern {
            unimplemented!("not exercised by these tests")
        }
        fn always_true(&self) -> bool { true }
        fn always_false(&self) -> bool { false }
        fn always_instruction_true(&self) -> bool { true }
        fn get_left_ellipsis(&self) -> bool { false }
        fn get_right_ellipsis(&self) -> bool { false }
        fn set_left_ellipsis(&mut self, _val: bool) {}
        fn set_right_ellipsis(&mut self, _val: bool) {}
        fn get_minimum_length(&self) -> i32 { 0 }
        fn simplify_pattern(&mut self) {}
        fn copy_into(&mut self, _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern) {}
        fn do_and(&self, _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> { Box::new(MockTokenPattern) }
        fn do_or(&self, _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> { Box::new(MockTokenPattern) }
        fn do_cat(&self, _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> { Box::new(MockTokenPattern) }
        fn common_sub_pattern(&self, _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> { Box::new(MockTokenPattern) }
    }

    impl PatternExpression for FixedValue {
        fn list_values<'a>(&'a self, list: &mut Vec<&'a dyn PatternValue>) {
            list.push(self);
        }
        fn get_min_max(&self, minlist: &mut VectorStl<i64>, maxlist: &mut VectorStl<i64>) {
            minlist.push_back(self.min_value());
            maxlist.push_back(self.max_value());
        }
        fn get_sub_value(&self, replace: &VectorStl<i64>, listpos: &mut MutableInt) -> i64 {
            let res = *replace.get(listpos.get() as usize);
            listpos.increment();
            res
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
    }

    impl PatternValue for FixedValue {
        fn gen_pattern(&self, _val: i64) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> {
            Box::new(MockTokenPattern)
        }
        fn min_value(&self) -> i64 {
            self.min
        }
        fn max_value(&self) -> i64 {
            self.max
        }
    }

    struct MockTripleSymbol {
        size: i32,
    }
    impl TripleSymbol for MockTripleSymbol {
        fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
            Box::new(FixedValue { min: 0, max: 0 })
        }
        fn get_size(&self) -> i32 {
            self.size
        }
    }

    #[test]
    fn new_creates_operand() {
        let operand = OperandSymbol::new(loc());
        assert_eq!(operand.symbol_type(), SymbolType::OperandSymbol);
    }

    #[test]
    fn with_name_stores_name() {
        let operand = OperandSymbol::with_name(loc(), "op1");
        assert_eq!(operand.symbol().name(), "op1");
    }

    #[test]
    fn with_operand_value_assigns_index_and_localexp() {
        let operand = OperandSymbol::with_operand_value(loc(), "op1", 2, Box::new(MockConstructor::default()));
        assert_eq!(operand.get_index(), 2);
        assert!(operand.localexp.is_some());
    }

    #[test]
    fn mark_sets_and_checks_marked_flag() {
        let mut operand = OperandSymbol::new(loc());
        assert!(!operand.is_marked());
        operand.set_mark();
        assert!(operand.is_marked());
    }

    #[test]
    fn clear_mark_removes_marked_flag() {
        let mut operand = OperandSymbol::new(loc());
        operand.set_mark();
        operand.clear_mark();
        assert!(!operand.is_marked());
    }

    #[test]
    fn offsets_are_mutable() {
        let mut operand = OperandSymbol::new(loc());
        operand.reloffset = 5;
        operand.offsetbase = 10;
        assert_eq!(operand.reloffset, 5);
        assert_eq!(operand.offsetbase, 10);
    }

    #[test]
    fn code_address_flag_round_trips() {
        let mut operand = OperandSymbol::new(loc());
        assert!(!operand.is_code_address());
        operand.set_code_address();
        assert!(operand.is_code_address());
    }

    #[test]
    fn variable_length_flag_round_trips() {
        let mut operand = OperandSymbol::new(loc());
        assert!(!operand.is_variable_length());
        operand.set_variable_length();
        assert!(operand.is_variable_length());
    }

    #[test]
    fn offset_irrelevant_flag_round_trips() {
        let mut operand = OperandSymbol::new(loc());
        assert!(!operand.is_offset_irrelevant());
        operand.set_offset_irrelevant();
        assert!(operand.is_offset_irrelevant());
    }

    #[test]
    fn flags_are_independent() {
        let mut operand = OperandSymbol::new(loc());
        operand.set_code_address();
        operand.set_variable_length();
        assert!(operand.is_code_address());
        assert!(operand.is_variable_length());
        assert!(!operand.is_offset_irrelevant());
        assert!(!operand.is_marked());
    }

    #[test]
    fn define_operand_expression_stores_it() {
        let mut operand = OperandSymbol::with_operand_value(loc(), "op1", 0, Box::new(MockConstructor::default()));
        operand.define_operand_expression(Box::new(FixedValue { min: 1, max: 4 }));
        assert!(operand.get_defining_expression().is_some());
        assert!(operand.get_defining_symbol().is_none());
    }

    #[test]
    #[should_panic(expected = "Redefining operand")]
    fn define_operand_expression_twice_panics() {
        let mut operand = OperandSymbol::with_operand_value(loc(), "op1", 0, Box::new(MockConstructor::default()));
        operand.define_operand_expression(Box::new(FixedValue { min: 1, max: 4 }));
        operand.define_operand_expression(Box::new(FixedValue { min: 1, max: 4 }));
    }

    #[test]
    fn define_operand_symbol_stores_it() {
        let mut operand = OperandSymbol::with_operand_value(loc(), "op1", 0, Box::new(MockConstructor::default()));
        operand.define_operand_symbol(OperandDefiningSymbol::Other(Box::new(MockTripleSymbol { size: 4 }), 99));
        assert!(operand.get_defining_symbol().is_some());
        assert!(operand.get_defining_expression().is_none());
        assert_eq!(TripleSymbol::get_size(&operand), 4);
    }

    #[test]
    fn get_size_defaults_to_zero_when_undefined() {
        let operand = OperandSymbol::with_operand_value(loc(), "op1", 0, Box::new(MockConstructor::default()));
        assert_eq!(TripleSymbol::get_size(&operand), 0);
    }

    #[test]
    fn get_pattern_expression_returns_the_backing_operand_value() {
        let operand = OperandSymbol::with_operand_value(loc(), "op1", 3, Box::new(MockConstructor::default()));
        let expr = TripleSymbol::get_pattern_expression(&operand);
        // list_values pushing exactly one entry (itself) proves the wrapper forwards to the
        // real, shared OperandValue rather than some disconnected stand-in.
        let mut list = Vec::new();
        expr.list_values(&mut list);
        assert_eq!(list.len(), 1);
    }

    #[test]
    #[should_panic(expected = "Operand used in pattern expression")]
    fn get_pattern_expression_get_min_max_reaches_the_real_operand_value_panic() {
        let operand = OperandSymbol::with_operand_value(loc(), "op1", 3, Box::new(MockConstructor::default()));
        let expr = TripleSymbol::get_pattern_expression(&operand);
        let mut min = VectorStl::new();
        let mut max = VectorStl::new();
        // OperandValue.getMinMax panics through min_value()/max_value() (an operand reference
        // can't itself be evaluated as a pattern value, matching Java's SleighError) -- reaching
        // that real panic through the shared wrapper (not a disconnected stand-in) is the point.
        expr.get_min_max(&mut min, &mut max);
    }

    #[test]
    fn get_varnode_with_expression_is_a_definite_constant_handle() {
        let mut operand = OperandSymbol::with_operand_value(loc(), "op1", 5, Box::new(MockConstructor::default()));
        operand.define_operand_expression(Box::new(FixedValue { min: 0, max: 0 }));
        let vn = OperandSymbol::get_varnode(&operand);
        assert!(vn.is_zero_size());
    }

    #[test]
    fn get_varnode_with_zero_size_symbol_is_a_definite_constant_handle() {
        let mut operand = OperandSymbol::with_operand_value(loc(), "op1", 5, Box::new(MockConstructor::default()));
        operand.define_operand_symbol(OperandDefiningSymbol::ZeroSize(Box::new(MockTripleSymbol { size: 0 }), 99));
        let vn = OperandSymbol::get_varnode(&operand);
        assert!(vn.is_zero_size());
    }

    #[test]
    fn get_varnode_with_other_symbol_is_a_possibly_dynamic_handle() {
        let mut operand = OperandSymbol::with_operand_value(loc(), "op1", 5, Box::new(MockConstructor::default()));
        operand.define_operand_symbol(OperandDefiningSymbol::Other(Box::new(MockTripleSymbol { size: 4 }), 99));
        let vn = OperandSymbol::get_varnode(&operand);
        assert!(!vn.is_zero_size());
    }

    #[test]
    fn get_varnode_with_no_definition_is_a_possibly_dynamic_handle() {
        let operand = OperandSymbol::with_operand_value(loc(), "op1", 5, Box::new(MockConstructor::default()));
        let vn = OperandSymbol::get_varnode(&operand);
        assert!(!vn.is_zero_size());
    }

    #[test]
    fn specific_symbol_get_varnode_matches_inherent_get_varnode() {
        let operand = OperandSymbol::with_operand_value(loc(), "op1", 5, Box::new(MockConstructor::default()));
        let via_trait = SpecificSymbol::get_varnode(&operand);
        let via_inherent = OperandSymbol::get_varnode(&operand);
        assert_eq!(via_trait.is_zero_size(), via_inherent.is_zero_size());
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        ints: Vec<i64>,
        bools: Vec<bool>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.closed.push(elem_id.name);
            Ok(())
        }
        fn write_bool(&mut self, _a: crate::program::model::pcode::ids::AttributeId, v: bool) -> io::Result<()> {
            self.bools.push(v);
            Ok(())
        }
        fn write_signed_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, v: i64) -> io::Result<()> {
            self.ints.push(v);
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: u64) -> io::Result<()> { Ok(()) }
        fn write_string(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_string_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_space(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _s: &crate::program::model::address::AddressSpace) -> io::Result<()> { Ok(()) }
        fn write_space_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _n: &str) -> io::Result<()> { Ok(()) }
        fn write_opcode(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> { Ok(()) }
        fn write_opcode_ordinal(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: i32) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn encode_writes_element_and_attributes() {
        let mut operand = OperandSymbol::with_operand_value(loc(), "op1", 5, Box::new(MockConstructor::default()));
        operand.reloffset = 2;
        operand.offsetbase = 1;
        operand.minimumlength = 4;
        operand.set_code_address();

        let mut encoder = RecordingEncoder::default();
        operand.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened.first(), Some(&"operand_sym"));
        assert_eq!(encoder.closed.last(), Some(&"operand_sym"));
        assert!(encoder.ints.contains(&2));
        assert!(encoder.ints.contains(&1));
        assert!(encoder.ints.contains(&4));
        assert!(encoder.ints.contains(&5));
        assert_eq!(encoder.bools, vec![true]);
    }

    #[test]
    fn encode_header_writes_header_element() {
        let operand = OperandSymbol::with_operand_value(loc(), "op1", 0, Box::new(MockConstructor::default()));
        let mut encoder = RecordingEncoder::default();
        operand.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["operand_sym_head"]);
        assert_eq!(encoder.closed, vec!["operand_sym_head"]);
    }
}
