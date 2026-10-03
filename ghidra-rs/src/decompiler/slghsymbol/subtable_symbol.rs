//! Models `ghidra.pcodeCPort.slghsymbol.SubtableSymbol`.

use std::io;

use crate::decompiler::context::SleighError;
use crate::decompiler::seam_stubs::Constructor;
use crate::decompiler::slghpatexpress::{PatternExpression, TokenPattern};
use crate::decompiler::slghsymbol::sleigh_symbol::SleighSymbol;
use crate::decompiler::slghsymbol::symbol_type::SymbolType;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;
use crate::program::model::pcode::ids::ELEM_SUBTABLE_SYM_HEAD;
use crate::program::model::pcode::Encoder;
use crate::sleigh::grammar::Location;

/// A SLEIGH subtable: a named collection of [`Constructor`]s (each an alternative match
/// pattern/printing/semantics rule) that together define one nonterminal of the instruction
/// grammar.
///
/// Models `ghidra.pcodeCPort.slghsymbol.SubtableSymbol`, which extends `TripleSymbol`.
///
/// `construct` holds `Box<dyn Constructor>` (the existing `seam_stubs::Constructor` trait, which
/// the concrete [`crate::decompiler::slghsymbol::Constructor`] implements) rather than the
/// concrete type directly: `SleighCompile`'s `new_table`/`create_constructor` (the only other
/// real production callers of anything subtable-shaped in this crate today) already work in
/// terms of that seam trait, and keeping `SubtableSymbol` on the same footing means neither
/// needs to change to interoperate with the other.
///
/// `buildPattern`/`buildDecisionTree` are NOT ported, for the same reasons documented on
/// [`crate::decompiler::slghsymbol::Constructor`]: `buildPattern` needs
/// `PatternExpression::gen_min_pattern` unified onto the trait plus mutual recursion with
/// `Constructor::build_pattern` (also not ported); `buildDecisionTree` needs `DecisionNode`
/// (`ghidra.pcodeCPort.slghsymbol.DecisionNode`), a separate, not-yet-ported subsystem. Since
/// `decisiontree` is consequently always absent, [`SubtableSymbol::encode`] always takes Java's
/// own "not fully formed" early-return branch -- a real, complete implementation of that branch,
/// not a stub.
pub struct SubtableSymbol {
    symbol: SleighSymbol,
    pattern: Option<Box<dyn TokenPattern>>,
    beingbuilt: bool,
    errors: bool,
    construct: Vec<Box<dyn Constructor>>,
}

impl SubtableSymbol {
    /// An unnamed subtable (Java's `SubtableSymbol(Location location)`).
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
            pattern: None,
            beingbuilt: false,
            errors: false,
            construct: Vec::new(),
        }
    }

    /// A named subtable (Java's `SubtableSymbol(Location location, String nm)`).
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            pattern: None,
            beingbuilt: false,
            errors: false,
            construct: Vec::new(),
        }
    }

    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    pub fn is_being_built(&self) -> bool {
        self.beingbuilt
    }

    pub fn is_error(&self) -> bool {
        self.errors
    }

    /// Appends `ct` to this subtable, assigning it an id equal to its index within the
    /// subtable's own constructor list (Java's `addConstructor`).
    pub fn add_constructor(&mut self, mut ct: Box<dyn Constructor>) -> i32 {
        let id = self.construct.len() as u64;
        ct.set_id(id);
        self.construct.push(ct);
        id as i32
    }

    pub fn get_pattern(&self) -> Option<&dyn TokenPattern> {
        self.pattern.as_deref()
    }

    pub fn get_num_constructors(&self) -> i32 {
        self.construct.len() as i32
    }

    pub fn get_constructor(&self, id: usize) -> &dyn Constructor {
        self.construct[id].as_ref()
    }

    pub fn get_constructor_mut(&mut self, id: usize) -> &mut dyn Constructor {
        self.construct[id].as_mut()
    }

    /// Encodes this subtable's header (Java's `encodeHeader`).
    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_SUBTABLE_SYM_HEAD)?;
        self.symbol.encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_SUBTABLE_SYM_HEAD)
    }
}

impl TripleSymbol for SubtableSymbol {
    /// A subtable can't itself be used as a value in a pattern expression (Java's
    /// `getPatternExpression` unconditionally `throw new SleighError("Cannot use subtable in
    /// expression", null)`).
    ///
    /// # Panics
    /// Always panics.
    fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
        panic!(
            "{}",
            SleighError::new("Cannot use subtable in expression", self.symbol.location().clone())
        )
    }

    /// A subtable's size is context-dependent, not fixed (Java's `getSize` unconditionally
    /// `-1`).
    fn get_size(&self) -> i32 {
        -1
    }

    fn collect_local_values(&self, results: &mut Vec<i64>) {
        for ct in &self.construct {
            ct.collect_local_exports(results);
        }
    }
}

impl crate::decompiler::seam_stubs::SubtableSymbol for SubtableSymbol {
    fn name(&self) -> &str {
        self.symbol.name()
    }

    fn add_constructor(&mut self, ct: Box<dyn Constructor>) -> i32 {
        SubtableSymbol::add_constructor(self, ct)
    }
}

/// The symbol type for a subtable is always [`SymbolType::SubtableSymbol`] (Java's `getType`).
impl SubtableSymbol {
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::SubtableSymbol
    }

    /// Encodes this subtable and every constructor it owns (Java's `encode`). Java's version
    /// guards the whole body on `decisiontree != null` ("not fully formed" otherwise); since
    /// `buildDecisionTree` is never called here (it isn't ported -- see this type's own doc
    /// comment), there's no `decisiontree` field to guard on at all -- this always takes that
    /// same early-return branch, unconditionally.
    pub fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::PatternValue;
    use crate::decompiler::utils::MutableInt;
    use crate::generic::stl::vector_stl::VectorStl;
    use crate::decompiler::slghsymbol::OperandSymbol;

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    struct MockConstructor {
        location: Location,
        operand: OperandSymbol,
        id: u64,
        exports: Vec<i64>,
    }

    impl Constructor for MockConstructor {
        fn location(&self) -> &Location {
            &self.location
        }
        fn get_operand(&self, _index: i32) -> &OperandSymbol {
            &self.operand
        }
        fn get_operand_sub_value(&self, _index: i32, _replace: &[i64], _listpos: &mut MutableInt) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn parent_id(&self) -> u64 {
            0
        }
        fn id(&self) -> u64 {
            self.id
        }
        fn set_id(&mut self, id: u64) {
            self.id = id;
        }
        fn collect_local_exports(&self, results: &mut Vec<i64>) {
            results.extend_from_slice(&self.exports);
        }
        fn num_operands(&self) -> i32 {
            1
        }
        fn add_operand(&mut self, sym: OperandSymbol) -> i32 {
            self.operand = sym;
            0
        }
        fn add_invisible_operand(&mut self, sym: OperandSymbol) -> i32 {
            self.operand = sym;
            0
        }
        fn get_operand_mut(&mut self, _index: i32) -> &mut OperandSymbol {
            &mut self.operand
        }
        fn set_source_file_index(&mut self, _index: i32) {}
        fn add_equation(&mut self, _pateq: Box<dyn crate::decompiler::slghpatexpress::PatternEquationOps>) {}
        fn remove_trailing_space(&mut self) {}
        fn add_context(&mut self, _contvec: Vec<Box<dyn crate::decompiler::slghsymbol::ContextChange>>) {}
        fn set_main_section(&mut self, _section: Option<crate::program::model::lang::sleigh::template::ConstructTpl>) {}
        fn set_named_section(&mut self, _section: crate::program::model::lang::sleigh::template::ConstructTpl, _index: i32) {}
    }

    fn mock_constructor(exports: Vec<i64>) -> Box<dyn Constructor> {
        Box::new(MockConstructor {
            location: loc(),
            operand: OperandSymbol::with_name(loc(), "op0"),
            id: 999, // Deliberately wrong -- add_constructor must overwrite this.
            exports,
        })
    }

    #[test]
    fn new_has_no_constructors() {
        let sub = SubtableSymbol::new(loc());
        assert_eq!(sub.get_num_constructors(), 0);
    }

    #[test]
    fn with_name_stores_name() {
        let sub = SubtableSymbol::with_name(loc(), "instr");
        assert_eq!(sub.symbol().name(), "instr");
    }

    #[test]
    fn add_constructor_assigns_sequential_ids() {
        let mut sub = SubtableSymbol::new(loc());
        let first = sub.add_constructor(mock_constructor(vec![]));
        let second = sub.add_constructor(mock_constructor(vec![]));
        assert_eq!(first, 0);
        assert_eq!(second, 1);
        assert_eq!(sub.get_constructor(0).id(), 0);
        assert_eq!(sub.get_constructor(1).id(), 1);
    }

    #[test]
    fn get_num_constructors_reflects_additions() {
        let mut sub = SubtableSymbol::new(loc());
        sub.add_constructor(mock_constructor(vec![]));
        sub.add_constructor(mock_constructor(vec![]));
        assert_eq!(sub.get_num_constructors(), 2);
    }

    #[test]
    fn symbol_type_is_subtable_symbol() {
        let sub = SubtableSymbol::new(loc());
        assert_eq!(sub.symbol_type(), SymbolType::SubtableSymbol);
    }

    #[test]
    fn get_size_is_always_negative_one() {
        let sub = SubtableSymbol::new(loc());
        assert_eq!(TripleSymbol::get_size(&sub), -1);
    }

    #[test]
    #[should_panic(expected = "Cannot use subtable in expression")]
    fn get_pattern_expression_panics() {
        let sub = SubtableSymbol::new(loc());
        let _ = TripleSymbol::get_pattern_expression(&sub);
    }

    #[test]
    fn collect_local_values_gathers_across_every_constructor() {
        let mut sub = SubtableSymbol::new(loc());
        sub.add_constructor(mock_constructor(vec![1, 2]));
        sub.add_constructor(mock_constructor(vec![3]));

        let mut results = Vec::new();
        TripleSymbol::collect_local_values(&sub, &mut results);
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[test]
    fn is_being_built_and_is_error_default_to_false() {
        let sub = SubtableSymbol::new(loc());
        assert!(!sub.is_being_built());
        assert!(!sub.is_error());
    }

    #[test]
    fn get_pattern_is_none_before_building() {
        let sub = SubtableSymbol::new(loc());
        assert!(sub.get_pattern().is_none());
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
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
        fn write_bool(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: bool) -> io::Result<()> { Ok(()) }
        fn write_signed_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: i64) -> io::Result<()> { Ok(()) }
        fn write_unsigned_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: u64) -> io::Result<()> { Ok(()) }
        fn write_string(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_string_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_space(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _s: &crate::program::model::address::AddressSpace) -> io::Result<()> { Ok(()) }
        fn write_space_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _n: &str) -> io::Result<()> { Ok(()) }
        fn write_opcode(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> { Ok(()) }
        fn write_opcode_ordinal(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: i32) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn encode_writes_nothing_before_the_decision_tree_is_built() {
        let mut sub = SubtableSymbol::new(loc());
        sub.add_constructor(mock_constructor(vec![]));
        let mut encoder = RecordingEncoder::default();
        sub.encode(&mut encoder).unwrap();
        assert!(encoder.opened.is_empty());
        assert!(encoder.closed.is_empty());
    }

    #[test]
    fn encode_header_writes_header_element() {
        let sub = SubtableSymbol::with_name(loc(), "instr");
        let mut encoder = RecordingEncoder::default();
        sub.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["subtable_sym_head"]);
        assert_eq!(encoder.closed, vec!["subtable_sym_head"]);
    }

    #[test]
    fn seam_trait_name_and_add_constructor_work_through_dyn() {
        let mut sub: Box<dyn crate::decompiler::seam_stubs::SubtableSymbol> =
            Box::new(SubtableSymbol::with_name(loc(), "instr"));
        assert_eq!(sub.name(), "instr");
        let idx = sub.add_constructor(mock_constructor(vec![]));
        assert_eq!(idx, 0);
    }
}
