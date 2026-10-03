//! Models `ghidra.pcodeCPort.slghsymbol.ValueSymbol`.

use std::io;
use std::sync::Arc;

use crate::decompiler::slghsymbol::family_symbol::FamilySymbol;
use crate::decompiler::slghsymbol::sleigh_symbol::SleighSymbol;
use crate::decompiler::slghsymbol::symbol_type::SymbolType;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;
use crate::decompiler::slghpatexpress::{PatternExpression, PatternValue};
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_ID, ELEM_VALUE_SYM, ELEM_VALUE_SYM_HEAD};
use crate::sleigh::grammar::Location;

/// A [`FamilySymbol`] whose family is exactly its single backing pattern value, with no further
/// specialization (unlike [`crate::decompiler::slghsymbol::ContextSymbol`], which additionally
/// carries a bit range, or [`crate::decompiler::slghsymbol::NameSymbol`]/
/// [`crate::decompiler::slghsymbol::ValueMapSymbol`], which additionally carry a lookup table).
///
/// Models `ghidra.pcodeCPort.slghsymbol.ValueSymbol`, which extends `FamilySymbol`. Unlike
/// `FamilySymbol`/`TripleSymbol` (both Java `abstract class`es), `ValueSymbol` is directly
/// instantiable in Java (`SleighCompile` constructs one for a bare `[ ... ]` context/token field
/// definition that isn't further specialized) -- so, in addition to the trait every specialized
/// subtype also implements, this module provides [`ValueSymbolImpl`], the concrete type Java
/// itself would construct.
pub trait ValueSymbol: FamilySymbol {
    /// Returns the symbol type for this value symbol.
    ///
    /// Every specialized subtype (`ContextSymbol`, `NameSymbol`, `ValueMapSymbol`) overrides this
    /// with its own variant on its own trait, the same way Java's `getType()` is overridden by
    /// each of `ValueSymbol`'s own subclasses; this default is only reached by a bare
    /// [`ValueSymbolImpl`].
    fn symbol_type(&self) -> SymbolType {
        SymbolType::ValueSymbol
    }
}

/// Forwards every [`PatternExpression`] method to a shared [`PatternValue`], letting
/// [`ValueSymbolImpl::get_pattern_expression`] return an owned `Box<dyn PatternExpression>` that
/// still refers to the *same* underlying value Java's `getPatternExpression() { return patval; }`
/// would -- `patval` is stored behind an `Arc` precisely so this wrapper can cheaply share it
/// rather than needing to reconstruct an equivalent value from an opaque trait object (which
/// isn't possible in general; `PatternValue` has no generic clone-and-recreate capability).
///
/// `pub(crate)`: every other `ValueSymbol` descendant with the same `Arc<dyn PatternValue>`
/// field (e.g. `VarnodeListSymbol`) has the identical problem, so this is shared rather than
/// re-defined per type.
pub(crate) struct SharedPatternExpression(pub(crate) Arc<dyn PatternValue>);

impl PatternExpression for SharedPatternExpression {
    fn list_values<'a>(&'a self, list: &mut Vec<&'a dyn PatternValue>) {
        self.0.list_values(list);
    }

    fn get_min_max(&self, minlist: &mut VectorStl<i64>, maxlist: &mut VectorStl<i64>) {
        self.0.get_min_max(minlist, maxlist);
    }

    fn get_sub_value(&self, replace: &VectorStl<i64>, listpos: &mut MutableInt) -> i64 {
        PatternExpression::get_sub_value(self.0.as_ref(), replace, listpos)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.0.encode(encoder)
    }
}

/// The concrete `ValueSymbol`: a plain, unspecialized value symbol.
///
/// Models the real (non-abstract) `ghidra.pcodeCPort.slghsymbol.ValueSymbol` class.
pub struct ValueSymbolImpl {
    header: SleighSymbol,
    patval: Option<Arc<dyn PatternValue>>,
}

impl ValueSymbolImpl {
    /// An unresolved value symbol with no backing pattern value yet (Java's
    /// `ValueSymbol(Location location)`).
    pub fn new(location: Location) -> Self {
        Self {
            header: SleighSymbol::new(location),
            patval: None,
        }
    }

    /// A value symbol backed by `pv` (Java's `ValueSymbol(Location location, String nm,
    /// PatternValue pv)`; `layClaim()` has no Rust equivalent -- ownership is tracked by the
    /// `Arc` instead).
    pub fn with_pattern_value(location: Location, name: impl Into<String>, pv: Arc<dyn PatternValue>) -> Self {
        Self {
            header: SleighSymbol::with_name(location, name),
            patval: Some(pv),
        }
    }

    /// Gets the base SleighSymbol (name/id/scope shared by every symbol kind).
    pub fn symbol(&self) -> &SleighSymbol {
        &self.header
    }

    /// Encodes this value symbol to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_VALUE_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.header.id() as u64)?;
        if let Some(patval) = &self.patval {
            patval.encode(encoder)?;
        }
        encoder.close_element(ELEM_VALUE_SYM)?;
        Ok(())
    }

    /// Encodes just the shared symbol header for this value symbol.
    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_VALUE_SYM_HEAD)?;
        self.header.encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_VALUE_SYM_HEAD)?;
        Ok(())
    }
}

impl TripleSymbol for ValueSymbolImpl {
    fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
        let patval = self
            .patval
            .clone()
            .expect("ValueSymbolImpl::get_pattern_expression called before a pattern value was set");
        Box::new(SharedPatternExpression(patval))
    }
}

impl FamilySymbol for ValueSymbolImpl {
    fn get_pattern_value(&self) -> &dyn PatternValue {
        self.patval
            .as_deref()
            .expect("ValueSymbolImpl::get_pattern_value called before a pattern value was set")
    }
}

impl ValueSymbol for ValueSymbolImpl {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::TokenPattern;

    struct MockTokenPattern;
    impl TokenPattern for MockTokenPattern {
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
        fn copy_into(&mut self, _tokpat: &dyn TokenPattern) {}
        fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> { Box::new(MockTokenPattern) }
        fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> { Box::new(MockTokenPattern) }
        fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> { Box::new(MockTokenPattern) }
        fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> { Box::new(MockTokenPattern) }
    }

    struct FixedValue {
        min: i64,
        max: i64,
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
        fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
            encoder.open_element(crate::program::model::pcode::ids::ELEM_INTB)?;
            encoder.write_signed_integer(crate::program::model::pcode::ids::ATTRIB_VAL, self.min)?;
            encoder.close_element(crate::program::model::pcode::ids::ELEM_INTB)?;
            Ok(())
        }
    }

    impl PatternValue for FixedValue {
        fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern)
        }
        fn min_value(&self) -> i64 {
            self.min
        }
        fn max_value(&self) -> i64 {
            self.max
        }
    }

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    #[test]
    fn new_has_no_pattern_value() {
        let sym = ValueSymbolImpl::new(loc());
        assert!(sym.patval.is_none());
    }

    #[test]
    fn with_pattern_value_stores_name_and_value() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 2, max: 9 });
        let sym = ValueSymbolImpl::with_pattern_value(loc(), "ctx1", pv);
        assert_eq!(sym.symbol().name(), "ctx1");
        assert_eq!(FamilySymbol::get_pattern_value(&sym).min_value(), 2);
        assert_eq!(FamilySymbol::get_pattern_value(&sym).max_value(), 9);
    }

    #[test]
    fn get_pattern_expression_shares_the_same_underlying_value() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 1, max: 4 });
        let sym = ValueSymbolImpl::with_pattern_value(loc(), "ctx1", pv);

        let expr = TripleSymbol::get_pattern_expression(&sym);
        let mut min = VectorStl::new();
        let mut max = VectorStl::new();
        expr.get_min_max(&mut min, &mut max);
        assert_eq!(*min.get(0), 1);
        assert_eq!(*max.get(0), 4);
    }

    #[test]
    fn symbol_type_defaults_to_value_symbol() {
        let sym = ValueSymbolImpl::new(loc());
        assert_eq!(ValueSymbol::symbol_type(&sym), SymbolType::ValueSymbol);
    }

    #[test]
    fn get_size_and_collect_local_values_use_triple_symbol_defaults() {
        let sym = ValueSymbolImpl::new(loc());
        assert_eq!(sym.get_size(), 0);
        let mut results = Vec::new();
        sym.collect_local_values(&mut results);
        assert!(results.is_empty());
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        uints: Vec<u64>,
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
        fn write_unsigned_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, v: u64) -> io::Result<()> {
            self.uints.push(v);
            Ok(())
        }
        fn write_string(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_string_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_space(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _s: &crate::program::model::address::AddressSpace) -> io::Result<()> { Ok(()) }
        fn write_space_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _n: &str) -> io::Result<()> { Ok(()) }
        fn write_opcode(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> { Ok(()) }
        fn write_opcode_ordinal(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: i32) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn encode_writes_element_id_and_pattern_value() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 5, max: 5 });
        let sym = ValueSymbolImpl::with_pattern_value(loc(), "ctx1", pv);
        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["value_sym", "intb"]);
        assert_eq!(encoder.closed, vec!["intb", "value_sym"]);
        assert_eq!(encoder.uints, vec![sym.symbol().id() as u64]);
    }

    #[test]
    fn encode_header_writes_header_element() {
        let sym = ValueSymbolImpl::new(loc());
        let mut encoder = RecordingEncoder::default();
        sym.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["value_sym_head"]);
        assert_eq!(encoder.closed, vec!["value_sym_head"]);
    }
}
