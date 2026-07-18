//! Models `ghidra.pcodeCPort.slghpatexpress.OperandValue`.

use crate::decompiler::context::SleighError;
use crate::decompiler::seam_stubs::Constructor;
use crate::decompiler::slghpatexpress::TokenPattern;
use crate::decompiler::utils::MutableInt;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_CT, ATTRIB_INDEX, ATTRIB_TABLE, ELEM_OPERAND_EXP};
use crate::sleigh::grammar::Location;
use std::io;

/// A reference, by index, to one of the operands of the constructor that defines it.
///
/// An operand cannot itself be interpreted as a static constraint in a pattern equation: if it
/// is being defined by the equation, it should appear only on the left-hand side. Consequently
/// [`OperandValue::gen_pattern`], [`OperandValue::min_value`], and [`OperandValue::max_value`]
/// always panic when reached, mirroring the Java `SleighError` this class throws instead.
///
/// Models `ghidra.pcodeCPort.slghpatexpress.OperandValue`.
pub struct OperandValue {
    location: Location,
    index: i32,
    ct: Option<Box<dyn Constructor>>,
}

impl OperandValue {
    /// Creates a new, unresolved operand value at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            location,
            index: 0,
            ct: None,
        }
    }

    /// Creates a new operand value referring to operand `index` of constructor `ct`.
    pub fn with_operand(location: Location, index: i32, ct: Box<dyn Constructor>) -> Self {
        Self {
            location,
            index,
            ct: Some(ct),
        }
    }

    /// Changes which operand of the constructor this value refers to.
    pub fn change_index(&mut self, newind: i32) {
        self.index = newind;
    }

    /// Generates the minimal token pattern for this operand, taken directly from `ops[index]`.
    /// Returns `None` if `index` is out of bounds, mirroring the Java `null` return.
    pub fn gen_min_pattern<'a>(&self, ops: &'a [Box<dyn TokenPattern>]) -> Option<&'a dyn TokenPattern> {
        ops.get(self.index as usize).map(|pat| pat.as_ref())
    }

    /// Whether this operand's offset is relative to the start of its constructor, rather than a
    /// fixed absolute offset (`getOffsetBase() == -1`).
    pub fn is_constructor_relative(&self) -> bool {
        let ct = self.resolved_constructor();
        ct.get_operand(self.index).offsetbase == -1
    }

    /// The name of the operand this value refers to.
    pub fn get_name(&self) -> &str {
        let ct = self.resolved_constructor();
        ct.get_operand(self.index).symbol().name()
    }

    /// Encodes this operand value to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_OPERAND_EXP)?;
        encoder.write_signed_integer(ATTRIB_INDEX, self.index as i64)?;
        let table_id = self.ct.as_deref().map(Constructor::parent_id).unwrap_or(0);
        encoder.write_unsigned_integer(ATTRIB_TABLE, table_id)?;
        let ct_id = self.ct.as_deref().map(Constructor::id).unwrap_or(0);
        encoder.write_unsigned_integer(ATTRIB_CT, ct_id)?;
        encoder.close_element(ELEM_OPERAND_EXP)?;
        Ok(())
    }

    /// The constructor this operand value refers to, panicking as Java's `ct.foo()` chains would
    /// NPE if `ct` were never resolved.
    fn resolved_constructor(&self) -> &dyn Constructor {
        self.ct
            .as_deref()
            .expect("OperandValue used before its constructor was resolved")
    }

    /// Builds the `SleighError` Java raises for `gen_pattern`/`min_value`/`max_value`, using the
    /// constructor's location when resolved (matching Java's `ct.location`) and falling back to
    /// this value's own location otherwise.
    fn operand_used_in_pattern_error(&self) -> SleighError {
        let location = self
            .ct
            .as_deref()
            .map(|ct| ct.location().clone())
            .unwrap_or_else(|| self.location.clone());
        SleighError::new("Operand used in pattern expression", location)
    }
}

impl crate::decompiler::seam_stubs::PatternExpression for OperandValue {}

impl crate::decompiler::slghpatexpress::PatternValue for OperandValue {
    fn gen_pattern(&self, _val: i64) -> Box<dyn TokenPattern> {
        panic!("{}", self.operand_used_in_pattern_error());
    }

    fn min_value(&self) -> i64 {
        panic!("{}", self.operand_used_in_pattern_error());
    }

    fn max_value(&self) -> i64 {
        panic!("{}", self.operand_used_in_pattern_error());
    }

    fn get_sub_value(&self, replace: &[i64], listpos: &mut MutableInt) -> i64 {
        let ct = self.resolved_constructor();
        ct.get_operand_sub_value(self.index, replace, listpos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::PatternValue;
    use crate::decompiler::slghsymbol::OperandSymbol;

    struct MockConstructor {
        location: Location,
        operand: OperandSymbol,
        parent_id: u64,
        id: u64,
        sub_value: i64,
    }

    impl Constructor for MockConstructor {
        fn location(&self) -> &Location {
            &self.location
        }

        fn get_operand(&self, _index: i32) -> &OperandSymbol {
            &self.operand
        }

        fn get_operand_sub_value(
            &self,
            _index: i32,
            _replace: &[i64],
            listpos: &mut MutableInt,
        ) -> i64 {
            listpos.increment();
            self.sub_value
        }

        fn parent_id(&self) -> u64 {
            self.parent_id
        }

        fn id(&self) -> u64 {
            self.id
        }
    }

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    struct TestTokenPattern {
        location: Location,
    }

    impl TokenPattern for TestTokenPattern {
        fn location(&self) -> &Location {
            &self.location
        }

        fn get_pattern(&self) -> &dyn crate::decompiler::seam_stubs::Pattern {
            struct EmptyPattern;
            impl crate::decompiler::seam_stubs::Pattern for EmptyPattern {}
            &EmptyPattern
        }

        fn always_true(&self) -> bool {
            false
        }

        fn always_false(&self) -> bool {
            false
        }

        fn always_instruction_true(&self) -> bool {
            false
        }

        fn get_left_ellipsis(&self) -> bool {
            false
        }

        fn get_right_ellipsis(&self) -> bool {
            false
        }

        fn set_left_ellipsis(&mut self, _val: bool) {}

        fn set_right_ellipsis(&mut self, _val: bool) {}

        fn get_minimum_length(&self) -> i32 {
            0
        }

        fn simplify_pattern(&mut self) {}

        fn copy_into(&mut self, _tokpat: &dyn TokenPattern) {}

        fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern {
                location: self.location.clone(),
            })
        }

        fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern {
                location: self.location.clone(),
            })
        }

        fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern {
                location: self.location.clone(),
            })
        }

        fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(TestTokenPattern {
                location: self.location.clone(),
            })
        }
    }

    #[derive(Default)]
    struct TestEncoder {
        opened: usize,
        closed: usize,
        signed_ints: Vec<i64>,
        unsigned_ints: Vec<u64>,
    }

    impl Encoder for TestEncoder {
        fn open_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.opened += 1;
            Ok(())
        }

        fn close_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.closed += 1;
            Ok(())
        }

        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_signed_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.signed_ints.push(val);
            Ok(())
        }

        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: u64,
        ) -> io::Result<()> {
            self.unsigned_ints.push(val);
            Ok(())
        }

        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    fn mock_constructor(operand: OperandSymbol) -> Box<dyn Constructor> {
        Box::new(MockConstructor {
            location: Location::new("ctor.sleigh", 5),
            operand,
            parent_id: 7,
            id: 42,
            sub_value: 99,
        })
    }

    #[test]
    fn new_initializes_index_zero_and_no_constructor() {
        let value = OperandValue::new(loc());
        assert_eq!(value.index, 0);
        assert!(value.ct.is_none());
    }

    #[test]
    fn with_operand_stores_index_and_constructor() {
        let operand = OperandSymbol::with_name(loc(), "op0");
        let value = OperandValue::with_operand(loc(), 2, mock_constructor(operand));
        assert_eq!(value.index, 2);
        assert!(value.ct.is_some());
    }

    #[test]
    fn change_index_updates_index() {
        let mut value = OperandValue::new(loc());
        value.change_index(3);
        assert_eq!(value.index, 3);
    }

    #[test]
    fn gen_min_pattern_returns_operand_at_index() {
        let mut value = OperandValue::new(loc());
        value.change_index(1);
        let ops: Vec<Box<dyn TokenPattern>> = vec![
            Box::new(TestTokenPattern {
                location: Location::new("a.sleigh", 1),
            }),
            Box::new(TestTokenPattern {
                location: Location::new("b.sleigh", 2),
            }),
        ];
        let pattern = value.gen_min_pattern(&ops).unwrap();
        assert_eq!(pattern.location(), &Location::new("b.sleigh", 2));
    }

    #[test]
    fn gen_min_pattern_returns_none_when_out_of_bounds() {
        let mut value = OperandValue::new(loc());
        value.change_index(5);
        let ops: Vec<Box<dyn TokenPattern>> = vec![Box::new(TestTokenPattern {
            location: Location::new("a.sleigh", 1),
        })];
        assert!(value.gen_min_pattern(&ops).is_none());
    }

    #[test]
    #[should_panic(expected = "Operand used in pattern expression")]
    fn gen_pattern_panics() {
        let value = OperandValue::new(loc());
        let _ = value.gen_pattern(0);
    }

    #[test]
    #[should_panic(expected = "Operand used in pattern expression")]
    fn min_value_panics() {
        let value = OperandValue::new(loc());
        let _ = value.min_value();
    }

    #[test]
    #[should_panic(expected = "Operand used in pattern expression")]
    fn max_value_panics() {
        let value = OperandValue::new(loc());
        let _ = value.max_value();
    }

    #[test]
    fn get_sub_value_delegates_to_constructor() {
        let operand = OperandSymbol::with_name(loc(), "op0");
        let value = OperandValue::with_operand(loc(), 0, mock_constructor(operand));
        let replace = vec![1, 2, 3];
        let mut listpos = MutableInt::new(0);
        let result = value.get_sub_value(&replace, &mut listpos);
        assert_eq!(result, 99);
        assert_eq!(listpos.get(), 1);
    }

    #[test]
    fn is_constructor_relative_true_when_offset_base_negative_one() {
        let mut operand = OperandSymbol::with_name(loc(), "op0");
        operand.offsetbase = -1;
        let value = OperandValue::with_operand(loc(), 0, mock_constructor(operand));
        assert!(value.is_constructor_relative());
    }

    #[test]
    fn is_constructor_relative_false_when_offset_base_nonnegative() {
        let mut operand = OperandSymbol::with_name(loc(), "op0");
        operand.offsetbase = 3;
        let value = OperandValue::with_operand(loc(), 0, mock_constructor(operand));
        assert!(!value.is_constructor_relative());
    }

    #[test]
    fn get_name_returns_operand_name() {
        let operand = OperandSymbol::with_name(loc(), "rs1");
        let value = OperandValue::with_operand(loc(), 0, mock_constructor(operand));
        assert_eq!(value.get_name(), "rs1");
    }

    #[test]
    fn encode_writes_index_table_and_ct_with_constructor() {
        let operand = OperandSymbol::with_name(loc(), "op0");
        let mut value = OperandValue::with_operand(loc(), 4, mock_constructor(operand));
        value.change_index(4);
        let mut encoder = TestEncoder::default();

        value.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, 1);
        assert_eq!(encoder.closed, 1);
        assert_eq!(encoder.signed_ints, vec![4]);
        assert_eq!(encoder.unsigned_ints, vec![7, 42]);
    }

    #[test]
    fn encode_writes_zero_table_and_ct_without_constructor() {
        let value = OperandValue::new(loc());
        let mut encoder = TestEncoder::default();

        value.encode(&mut encoder).unwrap();

        assert_eq!(encoder.signed_ints, vec![0]);
        assert_eq!(encoder.unsigned_ints, vec![0, 0]);
    }

    #[test]
    #[should_panic(expected = "OperandValue used before its constructor was resolved")]
    fn is_constructor_relative_panics_without_constructor() {
        let value = OperandValue::new(loc());
        let _ = value.is_constructor_relative();
    }
}
