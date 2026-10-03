//! Models `ghidra.pcodeCPort.slghsymbol.VarnodeListSymbol`.

use std::io;
use std::sync::Arc;

use crate::decompiler::context::SleighError;
use crate::decompiler::slghpatexpress::{PatternExpression, PatternValue};
use crate::decompiler::slghsymbol::family_symbol::FamilySymbol;
use crate::decompiler::slghsymbol::sleigh_symbol::SleighSymbol;
use crate::decompiler::slghsymbol::symbol_type::SymbolType;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;
use crate::decompiler::slghsymbol::value_symbol::{SharedPatternExpression, ValueSymbol};
use crate::decompiler::slghsymbol::varnode_symbol::VarnodeSymbol;
use crate::program::model::pcode::ids::{ATTRIB_ID, ELEM_NULL, ELEM_VARLIST_SYM, ELEM_VARLIST_SYM_HEAD, ELEM_VAR};
use crate::program::model::pcode::Encoder;
use crate::sleigh::grammar::Location;

/// A [`ValueSymbol`] backed by a lookup table of [`VarnodeSymbol`]s, one per possible pattern
/// value (e.g. a register-select field like a RISC `rs1`/`rs2` operand, where each numeric
/// encoding names a different physical register).
///
/// Models `ghidra.pcodeCPort.slghsymbol.VarnodeListSymbol`, which extends `ValueSymbol`.
pub struct VarnodeListSymbol {
    header: SleighSymbol,
    patval: Option<Arc<dyn PatternValue>>,
    varnode_table: Vec<Option<VarnodeSymbol>>,
    tableisfilled: bool,
}

impl VarnodeListSymbol {
    /// An unresolved varnode-list symbol (Java's `VarnodeListSymbol(Location location)`).
    pub fn new(location: Location) -> Self {
        Self {
            header: SleighSymbol::new(location),
            patval: None,
            varnode_table: Vec::new(),
            tableisfilled: false,
        }
    }

    /// A varnode-list symbol backed by `pv`, with `vt[i]` naming the varnode for pattern value
    /// `i` (`None` entries are gaps in the table -- Java's `VarnodeListSymbol(Location location,
    /// String nm, PatternValue pv, VectorSTL<SleighSymbol> vt)`, whose entries are always
    /// actually `VarnodeSymbol` despite the declared `SleighSymbol` element type).
    pub fn with_table(
        location: Location,
        name: impl Into<String>,
        pv: Arc<dyn PatternValue>,
        vt: Vec<Option<VarnodeSymbol>>,
    ) -> Self {
        let mut sym = Self {
            header: SleighSymbol::with_name(location, name),
            patval: Some(pv),
            varnode_table: vt,
            tableisfilled: false,
        };
        sym.check_table_fill();
        sym
    }

    /// Recomputes [`VarnodeListSymbol::table_is_filled`]: true when the pattern value's whole
    /// range `[min_value, max_value]` maps into `varnode_table` with no gaps (Java's private
    /// `checkTableFill`).
    fn check_table_fill(&mut self) {
        let patval = self.patval.as_ref().expect("VarnodeListSymbol::check_table_fill requires a pattern value");
        let min = patval.min_value();
        let max = patval.max_value();
        self.tableisfilled = min >= 0 && (max as usize) < self.varnode_table.len();
        if self.varnode_table.iter().any(|v| v.is_none()) {
            self.tableisfilled = false;
        }
    }

    /// Whether every value in the pattern value's range names a varnode with no gaps (Java's
    /// `tableisfilled` field, exposed here as it has no Java getter of its own but several
    /// sibling ports in this crate expose their analogous "is this table complete" state as a
    /// method).
    pub fn table_is_filled(&self) -> bool {
        self.tableisfilled
    }

    pub fn symbol(&self) -> &SleighSymbol {
        &self.header
    }

    pub fn varnode_table(&self) -> &[Option<VarnodeSymbol>] {
        &self.varnode_table
    }

    /// The size shared by every varnode in the table (Java's `getSize`, which assumes all
    /// entries are the same size and returns the first non-null one's).
    ///
    /// # Panics
    /// Panics with a [`SleighError`] if every entry is `None`, matching Java's own
    /// `throw new SleighError("No register attached to: " + getName(), getLocation())`.
    pub fn get_size(&self) -> i32 {
        for vnsym in self.varnode_table.iter().flatten() {
            return vnsym.get_size();
        }
        panic!(
            "{}",
            SleighError::new(
                format!("No register attached to: {}", self.header.name()),
                self.header.location().clone(),
            )
        )
    }

    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        let patval = self.patval.as_ref().expect("VarnodeListSymbol::encode requires a pattern value");
        encoder.open_element(ELEM_VARLIST_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.header.id() as u64)?;
        PatternExpression::encode(patval.as_ref(), encoder)?;
        for entry in &self.varnode_table {
            match entry {
                None => {
                    encoder.open_element(ELEM_NULL)?;
                    encoder.close_element(ELEM_NULL)?;
                }
                Some(vnsym) => {
                    encoder.open_element(ELEM_VAR)?;
                    encoder.write_unsigned_integer(ATTRIB_ID, vnsym.symbol().id() as u64)?;
                    encoder.close_element(ELEM_VAR)?;
                }
            }
        }
        encoder.close_element(ELEM_VARLIST_SYM)
    }

    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_VARLIST_SYM_HEAD)?;
        self.header.encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_VARLIST_SYM_HEAD)
    }
}

impl TripleSymbol for VarnodeListSymbol {
    fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
        let patval = self
            .patval
            .clone()
            .expect("VarnodeListSymbol::get_pattern_expression called before a pattern value was set");
        Box::new(SharedPatternExpression(patval))
    }

    fn get_size(&self) -> i32 {
        VarnodeListSymbol::get_size(self)
    }
}

impl FamilySymbol for VarnodeListSymbol {
    fn get_pattern_value(&self) -> &dyn PatternValue {
        self.patval
            .as_deref()
            .expect("VarnodeListSymbol::get_pattern_value called before a pattern value was set")
    }
}

impl ValueSymbol for VarnodeListSymbol {
    fn symbol_type(&self) -> SymbolType {
        SymbolType::VarnodelistSymbol
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::TokenPattern;
    use crate::generic::stl::vector_stl::VectorStl;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

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
        fn get_sub_value(&self, replace: &VectorStl<i64>, listpos: &mut crate::decompiler::utils::MutableInt) -> i64 {
            let res = *replace.get(listpos.get() as usize);
            listpos.increment();
            res
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
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

    fn reg_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn reg(name: &str, offset: u64) -> Option<VarnodeSymbol> {
        Some(VarnodeSymbol::with_fixed(loc(), name, reg_space(), offset, 4))
    }

    #[test]
    fn new_has_no_table() {
        let sym = VarnodeListSymbol::new(loc());
        assert!(sym.varnode_table().is_empty());
        assert!(!sym.table_is_filled());
    }

    #[test]
    fn with_table_stores_entries() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 0, max: 1 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![reg("r0", 0), reg("r1", 4)]);
        assert_eq!(sym.varnode_table().len(), 2);
    }

    #[test]
    fn table_is_filled_true_when_every_value_has_an_entry_and_range_matches() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 0, max: 1 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![reg("r0", 0), reg("r1", 4)]);
        assert!(sym.table_is_filled());
    }

    #[test]
    fn table_is_filled_false_when_an_entry_is_missing() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 0, max: 1 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![reg("r0", 0), None]);
        assert!(!sym.table_is_filled());
    }

    #[test]
    fn table_is_filled_false_when_min_value_is_negative() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: -1, max: 1 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![reg("r0", 0), reg("r1", 4)]);
        assert!(!sym.table_is_filled());
    }

    #[test]
    fn table_is_filled_false_when_max_value_reaches_beyond_table() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 0, max: 2 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![reg("r0", 0), reg("r1", 4)]);
        assert!(!sym.table_is_filled());
    }

    #[test]
    fn get_size_returns_first_non_null_entrys_size() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 0, max: 1 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![None, reg("r1", 4)]);
        assert_eq!(VarnodeListSymbol::get_size(&sym), 4);
    }

    #[test]
    #[should_panic(expected = "No register attached to")]
    fn get_size_panics_when_every_entry_is_none() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 0, max: 1 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![None, None]);
        VarnodeListSymbol::get_size(&sym);
    }

    #[test]
    fn symbol_type_is_varnodelist_symbol() {
        let sym = VarnodeListSymbol::new(loc());
        assert_eq!(ValueSymbol::symbol_type(&sym), SymbolType::VarnodelistSymbol);
    }

    #[test]
    fn get_pattern_value_exposes_backing_value() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 2, max: 9 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![]);
        let value = FamilySymbol::get_pattern_value(&sym);
        assert_eq!(value.min_value(), 2);
        assert_eq!(value.max_value(), 9);
    }

    #[test]
    fn get_pattern_expression_shares_the_same_underlying_value() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 1, max: 4 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![]);
        let expr = TripleSymbol::get_pattern_expression(&sym);
        let mut min = VectorStl::new();
        let mut max = VectorStl::new();
        expr.get_min_max(&mut min, &mut max);
        assert_eq!(*min.get(0), 1);
        assert_eq!(*max.get(0), 4);
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
    fn encode_writes_var_and_null_elements_matching_table_entries() {
        let pv: Arc<dyn PatternValue> = Arc::new(FixedValue { min: 0, max: 1 });
        let sym = VarnodeListSymbol::with_table(loc(), "regs", pv, vec![reg("r0", 0), None]);
        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened.first(), Some(&"varlist_sym"));
        assert_eq!(encoder.closed.last(), Some(&"varlist_sym"));
        assert!(encoder.opened.contains(&"var"));
        assert!(encoder.opened.contains(&"null"));
    }

    #[test]
    fn encode_header_writes_header_element() {
        let sym = VarnodeListSymbol::new(loc());
        let mut encoder = RecordingEncoder::default();
        sym.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["varlist_sym_head"]);
        assert_eq!(encoder.closed, vec!["varlist_sym_head"]);
    }
}
