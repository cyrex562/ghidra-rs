//! Models `ghidra.pcodeCPort.slghsymbol.Constructor`.

use std::io;

use crate::decompiler::context::SleighError;
use crate::decompiler::slghpatexpress::PatternEquationOps;
use crate::decompiler::slghpatexpress::TokenPattern;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;
use crate::decompiler::slghsymbol::{ContextChange, OperandSymbol};
use crate::decompiler::utils::MutableInt;
use crate::generic::stl::vector_stl::VectorStl;
use crate::program::model::address::AddressSpaceType;
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::pcode::ids::{
    ATTRIB_FIRST, ATTRIB_ID, ATTRIB_LENGTH, ATTRIB_LINE, ATTRIB_PARENT, ATTRIB_PIECE,
    ATTRIB_SOURCE, ELEM_CONSTRUCTOR, ELEM_OPER, ELEM_OPPRINT, ELEM_PRINT,
};
use crate::program::model::pcode::Encoder;
use crate::sleigh::grammar::Location;

/// One printing/pattern/semantics rule for a SLEIGH subtable: the constructor's match pattern
/// (built later by [`Constructor::order_operands`] and the not-yet-ported `buildPattern`), its
/// operand list, its literal print pieces, its context changes, and its p-code template(s).
///
/// Models `ghidra.pcodeCPort.slghsymbol.Constructor`. `parent`, a direct `SubtableSymbol`
/// reference in Java, is tracked here as [`Constructor::parent_id`] instead
/// (`Option<u64>`) -- `SubtableSymbol` owns its constructors directly (`construct:
/// Vec<Constructor>`), and a Constructor holding a live reference back to the SAME
/// SubtableSymbol that owns it would need an ownership cycle Rust doesn't support the way
/// Java's shared GC references do; every real use of `parent` (`encode`'s `ATTRIB_PARENT`,
/// `isRecursive`'s identity check) only ever needs the id, not live `SubtableSymbol` behavior.
///
/// `buildPattern` (Java's private `TokenPattern buildPattern(PrintStream s)`) is NOT ported:
/// it needs `PatternExpression::gen_min_pattern` unified onto the `PatternExpression` trait
/// (deliberately deferred when `PatternExpression` was promoted -- see that type's own doc
/// comment) and mutual recursion with `SubtableSymbol::build_pattern`/`is_being_built`, which in
/// turn needs `DecisionNode`/`DecisionProperties`-driven decision-tree construction, a separate,
/// substantially larger subsystem of its own (`ghidra.pcodeCPort.slghsymbol.DecisionNode`, not
/// yet ported). `markSubtableOperands` is also not ported for the same underlying reason: it
/// needs to distinguish "this operand's defining symbol is specifically a `SubtableSymbol`" at
/// runtime, which (like the `SpecificSymbol`/zero-size-family-symbol distinction
/// `OperandSymbol::get_varnode` needed) has no direct Rust equivalent without either an `Any`
/// downcast (which only works for a concrete type, not "implements trait X") or the caller
/// choosing at definition time (this crate's approach elsewhere) -- and its only caller in Java
/// is `DecisionNode`'s own construction, so there's no current caller to make that choice yet
/// either.
pub struct Constructor {
    location: Location,
    pattern: Option<Box<dyn TokenPattern>>,
    parent_id: Option<u64>,
    pateq: Option<Box<dyn PatternEquationOps>>,
    operands: Vec<OperandSymbol>,
    printpiece: Vec<String>,
    context: Vec<Box<dyn ContextChange>>,
    templ: Option<ConstructTpl>,
    namedtempl: Vec<Option<ConstructTpl>>,
    minimumlength: i32,
    id: u64,
    firstwhitespace: i32,
    inerror: bool,
    source_file_index: i32,
}

impl Constructor {
    /// A parentless constructor (Java's `Constructor(Location location)`).
    pub fn new(location: Location) -> Self {
        Self {
            location,
            pattern: None,
            parent_id: None,
            pateq: None,
            operands: Vec::new(),
            printpiece: Vec::new(),
            context: Vec::new(),
            templ: None,
            namedtempl: Vec::new(),
            minimumlength: 0,
            id: 0,
            firstwhitespace: -1,
            inerror: false,
            source_file_index: -1,
        }
    }

    /// A constructor belonging to the subtable with id `parent_id` (Java's `Constructor(Location
    /// location, SubtableSymbol p)`).
    pub fn with_parent(location: Location, parent_id: u64) -> Self {
        let mut ct = Self::new(location);
        ct.parent_id = Some(parent_id);
        ct
    }

    pub fn get_pattern(&self) -> Option<&dyn TokenPattern> {
        self.pattern.as_deref()
    }

    pub fn get_filename(&self) -> &str {
        &self.location.filename
    }

    pub fn set_minimum_length(&mut self, l: i32) {
        self.minimumlength = l;
    }

    pub fn get_minimum_length(&self) -> i32 {
        self.minimumlength
    }

    pub fn set_id(&mut self, i: u64) {
        self.id = i;
    }

    pub fn get_id(&self) -> u64 {
        self.id
    }

    pub fn get_lineno(&self) -> i32 {
        self.location.lineno
    }

    pub fn set_source_file_index(&mut self, index: i32) {
        self.source_file_index = index;
    }

    pub fn get_index(&self) -> i32 {
        self.source_file_index
    }

    pub fn add_context(&mut self, vec: Vec<Box<dyn ContextChange>>) {
        self.context = vec;
    }

    pub fn get_parent_id(&self) -> Option<u64> {
        self.parent_id
    }

    pub fn get_num_operands(&self) -> i32 {
        self.operands.len() as i32
    }

    pub fn get_operand(&self, i: i32) -> &OperandSymbol {
        &self.operands[i as usize]
    }

    pub fn get_operand_mut(&mut self, i: i32) -> &mut OperandSymbol {
        &mut self.operands[i as usize]
    }

    pub fn get_pattern_equation(&self) -> Option<&dyn PatternEquationOps> {
        self.pateq.as_deref()
    }

    pub fn get_templ(&self) -> Option<&ConstructTpl> {
        self.templ.as_ref()
    }

    pub fn get_named_templ(&self, secnum: usize) -> Option<&ConstructTpl> {
        self.namedtempl.get(secnum).and_then(|t| t.as_ref())
    }

    pub fn get_num_sections(&self) -> i32 {
        self.namedtempl.len() as i32
    }

    /// Collects every locally-exported value across this constructor's p-code result handle
    /// (Java's `collectLocalExports`).
    pub fn collect_local_exports(&self, results: &mut Vec<i64>) {
        use crate::program::model::lang::sleigh::template::ConstTplType;

        let Some(templ) = &self.templ else { return };
        let Some(handle) = &templ.result else { return };

        if handle.space.tp == ConstTplType::SpaceId {
            let is_const = handle
                .space
                .value_spaceid
                .as_ref()
                .map(|s| s.space_type() == AddressSpaceType::Constant)
                .unwrap_or(false);
            if is_const {
                return; // Even if the value is dynamic, the pointed-to value won't get used
            }
        }
        if handle.ptrspace.tp != ConstTplType::Real {
            let is_unique = handle
                .temp_space
                .value_spaceid
                .as_ref()
                .map(|s| s.space_type() == AddressSpaceType::Unique)
                .unwrap_or(false);
            if is_unique {
                results.push(handle.temp_offset.value_real as i64);
            }
            return;
        }
        let is_unique_space = handle
            .space
            .value_spaceid
            .as_ref()
            .map(|s| s.space_type() == AddressSpaceType::Unique)
            .unwrap_or(false);
        if is_unique_space {
            results.push(handle.ptroffset.value_real as i64);
            return;
        }
        if handle.space.tp == ConstTplType::Handle {
            let handle_index = handle.space.handle_index as i32;
            if let Some(op_sym) = self.operands.get(handle_index as usize) {
                op_sym.collect_local_values(results);
            }
        }
    }

    pub fn set_error(&mut self, val: bool) {
        self.inerror = val;
    }

    pub fn is_error(&self) -> bool {
        self.inerror
    }

    /// Whether any operand's defining symbol is this constructor's own parent subtable (Java's
    /// `isRecursive`, comparing object identity; here, comparing ids since operands track their
    /// defining symbol's id directly -- see [`crate::decompiler::slghsymbol::OperandSymbol`]).
    pub fn is_recursive(&self) -> bool {
        let Some(parent_id) = self.parent_id else { return false };
        self.operands
            .iter()
            .any(|op| op.defining_symbol_id() == Some(parent_id))
    }

    pub fn add_invisible_operand(&mut self, sym: OperandSymbol) {
        self.operands.push(sym);
    }

    pub fn add_operand(&mut self, sym: OperandSymbol) {
        let operstring = format!("\n{}", (b'A' + self.operands.len() as u8) as char);
        self.operands.push(sym);
        self.printpiece.push(operstring);
    }

    /// Appends a piece of literal print syntax, collapsing runs of whitespace to a single space
    /// and merging adjacent non-whitespace, non-operand-placeholder pieces (Java's `addSyntax`).
    pub fn add_syntax(&mut self, syn: &str) {
        let syn = if !syn.is_empty() && syn.trim().is_empty() {
            " ".to_string()
        } else {
            syn.to_string()
        };
        if self.firstwhitespace == -1 && syn == " " {
            self.firstwhitespace = self.printpiece.len() as i32;
        }
        if syn.is_empty() {
            return;
        }
        match self.printpiece.last() {
            None => self.printpiece.push(syn),
            Some(back) if back == " " && syn == " " => {
                // Don't add more whitespace.
            }
            Some(back) if back.starts_with('\n') || back == " " || syn == " " => {
                self.printpiece.push(syn);
            }
            Some(_) => {
                let back = self.printpiece.pop().unwrap();
                let mut push = back;
                push.push_str(&syn);
                if push.is_empty() {
                    push = " ".to_string();
                }
                self.printpiece.push(push);
            }
        }
    }

    pub fn add_equation(&mut self, pe: Box<dyn PatternEquationOps>) {
        self.pateq = Some(pe);
    }

    pub fn set_main_section(&mut self, tpl: ConstructTpl) {
        self.templ = Some(tpl);
    }

    pub fn set_named_section(&mut self, tpl: ConstructTpl, id: usize) {
        while self.namedtempl.len() <= id {
            self.namedtempl.push(None);
        }
        self.namedtempl[id] = Some(tpl);
    }

    /// Strips a single trailing whitespace placeholder from the print pieces, if present (Java's
    /// `removeTrailingSpace`, allowing a user to force extra space at the end of printing).
    pub fn remove_trailing_space(&mut self) {
        if self.printpiece.last().map(|s| s.as_str()) == Some(" ") {
            self.printpiece.pop();
        }
    }

    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_CONSTRUCTOR)?;
        encoder.write_unsigned_integer(
            ATTRIB_PARENT,
            self.parent_id.expect("Constructor::encode requires a parent id"),
        )?;
        encoder.write_signed_integer(ATTRIB_FIRST, self.firstwhitespace as i64)?;
        encoder.write_signed_integer(ATTRIB_LENGTH, self.minimumlength as i64)?;
        encoder.write_signed_integer(ATTRIB_SOURCE, self.source_file_index as i64)?;
        encoder.write_signed_integer(ATTRIB_LINE, self.get_lineno() as i64)?;
        for op in &self.operands {
            encoder.open_element(ELEM_OPER)?;
            encoder.write_unsigned_integer(ATTRIB_ID, op.symbol().id() as u64)?;
            encoder.close_element(ELEM_OPER)?;
        }
        for piece in &self.printpiece {
            if piece.starts_with('\n') {
                let index = piece.as_bytes()[1] - b'A';
                encoder.open_element(ELEM_OPPRINT)?;
                encoder.write_signed_integer(ATTRIB_ID, index as i64)?;
                encoder.close_element(ELEM_OPPRINT)?;
            } else {
                encoder.open_element(ELEM_PRINT)?;
                encoder.write_string(ATTRIB_PIECE, piece)?;
                encoder.close_element(ELEM_PRINT)?;
            }
        }
        for change in &self.context {
            change.encode(encoder)?;
        }
        if let Some(templ) = &self.templ {
            templ.encode(encoder, -1)?;
        }
        for (i, ntempl) in self.namedtempl.iter().enumerate() {
            if let Some(ntempl) = ntempl {
                ntempl.encode(encoder, i as i32)?;
            }
        }
        encoder.close_element(ELEM_CONSTRUCTOR)
    }

    /// Reorders `operands` into "handle order" -- each operand placed only once every operand
    /// its offset is relative to has already been placed -- fixing up every operand's assigned
    /// handle index, `offsetbase`, and every template's handle-index references to match (Java's
    /// private `orderOperands`).
    ///
    /// # Panics
    /// Panics with a [`SleighError`] if the operands' offset dependencies are circular, or if no
    /// pattern equation has been attached yet (mirrors Java's own `NullPointerException` on
    /// `pateq.operandOrder(...)` when `pateq` is null -- `orderOperands` is only ever called from
    /// `buildPattern`, by which point Java guarantees `pateq` is set).
    pub fn order_operands(&mut self) {
        let n = self.operands.len();
        let mut marked = vec![false; n];
        let mut patternorder: Vec<i32> = Vec::new();

        let pateq = self
            .pateq
            .as_ref()
            .expect("Constructor::order_operands requires a pattern equation");
        pateq.operand_order(&mut patternorder, &mut marked);

        // Make sure patternorder contains all operands.
        for i in 0..n {
            if !marked[i] {
                patternorder.push(i as i32);
                marked[i] = true;
            }
        }

        let mut newops: Vec<i32> = Vec::new();
        loop {
            let lastsize = newops.len();
            for &idx in &patternorder {
                let sym = &self.operands[idx as usize];
                if !marked[idx as usize] {
                    // "unmarked" means it is already in newops.
                    continue;
                }
                if sym.is_offset_irrelevant() {
                    // Expression operands come last.
                    continue;
                }
                let base = sym.offsetbase;
                if base == -1 || !marked[base as usize] {
                    newops.push(idx);
                    marked[idx as usize] = false;
                }
            }
            if newops.len() == lastsize {
                break;
            }
        }

        // Tack on expression operands.
        for &idx in &patternorder {
            let sym = &self.operands[idx as usize];
            if sym.is_offset_irrelevant() {
                newops.push(idx);
                marked[idx as usize] = false;
            }
        }

        if newops.len() != n {
            panic!(
                "{}",
                SleighError::new("Circular offset dependency between operands", self.location.clone())
            );
        }

        // Fix up operand indices: handmap[old_index] = new_index.
        let mut handmap = vec![0i32; n];
        for (new_index, &old_index) in newops.iter().enumerate() {
            handmap[old_index as usize] = new_index as i32;
        }
        for (new_index, &old_index) in newops.iter().enumerate() {
            self.operands[old_index as usize].set_hand(new_index as i32);
            self.operands[old_index as usize].change_local_expression_index(new_index as i32);
        }

        // Fix up offsetbase.
        for &old_index in &newops {
            let base = self.operands[old_index as usize].offsetbase;
            if base != -1 {
                self.operands[old_index as usize].offsetbase = handmap[base as usize];
            }
        }

        // Fix up templates.
        if let Some(templ) = &mut self.templ {
            templ.change_handle_index(&handmap);
        }
        for ntempl in self.namedtempl.iter_mut().flatten() {
            ntempl.change_handle_index(&handmap);
        }

        // Fix up printpiece operand refs.
        for piece in &mut self.printpiece {
            if piece.starts_with('\n') {
                let old_index = (piece.as_bytes()[1] - b'A') as i32;
                let new_index = handmap[old_index as usize];
                *piece = format!("\n{}", (b'A' + new_index as u8) as char);
            }
        }

        // Reorder operands themselves to match newops.
        let mut reordered: Vec<Option<OperandSymbol>> =
            std::mem::take(&mut self.operands).into_iter().map(Some).collect();
        let mut final_ops = Vec::with_capacity(n);
        for &old_index in &newops {
            final_ops.push(reordered[old_index as usize].take().expect("each operand moved exactly once"));
        }
        self.operands = final_ops;
    }
}

impl std::fmt::Display for Constructor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "constructor from {}", self.location)
    }
}

impl crate::decompiler::seam_stubs::Constructor for Constructor {
    fn location(&self) -> &Location {
        &self.location
    }

    fn get_operand(&self, index: i32) -> &OperandSymbol {
        Constructor::get_operand(self, index)
    }

    fn get_operand_sub_value(&self, index: i32, replace: &[i64], listpos: &mut MutableInt) -> i64 {
        let op = Constructor::get_operand(self, index);
        let defexp = op
            .get_defining_expression()
            .expect("Constructor::get_operand_sub_value requires a defined operand");
        let replace_vec: VectorStl<i64> = {
            let mut v = VectorStl::new();
            for x in replace {
                v.push_back(*x);
            }
            v
        };
        defexp.get_sub_value(&replace_vec, listpos)
    }

    fn parent_id(&self) -> u64 {
        self.parent_id.unwrap_or(0)
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn num_operands(&self) -> i32 {
        Constructor::get_num_operands(self)
    }

    fn add_operand(&mut self, sym: OperandSymbol) -> i32 {
        Constructor::add_operand(self, sym);
        (self.operands.len() - 1) as i32
    }

    fn add_invisible_operand(&mut self, sym: OperandSymbol) -> i32 {
        Constructor::add_invisible_operand(self, sym);
        (self.operands.len() - 1) as i32
    }

    fn get_operand_mut(&mut self, index: i32) -> &mut OperandSymbol {
        Constructor::get_operand_mut(self, index)
    }

    fn set_source_file_index(&mut self, index: i32) {
        Constructor::set_source_file_index(self, index)
    }

    fn add_equation(&mut self, pateq: Box<dyn PatternEquationOps>) {
        Constructor::add_equation(self, pateq)
    }

    fn remove_trailing_space(&mut self) {
        Constructor::remove_trailing_space(self)
    }

    fn add_context(&mut self, contvec: Vec<Box<dyn ContextChange>>) {
        Constructor::add_context(self, contvec)
    }

    fn set_main_section(&mut self, section: Option<ConstructTpl>) {
        if let Some(section) = section {
            Constructor::set_main_section(self, section);
        }
    }

    fn set_named_section(&mut self, section: ConstructTpl, index: i32) {
        Constructor::set_named_section(self, section, index as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpatexpress::{EquationCat, OperandEquation};

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    struct MockConstructor {
        location: Location,
    }
    impl crate::decompiler::seam_stubs::Constructor for MockConstructor {
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
        fn add_equation(&mut self, _pateq: Box<dyn PatternEquationOps>) {}
        fn remove_trailing_space(&mut self) {}
        fn add_context(&mut self, _contvec: Vec<Box<dyn ContextChange>>) {}
        fn set_main_section(&mut self, _section: Option<ConstructTpl>) {}
        fn set_named_section(&mut self, _section: ConstructTpl, _index: i32) {}
    }

    fn operand(index: i32) -> OperandSymbol {
        OperandSymbol::with_operand_value(
            loc(),
            format!("op{}", index),
            index,
            Box::new(MockConstructor { location: loc() }),
        )
    }

    #[test]
    fn new_has_no_parent() {
        let ct = Constructor::new(loc());
        assert_eq!(ct.get_parent_id(), None);
    }

    #[test]
    fn with_parent_stores_parent_id() {
        let ct = Constructor::with_parent(loc(), 7);
        assert_eq!(ct.get_parent_id(), Some(7));
    }

    #[test]
    fn get_filename_and_lineno_come_from_location() {
        let ct = Constructor::new(Location::new("foo.sleigh", 42));
        assert_eq!(ct.get_filename(), "foo.sleigh");
        assert_eq!(ct.get_lineno(), 42);
    }

    #[test]
    fn add_operand_appends_and_records_print_piece() {
        let mut ct = Constructor::new(loc());
        ct.add_operand(operand(0));
        ct.add_operand(operand(1));
        assert_eq!(ct.get_num_operands(), 2);
        assert_eq!(ct.printpiece, vec!["\nA", "\nB"]);
    }

    #[test]
    fn add_invisible_operand_does_not_record_print_piece() {
        let mut ct = Constructor::new(loc());
        ct.add_invisible_operand(operand(0));
        assert_eq!(ct.get_num_operands(), 1);
        assert!(ct.printpiece.is_empty());
    }

    #[test]
    fn add_syntax_collapses_whitespace_runs() {
        let mut ct = Constructor::new(loc());
        ct.add_syntax("foo");
        ct.add_syntax("   ");
        ct.add_syntax("   "); // Second run of whitespace should not add another piece.
        ct.add_syntax("bar");
        assert_eq!(ct.printpiece, vec!["foo", " ", "bar"]);
    }

    #[test]
    fn add_syntax_merges_adjacent_non_whitespace_pieces() {
        let mut ct = Constructor::new(loc());
        ct.add_syntax("foo");
        ct.add_syntax("bar");
        assert_eq!(ct.printpiece, vec!["foobar"]);
    }

    #[test]
    fn add_syntax_records_first_whitespace_index() {
        let mut ct = Constructor::new(loc());
        ct.add_syntax("foo");
        ct.add_syntax(" ");
        assert_eq!(ct.firstwhitespace, 1);
    }

    #[test]
    fn remove_trailing_space_strips_one_trailing_space_piece() {
        let mut ct = Constructor::new(loc());
        ct.add_syntax("foo");
        ct.add_syntax(" ");
        ct.remove_trailing_space();
        assert_eq!(ct.printpiece, vec!["foo"]);
    }

    #[test]
    fn remove_trailing_space_is_a_no_op_without_trailing_space() {
        let mut ct = Constructor::new(loc());
        ct.add_syntax("foo");
        ct.remove_trailing_space();
        assert_eq!(ct.printpiece, vec!["foo"]);
    }

    #[test]
    fn is_recursive_true_when_an_operand_is_defined_by_the_parent_subtable() {
        let mut ct = Constructor::with_parent(loc(), 42);
        let mut op = operand(0);
        op.define_operand_symbol(crate::decompiler::slghsymbol::operand_symbol::OperandDefiningSymbol::Other(
            Box::new(MockTripleSymbol),
            42,
        ));
        ct.add_operand(op);
        assert!(ct.is_recursive());
    }

    #[test]
    fn is_recursive_false_when_no_operand_matches_parent() {
        let mut ct = Constructor::with_parent(loc(), 42);
        let mut op = operand(0);
        op.define_operand_symbol(crate::decompiler::slghsymbol::operand_symbol::OperandDefiningSymbol::Other(
            Box::new(MockTripleSymbol),
            99,
        ));
        ct.add_operand(op);
        assert!(!ct.is_recursive());
    }

    struct MockTripleSymbol;
    impl TripleSymbol for MockTripleSymbol {
        fn get_pattern_expression(&self) -> Box<dyn crate::decompiler::slghpatexpress::PatternExpression> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// Builds a 3-operand constructor whose pattern equation references operand 1 then operand
    /// 0 (in that order -- proving the *pattern* order, not declaration order, seeds
    /// `patternorder`), where operand 1 depends on operand 0's offset and operand 2 is
    /// offset-irrelevant (tacked on last, regardless of pattern order).
    fn constructor_with_dependency_chain() -> Constructor {
        let mut ct = Constructor::new(loc());
        let mut op0 = operand(0);
        op0.offsetbase = -1;
        let mut op1 = operand(1);
        op1.offsetbase = 0; // Depends on op0.
        let mut op2 = operand(2);
        op2.set_offset_irrelevant();
        ct.add_operand(op0);
        ct.add_operand(op1);
        ct.add_operand(op2);

        // Pattern equation references operand 1 before operand 0.
        let eq = EquationCat::new(loc(), Box::new(OperandEquation::new(loc(), 1)), Box::new(OperandEquation::new(loc(), 0)));
        ct.add_equation(Box::new(eq));
        ct
    }

    #[test]
    fn order_operands_places_dependency_before_dependent() {
        let mut ct = constructor_with_dependency_chain();
        ct.order_operands();

        // op0 (no dependency) must end up before op1 (depends on op0's post-reorder position).
        assert_eq!(ct.get_operand(0).symbol().name(), "op0");
        assert_eq!(ct.get_operand(1).symbol().name(), "op1");
        // op1's offsetbase was remapped to op0's new handle index (0).
        assert_eq!(ct.get_operand(1).offsetbase, 0);
    }

    #[test]
    fn order_operands_places_offset_irrelevant_operands_last() {
        let mut ct = constructor_with_dependency_chain();
        ct.order_operands();
        assert_eq!(ct.get_operand(2).symbol().name(), "op2");
    }

    #[test]
    fn order_operands_reassigns_handle_indices_to_match_new_positions() {
        let mut ct = constructor_with_dependency_chain();
        ct.order_operands();
        for i in 0..ct.get_num_operands() {
            assert_eq!(ct.get_operand(i).get_index(), i);
        }
    }

    #[test]
    #[should_panic(expected = "Circular offset dependency")]
    fn order_operands_panics_on_circular_offset_dependency() {
        let mut ct = Constructor::new(loc());
        let mut op0 = operand(0);
        op0.offsetbase = 1; // Depends on op1.
        let mut op1 = operand(1);
        op1.offsetbase = 0; // Depends on op0: a cycle.
        ct.add_operand(op0);
        ct.add_operand(op1);

        let eq = EquationCat::new(loc(), Box::new(OperandEquation::new(loc(), 0)), Box::new(OperandEquation::new(loc(), 1)));
        ct.add_equation(Box::new(eq));

        ct.order_operands();
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
    fn encode_writes_element_and_operand_and_print_pieces() {
        let mut ct = Constructor::with_parent(loc(), 5);
        ct.add_operand(operand(0));
        ct.add_syntax(",");
        let mut encoder = RecordingEncoder::default();
        ct.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened.first(), Some(&"constructor"));
        assert_eq!(encoder.closed.last(), Some(&"constructor"));
        assert!(encoder.opened.contains(&"oper"));
        assert!(encoder.opened.contains(&"opprint")); // The "\nA" placeholder for op0.
        assert!(encoder.opened.contains(&"print")); // The "," literal.
    }

    #[test]
    #[should_panic(expected = "requires a parent id")]
    fn encode_panics_without_a_parent() {
        let ct = Constructor::new(loc());
        let mut encoder = RecordingEncoder::default();
        let _ = ct.encode(&mut encoder);
    }

    #[test]
    fn display_shows_location() {
        let ct = Constructor::new(Location::new("foo.sleigh", 3));
        let text = ct.to_string();
        assert!(text.contains("foo.sleigh"));
    }

    #[test]
    fn seam_trait_add_operand_returns_assigned_index() {
        let mut ct: Box<dyn crate::decompiler::seam_stubs::Constructor> = Box::new(Constructor::new(loc()));
        let first = ct.add_operand(operand(0));
        let second = ct.add_operand(operand(1));
        assert_eq!(first, 0);
        assert_eq!(second, 1);
    }
}
