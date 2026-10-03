//! Mirrors `ghidra.app.plugin.languages.sleigh.PcodeOpEntryVisitor`.

use crate::app::plugin::languages::sleigh::visitor_results::VisitorResult;
use crate::program::model::lang::sleigh::constructor::Constructor;
use crate::program::model::lang::sleigh::pattern::DisjointPattern;
use crate::program::model::lang::sleigh::symbol::SubtableSymbol;
use crate::program::model::lang::sleigh::template::op_tpl::OpTpl;

/// An interface for visiting Pcode operations in a SLEIGH language.
///
/// Mirrors `ghidra.app.plugin.languages.sleigh.PcodeOpEntryVisitor`, which extends
/// `VisitorResults` (see [`VisitorResult`]) purely to inherit its `CONTINUE`/`FINISHED`/
/// `TERMINATE` constants; that inheritance is instead modeled by this trait's `visit` returning
/// [`VisitorResult`] directly.
///
/// @see `SleighLanguages.traverseAllPcodeOps(SleighLanguage, PcodeOpEntryVisitor)`
pub trait PcodeOpEntryVisitor {
    /// Callback to visit a Pcode operation.
    ///
    /// * `subtable` - the table containing the constructor
    /// * `pattern` - the pattern corresponding to the constructor
    /// * `cons` - the constructor generating the Pcode operation
    /// * `op` - the Pcode operation
    ///
    /// Returns a [`VisitorResult`] controlling whether traversal continues.
    fn visit(
        &mut self,
        subtable: &SubtableSymbol,
        pattern: &DisjointPattern,
        cons: &Constructor,
        op: &OpTpl,
    ) -> VisitorResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::OpCode;
    use crate::program::model::address::{AddressFactory, AddressSpace};
    use crate::program::model::lang::sleigh::pattern::ContextPattern;
    use crate::program::model::lang::sleigh::symbol::SymbolHeader;
    use crate::program::model::pcode::decoder::{Decoder, DecoderError};
    use crate::program::model::pcode::ids::{
        AttributeId, ElementId, ATTRIB_NONZERO, ATTRIB_OFF, ELEM_MASK_WORD,
    };
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    /// Decoder that plays back a single always-true `<context_pat><pat_block off="0"
    /// nonzero="0"/></context_pat>` sequence, just enough for [`ContextPattern::decode`] to
    /// build a real [`DisjointPattern`] without needing the full packed binary decoder.
    struct MockPatternDecoder {
        open_calls: AtomicI32,
    }

    impl Decoder for MockPatternDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(self.open_calls.fetch_add(1, Ordering::SeqCst) + 1)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            self.open_element()
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(
            &self,
            attrib_id: AttributeId,
        ) -> Result<i64, DecoderError> {
            if attrib_id.id == ATTRIB_OFF.id || attrib_id.id == ATTRIB_NONZERO.id {
                Ok(0)
            } else {
                Err(DecoderError::MissingAttribute(attrib_id.name.to_string()))
            }
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    fn dummy_pattern() -> DisjointPattern {
        let decoder = MockPatternDecoder {
            open_calls: AtomicI32::new(0),
        };
        assert_ne!(decoder.peek_element().unwrap(), ELEM_MASK_WORD.id);
        DisjointPattern::Context(ContextPattern::decode(&decoder).unwrap())
    }

    fn dummy_subtable(name: &str) -> SubtableSymbol {
        SubtableSymbol {
            header: SymbolHeader {
                name: name.to_string(),
                id: 0,
                scope_id: 0,
            },
            constructors: Vec::new(),
            decision_tree: None,
        }
    }

    fn dummy_constructor() -> Constructor {
        Constructor::new()
    }

    /// Counts pcode ops visited, terminating early once a target opcode is seen -- exercising
    /// both the trait's mutable accumulation and its early-exit control flow.
    struct CountingVisitor {
        count: usize,
        stop_at: OpCode,
    }

    impl PcodeOpEntryVisitor for CountingVisitor {
        fn visit(
            &mut self,
            _subtable: &SubtableSymbol,
            _pattern: &DisjointPattern,
            _cons: &Constructor,
            op: &OpTpl,
        ) -> VisitorResult {
            self.count += 1;
            if op.opc == self.stop_at {
                VisitorResult::Finished
            } else {
                VisitorResult::Continue
            }
        }
    }

    #[test]
    fn object_safe_mock_visits_and_terminates() {
        let mut visitor = CountingVisitor {
            count: 0,
            stop_at: OpCode::CpuiCopy,
        };
        let boxed: &mut dyn PcodeOpEntryVisitor = &mut visitor;

        let subtable = dummy_subtable("instr");
        let pattern = dummy_pattern();
        let cons = dummy_constructor();
        let op_a = OpTpl::with_opcode(OpCode::CpuiLoad);
        let op_b = OpTpl::with_opcode(OpCode::CpuiCopy);

        assert_eq!(
            boxed.visit(&subtable, &pattern, &cons, &op_a),
            VisitorResult::Continue
        );
        assert_eq!(
            boxed.visit(&subtable, &pattern, &cons, &op_b),
            VisitorResult::Finished
        );
        assert_eq!(visitor.count, 2);
    }
}
