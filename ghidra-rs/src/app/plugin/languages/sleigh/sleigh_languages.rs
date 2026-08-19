//! Mirrors `ghidra.app.plugin.languages.sleigh.SleighLanguages`.

use crate::app::plugin::languages::sleigh::constructor_entry_visitor::ConstructorEntryVisitor;
use crate::app::plugin::languages::sleigh::pcode_op_entry_visitor::PcodeOpEntryVisitor;
use crate::app::plugin::languages::sleigh::subtable_entry_visitor::SubtableEntryVisitor;
use crate::app::plugin::languages::sleigh::visitor_results::VisitorResult;
use crate::app::seam_stubs::{ConstructorTraversal, PcodeTraversal, SubtableTraversal};
use crate::program::model::lang::sleigh::constructor::Constructor;
use crate::program::model::lang::sleigh::pattern::DisjointPattern;
use crate::program::model::lang::sleigh::symbol::SubtableSymbol;

/// A collection of utility functions for traversing constructors and Pcode operations of SLEIGH
/// languages.
///
/// Mirrors `ghidra.app.plugin.languages.sleigh.SleighLanguages`, a stateless class of `public
/// static` methods. That class was chosen as the cut-point for a dependency cycle involving the
/// three traversal helpers it thinly wraps -- `SleighConstructorTraversal`,
/// `SleighSubtableTraversal`, and `SleighPcodeTraversal` -- none of which are ported to this
/// crate yet. Rather than reproduce e.g. `new SleighConstructorTraversal(lang).traverse(visitor)`
/// by concretely depending on a `SleighLanguage` plus an unported traversal struct, this trait's
/// methods take an already-built traversal object through the placeholder seams
/// [`ConstructorTraversal`](crate::app::seam_stubs::ConstructorTraversal),
/// [`SubtableTraversal`](crate::app::seam_stubs::SubtableTraversal), and
/// [`PcodeTraversal`](crate::app::seam_stubs::PcodeTraversal), decoupling this trait from any
/// concrete traversal implementation. None of the methods need per-instance state; `&self` keeps
/// the trait object-safe and matches the sibling visitor traits in this module.
pub trait SleighLanguages {
    /// Mirrors `SleighLanguages.traverseConstructors(SleighLanguage, ConstructorEntryVisitor)`.
    ///
    /// * `traversal` - a traversal already scoped to the language whose constructors to visit
    /// * `visitor` - a callback for each constructor visited
    ///
    /// Returns a [`VisitorResult`] indicating how traversal terminated.
    fn traverse_constructors_in_language(
        &self,
        traversal: &dyn ConstructorTraversal,
        visitor: &mut dyn ConstructorEntryVisitor,
    ) -> VisitorResult {
        traversal.traverse(visitor)
    }

    /// Mirrors `SleighLanguages.traverseConstructors(SubtableSymbol, SubtableEntryVisitor)`.
    ///
    /// * `traversal` - a traversal already scoped to the table whose constructors to visit
    /// * `visitor` - a callback for each constructor visited
    ///
    /// Returns a [`VisitorResult`] indicating how traversal terminated.
    fn traverse_constructors_in_subtable(
        &self,
        traversal: &dyn SubtableTraversal,
        visitor: &mut dyn SubtableEntryVisitor,
    ) -> VisitorResult {
        traversal.traverse(visitor)
    }

    /// Builds the per-constructor Pcode traversal used internally by
    /// [`traverse_all_pcode_ops`](Self::traverse_all_pcode_ops). Stands in for
    /// `new SleighPcodeTraversal(cons)`, which cannot be constructed directly here because
    /// `SleighPcodeTraversal` is not yet ported.
    fn pcode_traversal_for<'c>(&self, cons: &'c Constructor) -> Box<dyn PcodeTraversal + 'c>;

    /// Mirrors `SleighLanguages.traverseAllPcodeOps(SleighLanguage, PcodeOpEntryVisitor)`.
    ///
    /// * `traversal` - a traversal already scoped to the language whose constructors to visit
    /// * `visitor` - a callback for each Pcode operation visited
    ///
    /// Returns a [`VisitorResult`] indicating how traversal terminated.
    ///
    /// NOTE: the Java original also invokes the callback once with a `null` Pcode operation for a
    /// "NOP" constructor (one with no Pcode operations), so such constructors are not overlooked.
    /// This port's [`PcodeOpEntryVisitor::visit`] takes `op: &OpTpl` rather than a nullable
    /// `OpTpl` (a choice already made when that trait was ported), so that NOP callback is not
    /// reproduced here.
    fn traverse_all_pcode_ops(
        &self,
        traversal: &dyn ConstructorTraversal,
        visitor: &mut dyn PcodeOpEntryVisitor,
    ) -> VisitorResult {
        /// An internal visitor.
        ///
        /// [`SleighLanguages::traverse_all_pcode_ops`] uses this visitor to traverse every
        /// constructor of a given language. For each constructor, it then applies the
        /// constructor's [`PcodeTraversal`] to traverse each Pcode operation in the visited
        /// constructor. That traversal wraps the visitor given by the caller.
        struct ConsVisitForPcode<'a, L: SleighLanguages + ?Sized> {
            engine: &'a L,
            visitor: &'a mut dyn PcodeOpEntryVisitor,
        }

        impl<L: SleighLanguages + ?Sized> ConstructorEntryVisitor for ConsVisitForPcode<'_, L> {
            fn visit(
                &mut self,
                subtable: &SubtableSymbol,
                pattern: &DisjointPattern,
                cons: &Constructor,
            ) -> VisitorResult {
                let pcode_traversal = self.engine.pcode_traversal_for(cons);
                let visitor: &mut dyn PcodeOpEntryVisitor = self.visitor;
                let result =
                    pcode_traversal.traverse(&mut |op| visitor.visit(subtable, pattern, cons, op));
                match result {
                    VisitorResult::Terminate => VisitorResult::Terminate,
                    _ => VisitorResult::Continue,
                }
            }
        }

        traversal.traverse(&mut ConsVisitForPcode::<Self> {
            engine: self,
            visitor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::OpCode;
    use crate::program::model::address::{AddressFactory, AddressSpace};
    use crate::program::model::lang::sleigh::pattern::ContextPattern;
    use crate::program::model::lang::sleigh::symbol::SymbolHeader;
    use crate::program::model::lang::sleigh::template::op_tpl::OpTpl;
    use crate::program::model::pcode::decoder::{Decoder, DecoderError};
    use crate::program::model::pcode::ids::{
        AttributeId, ElementId, ATTRIB_NONZERO, ATTRIB_OFF, ELEM_MASK_WORD,
    };
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
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

    /// Mock [`ConstructorTraversal`] that replays a fixed list of `(subtable, pattern,
    /// constructor)` entries, stopping early if the visitor ever returns a non-[`Continue`]
    /// result -- exercising the same short-circuit contract as the real
    /// `SleighConstructorTraversal.traverse`.
    ///
    /// [`Continue`]: VisitorResult::Continue
    struct MockConstructorTraversal {
        entries: Vec<(SubtableSymbol, DisjointPattern, Constructor)>,
    }

    impl ConstructorTraversal for MockConstructorTraversal {
        fn traverse(&self, visitor: &mut dyn ConstructorEntryVisitor) -> VisitorResult {
            for (subtable, pattern, cons) in &self.entries {
                let result = visitor.visit(subtable, pattern, cons);
                if result != VisitorResult::Continue {
                    return result;
                }
            }
            VisitorResult::Finished
        }
    }

    /// Mock [`SubtableTraversal`] that replays a fixed list of `(pattern, constructor)` entries.
    struct MockSubtableTraversal {
        entries: Vec<(DisjointPattern, Constructor)>,
    }

    impl SubtableTraversal for MockSubtableTraversal {
        fn traverse(&self, visitor: &mut dyn SubtableEntryVisitor) -> VisitorResult {
            for (pattern, cons) in &self.entries {
                let result = visitor.visit(pattern, cons);
                if result != VisitorResult::Continue {
                    return result;
                }
            }
            VisitorResult::Finished
        }
    }

    /// Mock [`PcodeTraversal`] that replays a fixed list of Pcode ops for one constructor.
    struct MockPcodeTraversal {
        ops: Vec<OpTpl>,
    }

    impl PcodeTraversal for MockPcodeTraversal {
        fn traverse(
            &self,
            visit: &mut dyn FnMut(&OpTpl) -> VisitorResult,
        ) -> VisitorResult {
            for op in &self.ops {
                let result = visit(op);
                if result != VisitorResult::Continue {
                    return result;
                }
            }
            VisitorResult::Finished
        }
    }

    /// Counts constructors visited, terminating early once a target subtable name is seen.
    struct CountingConstructorVisitor {
        count: usize,
        stop_at: String,
    }

    impl ConstructorEntryVisitor for CountingConstructorVisitor {
        fn visit(
            &mut self,
            subtable: &SubtableSymbol,
            _pattern: &DisjointPattern,
            _cons: &Constructor,
        ) -> VisitorResult {
            self.count += 1;
            if subtable.header.name == self.stop_at {
                VisitorResult::Finished
            } else {
                VisitorResult::Continue
            }
        }
    }

    /// Counts constructors visited via a subtable-scoped traversal, terminating early once a
    /// target count is reached.
    struct CountingSubtableVisitor {
        count: usize,
        stop_at: usize,
    }

    impl SubtableEntryVisitor for CountingSubtableVisitor {
        fn visit(&mut self, _pattern: &DisjointPattern, _cons: &Constructor) -> VisitorResult {
            self.count += 1;
            if self.count == self.stop_at {
                VisitorResult::Finished
            } else {
                VisitorResult::Continue
            }
        }
    }

    /// Records every `(subtable name, opcode)` pair visited, terminating early once a target
    /// opcode is seen.
    struct RecordingPcodeOpVisitor {
        visits: Vec<(String, OpCode)>,
        stop_at: OpCode,
    }

    impl PcodeOpEntryVisitor for RecordingPcodeOpVisitor {
        fn visit(
            &mut self,
            subtable: &SubtableSymbol,
            _pattern: &DisjointPattern,
            _cons: &Constructor,
            op: &OpTpl,
        ) -> VisitorResult {
            self.visits.push((subtable.header.name.clone(), op.opc));
            if op.opc == self.stop_at {
                VisitorResult::Terminate
            } else {
                VisitorResult::Continue
            }
        }
    }

    /// The engine under test: hands out one [`MockPcodeTraversal`] per
    /// [`pcode_traversal_for`](SleighLanguages::pcode_traversal_for) call, in call order, from a
    /// preloaded list of op lists (one per constructor the associated [`ConstructorTraversal`]
    /// will visit).
    struct Engine {
        ops_lists: Vec<Vec<OpTpl>>,
        call_index: AtomicUsize,
    }

    impl SleighLanguages for Engine {
        fn pcode_traversal_for<'c>(&self, _cons: &'c Constructor) -> Box<dyn PcodeTraversal + 'c> {
            let idx = self.call_index.fetch_add(1, Ordering::SeqCst);
            Box::new(MockPcodeTraversal {
                ops: self.ops_lists[idx].clone(),
            })
        }
    }

    #[test]
    fn object_safe_mock_traverses_constructors_in_language_and_terminates() {
        let engine = Engine {
            ops_lists: Vec::new(),
            call_index: AtomicUsize::new(0),
        };
        let traversal = MockConstructorTraversal {
            entries: vec![
                (dummy_subtable("addrmode"), dummy_pattern(), dummy_constructor()),
                (dummy_subtable("instr"), dummy_pattern(), dummy_constructor()),
                (dummy_subtable("unreached"), dummy_pattern(), dummy_constructor()),
            ],
        };
        let mut visitor = CountingConstructorVisitor {
            count: 0,
            stop_at: "instr".to_string(),
        };

        let engine_ref: &dyn SleighLanguages = &engine;
        let result = engine_ref.traverse_constructors_in_language(&traversal, &mut visitor);

        assert_eq!(result, VisitorResult::Finished);
        assert_eq!(visitor.count, 2);
    }

    #[test]
    fn object_safe_mock_traverses_constructors_in_subtable_and_terminates() {
        let engine = Engine {
            ops_lists: Vec::new(),
            call_index: AtomicUsize::new(0),
        };
        let traversal = MockSubtableTraversal {
            entries: vec![
                (dummy_pattern(), dummy_constructor()),
                (dummy_pattern(), dummy_constructor()),
                (dummy_pattern(), dummy_constructor()),
            ],
        };
        let mut visitor = CountingSubtableVisitor {
            count: 0,
            stop_at: 2,
        };

        let engine_ref: &dyn SleighLanguages = &engine;
        let result = engine_ref.traverse_constructors_in_subtable(&traversal, &mut visitor);

        assert_eq!(result, VisitorResult::Finished);
        assert_eq!(visitor.count, 2);
    }

    #[test]
    fn traverse_all_pcode_ops_visits_ops_in_order_and_propagates_terminate() {
        let constructor_traversal = MockConstructorTraversal {
            entries: vec![
                (dummy_subtable("addrmode"), dummy_pattern(), dummy_constructor()),
                (dummy_subtable("instr"), dummy_pattern(), dummy_constructor()),
                (dummy_subtable("unreached"), dummy_pattern(), dummy_constructor()),
            ],
        };
        let engine = Engine {
            ops_lists: vec![
                vec![OpTpl::with_opcode(OpCode::CpuiCopy)],
                vec![
                    OpTpl::with_opcode(OpCode::CpuiIntAdd),
                    OpTpl::with_opcode(OpCode::CpuiLoad),
                ],
                vec![OpTpl::with_opcode(OpCode::CpuiCopy)],
            ],
            call_index: AtomicUsize::new(0),
        };
        let mut visitor = RecordingPcodeOpVisitor {
            visits: Vec::new(),
            stop_at: OpCode::CpuiLoad,
        };

        let engine_ref: &dyn SleighLanguages = &engine;
        let result = engine_ref.traverse_all_pcode_ops(&constructor_traversal, &mut visitor);

        assert_eq!(result, VisitorResult::Terminate);
        assert_eq!(
            visitor.visits,
            vec![
                ("addrmode".to_string(), OpCode::CpuiCopy),
                ("instr".to_string(), OpCode::CpuiIntAdd),
                ("instr".to_string(), OpCode::CpuiLoad),
            ]
        );
    }
}
