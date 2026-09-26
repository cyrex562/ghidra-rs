//! Mirrors `ghidra.app.plugin.languages.sleigh.ConstructorEntryVisitor`.

use crate::app::plugin::languages::sleigh::visitor_results::VisitorResult;
use crate::program::model::lang::sleigh::constructor::Constructor;
use crate::program::model::lang::sleigh::pattern::DisjointPattern;
use crate::program::model::lang::sleigh::symbol::SubtableSymbol;

/// An interface for visiting constructors in a SLEIGH language.
///
/// Mirrors `ghidra.app.plugin.languages.sleigh.ConstructorEntryVisitor`, which extends
/// `VisitorResults` (see [`VisitorResult`]) purely to inherit its `CONTINUE`/`FINISHED`/
/// `TERMINATE` constants; that inheritance is instead modeled by this trait's `visit` returning
/// [`VisitorResult`] directly.
pub trait ConstructorEntryVisitor {
    /// Callback to visit a constructor.
    ///
    /// * `subtable` - the table containing the constructor
    /// * `pattern` - the pattern corresponding to the constructor
    /// * `cons` - the constructor
    ///
    /// Returns a [`VisitorResult`] controlling whether traversal continues.
    fn visit(
        &mut self,
        subtable: &SubtableSymbol,
        pattern: &DisjointPattern,
        cons: &Constructor,
    ) -> VisitorResult;
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // Sanity: this mock never emits an `ELEM_MASK_WORD`, so `PatternBlock::decode`'s loop
        // exits immediately.
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

    /// Counts constructors visited, terminating early once a target subtable name is seen --
    /// exercising both the trait's mutable accumulation and its early-exit control flow.
    struct CountingVisitor {
        count: usize,
        stop_at: String,
    }

    impl ConstructorEntryVisitor for CountingVisitor {
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

    #[test]
    fn object_safe_mock_visits_and_terminates() {
        let mut visitor = CountingVisitor {
            count: 0,
            stop_at: "instr".to_string(),
        };
        let boxed: &mut dyn ConstructorEntryVisitor = &mut visitor;

        let subtable_a = dummy_subtable("addrmode");
        let subtable_b = dummy_subtable("instr");
        let pattern = dummy_pattern();
        let cons = dummy_constructor();

        assert_eq!(
            boxed.visit(&subtable_a, &pattern, &cons),
            VisitorResult::Continue
        );
        assert_eq!(
            boxed.visit(&subtable_b, &pattern, &cons),
            VisitorResult::Finished
        );
        assert_eq!(visitor.count, 2);
    }
}
