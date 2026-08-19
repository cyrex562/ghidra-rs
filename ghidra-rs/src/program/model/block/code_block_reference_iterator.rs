use crate::program::model::block::code_block_reference::CodeBlockReference;
use crate::util::exception::CancelledException;

/// An iterator interface over [`CodeBlockReference`]s.
///
/// Port of `ghidra.program.model.block.CodeBlockReferenceIterator`.
pub trait CodeBlockReferenceIterator {
    /// Return true if `next()` will return a `CodeBlockReference`.
    fn has_next(&mut self) -> Result<bool, CancelledException>;

    /// Return the next `CodeBlockReference`.
    fn next(&mut self) -> Result<Box<dyn CodeBlockReference>, CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::block::code_block::CodeBlock;
    use crate::program::seam_stubs::FlowType;
    use std::sync::Arc;

    crate::impl_empty_address_set_view!(MockCodeBlock);

    struct MockCodeBlock;

    impl CodeBlock for MockCodeBlock {
        fn get_model(&self) -> Box<dyn crate::program::model::block::CodeBlockModel> {
            unimplemented!()
        }
        fn get_destinations(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }
    }

    struct MockFlowType;

    impl FlowType for MockFlowType {}

    struct MockCodeBlockReference {
        source: Address,
        destination: Address,
    }

    impl CodeBlockReference for MockCodeBlockReference {
        fn get_source_address(&self) -> Address {
            self.source.clone()
        }

        fn get_destination_address(&self) -> Address {
            self.destination.clone()
        }

        fn get_flow_type(&self) -> Box<dyn FlowType> {
            Box::new(MockFlowType)
        }

        fn get_reference(&self) -> Address {
            self.destination.clone()
        }

        fn get_referent(&self) -> Address {
            self.source.clone()
        }

        fn get_destination_block(&self) -> Box<dyn CodeBlock> {
            Box::new(MockCodeBlock)
        }

        fn get_source_block(&self) -> Box<dyn CodeBlock> {
            Box::new(MockCodeBlock)
        }
    }

    /// A mock iterator over a fixed count of references, proving `CodeBlockReferenceIterator` is
    /// object-safe and that a `CancelledException` from `has_next`/`next` behaves like the Java
    /// contract.
    struct CountingCodeBlockReferenceIterator {
        remaining: usize,
        space: Arc<AddressSpace>,
        cancel_after: Option<usize>,
    }

    impl CodeBlockReferenceIterator for CountingCodeBlockReferenceIterator {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            if let Some(0) = self.cancel_after {
                return Err(CancelledException("cancelled".to_string()));
            }
            Ok(self.remaining > 0)
        }

        fn next(&mut self) -> Result<Box<dyn CodeBlockReference>, CancelledException> {
            if let Some(n) = self.cancel_after {
                if n == 0 {
                    return Err(CancelledException("cancelled".to_string()));
                }
                self.cancel_after = Some(n - 1);
            }
            if self.remaining == 0 {
                return Err(CancelledException("no more references".to_string()));
            }
            let source = Address::new(self.space.clone(), 0x1000 * self.remaining as i64);
            self.remaining -= 1;
            let destination = Address::new(self.space.clone(), 0x1000 * self.remaining as i64);
            Ok(Box::new(MockCodeBlockReference {
                source,
                destination,
            }))
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn has_next_and_next_walk_all_references() {
        let mut iter: Box<dyn CodeBlockReferenceIterator> =
            Box::new(CountingCodeBlockReferenceIterator {
                remaining: 3,
                space: test_space(),
                cancel_after: None,
            });

        let mut count = 0;
        while iter.has_next().unwrap() {
            let reference = iter.next().unwrap();
            assert!(reference.get_source_address().offset() >= reference.get_destination_address().offset());
            count += 1;
        }
        assert_eq!(count, 3);
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn has_next_propagates_cancellation() {
        let mut iter = CountingCodeBlockReferenceIterator {
            remaining: 5,
            space: test_space(),
            cancel_after: Some(2),
        };

        assert!(iter.has_next().unwrap());
        iter.next().unwrap();
        assert!(iter.has_next().unwrap());
        iter.next().unwrap();
        assert!(iter.has_next().is_err());
    }
}
