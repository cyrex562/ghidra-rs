use crate::program::model::block::code_block_iterator::CodeBlockIterator;
use crate::program::model::block::code_block_reference::CodeBlockReference;
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::seam_stubs::CodeBlock;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A unidirectional iterator over the destination `CodeBlockReference`s for a `CodeBlock`
/// representing a subroutine (as obtained from
/// [`PartitionCodeSubModel`](crate::program::model::block::partition_code_sub_model::PartitionCodeSubModel)
/// or a similar subroutine block model). External references are ignored unless the owning
/// model includes them.
///
/// Port of `ghidra.program.model.block.SubroutineDestReferenceIterator`. In Java this is a
/// concrete class; callers only ever construct one and use it polymorphically as a
/// `CodeBlockReferenceIterator` (see `MultEntSubModel`/`OverlapCodeSubModel`/
/// `PartitionCodeSubModel`'s `getDestinations`), so it is ported here as a marker trait over that
/// already-ported interface. The private `getDestinations`/`queueDestReferences` algorithm that
/// populates the actual queue of `CodeBlockReference`s is not modeled: it constructs
/// `CodeBlockReferenceImpl` instances and lazily resolves destination blocks via
/// `CodeBlockModel.getFirstCodeBlockContaining`, neither of which is ported yet, and (matching
/// the precedent set by
/// [`PartitionCodeSubModel`](crate::program::model::block::partition_code_sub_model::PartitionCodeSubModel)'s
/// own private partitioning algorithm) is an implementation detail rather than part of the
/// public API.
///
/// The public static `getNumDestinations` helper, which never constructs a `CodeBlockReference`
/// (it drives the same counting loop with a `null` queue), is fully ported below as
/// [`get_num_destinations`].
pub trait SubroutineDestReferenceIterator: CodeBlockReferenceIterator {}

/// Get the number of destination references flowing out of `block` (a subroutine). All calls
/// from this block, and all external `FlowType` block references from this block, are counted.
///
/// Port of `SubroutineDestReferenceIterator.getNumDestinations(CodeBlock, TaskMonitor)`
/// (via the shared private `getDestinations` helper, called here with no queue to populate).
/// `block` being `None`/having no minimum address mirrors `block == null ||
/// block.getMinAddress() == null` in the Java method.
pub fn get_num_destinations(
    block: Option<&dyn CodeBlock>,
    monitor: &dyn TaskMonitor,
) -> Result<i32, CancelledException> {
    let Some(block) = block else {
        return Ok(0);
    };
    if block.get_min_address().is_none() {
        return Ok(0);
    }

    let model = block.get_model();
    let include_externals = model.externals_included();

    let mut count = 0;

    // Iterate over all basic blocks within the specified block.
    let mut bblock_iter = model
        .get_basic_block_model()
        .get_code_blocks_containing(block, monitor)?;
    while bblock_iter.has_next()? {
        let bblock = bblock_iter.next()?;

        // Get basic block destinations.
        let mut bb_dest_iter = bblock.get_destinations(monitor)?;
        while bb_dest_iter.has_next()? {
            let bb_dest_ref = bb_dest_iter.next()?;
            let ref_flow_type = bb_dest_ref.get_flow_type();
            let dest_addr = bb_dest_ref.get_reference();

            let mut add_block_ref = false;
            if dest_addr.is_external_address() {
                if include_externals {
                    // Count all forward external references if includeExternals.
                    add_block_ref = true;
                }
            } else if ref_flow_type.is_call() {
                // Count all forward CALL references.
                add_block_ref = true;
            } else if ref_flow_type.is_jump() || ref_flow_type.is_fallthrough() {
                // Count forward external JUMP and FALL-THROUGH references.
                if !block.contains(&dest_addr) {
                    add_block_ref = true;
                }
            }
            if add_block_ref {
                count += 1;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::{CodeBlockModel, FlowType};
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn external_space() -> Arc<AddressSpace> {
        AddressSpace::new("EXTERNAL", 32, 1, AddressSpaceType::External, 0)
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Flow {
        Call,
        Jump,
        Fallthrough,
    }

    struct MockFlowType(Flow);

    impl FlowType for MockFlowType {
        fn is_call(&self) -> bool {
            self.0 == Flow::Call
        }
        fn is_jump(&self) -> bool {
            self.0 == Flow::Jump
        }
        fn is_fallthrough(&self) -> bool {
            self.0 == Flow::Fallthrough
        }
    }

    /// A single outgoing flow from a basic block, carrying just the flow type and destination
    /// address that `get_num_destinations`'s counting loop reads off each `CodeBlockReference`.
    struct MockCodeBlockReference {
        flow_type: Flow,
        reference: Address,
    }

    impl CodeBlockReference for MockCodeBlockReference {
        fn get_source_address(&self) -> Address {
            self.reference.clone()
        }
        fn get_destination_address(&self) -> Address {
            self.reference.clone()
        }
        fn get_flow_type(&self) -> Box<dyn FlowType> {
            Box::new(MockFlowType(self.flow_type))
        }
        fn get_reference(&self) -> Address {
            self.reference.clone()
        }
        fn get_referent(&self) -> Address {
            self.reference.clone()
        }
        fn get_destination_block(&self) -> Box<dyn CodeBlock> {
            unimplemented!("not read by get_num_destinations")
        }
        fn get_source_block(&self) -> Box<dyn CodeBlock> {
            unimplemented!("not read by get_num_destinations")
        }
    }

    struct VecCodeBlockReferenceIterator {
        refs: std::vec::IntoIter<MockCodeBlockReference>,
    }

    impl CodeBlockReferenceIterator for VecCodeBlockReferenceIterator {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            Ok(self.refs.as_slice().first().is_some())
        }
        fn next(&mut self) -> Result<Box<dyn CodeBlockReference>, CancelledException> {
            Ok(Box::new(self.refs.next().expect("has_next was checked")))
        }
    }

    /// A basic block spanning `[start, end)` with a fixed list of outgoing flows, each targeting
    /// a (possibly external) address. Stands in for `SimpleBlock`.
    #[derive(Clone)]
    struct BasicBlock {
        start: i64,
        end: i64,
        destinations: Vec<(Flow, Arc<AddressSpace>, i64)>,
        space: Arc<AddressSpace>,
    }

    impl CodeBlock for BasicBlock {
        fn get_min_address(&self) -> Option<Address> {
            Some(Address::new(self.space.clone(), self.start))
        }
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("basic blocks are only iterated over, never re-modeled")
        }
        fn contains(&self, address: &Address) -> bool {
            Arc::ptr_eq(address.space(), &self.space)
                && address.offset() >= self.start
                && address.offset() < self.end
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            let refs = self
                .destinations
                .iter()
                .map(|(flow, space, offset)| MockCodeBlockReference {
                    flow_type: *flow,
                    reference: Address::new(space.clone(), *offset),
                })
                .collect::<Vec<_>>();
            Ok(Box::new(VecCodeBlockReferenceIterator {
                refs: refs.into_iter(),
            }))
        }
    }

    struct VecCodeBlockIterator {
        blocks: std::vec::IntoIter<BasicBlock>,
    }

    impl CodeBlockIterator for VecCodeBlockIterator {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            Ok(self.blocks.as_slice().first().is_some())
        }
        fn next(&mut self) -> Result<Box<dyn CodeBlock>, CancelledException> {
            Ok(Box::new(self.blocks.next().expect("has_next was checked")))
        }
    }

    /// A subroutine block model backed by a fixed list of basic blocks, reporting itself as its
    /// own "basic block model" the way a single-layer block model would.
    #[derive(Clone)]
    struct SubroutineModel {
        include_externals: bool,
        basic_blocks: Vec<BasicBlock>,
    }

    impl CodeBlockModel for SubroutineModel {
        fn externals_included(&self) -> bool {
            self.include_externals
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            Box::new(self.clone())
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            Ok(Box::new(VecCodeBlockIterator {
                blocks: self.basic_blocks.clone().into_iter(),
            }))
        }
    }

    /// The subroutine-level `CodeBlock` handed to `get_num_destinations`, spanning the union of
    /// its basic blocks and reporting `model` from `get_model`.
    struct SubroutineBlock {
        start: i64,
        end: i64,
        space: Arc<AddressSpace>,
        model: SubroutineModel,
    }

    impl CodeBlock for SubroutineBlock {
        fn get_min_address(&self) -> Option<Address> {
            Some(Address::new(self.space.clone(), self.start))
        }
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            Box::new(self.model.clone())
        }
        fn contains(&self, address: &Address) -> bool {
            Arc::ptr_eq(address.space(), &self.space)
                && address.offset() >= self.start
                && address.offset() < self.end
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unreachable!("get_num_destinations only queries destinations of basic blocks")
        }
    }

    /// A subroutine `[0x1000, 0x2000)` made of two basic blocks with a mix of internal/external,
    /// call/jump/fallthrough flows: a call (always counted), an internal jump (never counted), a
    /// forward jump leaving the subroutine (counted), an internal fallthrough (never counted),
    /// and a forward fallthrough leaving the subroutine (counted).
    fn subroutine_block() -> SubroutineBlock {
        let space = ram_space();
        let basic_blocks = vec![
            BasicBlock {
                start: 0x1000,
                end: 0x1800,
                destinations: vec![
                    (Flow::Call, space.clone(), 0x5000),
                    (Flow::Jump, space.clone(), 0x1500),
                    (Flow::Jump, space.clone(), 0x3000),
                    (Flow::Fallthrough, space.clone(), 0x1800),
                ],
                space: space.clone(),
            },
            BasicBlock {
                start: 0x1800,
                end: 0x2000,
                destinations: vec![(Flow::Fallthrough, space.clone(), 0x4000)],
                space: space.clone(),
            },
        ];
        SubroutineBlock {
            start: 0x1000,
            end: 0x2000,
            space: space.clone(),
            model: SubroutineModel {
                include_externals: true,
                basic_blocks,
            },
        }
    }

    #[test]
    fn counts_calls_and_forward_jumps_but_not_internal_flow() {
        let block = subroutine_block();
        let count = get_num_destinations(Some(&block), &DummyMonitor).unwrap();
        // Call to 0x5000, jump to 0x3000, fallthrough to 0x4000 => 3. The internal jump and
        // fallthrough within [0x1000, 0x2000) are excluded.
        assert_eq!(count, 3);
    }

    #[test]
    fn external_destination_only_counted_when_model_includes_externals() {
        let space = ram_space();
        let external = external_space();
        let make_block = |include_externals: bool| SubroutineBlock {
            start: 0x1000,
            end: 0x2000,
            space: space.clone(),
            model: SubroutineModel {
                include_externals,
                basic_blocks: vec![BasicBlock {
                    start: 0x1000,
                    end: 0x2000,
                    // Flow type is irrelevant once the destination is external: the Java
                    // implementation checks `isExternalAddress()` first.
                    destinations: vec![(Flow::Jump, external.clone(), 1)],
                    space: space.clone(),
                }],
            },
        };

        let included = get_num_destinations(Some(&make_block(true)), &DummyMonitor).unwrap();
        let excluded = get_num_destinations(Some(&make_block(false)), &DummyMonitor).unwrap();
        assert_eq!(included, 1);
        assert_eq!(excluded, 0);
    }

    #[test]
    fn none_block_short_circuits_to_zero() {
        let count = get_num_destinations(None, &DummyMonitor).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn block_with_no_min_address_short_circuits_without_touching_model() {
        struct NoAddressBlock;
        impl CodeBlock for NoAddressBlock {
            fn get_model(&self) -> Box<dyn CodeBlockModel> {
                panic!("get_num_destinations must short-circuit before calling get_model");
            }
            fn get_destinations(
                &self,
                _monitor: &dyn TaskMonitor,
            ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                panic!("get_num_destinations must short-circuit before calling get_destinations");
            }
        }

        let count = get_num_destinations(Some(&NoAddressBlock), &DummyMonitor).unwrap();
        assert_eq!(count, 0);
    }

    /// A mock iterator over a fixed count of destination references, proving
    /// `SubroutineDestReferenceIterator` is object-safe and behaves like any other
    /// `CodeBlockReferenceIterator`, including `CancelledException` propagation.
    struct CountingSubroutineDestReferenceIterator {
        remaining: usize,
        space: Arc<AddressSpace>,
        cancel_after: Option<usize>,
    }

    impl CodeBlockReferenceIterator for CountingSubroutineDestReferenceIterator {
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
            self.remaining -= 1;
            Ok(Box::new(MockCodeBlockReference {
                flow_type: Flow::Call,
                reference: Address::new(self.space.clone(), 0x1000 * self.remaining as i64),
            }))
        }
    }

    impl SubroutineDestReferenceIterator for CountingSubroutineDestReferenceIterator {}

    #[test]
    fn marker_trait_is_object_safe_and_walks_all_references() {
        let mut iter: Box<dyn SubroutineDestReferenceIterator> =
            Box::new(CountingSubroutineDestReferenceIterator {
                remaining: 3,
                space: ram_space(),
                cancel_after: None,
            });

        let mut count = 0;
        while iter.has_next().unwrap() {
            iter.next().unwrap();
            count += 1;
        }
        assert_eq!(count, 3);
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn marker_trait_propagates_cancellation() {
        let mut iter: Box<dyn SubroutineDestReferenceIterator> =
            Box::new(CountingSubroutineDestReferenceIterator {
                remaining: 5,
                space: ram_space(),
                cancel_after: Some(1),
            });

        assert!(iter.has_next().unwrap());
        iter.next().unwrap();
        assert!(iter.has_next().is_err());
    }
}
