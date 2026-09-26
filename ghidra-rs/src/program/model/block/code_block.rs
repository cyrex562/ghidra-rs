use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::block::code_block_model::CodeBlockModel;
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::seam_stubs::{EmptyCodeBlockReferenceIterator, FlowType};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `CodeBlock` represents some group of Instructions/Data. Each block has some set of source
/// blocks that flow into it and some set of destination blocks that flow out of it. A
/// [`CodeBlockModel`] is used to produce `CodeBlock`s. Each model produces blocks based on its
/// interpretation of Instruction/Data grouping and flow between those groups.
///
/// Port of `ghidra.program.model.block.CodeBlock`. This trait absorbs (see `STUBS.tsv`) the
/// placeholder previously at `crate::program::seam_stubs::CodeBlock`: [`get_model`](Self::get_model)
/// and [`get_destinations`](Self::get_destinations) keep the placeholder's required status (every
/// existing implementor already supplied both), while the placeholder's `get_min_address`/
/// `contains`/`is_empty` are now inherited from the real [`AddressSetView`] supertrait (matching
/// Java's `CodeBlock extends AddressSetView`) instead of being declared here. Every other member
/// is new and defaults in a way that keeps a bare, address-set-only implementation compiling:
/// [`get_first_start_address`](Self::get_first_start_address)/[`get_start_addresses`](Self::get_start_addresses)
/// derive from [`AddressSetView::min_address`], [`get_flow_type`](Self::get_flow_type) falls back
/// to a null-object "unknown" flow (matching Java's own documented UNKNOWN fallback), and
/// [`get_num_sources`](Self::get_num_sources)/[`get_num_destinations`](Self::get_num_destinations)
/// default to the naive count-via-iteration the Java docs describe ("almost as much work as
/// getting the actual source references").
pub trait CodeBlock: AddressSetView {
    /// Return the first start address of the `CodeBlock`. Depending on the model used to
    /// generate the `CodeBlock`, there may be multiple entry points to the block. This will
    /// return the first start address for the block. It should always return the same address
    /// for a given block if there is more than one entry point.
    ///
    /// Defaults to [`AddressSetView::min_address`], panicking if the block has no addresses --
    /// implementors of a genuinely empty block should override this along with
    /// [`get_start_addresses`](Self::get_start_addresses).
    fn get_first_start_address(&self) -> Address {
        self.min_address()
            .expect("CodeBlock.getFirstStartAddress: block has no addresses")
    }

    /// Get all the entry points to this block. Depending on the model, there may be more than
    /// one entry point. Entry points are returned in natural sorted order; an empty vec if there
    /// are none.
    ///
    /// Defaults to a single-element vec wrapping [`AddressSetView::min_address`] (or empty if the
    /// block has no addresses), matching single-entry block models that don't override this.
    fn get_start_addresses(&self) -> Vec<Address> {
        match self.min_address() {
            Some(addr) => vec![addr],
            None => Vec::new(),
        }
    }

    /// Return the name of the block, normally the symbol at the starting address.
    ///
    /// Defaults to the first start address's display string (empty string if the block has no
    /// addresses).
    fn get_name(&self) -> String {
        match self.min_address() {
            Some(addr) => addr.to_string(),
            None => String::new(),
        }
    }

    /// Return, in theory, how things flow out of this node. If there are any abnormal ways to
    /// flow out of this node (i.e. jump, call, etc...) then the flow type of the node takes on
    /// that type. If there are multiple unique ways out of the node, then we should return
    /// `FlowType.UNKNOWN`. Fallthrough is returned if that is the only way out.
    ///
    /// Defaults to a null-object "unknown" flow type, matching the UNKNOWN fallback above.
    fn get_flow_type(&self) -> Box<dyn FlowType> {
        Box::new(UnknownFlowType)
    }

    /// Get the number of `CodeBlock`s that flow into this `CodeBlock`. Note that this is almost
    /// as much work as getting the actual source references.
    ///
    /// Defaults to counting [`get_sources`](Self::get_sources).
    fn get_num_sources(&self, monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
        count_references(self.get_sources(monitor)?)
    }

    /// Get an iterator over the `CodeBlock`s that flow into this `CodeBlock`.
    ///
    /// Defaults to reporting no sources, matching the placeholder's prior default.
    fn get_sources(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
        let _ = monitor;
        Ok(Box::new(EmptyCodeBlockReferenceIterator))
    }

    /// Get the number of `CodeBlock`s this block flows to. Note that this is almost as much work
    /// as getting the actual destination references.
    ///
    /// Defaults to counting [`get_destinations`](Self::get_destinations).
    fn get_num_destinations(&self, monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
        count_references(self.get_destinations(monitor)?)
    }

    /// Get an iterator over the `CodeBlock`s that are flowed to from this `CodeBlock`.
    fn get_destinations(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException>;

    /// Get the model instance which was used to generate this block.
    fn get_model(&self) -> Box<dyn CodeBlockModel>;
}

fn count_references(
    mut iter: Box<dyn CodeBlockReferenceIterator>,
) -> Result<i32, CancelledException> {
    let mut count = 0;
    while iter.has_next()? {
        iter.next()?;
        count += 1;
    }
    Ok(count)
}

/// Null-object [`FlowType`] used as [`CodeBlock::get_flow_type`]'s default, standing in for
/// Java's `FlowType.UNKNOWN` fallback. Not a port of any specific Java class.
struct UnknownFlowType;

impl FlowType for UnknownFlowType {}

/// Implements [`AddressSetView`] for a zero-sized/marker type as an always-empty, unbounded
/// address set (every query reports "nothing here"). Used by tests across the `block` module for
/// `CodeBlock` mocks that only exercise [`CodeBlock::get_model`]/[`CodeBlock::get_destinations`]
/// and never actually need real address-set behavior, mirroring the semantics the old
/// `program::seam_stubs::CodeBlock` placeholder's defaults used to provide directly.
#[cfg(test)]
#[macro_export]
macro_rules! impl_empty_address_set_view {
    ($ty:ty) => {
        impl $crate::program::model::address::AddressSetView for $ty {
            fn contains(&self, _address: &$crate::program::model::address::Address) -> bool {
                false
            }
            fn contains_range(
                &self,
                _start: &$crate::program::model::address::Address,
                _end: &$crate::program::model::address::Address,
            ) -> bool {
                false
            }
            fn contains_set(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> bool {
                false
            }
            fn is_empty(&self) -> bool {
                true
            }
            fn min_address(&self) -> Option<$crate::program::model::address::Address> {
                None
            }
            fn max_address(&self) -> Option<$crate::program::model::address::Address> {
                None
            }
            fn num_address_ranges(&self) -> usize {
                0
            }
            fn address_ranges(
                &self,
            ) -> Box<dyn $crate::program::model::address::AddressRangeIterator> {
                Box::new($crate::program::model::address::EmptyAddressRangeIterator)
            }
            fn address_ranges_ordered(
                &self,
                _forward: bool,
            ) -> Box<dyn $crate::program::model::address::AddressRangeIterator> {
                Box::new($crate::program::model::address::EmptyAddressRangeIterator)
            }
            fn address_ranges_from(
                &self,
                _start: &$crate::program::model::address::Address,
                _forward: bool,
            ) -> Box<dyn $crate::program::model::address::AddressRangeIterator> {
                Box::new($crate::program::model::address::EmptyAddressRangeIterator)
            }
            fn num_addresses(&self) -> u64 {
                0
            }
            fn addresses(
                &self,
                _forward: bool,
            ) -> $crate::program::model::address::BoxedAddressIterator {
                Box::new($crate::program::model::address::EmptyAddressIterator)
            }
            fn addresses_from(
                &self,
                _start: &$crate::program::model::address::Address,
                _forward: bool,
            ) -> $crate::program::model::address::BoxedAddressIterator {
                Box::new($crate::program::model::address::EmptyAddressIterator)
            }
            fn intersects_set(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> bool {
                false
            }
            fn intersects_range(
                &self,
                _start: &$crate::program::model::address::Address,
                _end: &$crate::program::model::address::Address,
            ) -> bool {
                false
            }
            fn intersect(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> $crate::program::model::address::AddressSet {
                $crate::program::model::address::AddressSet::new()
            }
            fn intersect_range(
                &self,
                _start: &$crate::program::model::address::Address,
                _end: &$crate::program::model::address::Address,
            ) -> $crate::program::model::address::AddressSet {
                $crate::program::model::address::AddressSet::new()
            }
            fn union(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> $crate::program::model::address::AddressSet {
                $crate::program::model::address::AddressSet::new()
            }
            fn subtract(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> $crate::program::model::address::AddressSet {
                $crate::program::model::address::AddressSet::new()
            }
            fn xor(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> $crate::program::model::address::AddressSet {
                $crate::program::model::address::AddressSet::new()
            }
            fn has_same_addresses(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> bool {
                false
            }
            fn first_range(&self) -> Option<$crate::program::model::address::AddressRange> {
                None
            }
            fn last_range(&self) -> Option<$crate::program::model::address::AddressRange> {
                None
            }
            fn range_containing(
                &self,
                _address: &$crate::program::model::address::Address,
            ) -> Option<$crate::program::model::address::AddressRange> {
                None
            }
            fn find_first_address_in_common(
                &self,
                _set: &dyn $crate::program::model::address::AddressSetView,
            ) -> Option<$crate::program::model::address::Address> {
                None
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::block::code_block_reference::CodeBlockReference;
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    /// A `CodeBlock` backed by a single contiguous address range, proving `CodeBlock` is
    /// object-safe over a real `AddressSetView` implementation (not just the empty-mock stand-in
    /// used elsewhere) and that the default accessors derive real values from it.
    struct RangeBlock {
        start: Address,
        end: Address,
        sources: Vec<Address>,
    }

    impl AddressSetView for RangeBlock {
        fn contains(&self, address: &Address) -> bool {
            address.space() == self.start.space()
                && address >= &self.start
                && address <= &self.end
        }
        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.contains(start) && self.contains(end)
        }
        fn contains_set(&self, set: &dyn AddressSetView) -> bool {
            let mut ranges = set.address_ranges();
            while let Some(range) = ranges.next() {
                if !self.contains_range(range.min_address(), range.max_address()) {
                    return false;
                }
            }
            true
        }
        fn is_empty(&self) -> bool {
            false
        }
        fn min_address(&self) -> Option<Address> {
            Some(self.start.clone())
        }
        fn max_address(&self) -> Option<Address> {
            Some(self.end.clone())
        }
        fn num_address_ranges(&self) -> usize {
            1
        }
        fn address_ranges(&self) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn address_ranges_ordered(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn address_ranges_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn num_addresses(&self) -> u64 {
            (self.end.offset() - self.start.offset() + 1) as u64
        }
        fn addresses(&self, _forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not needed for this smoke test")
        }
        fn addresses_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not needed for this smoke test")
        }
        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn intersect(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!("not needed for this smoke test")
        }
        fn intersect_range(
            &self,
            _start: &Address,
            _end: &Address,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!("not needed for this smoke test")
        }
        fn union(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            unimplemented!("not needed for this smoke test")
        }
        fn subtract(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            unimplemented!("not needed for this smoke test")
        }
        fn xor(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            unimplemented!("not needed for this smoke test")
        }
        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
            unimplemented!("not needed for this smoke test")
        }
        fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
            unimplemented!("not needed for this smoke test")
        }
        fn range_containing(
            &self,
            _address: &Address,
        ) -> Option<crate::program::model::address::AddressRange> {
            unimplemented!("not needed for this smoke test")
        }
        fn find_first_address_in_common(&self, _set: &dyn AddressSetView) -> Option<Address> {
            unimplemented!("not needed for this smoke test")
        }
    }

    struct VecSourceIterator {
        sources: std::vec::IntoIter<Address>,
        block_end: Address,
    }

    impl CodeBlockReferenceIterator for VecSourceIterator {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            Ok(self.sources.as_slice().first().is_some())
        }
        fn next(&mut self) -> Result<Box<dyn CodeBlockReference>, CancelledException> {
            let source = self.sources.next().expect("has_next was checked");
            Ok(Box::new(FixedReference {
                source,
                destination: self.block_end.clone(),
            }))
        }
    }

    struct FixedReference {
        source: Address,
        destination: Address,
    }

    impl CodeBlockReference for FixedReference {
        fn get_source_address(&self) -> Address {
            self.source.clone()
        }
        fn get_destination_address(&self) -> Address {
            self.destination.clone()
        }
        fn get_flow_type(&self) -> Box<dyn FlowType> {
            Box::new(UnknownFlowType)
        }
        fn get_reference(&self) -> Address {
            self.destination.clone()
        }
        fn get_referent(&self) -> Address {
            self.source.clone()
        }
        fn get_destination_block(&self) -> Box<dyn CodeBlock> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_source_block(&self) -> Box<dyn CodeBlock> {
            unimplemented!("not needed for this smoke test")
        }
    }

    impl CodeBlock for RangeBlock {
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_sources(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            Ok(Box::new(VecSourceIterator {
                sources: self.sources.clone().into_iter(),
                block_end: self.end.clone(),
            }))
        }
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not needed for this smoke test")
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn defaults_derive_real_values_from_the_address_set_view_supertrait() {
        let space = ram_space();
        let start = Address::new(space.clone(), 0x400000);
        let end = Address::new(space.clone(), 0x400100);
        let block: Box<dyn CodeBlock> = Box::new(RangeBlock {
            start: start.clone(),
            end: end.clone(),
            sources: vec![],
        });

        assert_eq!(block.get_first_start_address(), start);
        assert_eq!(block.get_start_addresses(), vec![start.clone()]);
        assert_eq!(block.get_name(), start.to_string());
        assert!(!block.get_flow_type().is_call());
        assert!(block.contains(&start));
        assert!(!block.contains(&Address::new(space, 0x500000)));
    }

    #[test]
    fn get_num_sources_default_counts_the_source_iterator() {
        let space = ram_space();
        let start = Address::new(space.clone(), 0x400000);
        let end = Address::new(space.clone(), 0x400100);
        let block: Box<dyn CodeBlock> = Box::new(RangeBlock {
            start: start.clone(),
            end: end.clone(),
            sources: vec![
                Address::new(space.clone(), 0x100),
                Address::new(space.clone(), 0x200),
                Address::new(space, 0x300),
            ],
        });

        let count = block.get_num_sources(&DummyMonitor).unwrap();
        assert_eq!(count, 3);
    }

    impl_empty_address_set_view!(EmptyMockCodeBlock);

    struct EmptyMockCodeBlock;

    impl CodeBlock for EmptyMockCodeBlock {
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[test]
    fn bare_impl_over_empty_address_set_view_compiles_and_uses_empty_defaults() {
        let block: Box<dyn CodeBlock> = Box::new(EmptyMockCodeBlock);

        assert!(block.is_empty());
        assert!(block.get_start_addresses().is_empty());
        assert_eq!(block.get_name(), "");
        assert!(block.get_sources(&DummyMonitor).unwrap().has_next().is_ok());
    }
}
