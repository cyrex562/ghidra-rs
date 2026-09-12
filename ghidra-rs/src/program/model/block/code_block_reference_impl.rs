use std::rc::Rc;

use crate::program::model::address::{
    Address, AddressRange, AddressRangeIterator, AddressSet, AddressSetView, BoxedAddressIterator,
};
use crate::program::model::block::code_block::CodeBlock;
use crate::program::model::block::code_block_model::CodeBlockModel;
use crate::program::model::block::code_block_reference::CodeBlockReference;
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::seam_stubs::FlowType;
use crate::util::exception::CancelledException;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// Implements a [`CodeBlockReference`].
///
/// A `CodeBlockReference` represents the flow from one source block to a destination block,
/// including information about how flow occurs between the two blocks (JUMP, CALL, etc.).
///
/// The `reference` is the address in the destination block that is actually flowed to by some
/// instruction in the source block.
///
/// The `referent` is the address of the instruction in the source block that flows to the
/// destination block.
///
/// Port of `ghidra.program.model.block.CodeBlockReferenceImpl`.
///
/// ## `Rc` instead of `Box` for the known blocks
///
/// Java stores `source`/`destination` as plain `CodeBlock` object references and hands one back
/// (or looks one up on demand) from `getSourceBlock()`/`getDestinationBlock()` on every call --
/// Java references are handed out by alias, at no cost. The [`CodeBlockReference`] trait mirrors
/// the return value's *shape* (an owned `Box<dyn CodeBlock>`), but neither `CodeBlock` nor any of
/// its implementors are `Clone` (indeed, no concrete `CodeBlock` implementation exists yet at all
/// -- `CodeBlockImpl` is still unported), so a stored `Box<dyn CodeBlock>` could not be handed out
/// more than once. Storing the known block as `Rc<dyn CodeBlock>` instead lets it be shared
/// cheaply (bump the refcount) and re-wrapped in a fresh `Box` on each call, via the delegating
/// [`AddressSetView`]/[`CodeBlock`] impls for `Rc<dyn CodeBlock>` below -- observably equivalent to
/// Java's aliasing, even though the returned `Box` is a distinct wrapper each time.
///
/// The same reasoning applies to the stored `flow_type` (`Rc<dyn FlowType>` plus a delegating
/// impl), since [`CodeBlockReference::get_flow_type`] has the same "owned `Box`, no `Clone`"
/// shape.
pub struct CodeBlockReferenceImpl {
    /// Source block for this flow, if already known.
    source: Option<Rc<dyn CodeBlock>>,
    /// Destination block for this flow, if already known.
    destination: Option<Rc<dyn CodeBlock>>,
    /// How we flow to the block.
    flow_type: Rc<dyn FlowType>,
    /// The actual address in the destination block referenced by the instruction in the source
    /// block.
    reference: Address,
    /// The address of the instruction in the source block that causes flow to the destination
    /// block.
    referent: Address,
}

impl CodeBlockReferenceImpl {
    /// Constructs a `CodeBlockReferenceImpl`.
    ///
    /// Port of `CodeBlockReferenceImpl(CodeBlock source, CodeBlock destination, FlowType
    /// flowType, Address reference, Address referent)`. `source`/`destination` are `None` where
    /// Java would pass `null` (unknown up front, to be resolved lazily via the owning model).
    pub fn new(
        source: Option<Rc<dyn CodeBlock>>,
        destination: Option<Rc<dyn CodeBlock>>,
        flow_type: Rc<dyn FlowType>,
        reference: Address,
        referent: Address,
    ) -> Self {
        Self {
            source,
            destination,
            flow_type,
            reference,
            referent,
        }
    }

    /// Gets the block (source or destination). If the block is needed, assume we have
    /// `block_have` and compute `block_needed` using that block.
    ///
    /// Port of the private `CodeBlockReferenceImpl.getBlock(CodeBlock blockNeeded, CodeBlock
    /// blockHave, Address addrInBlock)`.
    fn get_block(
        block_needed: &Option<Rc<dyn CodeBlock>>,
        block_have: &Option<Rc<dyn CodeBlock>>,
        addr_in_block: &Address,
    ) -> Option<Rc<dyn CodeBlock>> {
        if let Some(block) = block_needed {
            return Some(block.clone());
        }

        // Java: `CodeBlockModel model = blockHave.getModel();` -- if the caller constructed this
        // reference with both `source` and `destination` unknown, Java would
        // NullPointerException dereferencing a null `blockHave` right here.
        let block_have = block_have.as_ref().unwrap_or_else(|| {
            panic!(
                "CodeBlockReferenceImpl::get_block: both source and destination are None; \
                 Java's getBlock() would NullPointerException calling blockHave.getModel() in \
                 this situation"
            )
        });
        let model = block_have.get_model();

        // Java: `model.getFirstCodeBlockContaining(addrInBlock, TaskMonitor.DUMMY)`, wrapped in
        // a try/catch whose comment reads "can't happen, dummy monitor can't be canceled" --
        // `DummyMonitor` never reports cancellation, so unwrapping here mirrors that guarantee.
        let found = model
            .get_first_code_block_containing(addr_in_block, &DummyMonitor)
            .expect("DummyMonitor never reports cancellation");

        match found {
            Some(block) => Some(Rc::from(block)),
            None => {
                // Java: "means that there wasn't a good source block there, make an invalid
                // source block" -- `if (model instanceof SimpleBlockModel) { blockNeeded =
                // ((SimpleBlockModel) model).createSimpleDataBlock(addrInBlock, addrInBlock); }`.
                //
                // `SimpleBlockModel::create_simple_data_block` (Java's private
                // `createSimpleDataBlock`) is explicitly *not* part of the ported
                // `SimpleBlockModel` trait -- see that module's docs: its private helpers are
                // "implementation details of a concrete implementor, not part of the trait
                // contract" -- so this fallback cannot be reproduced yet. Reporting `None` here
                // matches Java's own behavior for every model that *isn't* a `SimpleBlockModel`
                // (where `getSourceBlock`/`getDestinationBlock` can genuinely return `null`).
                None
            }
        }
    }

    fn resolve_source(&self) -> Option<Rc<dyn CodeBlock>> {
        Self::get_block(&self.source, &self.destination, &self.referent)
    }

    fn resolve_destination(&self) -> Option<Rc<dyn CodeBlock>> {
        Self::get_block(&self.destination, &self.source, &self.reference)
    }
}

impl CodeBlockReference for CodeBlockReferenceImpl {
    /// Port of `CodeBlockReferenceImpl.getSourceAddress()`.
    fn get_source_address(&self) -> Address {
        match self.resolve_source() {
            Some(block) => block.get_first_start_address(),
            None => self.referent.clone(),
        }
    }

    /// Port of `CodeBlockReferenceImpl.getDestinationAddress()`.
    fn get_destination_address(&self) -> Address {
        match self.resolve_destination() {
            Some(block) => block.get_first_start_address(),
            None => self.reference.clone(),
        }
    }

    /// Port of `CodeBlockReferenceImpl.getFlowType()`.
    fn get_flow_type(&self) -> Box<dyn FlowType> {
        Box::new(self.flow_type.clone())
    }

    /// Port of `CodeBlockReferenceImpl.getReference()`.
    fn get_reference(&self) -> Address {
        self.reference.clone()
    }

    /// Port of `CodeBlockReferenceImpl.getReferent()`.
    fn get_referent(&self) -> Address {
        self.referent.clone()
    }

    /// Port of `CodeBlockReferenceImpl.getDestinationBlock()`.
    ///
    /// Java's `getDestinationBlock()` can return `null` when no destination block was supplied
    /// and none could be resolved from the model (and the model isn't a `SimpleBlockModel`; see
    /// [`get_block`](Self::get_block)'s doc comment). [`CodeBlockReference::get_destination_block`]
    /// has no way to represent that (it returns an owned `Box<dyn CodeBlock>`, not an `Option`),
    /// so that case panics here instead of fabricating a block.
    fn get_destination_block(&self) -> Box<dyn CodeBlock> {
        let block: Rc<dyn CodeBlock> = self.resolve_destination().unwrap_or_else(|| {
            panic!(
                "CodeBlockReferenceImpl::get_destination_block: no destination block is known \
                 and none could be resolved; Java's CodeBlockReference#getDestinationBlock() can \
                 return null here (see get_block's doc comment)"
            )
        });
        Box::new(block)
    }

    /// Port of `CodeBlockReferenceImpl.getSourceBlock()`.
    ///
    /// See [`get_destination_block`](Self::get_destination_block)'s doc comment: the analogous
    /// unresolvable case panics here for the same reason.
    fn get_source_block(&self) -> Box<dyn CodeBlock> {
        let block: Rc<dyn CodeBlock> = self.resolve_source().unwrap_or_else(|| {
            panic!(
                "CodeBlockReferenceImpl::get_source_block: no source block is known and none \
                 could be resolved; Java's CodeBlockReference#getSourceBlock() can return null \
                 here (see get_block's doc comment)"
            )
        });
        Box::new(block)
    }
}

impl std::fmt::Display for CodeBlockReferenceImpl {
    /// Port of `CodeBlockReferenceImpl.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.referent, self.reference)
    }
}

// --- `Rc<dyn CodeBlock>` / `Rc<dyn FlowType>` delegation ---------------------------------------
//
// See the "Rc instead of Box" section of `CodeBlockReferenceImpl`'s doc comment above for why
// these exist: they let an `Rc`-shared value satisfy a trait whose object-safe methods return an
// owned `Box` of that same trait, by forwarding every method to the shared pointee.

impl AddressSetView for Rc<dyn CodeBlock> {
    fn contains(&self, address: &Address) -> bool {
        (**self).contains(address)
    }
    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        (**self).contains_range(start, end)
    }
    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        (**self).contains_set(set)
    }
    fn is_empty(&self) -> bool {
        (**self).is_empty()
    }
    fn min_address(&self) -> Option<Address> {
        (**self).min_address()
    }
    fn max_address(&self) -> Option<Address> {
        (**self).max_address()
    }
    fn num_address_ranges(&self) -> usize {
        (**self).num_address_ranges()
    }
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        (**self).address_ranges()
    }
    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        (**self).address_ranges_ordered(forward)
    }
    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        (**self).address_ranges_from(start, forward)
    }
    fn num_addresses(&self) -> u64 {
        (**self).num_addresses()
    }
    fn addresses(&self, forward: bool) -> BoxedAddressIterator {
        (**self).addresses(forward)
    }
    fn addresses_from(&self, start: &Address, forward: bool) -> BoxedAddressIterator {
        (**self).addresses_from(start, forward)
    }
    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        (**self).intersects_set(set)
    }
    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        (**self).intersects_range(start, end)
    }
    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
        (**self).intersect(set)
    }
    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        (**self).intersect_range(start, end)
    }
    fn union(&self, set: &dyn AddressSetView) -> AddressSet {
        (**self).union(set)
    }
    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
        (**self).subtract(set)
    }
    fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
        (**self).xor(set)
    }
    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        (**self).has_same_addresses(set)
    }
    fn first_range(&self) -> Option<AddressRange> {
        (**self).first_range()
    }
    fn last_range(&self) -> Option<AddressRange> {
        (**self).last_range()
    }
    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        (**self).range_containing(address)
    }
    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        (**self).find_first_address_in_common(set)
    }
}

impl CodeBlock for Rc<dyn CodeBlock> {
    fn get_first_start_address(&self) -> Address {
        (**self).get_first_start_address()
    }
    fn get_start_addresses(&self) -> Vec<Address> {
        (**self).get_start_addresses()
    }
    fn get_name(&self) -> String {
        (**self).get_name()
    }
    fn get_flow_type(&self) -> Box<dyn FlowType> {
        (**self).get_flow_type()
    }
    fn get_num_sources(&self, monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
        (**self).get_num_sources(monitor)
    }
    fn get_sources(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
        (**self).get_sources(monitor)
    }
    fn get_num_destinations(&self, monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
        (**self).get_num_destinations(monitor)
    }
    fn get_destinations(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
        (**self).get_destinations(monitor)
    }
    fn get_model(&self) -> Box<dyn CodeBlockModel> {
        (**self).get_model()
    }
}

impl FlowType for Rc<dyn FlowType> {
    fn is_call(&self) -> bool {
        (**self).is_call()
    }
    fn is_jump(&self) -> bool {
        (**self).is_jump()
    }
    fn is_fallthrough(&self) -> bool {
        (**self).is_fallthrough()
    }
    fn is_indirect(&self) -> bool {
        (**self).is_indirect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::block::code_block_iterator::CodeBlockIterator;
    use std::panic;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// A minimal `CodeBlock` with a single, fixed start address, optionally reporting a model
    /// to resolve lookups through. Every member not exercised by the tests below panics with
    /// `unimplemented!()`, matching this crate's established mock style (see e.g.
    /// `overlap_code_sub_model.rs`'s `TaggedListing`).
    struct FixedBlock {
        start: Address,
        model: Option<Rc<StubModel>>,
    }

    impl AddressSetView for FixedBlock {
        fn contains(&self, _address: &Address) -> bool {
            unimplemented!()
        }
        fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
            unimplemented!()
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!()
        }
        fn is_empty(&self) -> bool {
            false
        }
        fn min_address(&self) -> Option<Address> {
            Some(self.start.clone())
        }
        fn max_address(&self) -> Option<Address> {
            Some(self.start.clone())
        }
        fn num_address_ranges(&self) -> usize {
            unimplemented!()
        }
        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            unimplemented!()
        }
        fn address_ranges_ordered(&self, _forward: bool) -> Box<dyn AddressRangeIterator> {
            unimplemented!()
        }
        fn address_ranges_from(&self, _start: &Address, _forward: bool) -> Box<dyn AddressRangeIterator> {
            unimplemented!()
        }
        fn num_addresses(&self) -> u64 {
            unimplemented!()
        }
        fn addresses(&self, _forward: bool) -> BoxedAddressIterator {
            unimplemented!()
        }
        fn addresses_from(&self, _start: &Address, _forward: bool) -> BoxedAddressIterator {
            unimplemented!()
        }
        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!()
        }
        fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
            unimplemented!()
        }
        fn intersect(&self, _set: &dyn AddressSetView) -> AddressSet {
            unimplemented!()
        }
        fn intersect_range(&self, _start: &Address, _end: &Address) -> AddressSet {
            unimplemented!()
        }
        fn union(&self, _set: &dyn AddressSetView) -> AddressSet {
            unimplemented!()
        }
        fn subtract(&self, _set: &dyn AddressSetView) -> AddressSet {
            unimplemented!()
        }
        fn xor(&self, _set: &dyn AddressSetView) -> AddressSet {
            unimplemented!()
        }
        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!()
        }
        fn first_range(&self) -> Option<AddressRange> {
            unimplemented!()
        }
        fn last_range(&self) -> Option<AddressRange> {
            unimplemented!()
        }
        fn range_containing(&self, _address: &Address) -> Option<AddressRange> {
            unimplemented!()
        }
        fn find_first_address_in_common(&self, _set: &dyn AddressSetView) -> Option<Address> {
            unimplemented!()
        }
    }

    impl CodeBlock for FixedBlock {
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            match &self.model {
                Some(model) => Box::new(StubModelHandle(model.clone())),
                None => unimplemented!("FixedBlock has no configured model"),
            }
        }
    }

    /// A `CodeBlockModel` whose only meaningfully-implemented member is
    /// [`get_first_code_block_containing`](CodeBlockModel::get_first_code_block_containing),
    /// which reports whatever block (if any) was configured for a given address. Used to drive
    /// `CodeBlockReferenceImpl::get_block`'s model-lookup fallback path.
    struct StubModel {
        found_at: Option<(Address, Address)>, // (query address, resolved block's start address)
    }

    /// `CodeBlockModel::get_model` must return an owned `Box`; this wraps a shared `StubModel`
    /// so the same configuration can be handed out more than once without requiring `StubModel`
    /// itself to be `Clone`.
    struct StubModelHandle(Rc<StubModel>);

    impl CodeBlockModel for StubModelHandle {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn get_code_block_at(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!()
        }
        fn get_first_code_block_containing(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            match &self.0.found_at {
                Some((query, start)) if query == addr => Ok(Some(Box::new(FixedBlock {
                    start: start.clone(),
                    model: None,
                }))),
                _ => Ok(None),
            }
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!()
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!()
        }
        fn get_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }
        fn get_num_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }
        fn get_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }
        fn get_num_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!()
        }
        fn get_flow_type(&self, _block: &dyn CodeBlock) -> Box<dyn FlowType> {
            unimplemented!()
        }
        fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
            unimplemented!()
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }
    }

    struct AlwaysCall;
    impl FlowType for AlwaysCall {
        fn is_call(&self) -> bool {
            true
        }
    }

    #[test]
    fn known_blocks_are_returned_repeatedly_without_being_consumed() {
        let space = ram_space();
        let source_start = addr(&space, 0x1000);
        let dest_start = addr(&space, 0x2000);
        let referent = addr(&space, 0x1004);
        let reference = addr(&space, 0x2000);

        let source = Rc::new(FixedBlock { start: source_start.clone(), model: None }) as Rc<dyn CodeBlock>;
        let destination = Rc::new(FixedBlock { start: dest_start.clone(), model: None }) as Rc<dyn CodeBlock>;

        let reference_impl = CodeBlockReferenceImpl::new(
            Some(source),
            Some(destination),
            Rc::new(AlwaysCall),
            reference.clone(),
            referent.clone(),
        );

        // Calling the accessors more than once must keep working: nothing gets consumed.
        for _ in 0..2 {
            assert_eq!(
                reference_impl.get_source_block().get_first_start_address().offset(),
                source_start.offset()
            );
            assert_eq!(
                reference_impl.get_destination_block().get_first_start_address().offset(),
                dest_start.offset()
            );
        }
        assert_eq!(reference_impl.get_source_address().offset(), source_start.offset());
        assert_eq!(reference_impl.get_destination_address().offset(), dest_start.offset());
        assert_eq!(reference_impl.get_reference().offset(), reference.offset());
        assert_eq!(reference_impl.get_referent().offset(), referent.offset());
        assert!(reference_impl.get_flow_type().is_call());
    }

    #[test]
    fn unknown_block_resolves_via_model_lookup() {
        let space = ram_space();
        let source_start = addr(&space, 0x1000);
        let referent = addr(&space, 0x1004);
        let reference = addr(&space, 0x2000); // the destination's entry point, per Java's field doc
        let resolved_dest_start = addr(&space, 0x1fff); // model resolves to the block containing `reference`

        let model = Rc::new(StubModel {
            found_at: Some((reference.clone(), resolved_dest_start.clone())),
        });
        let source = Rc::new(FixedBlock {
            start: source_start,
            model: Some(model),
        }) as Rc<dyn CodeBlock>;

        let reference_impl = CodeBlockReferenceImpl::new(
            Some(source),
            None, // destination unknown -- resolved via source's model
            Rc::new(AlwaysCall),
            reference.clone(),
            referent,
        );

        let destination_block = reference_impl.get_destination_block();
        assert_eq!(
            destination_block.get_first_start_address().offset(),
            resolved_dest_start.offset()
        );
        assert_eq!(
            reference_impl.get_destination_address().offset(),
            resolved_dest_start.offset()
        );
    }

    #[test]
    fn unresolvable_destination_falls_back_to_reference_address_but_block_accessor_panics() {
        let space = ram_space();
        let source_start = addr(&space, 0x1000);
        let referent = addr(&space, 0x1004);
        let reference = addr(&space, 0x2000);

        // Model finds nothing at `reference`, and (per get_block's doc comment) the
        // SimpleBlockModel fallback isn't modeled, so resolution genuinely fails.
        let model = Rc::new(StubModel { found_at: None });
        let source = Rc::new(FixedBlock {
            start: source_start,
            model: Some(model),
        }) as Rc<dyn CodeBlock>;

        let reference_impl = CodeBlockReferenceImpl::new(
            Some(source),
            None,
            Rc::new(AlwaysCall),
            reference.clone(),
            referent,
        );

        // get_destination_address gracefully falls back to `reference`, exactly like Java's
        // `getDestinationAddress()` falling back to the `reference` field.
        assert_eq!(
            reference_impl.get_destination_address().offset(),
            reference.offset()
        );

        // get_destination_block has no `null` to return, so it panics -- verify that specific
        // call panics (not merely that a panic occurs somewhere in this test), per this repo's
        // #[should_panic] caution.
        let panicked = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            reference_impl.get_destination_block();
        }))
        .is_err();
        assert!(panicked, "get_destination_block should panic when unresolvable");
    }

    #[test]
    fn both_blocks_unknown_panics_like_javas_null_pointer_exception() {
        let space = ram_space();
        let reference = addr(&space, 0x2000);
        let referent = addr(&space, 0x1000);

        let reference_impl = CodeBlockReferenceImpl::new(
            None,
            None,
            Rc::new(AlwaysCall),
            reference,
            referent,
        );

        // Java: `getBlock(source, destination, referent)` with both `source` and `destination`
        // null dereferences `blockHave.getModel()` on a null reference -- an NPE. Verify the
        // *specific* call panics.
        let panicked = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            reference_impl.get_source_block();
        }))
        .is_err();
        assert!(panicked, "get_source_block should panic when both blocks are unknown");
    }

    #[test]
    fn display_matches_java_to_string() {
        let space = ram_space();
        let reference = addr(&space, 0x2000);
        let referent = addr(&space, 0x1000);

        let reference_impl = CodeBlockReferenceImpl::new(
            None,
            None,
            Rc::new(AlwaysCall),
            reference.clone(),
            referent.clone(),
        );

        // Port of `CodeBlockReferenceImpl.toString()`: `return referent + " -> " + reference;`
        assert_eq!(
            format!("{}", reference_impl),
            format!("{} -> {}", referent, reference)
        );
    }
}
