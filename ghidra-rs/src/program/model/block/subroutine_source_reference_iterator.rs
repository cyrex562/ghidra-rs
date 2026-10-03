use std::collections::VecDeque;
use std::rc::Rc;

use crate::program::model::address::Address;
use crate::program::model::block::code_block::CodeBlock;
use crate::program::model::block::code_block_model::CodeBlockModel;
use crate::program::model::block::code_block_reference::CodeBlockReference;
use crate::program::model::block::code_block_reference_impl::CodeBlockReferenceImpl;
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::seam_stubs::FlowType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A unidirectional iterator over the source [`CodeBlockReference`]s for a [`CodeBlock`]
/// representing a subroutine (as obtained from a `SubroutineBlockModel`).
///
/// Port of `ghidra.program.model.block.SubroutineSourceReferenceIterator`. Unlike
/// [`SubroutineDestReferenceIterator`](crate::program::model::block::subroutine_dest_reference_iterator::SubroutineDestReferenceIterator)
/// (ported earlier in this package as a marker trait only, because
/// [`CodeBlockReferenceImpl`] and [`CodeBlockModel::get_first_code_block_containing`] weren't
/// available yet), this class is ported as a full concrete struct: both of those are now ported,
/// so the private `getSources`/`queueSrcReferences` algorithm that actually populates the queue
/// of `CodeBlockReference`s is faithfully reproduced below, not just its public
/// `getNumSources` counting helper.
///
/// ## `Rc<dyn CodeBlock>` for the subroutine block
///
/// Java's constructor takes a plain `CodeBlock block` reference and aliases it freely: it's
/// stored implicitly (via closures over local variables during construction) and handed to every
/// `CodeBlockReferenceImpl` constructed along the way as `destBlock`. [`CodeBlockReferenceImpl`]
/// mirrors that aliasing in Rust via `Rc<dyn CodeBlock>` (see its own doc comment), so
/// [`new`](Self::new) takes `block` as `Rc<dyn CodeBlock>` too, to share it into every reference
/// queued without cloning the underlying block itself.
///
/// The public static [`get_num_sources`] helper never constructs a `CodeBlockReferenceImpl` (Java
/// calls the same private `getSources`/`queueSrcReferences` with a `null` queue, which skips
/// every block that would be constructed), so it never needs that sharing and keeps taking a
/// plain `&dyn CodeBlock`, matching the shape already established by
/// [`get_num_destinations`](crate::program::model::block::subroutine_dest_reference_iterator::get_num_destinations).
/// It is implemented as an independent counting-only walk ([`count_sources`]/
/// [`count_src_references`]) rather than by threading an `Option` queue through the real
/// `get_sources`/`queue_src_references`, since Rust's ownership rules would otherwise force even
/// pure counting callers to supply an `Rc` they may not have, for a queue they don't want.
pub struct SubroutineSourceReferenceIterator {
    /// Queue of discovered source block references.
    block_ref_queue: VecDeque<Box<dyn CodeBlockReference>>,

    /// Task monitor which allows the user to cancel the operation.
    ///
    /// `None` here matches Java's constructor storing a possibly-null `monitor` unconditionally
    /// (`this.monitor = monitor;`, with no `!= null` fallback) -- see [`new`](Self::new) and
    /// [`check_monitor`](Self::check_monitor)'s doc comments for the resulting quirk.
    monitor: Option<Box<dyn TaskMonitor>>,
}

impl SubroutineSourceReferenceIterator {
    /// Construct an iterator over source blocks for a `CodeBlock`.
    ///
    /// Port of `SubroutineSourceReferenceIterator(CodeBlock block, TaskMonitor monitor)`.
    /// `block` being `None` mirrors a `null` `block` argument in Java (see
    /// [`get_sources`]'s `block == null` check, which this short-circuits before calling).
    ///
    /// ## Java quirk: constructing with a `None` monitor can silently succeed
    ///
    /// Java's constructor body is exactly:
    /// ```java
    /// this.monitor = monitor;
    /// getSources(block, blockRefQueue, monitor);
    /// ```
    /// There is no `monitor != null ? monitor : TaskMonitor.DUMMY` fallback (unlike, e.g.,
    /// `SingleEntSubIterator`'s single-arg constructor). If `block` is `null`, or has no minimum
    /// address, `getSources` returns immediately (`if (block == null || block.getMinAddress() ==
    /// null) return 0;`) without ever dereferencing `monitor` -- so a `null` monitor is perfectly
    /// safe to pass *in that case*, and the constructor completes normally, storing the null
    /// monitor in `this.monitor`.
    ///
    /// The catch (mirrored by [`check_monitor`](Self::check_monitor)) is that `hasNext()`/
    /// `next()` call `monitor.checkCancelled()` *unconditionally*, with no null check of their
    /// own -- so an iterator constructed this way blows up with a `NullPointerException` the
    /// first time either is called, even though construction itself raised nothing. This is
    /// reproduced here by storing `monitor` as-is (`Option<Box<dyn TaskMonitor>>`, no fallback)
    /// and having [`check_monitor`](Self::check_monitor) panic on `None` instead of silently
    /// substituting a dummy monitor. See
    /// `monitor_none_with_short_circuited_block_panics_on_first_has_next_call` below.
    ///
    /// If `block` is `Some` and has a minimum address, `get_sources` genuinely needs a monitor
    /// to drive the underlying model calls; a `None` monitor panics right here in the
    /// constructor in that case, standing in for the `NullPointerException` Java would raise the
    /// moment it dereferences the null monitor while iterating basic blocks.
    pub fn new(
        block: Option<Rc<dyn CodeBlock>>,
        monitor: Option<Box<dyn TaskMonitor>>,
    ) -> Result<Self, CancelledException> {
        let mut block_ref_queue = VecDeque::new();

        if let Some(block) = block.as_ref() {
            if block.min_address().is_some() {
                let monitor_ref: &dyn TaskMonitor = monitor.as_deref().unwrap_or_else(|| {
                    panic!(
                        "SubroutineSourceReferenceIterator::new: monitor is None but block is \
                         Some with a minimum address; Java's constructor stores a possibly-null \
                         monitor unconditionally and getSources() would \
                         NullPointerException once it dereferences it while iterating basic \
                         blocks"
                    )
                });
                get_sources(block, &mut block_ref_queue, monitor_ref)?;
            }
        }

        Ok(Self {
            block_ref_queue,
            monitor,
        })
    }

    /// Port of `SubroutineSourceReferenceIterator.hasNext()`/`next()`'s shared
    /// `monitor.checkCancelled()` call. See [`new`](Self::new)'s doc comment for why `monitor`
    /// can be `None` here, and why that's a real (if narrow) Java NullPointerException risk
    /// rather than something to paper over.
    fn check_monitor(&self) -> Result<(), CancelledException> {
        match &self.monitor {
            Some(monitor) => monitor.check_cancelled(),
            None => panic!(
                "SubroutineSourceReferenceIterator::{{has_next,next}}: monitor is None; Java's \
                 hasNext()/next() call monitor.checkCancelled() unconditionally with no null \
                 check, which would NullPointerException here"
            ),
        }
    }
}

impl CodeBlockReferenceIterator for SubroutineSourceReferenceIterator {
    /// Port of `SubroutineSourceReferenceIterator.hasNext()`.
    fn has_next(&mut self) -> Result<bool, CancelledException> {
        self.check_monitor()?;
        Ok(!self.block_ref_queue.is_empty())
    }

    /// Port of `SubroutineSourceReferenceIterator.next()`.
    ///
    /// Java returns `null` once the queue is empty (`return blockRefQueue.isEmpty() ? null :
    /// blockRefQueue.removeFirst();`); this trait's `next()` has no way to represent that (it
    /// returns `Result<Box<dyn CodeBlockReference>, CancelledException>`, not an `Option`), so it
    /// reports a `CancelledException` instead, matching the convention already established by
    /// this trait's own doc-test (`CountingCodeBlockReferenceIterator`) and by
    /// `SingleEntSubIterator::next()`.
    fn next(&mut self) -> Result<Box<dyn CodeBlockReference>, CancelledException> {
        self.check_monitor()?;
        self.block_ref_queue.pop_front().ok_or_else(|| {
            CancelledException(
                "SubroutineSourceReferenceIterator::next called with no more elements"
                    .to_string(),
            )
        })
    }
}

/// Get the number of source references flowing into this subroutine (block). All calls to this
/// block, and all external `FlowType` block references to this block, are counted.
///
/// Port of `SubroutineSourceReferenceIterator.getNumSources(CodeBlock, TaskMonitor)`. `block`
/// being `None`/having no minimum address mirrors `block == null || block.getMinAddress() ==
/// null` in Java's shared `getSources` helper.
pub fn get_num_sources(
    block: Option<&dyn CodeBlock>,
    monitor: &dyn TaskMonitor,
) -> Result<i32, CancelledException> {
    let Some(block) = block else {
        return Ok(0);
    };
    if block.min_address().is_none() {
        return Ok(0);
    }
    count_sources(block, monitor)
}

/// Populate `block_ref_queue` with every source [`CodeBlockReference`] flowing into `block` (a
/// subroutine), returning the number queued.
///
/// Port of the private `SubroutineSourceReferenceIterator.getSources(CodeBlock, List,
/// TaskMonitor)`, specialized to the case where `block` is already known to be non-null with a
/// real minimum address (callers -- just [`SubroutineSourceReferenceIterator::new`] -- perform
/// that check themselves so they can decide whether touching `monitor` at all is safe; see
/// [`new`](SubroutineSourceReferenceIterator::new)'s doc comment) and where a real queue is
/// always supplied (see [`count_sources`] for the `null`-queue counting counterpart).
fn get_sources(
    block: &Rc<dyn CodeBlock>,
    block_ref_queue: &mut VecDeque<Box<dyn CodeBlockReference>>,
    monitor: &dyn TaskMonitor,
) -> Result<i32, CancelledException> {
    let mut count = 0;
    let model = block.get_model();

    // Iterate over all basic blocks within the specified block.
    let mut bblock_iter = model
        .get_basic_block_model()
        .get_code_blocks_containing(&**block, monitor)?;
    while bblock_iter.has_next()? {
        // Get the next basic block.
        let bblock = bblock_iter.next()?;

        // Get the basic block's sources.
        let mut bb_src_iter = bblock.get_sources(monitor)?;
        while bb_src_iter.has_next()? {
            let bb_src_ref = bb_src_iter.next()?;
            let ref_flow_type = bb_src_ref.get_flow_type();

            if ref_flow_type.is_call() {
                // Add all forward CALL references to the queue.
                count += queue_src_references(
                    block_ref_queue,
                    block,
                    bb_src_ref.get_reference(),
                    bb_src_ref.get_referent(),
                    Rc::from(ref_flow_type),
                    monitor,
                )?;
            } else if ref_flow_type.is_jump() || ref_flow_type.is_fallthrough() {
                // Add external JUMP and FALL-THROUGH references to the queue.
                let src_addr = bb_src_ref.get_referent();
                if !block.contains(&src_addr)
                    && model
                        .get_first_code_block_containing(&src_addr, monitor)?
                        .is_some()
                {
                    count += queue_src_references(
                        block_ref_queue,
                        block,
                        bb_src_ref.get_reference(),
                        src_addr,
                        Rc::from(ref_flow_type),
                        monitor,
                    )?;
                }
            }
        }
    }
    Ok(count)
}

/// Create source block reference(s) and add them to `block_ref_queue` if a block is found at
/// `src_addr`. A valid block must exist at `src_addr` for the reference(s) to be counted.
///
/// Port of the private `SubroutineSourceReferenceIterator.queueSrcReferences(List, CodeBlock,
/// Address, Address, FlowType, TaskMonitor)`, specialized to the case where `block_ref_queue` is
/// always a real queue (see [`get_sources`]'s doc comment; the `null`-queue case is handled
/// separately by [`count_src_references`]).
fn queue_src_references(
    block_ref_queue: &mut VecDeque<Box<dyn CodeBlockReference>>,
    dest_block: &Rc<dyn CodeBlock>,
    dest_addr: Address,
    src_addr: Address,
    flow_type: Rc<dyn FlowType>,
    monitor: &dyn TaskMonitor,
) -> Result<i32, CancelledException> {
    let model = dest_block.get_model();

    if model.allows_block_overlap() {
        let src_blocks = model.get_code_blocks_containing_addr(&src_addr, monitor)?;
        let cnt = src_blocks.len() as i32;
        for src_block in src_blocks {
            // Non-block references are lost since they don't have a corresponding code block
            // (matches the Java `// ?? ...` comment at this call site).
            let block_ref = CodeBlockReferenceImpl::new(
                Some(Rc::from(src_block)),
                Some(dest_block.clone()),
                flow_type.clone(),
                dest_addr.clone(),
                src_addr.clone(),
            );
            block_ref_queue.push_back(Box::new(block_ref));
        }
        if cnt != 0 {
            return Ok(cnt);
        }
    }

    let block_ref = CodeBlockReferenceImpl::new(
        None,
        Some(dest_block.clone()),
        flow_type,
        dest_addr,
        src_addr,
    );
    block_ref_queue.push_back(Box::new(block_ref));
    Ok(1)
}

/// Counting-only counterpart of [`get_sources`], used by [`get_num_sources`]. Mirrors Java's
/// `getSources`/`queueSrcReferences` being invoked with a `null` `blockRefQueue`: no
/// `CodeBlockReferenceImpl` is ever constructed on this path, so `block` never needs to be
/// shared via `Rc` here (only [`SubroutineSourceReferenceIterator::new`], which does construct
/// real references, needs that).
fn count_sources(block: &dyn CodeBlock, monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
    let mut count = 0;
    let model = block.get_model();

    let mut bblock_iter = model
        .get_basic_block_model()
        .get_code_blocks_containing(block, monitor)?;
    while bblock_iter.has_next()? {
        let bblock = bblock_iter.next()?;

        let mut bb_src_iter = bblock.get_sources(monitor)?;
        while bb_src_iter.has_next()? {
            let bb_src_ref = bb_src_iter.next()?;
            let ref_flow_type = bb_src_ref.get_flow_type();

            if ref_flow_type.is_call() {
                count += count_src_references(block, &bb_src_ref.get_referent(), monitor)?;
            } else if ref_flow_type.is_jump() || ref_flow_type.is_fallthrough() {
                let src_addr = bb_src_ref.get_referent();
                if !block.contains(&src_addr)
                    && model
                        .get_first_code_block_containing(&src_addr, monitor)?
                        .is_some()
                {
                    count += count_src_references(block, &src_addr, monitor)?;
                }
            }
        }
    }
    Ok(count)
}

/// Counting-only counterpart of [`queue_src_references`], used by [`count_sources`].
fn count_src_references(
    dest_block: &dyn CodeBlock,
    src_addr: &Address,
    monitor: &dyn TaskMonitor,
) -> Result<i32, CancelledException> {
    let model = dest_block.get_model();
    if model.allows_block_overlap() {
        let cnt = model.get_code_blocks_containing_addr(src_addr, monitor)?.len() as i32;
        if cnt != 0 {
            return Ok(cnt);
        }
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::block::code_block_iterator::CodeBlockIterator;
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
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

    /// A single incoming flow into a basic block, carrying the flow type plus the reference
    /// (address in the destination actually flowed to) and referent (address of the flowing
    /// instruction) that `get_sources`'s loop reads off each `CodeBlockReference`.
    struct MockCodeBlockReference {
        flow_type: Flow,
        reference: Address,
        referent: Address,
    }

    impl CodeBlockReference for MockCodeBlockReference {
        fn get_source_address(&self) -> Address {
            self.referent.clone()
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
            self.referent.clone()
        }
        fn get_destination_block(&self) -> Box<dyn CodeBlock> {
            unimplemented!("not read by get_sources/get_num_sources")
        }
        fn get_source_block(&self) -> Box<dyn CodeBlock> {
            unimplemented!("not read by get_sources/get_num_sources")
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

    /// A basic block spanning `[start, end)` with a fixed list of incoming flows, each
    /// originating at a source address. Stands in for `SimpleBlock`.
    #[derive(Clone)]
    struct BasicBlock {
        start: i64,
        end: i64,
        sources: Vec<(Flow, Address, Address)>, // (flow, reference, referent)
        space: Arc<AddressSpace>,
    }

    impl AddressSetView for BasicBlock {
        fn contains(&self, address: &Address) -> bool {
            Arc::ptr_eq(address.space(), &self.space)
                && address.offset() >= self.start
                && address.offset() < self.end
        }
        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.contains(start) && self.contains(end)
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn is_empty(&self) -> bool {
            self.start >= self.end
        }
        fn min_address(&self) -> Option<Address> {
            Some(Address::new(self.space.clone(), self.start))
        }
        fn max_address(&self) -> Option<Address> {
            Some(Address::new(self.space.clone(), self.end - 1))
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
            (self.end - self.start) as u64
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
        fn intersect(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
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

    impl CodeBlock for BasicBlock {
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("basic blocks are only iterated over, never re-modeled")
        }
        fn get_sources(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            let refs = self
                .sources
                .iter()
                .map(|(flow, reference, referent)| MockCodeBlockReference {
                    flow_type: *flow,
                    reference: reference.clone(),
                    referent: referent.clone(),
                })
                .collect::<Vec<_>>();
            Ok(Box::new(VecCodeBlockReferenceIterator {
                refs: refs.into_iter(),
            }))
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
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

    /// A block found at a fixed address by [`SubroutineModel::get_first_code_block_containing`]
    /// or returned by [`SubroutineModel::get_code_blocks_containing_addr`], carrying just a start
    /// address (enough to drive `CodeBlockReferenceImpl::get_source_address`'s model-lookup
    /// fallback).
    struct FoundBlock {
        start: Address,
    }

    // `min_address` must report the real `start` (used by `CodeBlock::get_first_start_address`'s
    // default), so this can't use the `impl_empty_address_set_view!` macro (whose `min_address`
    // always returns `None`); every other member is still just an always-empty/unimplemented
    // stand-in, since nothing else about this block is exercised by the tests below.
    impl AddressSetView for FoundBlock {
        fn contains(&self, address: &Address) -> bool {
            address == &self.start
        }
        fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not needed for this smoke test")
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
            1
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
        fn intersect(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
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

    impl CodeBlock for FoundBlock {
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// A subroutine block model backed by a fixed list of basic blocks, reporting itself as its
    /// own "basic block model" the way a single-layer block model would, and able to resolve
    /// `get_first_code_block_containing`/`get_code_blocks_containing_addr` against a small fixed
    /// address -> block table.
    #[derive(Clone)]
    struct SubroutineModel {
        basic_blocks: Vec<BasicBlock>,
        allow_overlap: bool,
        /// (query address, resolved block start addresses) -- `get_first_code_block_containing`
        /// reports the first entry, `get_code_blocks_containing_addr` reports all of them.
        found_at: Vec<(Address, Vec<Address>)>,
    }

    impl SubroutineModel {
        fn lookup(&self, addr: &Address) -> Vec<Address> {
            self.found_at
                .iter()
                .find(|(query, _)| query == addr)
                .map(|(_, starts)| starts.clone())
                .unwrap_or_default()
        }
    }

    impl CodeBlockModel for SubroutineModel {
        fn get_name(&self) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_block_at(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_first_code_block_containing(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            Ok(self
                .lookup(addr)
                .into_iter()
                .next()
                .map(|start| Box::new(FoundBlock { start }) as Box<dyn CodeBlock>))
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
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
        fn get_code_blocks_containing_addr(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<Box<dyn CodeBlock>>, CancelledException> {
            Ok(self
                .lookup(addr)
                .into_iter()
                .map(|start| Box::new(FoundBlock { start }) as Box<dyn CodeBlock>)
                .collect())
        }
        fn get_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_num_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_num_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_flow_type(&self, _block: &dyn CodeBlock) -> Box<dyn FlowType> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not needed for this smoke test")
        }
        fn allows_block_overlap(&self) -> bool {
            self.allow_overlap
        }
    }

    /// The subroutine-level `CodeBlock` handed to `get_sources`/`get_num_sources`, spanning the
    /// union of its basic blocks and reporting `model` from `get_model`.
    struct SubroutineBlock {
        start: i64,
        end: i64,
        space: Arc<AddressSpace>,
        model: SubroutineModel,
    }

    impl AddressSetView for SubroutineBlock {
        fn contains(&self, address: &Address) -> bool {
            Arc::ptr_eq(address.space(), &self.space)
                && address.offset() >= self.start
                && address.offset() < self.end
        }
        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.contains(start) && self.contains(end)
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn is_empty(&self) -> bool {
            self.start >= self.end
        }
        fn min_address(&self) -> Option<Address> {
            Some(Address::new(self.space.clone(), self.start))
        }
        fn max_address(&self) -> Option<Address> {
            Some(Address::new(self.space.clone(), self.end - 1))
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
            (self.end - self.start) as u64
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
        fn intersect(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
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

    impl CodeBlock for SubroutineBlock {
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            Box::new(self.model.clone())
        }
        fn get_sources(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unreachable!("get_sources/get_num_sources only query sources of basic blocks")
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// A subroutine `[0x1000, 0x2000)` made of two basic blocks with a mix of internal/external,
    /// call/jump/fallthrough flows: a call (always counted, source unresolvable), an internal
    /// jump (never counted, filtered by the `block.contains(srcAddr)` check), a forward jump
    /// entering from outside the subroutine (counted, source resolvable), an internal
    /// fallthrough (never counted, same `contains` filter), and a forward fallthrough entering
    /// from outside with no block found there at all (never counted, mirroring Java's
    /// `model.getFirstCodeBlockContaining(srcAddr, monitor) != null` guard).
    fn subroutine_block(allow_overlap: bool) -> SubroutineBlock {
        let space = ram_space();
        let call_referent = addr(&space, 0x5000); // caller's address, outside the subroutine
        let jump_referent = addr(&space, 0x4000); // another caller's address, outside
        let basic_blocks = vec![
            BasicBlock {
                start: 0x1000,
                end: 0x1800,
                sources: vec![
                    (Flow::Call, addr(&space, 0x1000), call_referent.clone()),
                    (Flow::Jump, addr(&space, 0x1200), addr(&space, 0x1100)), // internal
                    (Flow::Jump, addr(&space, 0x1300), jump_referent.clone()),
                    (Flow::Fallthrough, addr(&space, 0x1400), addr(&space, 0x1500)), // internal
                ],
                space: space.clone(),
            },
            BasicBlock {
                start: 0x1800,
                end: 0x2000,
                // No block registered at 0x6000 in `found_at`, so this is never counted.
                sources: vec![(Flow::Fallthrough, addr(&space, 0x1900), addr(&space, 0x6000))],
                space: space.clone(),
            },
        ];
        SubroutineBlock {
            start: 0x1000,
            end: 0x2000,
            space: space.clone(),
            model: SubroutineModel {
                basic_blocks,
                allow_overlap,
                found_at: vec![
                    (call_referent, vec![addr(&space, 0x5000)]),
                    (jump_referent, vec![addr(&space, 0x4000)]),
                ],
            },
        }
    }

    #[test]
    fn get_num_sources_counts_calls_and_forward_jumps_but_not_internal_flow() {
        let block = subroutine_block(false);
        let count = get_num_sources(Some(&block), &DummyMonitor).unwrap();
        // Call from 0x5000, jump from 0x4000 => 2. The internal jump/fallthrough and the
        // fallthrough from an address with no resolvable block (0x6000) are excluded.
        assert_eq!(count, 2);
    }

    #[test]
    fn get_num_sources_none_block_short_circuits_to_zero() {
        let count = get_num_sources(None, &DummyMonitor).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn get_num_sources_block_with_no_min_address_short_circuits_without_touching_model() {
        struct NoAddressBlock;
        crate::impl_empty_address_set_view!(NoAddressBlock);
        impl CodeBlock for NoAddressBlock {
            fn get_model(&self) -> Box<dyn CodeBlockModel> {
                panic!("get_num_sources must short-circuit before calling get_model");
            }
            fn get_sources(
                &self,
                _monitor: &dyn TaskMonitor,
            ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                panic!("get_num_sources must short-circuit before calling get_sources");
            }
            fn get_destinations(
                &self,
                _monitor: &dyn TaskMonitor,
            ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                panic!("get_num_sources must short-circuit before calling get_destinations");
            }
        }

        let count = get_num_sources(Some(&NoAddressBlock), &DummyMonitor).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn new_queues_real_references_matching_get_num_sources_count() {
        let block: Rc<dyn CodeBlock> = Rc::new(subroutine_block(false));
        let mut iter =
            SubroutineSourceReferenceIterator::new(Some(block), Some(Box::new(DummyMonitor)))
                .unwrap();

        let mut references = Vec::new();
        while iter.has_next().unwrap() {
            references.push(iter.next().unwrap());
        }
        assert_eq!(references.len(), 2);

        // The destination address is always the subroutine's own first start address, since
        // `destBlock` is always known up front (per `CodeBlockReferenceImpl::getDestinationAddress`
        // returning the known block's first start address rather than the raw stored `reference`).
        let sub_start = addr(&ram_space(), 0x1000);
        for reference in &references {
            assert_eq!(reference.get_destination_address(), sub_start);
        }

        // `allow_overlap` is false, so every reference has an unknown *source* block that must
        // be lazily resolved via `CodeBlockModel::get_first_code_block_containing` -- exercised
        // here through `get_source_address()`, which reports the resolved block's first start
        // address instead of falling back to the raw referent.
        let source_addrs: Vec<i64> = references
            .iter()
            .map(|r| r.get_source_address().offset())
            .collect();
        assert_eq!(source_addrs, vec![0x5000, 0x4000]);

        // Once exhausted, `next()` reports "no more elements" rather than panicking (Java would
        // return `null` here, which this trait can't represent -- see `next()`'s doc comment).
        assert!(!iter.has_next().unwrap());
        assert!(iter.next().is_err());
    }

    #[test]
    fn new_with_block_overlap_queues_one_reference_per_matching_src_block() {
        let space = ram_space();
        let call_referent = addr(&space, 0x5000);
        let basic_blocks = vec![BasicBlock {
            start: 0x1000,
            end: 0x2000,
            sources: vec![(Flow::Call, addr(&space, 0x1000), call_referent.clone())],
            space: space.clone(),
        }];
        let block = SubroutineBlock {
            start: 0x1000,
            end: 0x2000,
            space: space.clone(),
            model: SubroutineModel {
                basic_blocks,
                allow_overlap: true,
                // Two overlapping blocks resolve at the caller's address.
                found_at: vec![(
                    call_referent,
                    vec![addr(&space, 0x5000), addr(&space, 0x5100)],
                )],
            },
        };

        // The counting-only path and the real queueing path must agree on how many references
        // this scenario produces.
        assert_eq!(get_num_sources(Some(&block), &DummyMonitor).unwrap(), 2);

        let block: Rc<dyn CodeBlock> = Rc::new(block);
        let mut iter =
            SubroutineSourceReferenceIterator::new(Some(block), Some(Box::new(DummyMonitor)))
                .unwrap();

        let mut source_addrs = Vec::new();
        while iter.has_next().unwrap() {
            // Both references have their source block known up front (no lazy model lookup
            // needed), since `allows_block_overlap()` supplied them directly.
            source_addrs.push(iter.next().unwrap().get_source_address().offset());
        }
        assert_eq!(source_addrs, vec![0x5000, 0x5100]);
    }

    #[test]
    fn monitor_none_with_short_circuited_block_constructs_but_panics_on_first_has_next_call() {
        // block == None means `get_sources` never runs, so a None monitor is never dereferenced
        // during construction -- matching Java's constructor completing normally with a null
        // monitor stored in `this.monitor`. See `new`'s doc comment.
        let mut iter = SubroutineSourceReferenceIterator::new(None, None).unwrap();

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            iter.has_next().unwrap();
        }))
        .is_err();
        assert!(
            panicked,
            "has_next() must panic when monitor is None, mirroring Java's unconditional \
             monitor.checkCancelled() NullPointerException"
        );
    }

    #[test]
    fn monitor_none_with_usable_block_panics_during_construction() {
        let block: Rc<dyn CodeBlock> = Rc::new(subroutine_block(false));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SubroutineSourceReferenceIterator::new(Some(block), None)
        }))
        .is_err();
        assert!(
            panicked,
            "new() must panic when monitor is None and block is Some with a minimum address"
        );
    }

    #[test]
    fn has_next_and_next_propagate_cancellation() {
        struct CancellingMonitor;
        impl TaskMonitor for CancellingMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException("cancelled".to_string()))
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        // The subroutine block is `None`, so construction itself never touches the monitor;
        // cancellation is only observed once `has_next`/`next` are called.
        let mut iter =
            SubroutineSourceReferenceIterator::new(None, Some(Box::new(CancellingMonitor)))
                .unwrap();
        assert!(iter.has_next().is_err());
        assert!(iter.next().is_err());
    }
}
