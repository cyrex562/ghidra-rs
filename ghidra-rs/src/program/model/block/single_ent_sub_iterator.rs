use std::collections::VecDeque;
use std::rc::Rc;

use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::block::code_block::CodeBlock;
use crate::program::model::block::code_block_iterator::CodeBlockIterator;
use crate::program::model::block::overlap_code_sub_model::OverlapCodeSubModel;
use crate::util::exception::CancelledException;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// `SingleEntSubIterator` is an implementation of [`CodeBlockIterator`] capable of iterating in
/// the forward direction over subroutine code blocks. This iterator supports subroutine models
/// which allow only one called/source entry point within a subroutine and may share code with
/// other subroutines produced by the same model. All entry points must be accounted for within
/// M-Model subroutines.
///
/// NOTE: This iterator only supports [`OverlapCodeSubModel`] block models and extensions.
///
/// NOTE: If the containing M-model subroutine has two entry points, say A and B, such that the
/// code traversed from A is identical to the code traversed by B (due to a cycle), then this
/// iterator will include it twice rather than skipping over the identical address set. This is
/// because the iterator works by iterating through M-model subroutines, and wherever M-model
/// subroutines have n > 1 multiple entry points, the iterator produces an O-model subroutine for
/// every one of the entry points.
///
/// Port of `ghidra.program.model.block.SingleEntSubIterator`.
///
/// ## Substituting for the unported `getModelM()`/`getCodeBlocksContaining(AddressSetView, ...)`
///
/// Java's constructors pull the M-Model out of `model` via the `protected MultEntSubModel
/// getModelM()` accessor and call its `getCodeBlocks`/`getCodeBlocksContaining(AddressSetView,
/// TaskMonitor)`. `getModelM()` is deliberately not modeled on [`OverlapCodeSubModel`] (see that
/// trait's doc comment), so this uses the *public* equivalent instead:
/// `SubroutineBlockModel::get_base_subroutine_model()`, which Java's own
/// `OverlapCodeSubModel.getBaseSubroutineModel()` implements as `return modelM;` -- the exact
/// same object, just reached through public API.
///
/// The `AddressSetView`-taking overload of `getCodeBlocksContaining` has no Rust counterpart
/// either: [`CodeBlockModel::get_code_blocks_containing`](crate::program::model::block::code_block_model::CodeBlockModel::get_code_blocks_containing)
/// stands in for it but (per that trait's doc comment) takes a `&dyn CodeBlock` rather than a
/// `&dyn AddressSetView`, which doesn't fit an arbitrary caller-supplied address set here. Instead,
/// [`new_with_address_set`](SingleEntSubIterator::new_with_address_set) wraps the base model's
/// whole-program [`get_code_blocks`](crate::program::model::block::code_block_model::CodeBlockModel::get_code_blocks)
/// iterator in a private [`FilteredCodeBlockIterator`] that skips blocks not overlapping the
/// address set -- the same sequence a real `getCodeBlocksContaining(AddressSetView, TaskMonitor)`
/// would produce, one block at a time.
pub struct SingleEntSubIterator {
    /// The O-Model this iterator produces subroutine blocks for.
    model: Box<dyn OverlapCodeSubModel>,

    /// Address range set specified for the iterator, if restricted.
    addr_set: Option<Rc<dyn AddressSetView>>,

    /// Iterator over the M-Model's subroutines.
    model_m_iter: Box<dyn CodeBlockIterator>,

    /// Holder for O-Model subs that came from an M-Model sub with multiple entry points.
    sub_list: VecDeque<Box<dyn CodeBlock>>,

    /// At any given time, holds the next block to be returned by `next()`, or `None`.
    next_sub: Option<Box<dyn CodeBlock>>,

    monitor: Box<dyn TaskMonitor>,
}

impl SingleEntSubIterator {
    /// Creates a new iterator that will iterate over the entire program starting from its
    /// current minimum address.
    ///
    /// Port of `SingleEntSubIterator(OverlapCodeSubModel model, TaskMonitor monitor)`.
    ///
    /// Java: `this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;` -- a `None` monitor
    /// is defended against here, substituting a dummy monitor. Compare
    /// [`new_with_address_set`](Self::new_with_address_set), whose Java counterpart has no such
    /// fallback.
    pub fn new(
        model: Box<dyn OverlapCodeSubModel>,
        monitor: Option<Box<dyn TaskMonitor>>,
    ) -> Result<Self, CancelledException> {
        let monitor: Box<dyn TaskMonitor> = monitor.unwrap_or_else(|| Box::new(DummyMonitor));

        let model_m_iter = model
            .get_base_subroutine_model()
            .get_code_blocks(monitor.as_ref())?;

        Ok(Self {
            model,
            addr_set: None,
            model_m_iter,
            sub_list: VecDeque::new(),
            next_sub: None,
            monitor,
        })
    }

    /// Creates a new iterator that will iterate over the program within a given address range
    /// set. All blocks which overlap the address set will be returned.
    ///
    /// Port of `SingleEntSubIterator(OverlapCodeSubModel model, AddressSetView set, TaskMonitor
    /// monitor)`.
    ///
    /// ## Java quirk: no null-monitor fallback
    ///
    /// Unlike [`new`](Self::new), Java's second constructor stores the caller's `monitor`
    /// directly (`this.monitor = monitor;` -- no `!= null` fallback) and, before doing anything
    /// else, calls `monitor.setIndeterminate(true)` on it. A `null` monitor therefore
    /// `NullPointerException`s immediately, right there in the constructor -- unlike the first
    /// constructor, which never dereferences a null monitor because it substitutes
    /// `TaskMonitor.DUMMY` first. Passing `monitor: None` here faithfully reproduces that: this
    /// function panics before ever constructing a `Self`, rather than silently substituting a
    /// dummy monitor.
    pub fn new_with_address_set(
        model: Box<dyn OverlapCodeSubModel>,
        addr_set: Rc<dyn AddressSetView>,
        monitor: Option<Box<dyn TaskMonitor>>,
    ) -> Result<Self, CancelledException> {
        let monitor = monitor.unwrap_or_else(|| {
            panic!(
                "SingleEntSubIterator::new_with_address_set: monitor is None; Java's \
                 `monitor.setIndeterminate(true)` would NullPointerException here since this \
                 constructor (unlike the single-arg-monitor `new`) never substitutes \
                 TaskMonitor.DUMMY for a null monitor"
            )
        });
        monitor.set_indeterminate(true);

        let base_iter = model
            .get_base_subroutine_model()
            .get_code_blocks(monitor.as_ref())?;
        let model_m_iter: Box<dyn CodeBlockIterator> =
            Box::new(FilteredCodeBlockIterator::new(base_iter, addr_set.clone()));

        Ok(Self {
            model,
            addr_set: Some(addr_set),
            model_m_iter,
            sub_list: VecDeque::new(),
            next_sub: None,
            monitor,
        })
    }
}

impl CodeBlockIterator for SingleEntSubIterator {
    /// Port of `SingleEntSubIterator.hasNext()`.
    ///
    /// ## Two faithfully-reproduced Java quirks
    ///
    /// 1. **Only one Model-M subroutine is inspected per call.** If `modelMIter.hasNext()` is
    ///    true, Java pulls exactly one `modelMSub` and processes its entry points; if none of
    ///    them yield a usable Model-O subroutine (e.g. every candidate is filtered out by
    ///    `addrSet`), this method returns `false` immediately -- it does *not* loop around to try
    ///    the next Model-M subroutine, even though `modelMIter` may still have elements that
    ///    would produce results. See `premature_termination_after_one_empty_model_m_sub_is_a_java_quirk`
    ///    below.
    /// 2. **A cancelled monitor silently ends iteration instead of raising an error.** Java's
    ///    `if (monitor.isCancelled()) return false;` (inside the entry-point loop) reports "no
    ///    more elements" rather than throwing `CancelledException`, unlike the more common Ghidra
    ///    convention of throwing (compare `OverlapCodeSubModel.getSubroutine`'s `throw new
    ///    CancelledException()`). See `cancelled_monitor_silently_ends_iteration_is_a_java_quirk`
    ///    below. (A `CancelledException` can still surface from `modelMIter.hasNext()`/`.next()`
    ///    themselves, which Java does not catch.)
    fn has_next(&mut self) -> Result<bool, CancelledException> {
        if self.next_sub.is_some() {
            return Ok(true);
        }

        if let Some(sub) = self.sub_list.pop_front() {
            self.next_sub = Some(sub);
            return Ok(true);
        }

        if self.model_m_iter.has_next()? {
            let model_m_sub = self.model_m_iter.next()?;
            let entry_points = model_m_sub.get_start_addresses();

            for entry_point in entry_points {
                let Some(sub) = self.model.get_code_block_at(&entry_point, self.monitor.as_ref())? else {
                    // "should only happen with screwy code"
                    continue;
                };

                // Quirk 2: see the doc comment above.
                if self.monitor.is_cancelled() {
                    return Ok(false);
                }

                if let Some(addr_set) = &self.addr_set {
                    if !sub.intersects_set(&**addr_set) {
                        continue;
                    }
                }

                self.sub_list.push_back(sub);
            }

            // Quirk 1: if the loop above added nothing (e.g. `entry_points` was empty, every
            // candidate was `None`, or every candidate was filtered out by `addr_set`), this
            // returns `false` here without ever looking at the next `model_m_iter` element.
            if let Some(sub) = self.sub_list.pop_front() {
                self.next_sub = Some(sub);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Port of `SingleEntSubIterator.next()`.
    ///
    /// Java returns `null` if there is nothing left once `hasNext()` has been (re-)run; this
    /// trait's `next()` has no way to represent that (it returns `Result<Box<dyn CodeBlock>,
    /// CancelledException>`, not an `Option`), so it reports a `CancelledException` instead --
    /// matching the convention already established by this trait's other implementors (e.g.
    /// `CodeBlockIterator`'s own doc-test `CountingCodeBlockIterator`) rather than panicking.
    fn next(&mut self) -> Result<Box<dyn CodeBlock>, CancelledException> {
        if self.next_sub.is_none() {
            self.has_next()?;
        }
        self.next_sub.take().ok_or_else(|| {
            CancelledException("SingleEntSubIterator::next called with no more elements".to_string())
        })
    }
}

/// Adapts a [`CodeBlockIterator`] to skip blocks that don't overlap a given address set.
///
/// Stands in for the unported `CodeBlockModel.getCodeBlocksContaining(AddressSetView,
/// TaskMonitor)` overload -- see [`SingleEntSubIterator`]'s doc comment for why that method isn't
/// available to call directly. This produces the same sequence such a method would: only
/// overlapping blocks, in the same relative order, one at a time.
struct FilteredCodeBlockIterator {
    inner: Box<dyn CodeBlockIterator>,
    addr_set: Rc<dyn AddressSetView>,
    pending: Option<Box<dyn CodeBlock>>,
}

impl FilteredCodeBlockIterator {
    fn new(inner: Box<dyn CodeBlockIterator>, addr_set: Rc<dyn AddressSetView>) -> Self {
        Self {
            inner,
            addr_set,
            pending: None,
        }
    }
}

impl CodeBlockIterator for FilteredCodeBlockIterator {
    fn has_next(&mut self) -> Result<bool, CancelledException> {
        if self.pending.is_some() {
            return Ok(true);
        }
        while self.inner.has_next()? {
            let candidate = self.inner.next()?;
            if candidate.intersects_set(&*self.addr_set) {
                self.pending = Some(candidate);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn next(&mut self) -> Result<Box<dyn CodeBlock>, CancelledException> {
        if self.pending.is_none() {
            self.has_next()?;
        }
        self.pending.take().ok_or_else(|| {
            CancelledException(
                "FilteredCodeBlockIterator::next called with no more elements".to_string(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        AddressRange, AddressRangeIterator, AddressSet, AddressSpace, AddressSpaceType,
        BoxedAddressIterator,
    };
    use crate::program::model::block::code_block_model::CodeBlockModel;
    use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
    use crate::program::model::block::subroutine_block_model::SubroutineBlockModel;
    use crate::program::model::listing::listing::Listing;
    use crate::program::seam_stubs::FlowType;
    use crate::util::task::CancelledListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// A `CodeBlock` with one or more fixed start addresses, standing in for both Model-M
    /// subroutines (multiple entry points) and Model-O subroutines (single entry point). Every
    /// member not exercised by the tests below panics, matching this crate's established mock
    /// style.
    struct StubBlock {
        starts: Vec<Address>,
    }

    impl AddressSetView for StubBlock {
        fn contains(&self, address: &Address) -> bool {
            self.starts.iter().any(|a| a == address)
        }
        fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
            unimplemented!()
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!()
        }
        fn is_empty(&self) -> bool {
            self.starts.is_empty()
        }
        fn min_address(&self) -> Option<Address> {
            self.starts.first().cloned()
        }
        fn max_address(&self) -> Option<Address> {
            self.starts.last().cloned()
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
        fn address_ranges_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn AddressRangeIterator> {
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
        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            self.starts.iter().any(|a| set.contains(a))
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

    impl CodeBlock for StubBlock {
        fn get_start_addresses(&self) -> Vec<Address> {
            self.starts.clone()
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!()
        }
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!()
        }
    }

    /// A `CodeBlockIterator` yielding a pre-scripted sequence of `StubBlock`s, standing in for
    /// the M-Model's `get_code_blocks` iterator.
    struct ScriptedIter {
        remaining: VecDeque<Vec<Address>>,
    }

    impl CodeBlockIterator for ScriptedIter {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            Ok(!self.remaining.is_empty())
        }
        fn next(&mut self) -> Result<Box<dyn CodeBlock>, CancelledException> {
            let starts = self.remaining.pop_front().ok_or_else(|| {
                CancelledException("ScriptedIter exhausted".to_string())
            })?;
            Ok(Box::new(StubBlock { starts }))
        }
    }

    /// The M-Model (base subroutine model) backing an [`OModel`]: its `get_code_blocks` yields a
    /// pre-scripted sequence of Model-M subroutines (each possibly multi-entry).
    struct MModel {
        m_subs: Vec<Vec<Address>>,
    }

    impl CodeBlockModel for MModel {
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
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!()
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            Ok(Box::new(ScriptedIter {
                remaining: self.m_subs.iter().cloned().collect(),
            }))
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

    impl SubroutineBlockModel for MModel {
        fn get_base_subroutine_model(&self) -> Box<dyn SubroutineBlockModel> {
            unimplemented!()
        }
    }

    /// The O-Model (`model` field): `get_code_block_at` resolves every entry point to a
    /// single-entry `StubBlock` at that address, *except* for addresses listed in
    /// `unresolvable`, which get Java's "should only happen with screwy code" `None` instead
    /// (standing in for a Model-M entry point with no corresponding Model-O subroutine).
    /// `get_base_subroutine_model` hands back the scripted [`MModel`].
    struct OModel {
        m_subs: Vec<Vec<Address>>,
        unresolvable: std::collections::HashSet<i64>,
    }

    impl CodeBlockModel for OModel {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn get_code_block_at(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            if self.unresolvable.contains(&addr.offset()) {
                return Ok(None);
            }
            Ok(Some(Box::new(StubBlock {
                starts: vec![addr.clone()],
            })))
        }
        fn get_first_code_block_containing(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!()
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

    impl SubroutineBlockModel for OModel {
        fn get_base_subroutine_model(&self) -> Box<dyn SubroutineBlockModel> {
            Box::new(MModel {
                m_subs: self.m_subs.clone(),
            })
        }
    }

    impl OverlapCodeSubModel for OModel {
        fn get_listing(&self) -> Arc<dyn Listing> {
            unimplemented!()
        }
    }

    /// A `TaskMonitor` whose cancellation can be toggled by the test, and which records how many
    /// times `set_indeterminate` was called (via a shared `Arc<AtomicUsize>` so the count can be
    /// inspected after the monitor has been moved into a `Box<dyn TaskMonitor>`). `Send + Sync`
    /// via `AtomicBool`/`AtomicUsize`, as required by the `TaskMonitor` trait.
    struct ControllableMonitor {
        cancelled: AtomicBool,
        set_indeterminate_calls: Arc<AtomicUsize>,
    }

    impl ControllableMonitor {
        fn new() -> Self {
            Self {
                cancelled: AtomicBool::new(false),
                set_indeterminate_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl TaskMonitor for ControllableMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
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
        fn set_indeterminate(&self, _indeterminate: bool) {
            self.set_indeterminate_calls.fetch_add(1, Ordering::SeqCst);
        }
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.is_cancelled() {
                Err(CancelledException("cancelled".to_string()))
            } else {
                Ok(())
            }
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            -1
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {
            self.cancelled.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn whole_program_iteration_yields_one_sub_per_model_m_entry_point() {
        let space = ram_space();
        let e1 = addr(&space, 0x1000);
        let e2a = addr(&space, 0x2000);
        let e2b = addr(&space, 0x3000);

        let model = Box::new(OModel {
            m_subs: vec![vec![e1.clone()], vec![e2a.clone(), e2b.clone()]],
            unresolvable: Default::default(),
        });

        let mut iter = SingleEntSubIterator::new(model, None).unwrap();

        let mut seen = Vec::new();
        while iter.has_next().unwrap() {
            let sub = iter.next().unwrap();
            seen.push(sub.get_first_start_address().offset());
        }

        // One Model-O sub per Model-M entry point across both Model-M subs.
        seen.sort();
        assert_eq!(seen, vec![e1.offset(), e2a.offset(), e2b.offset()]);
    }

    #[test]
    fn address_restricted_iteration_only_returns_overlapping_subs() {
        let space = ram_space();
        let inside = addr(&space, 0x1000);
        let outside = addr(&space, 0x9000);

        let model = Box::new(OModel {
            m_subs: vec![vec![inside.clone()], vec![outside.clone()]],
            unresolvable: Default::default(),
        });

        let restrict = Rc::new(AddressSet::from_start_end(inside.clone(), inside.clone()))
            as Rc<dyn AddressSetView>;

        let mut iter = SingleEntSubIterator::new_with_address_set(
            model,
            restrict,
            Some(Box::new(ControllableMonitor::new())),
        )
        .unwrap();

        let mut seen = Vec::new();
        while iter.has_next().unwrap() {
            seen.push(iter.next().unwrap().get_first_start_address().offset());
        }

        assert_eq!(seen, vec![inside.offset()]);
    }

    /// Java quirk #1 (see `SingleEntSubIterator::has_next`'s doc comment): `hasNext()` only ever
    /// inspects a single Model-M subroutine per call. Here the *first* Model-M sub's only entry
    /// point fails to resolve to a Model-O subroutine at all (`model.getCodeBlockAt` returns
    /// `null` -- "should only happen with screwy code"), leaving `subList` empty, while the
    /// *second* Model-M sub's entry point resolves just fine -- but because Java never advances
    /// to it within the same `hasNext()` call, iteration ends prematurely and that perfectly
    /// valid subroutine is never seen. This is a faithful reproduction of Java's behavior, not a
    /// bug introduced by this port.
    #[test]
    fn premature_termination_after_one_empty_model_m_sub_is_a_java_quirk() {
        let space = ram_space();
        let unresolvable = addr(&space, 0x1000);
        let resolvable = addr(&space, 0x2000);

        let model = Box::new(OModel {
            m_subs: vec![vec![unresolvable.clone()], vec![resolvable]],
            unresolvable: [unresolvable.offset()].into_iter().collect(),
        });

        let mut iter = SingleEntSubIterator::new(model, None).unwrap();

        // The only resolvable subroutine belongs to the *second* Model-M sub, but hasNext()
        // gives up after the first (empty) one instead of trying the second.
        assert!(!iter.has_next().unwrap());
    }

    /// Java quirk #2 (see `SingleEntSubIterator::has_next`'s doc comment): a cancelled monitor
    /// makes `hasNext()` return `Ok(false)` (silently ending iteration) rather than propagating a
    /// `CancelledException`, even though there is a further, un-inspected Model-O subroutine
    /// available.
    #[test]
    fn cancelled_monitor_silently_ends_iteration_is_a_java_quirk() {
        let space = ram_space();
        let e1 = addr(&space, 0x1000);
        let e2 = addr(&space, 0x2000);

        let model = Box::new(OModel {
            m_subs: vec![vec![e1, e2]],
            unresolvable: Default::default(),
        });

        let monitor = ControllableMonitor::new();
        monitor.cancel();

        let mut iter = SingleEntSubIterator::new(model, Some(Box::new(monitor))).unwrap();

        // Cancelled *before* the first hasNext() call: the very first entry point resolved
        // triggers `monitor.isCancelled()`, so hasNext() reports `Ok(false)` -- not an `Err`.
        assert_eq!(iter.has_next(), Ok(false));
    }

    #[test]
    #[should_panic(expected = "monitor is None")]
    fn address_set_constructor_panics_on_null_monitor() {
        let space = ram_space();
        let e1 = addr(&space, 0x1000);
        let model = Box::new(OModel {
            m_subs: vec![vec![e1.clone()]],
            unresolvable: Default::default(),
        });
        let restrict = Rc::new(AddressSet::from_start_end(e1.clone(), e1)) as Rc<dyn AddressSetView>;

        // Directly verifies the panic happens inside `new_with_address_set` itself (matching
        // Java's constructor-time NPE), not merely somewhere in this test function.
        let _ = SingleEntSubIterator::new_with_address_set(model, restrict, None);
    }

    #[test]
    fn address_set_constructor_calls_set_indeterminate_on_a_real_monitor() {
        let space = ram_space();
        let e1 = addr(&space, 0x1000);
        let model = Box::new(OModel {
            m_subs: vec![vec![e1.clone()]],
            unresolvable: Default::default(),
        });
        let restrict = Rc::new(AddressSet::from_start_end(e1.clone(), e1)) as Rc<dyn AddressSetView>;
        let monitor = ControllableMonitor::new();
        let calls = monitor.set_indeterminate_calls.clone();

        let _iter =
            SingleEntSubIterator::new_with_address_set(model, restrict, Some(Box::new(monitor)))
                .unwrap();

        // Java: `monitor.setIndeterminate(true);` is called unconditionally, right at the top of
        // this constructor.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
