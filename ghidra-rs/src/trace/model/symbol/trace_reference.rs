use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::address::AddressRange;
use crate::program::model::symbol::{RefType, Reference, Symbol};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;

/// A [`Reference`] within a [`Trace`].
///
/// Port of `ghidra.trace.model.symbol.TraceReference`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface overrides several `Reference` defaults purely in terms of members declared
/// here. Rust has no notion of re-overriding an inherited abstract method, so implementations of
/// [`Reference`] for a `TraceReference` type must reproduce these directly:
/// - `to_address()` returns `get_to_range().min_address().clone()` (because a trace reference's
///   "to" part is actually a range; see [`Self::get_to_range`]).
/// - `is_mnemonic_reference()` returns `!is_operand_reference()`.
/// - `is_operand_reference()` returns `operand_index() >= 0`.
/// - `is_stack_reference()` returns `false` (overridden `true` by
///   [`TraceStackReference`](crate::trace::model::symbol::trace_stack_reference::TraceStackReference)).
/// - `is_external_reference()` and `is_entry_point_reference()` always return `false`: a trace
///   should have all modules present, and entry points are not recorded in traces.
/// - `is_offset_reference()` returns `false` (overridden `true` by
///   [`TraceOffsetReference`](crate::trace::model::symbol::trace_offset_reference::TraceOffsetReference)).
/// - `is_shifted_reference()` returns `false` (overridden `true` by
///   [`TraceShiftedReference`](crate::trace::model::symbol::trace_shifted_reference::TraceShiftedReference)).
/// - `is_memory_reference()` returns `to_address().is_memory_address()`.
/// - `is_register_reference()` returns `to_address().is_register_address()`.
pub trait TraceReference: Reference {
    /// Get the trace containing this reference.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the lifespan for which this reference is effective.
    fn get_lifespan(&self) -> Box<dyn Lifespan>;

    /// Get the starting snapshot key of this reference's lifespan.
    ///
    /// See [`Self::get_lifespan`].
    fn get_start_snap(&self) -> i64;

    /// Get the "to" range of this reference.
    ///
    /// Because references are often used in traces to indicate *actual* run-time writes, it is
    /// not sufficient to examine the code unit at a single "to" address and assume the reference
    /// is to the entire unit. For one, the read might be of a specific field in a structure data
    /// unit. For two, a read of a large unit may be implemented as a loop of several smaller
    /// reads. The trace could (and probably should) record each atomic read. In theory, one
    /// could examine the "from" instruction and operand index to derive the length, but that is
    /// onerous and not indexed. So instead, the exact "to" range is recorded in each reference
    /// and indexed. This allows for easy implementation of, e.g., access breakpoints.
    fn get_to_range(&self) -> AddressRange;

    /// Make this reference primary.
    ///
    /// Only one reference at a given "from" location can be primary. If a primary reference
    /// already exists at this location, it will become a secondary reference.
    fn set_primary(&mut self, primary: bool);

    /// Set the reference type.
    fn set_reference_type(&mut self, ref_type: RefType);

    /// Set the symbol associated with this reference.
    ///
    /// See [`Self::get_associated_symbol`].
    fn set_associated_symbol(&mut self, symbol: Arc<dyn Symbol>);

    /// Clear the associated symbol.
    ///
    /// See [`Self::get_associated_symbol`].
    fn clear_associated_symbol(&mut self);

    /// Get the symbol associated with this reference.
    ///
    /// Mirrors the Java default, which resolves the id via
    /// `getTrace().getSymbolManager().getSymbolByID(id)`.
    fn get_associated_symbol(&self) -> Option<Arc<dyn Symbol>> {
        let id = self.symbol_id();
        if id == -1 {
            None
        } else {
            self.get_trace().get_symbol_manager().get_symbol_by_id(id)
        }
    }

    /// Orders references by "from" address, then operand index, then "to" address.
    ///
    /// Mirrors the Java default `compareTo(Reference)`.
    fn compare_to(&self, that: &dyn Reference) -> Ordering {
        self.from_address()
            .cmp(&that.from_address())
            .then_with(|| self.operand_index().cmp(&that.operand_index()))
            .then_with(|| self.to_address().cmp(&that.to_address()))
    }

    /// Delete this reference.
    fn delete(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::model::symbol::{SourceType, SymbolType};
    use crate::program::seam_stubs::DataTypeManagerOwner;
    use crate::trace::model::listing::TraceCodeManager;
    use crate::trace::model::modules::TraceStaticMappingManager;
    use crate::trace::model::program::TraceProgramView;
    use crate::trace::model::trace::TraceProgramViewListener;
    use crate::trace::model::time::trace_time_manager::TraceTimeManager;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;
    use crate::trace::seam_stubs::{
        TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceBreakpointManager, TraceEquateManager, TraceMemoryManager,
        TraceModuleManager, TraceObjectManager, TracePlatformManager, TraceReferenceManager,
        TraceRegisterContextManager, TraceStackManager,
        TraceSymbolManager, TraceThreadManager, TraceVariableSnapProgramView,
    };
    use crate::util::lock_hold::{Lock, LockHold};
    use std::any::Any;

    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    struct MockSymbol {
        id: i64,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            addr(0x400)
        }

        fn get_name(&self) -> &str {
            "mock_symbol"
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::Default
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockSymbolManager {
        symbol_id: i64,
    }

    impl TraceSymbolManager for MockSymbolManager {
        fn get_symbol_by_id(&self, id: i64) -> Option<Arc<dyn Symbol>> {
            if id == self.symbol_id {
                Some(Arc::new(MockSymbol { id }))
            } else {
                None
            }
        }
    }

    struct MockTrace {
        symbol_id: i64,
    }

    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {}

        fn get_emulator_cache_version(&self) -> i64 {
            0
        }

        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
            Box::new(MockSymbolManager {
                symbol_id: self.symbol_id,
            })
        }

        fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_program_view(&self, _snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {}

        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {}

        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }

        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockTraceReference {
        from: Address,
        to_range: AddressRange,
        operand_index: i32,
        symbol_id: i64,
        start_snap: i64,
        primary: bool,
        ref_type: RefType,
        deleted: bool,
    }

    impl Reference for MockTraceReference {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn from_address(&self) -> Address {
            self.from.clone()
        }

        fn to_address(&self) -> Address {
            // Mirrors the Java override: the minimum of the recorded "to" range.
            self.to_range.min_address().clone()
        }

        fn is_primary(&self) -> bool {
            self.primary
        }

        fn symbol_id(&self) -> i64 {
            self.symbol_id
        }

        fn reference_type(&self) -> RefType {
            self.ref_type
        }

        fn operand_index(&self) -> i32 {
            self.operand_index
        }

        fn is_mnemonic_reference(&self) -> bool {
            !self.is_operand_reference()
        }

        fn is_operand_reference(&self) -> bool {
            self.operand_index >= 0
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            false
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            self.to_address().is_memory_address()
        }

        fn is_register_reference(&self) -> bool {
            self.to_address().is_register_address()
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            SourceType::Default
        }
    }

    impl TraceReference for MockTraceReference {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace {
                symbol_id: self.symbol_id,
            })
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.start_snap,
                max: i64::MAX,
            })
        }

        fn get_start_snap(&self) -> i64 {
            self.start_snap
        }

        fn get_to_range(&self) -> AddressRange {
            self.to_range.clone()
        }

        fn set_primary(&mut self, primary: bool) {
            self.primary = primary;
        }

        fn set_reference_type(&mut self, ref_type: RefType) {
            self.ref_type = ref_type;
        }

        fn set_associated_symbol(&mut self, symbol: Arc<dyn Symbol>) {
            self.symbol_id = symbol.get_id();
        }

        fn clear_associated_symbol(&mut self) {
            self.symbol_id = -1;
        }

        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_ref(from: i64, to: i64, operand_index: i32) -> MockTraceReference {
        MockTraceReference {
            from: addr(from),
            to_range: AddressRange::new(addr(to), addr(to)),
            operand_index,
            symbol_id: -1,
            start_snap: 0,
            primary: false,
            ref_type: RefType::Data,
            deleted: false,
        }
    }

    #[test]
    fn to_address_and_operand_defaults_derive_from_to_range_and_operand_index() {
        let r = make_ref(0x400, 0x2000, -1);
        assert_eq!(r.to_address(), addr(0x2000));
        assert!(r.is_mnemonic_reference());
        assert!(!r.is_operand_reference());

        let r = make_ref(0x400, 0x2000, 0);
        assert!(!r.is_mnemonic_reference());
        assert!(r.is_operand_reference());
    }

    #[test]
    fn compare_to_orders_by_from_then_operand_then_to() {
        let a = make_ref(0x400, 0x2000, 0);
        let b = make_ref(0x400, 0x2000, 1);
        let c = make_ref(0x500, 0x1000, 0);
        let d = make_ref(0x400, 0x2000, 0);

        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert_eq!(a.compare_to(&c), Ordering::Less);
        assert_eq!(a.compare_to(&d), Ordering::Equal);
    }

    #[test]
    fn delete_marks_the_reference_deleted() {
        let mut r = make_ref(0x400, 0x2000, 0);
        assert!(!r.deleted);
        r.delete();
        assert!(r.deleted);
    }

    #[test]
    fn get_associated_symbol_short_circuits_when_no_symbol_is_set() {
        let r = make_ref(0x400, 0x2000, 0);
        assert_eq!(r.symbol_id(), -1);
        assert!(r.get_associated_symbol().is_none());
    }

    #[test]
    fn get_associated_symbol_resolves_through_trace_symbol_manager() {
        let mut r = make_ref(0x400, 0x2000, 0);
        r.symbol_id = 42;

        let sym = r.get_associated_symbol().expect("symbol should resolve");
        assert_eq!(sym.get_id(), 42);
    }

    #[test]
    fn mutators_and_object_safety_via_trait_object() {
        let mut boxed: Box<dyn TraceReference> = Box::new(make_ref(0x400, 0x2000, 0));

        boxed.set_primary(true);
        assert!(boxed.is_primary());

        boxed.set_reference_type(RefType::Read);
        assert_eq!(boxed.reference_type(), RefType::Read);

        boxed.set_associated_symbol(Arc::new(MockSymbol { id: 7 }));
        assert_eq!(boxed.symbol_id(), 7);

        boxed.clear_associated_symbol();
        assert_eq!(boxed.symbol_id(), -1);

        assert_eq!(boxed.get_start_snap(), 0);
        assert_eq!(boxed.get_lifespan().lmin(), 0);
        assert_eq!(boxed.get_to_range(), AddressRange::new(addr(0x2000), addr(0x2000)));

        boxed.delete();
    }
}
