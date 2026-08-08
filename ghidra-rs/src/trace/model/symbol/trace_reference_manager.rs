//! The reference table for a trace.
//!
//! Port of `ghidra.trace.model.symbol.TraceReferenceManager`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java interface's two `getReferenceRegisterSpace` overloads (one taking a `TraceThread`,
//! the other a `TraceStackFrame`) cannot be represented as same-named Rust methods, so each is
//! given a distinct, descriptive name below, following the convention set by
//! [`TraceEquateManager`](crate::trace::model::symbol::trace_equate_manager::TraceEquateManager).

use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::symbol::trace_reference_operations::TraceReferenceOperations;
use crate::trace::model::symbol::trace_reference_space::TraceReferenceSpace;
use crate::trace::seam_stubs::{TraceStackFrame, TraceThread};

/// The reference table for a trace.
pub trait TraceReferenceManager: TraceReferenceOperations {
    /// Get the reference space for the given address space, optionally creating it if absent.
    ///
    /// Returns `None` if the space does not exist and `create_if_absent` is `false`.
    fn get_reference_space(
        &mut self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceReferenceSpace>>;

    /// Get the reference register space for the given thread's registers, optionally creating it
    /// if absent.
    ///
    /// Returns `None` if the space does not exist and `create_if_absent` is `false`.
    ///
    /// Mirrors the Java overload `getReferenceRegisterSpace(TraceThread, boolean)`.
    fn get_reference_register_space_for_thread(
        &mut self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceReferenceSpace>>;

    /// Get the reference register space for the given stack frame's registers, optionally
    /// creating it if absent.
    ///
    /// Returns `None` if the space does not exist and `create_if_absent` is `false`.
    ///
    /// Mirrors the Java overload `getReferenceRegisterSpace(TraceStackFrame, boolean)`.
    fn get_reference_register_space_for_frame(
        &mut self,
        frame: &dyn TraceStackFrame,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceReferenceSpace>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSetView, AddressSpaceType,
    };
    use crate::program::model::lang::Register;
    use crate::program::model::symbol::{RefType, Reference, SourceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::symbol::trace_offset_reference::TraceOffsetReference;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_shifted_reference::TraceShiftedReference;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::Rectangle2DDirection;
    use std::any::Any;

    struct DummySpan;
    impl Lifespan for DummySpan {
        fn lmin(&self) -> i64 {
            0
        }
        fn lmax(&self) -> i64 {
            0
        }
        fn contains(&self, n: i64) -> bool {
            n == 0
        }
        fn with_min(&self, _min: i64) -> Box<dyn Lifespan> {
            Box::new(DummySpan)
        }
        fn with_max(&self, _max: i64) -> Box<dyn Lifespan> {
            Box::new(DummySpan)
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(std::iter::once(0))
        }
    }

    #[derive(Clone)]
    struct MockReference {
        from: Address,
        to_range: AddressRange,
        ref_type: RefType,
        source: SourceType,
        operand_index: i32,
        primary: bool,
    }

    impl Reference for MockReference {
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn from_address(&self) -> Address {
            self.from.clone()
        }
        fn to_address(&self) -> Address {
            self.to_range.min_address().clone()
        }
        fn is_primary(&self) -> bool {
            self.primary
        }
        fn symbol_id(&self) -> i64 {
            -1
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
            self.source
        }
    }

    impl TraceReference for MockReference {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_start_snap(&self) -> i64 {
            0
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
        fn set_associated_symbol(&mut self, _symbol: Arc<dyn crate::program::model::symbol::Symbol>) {}
        fn clear_associated_symbol(&mut self) {}
        fn delete(&mut self) {}
    }

    /// A single-space `TraceReferenceSpace`, storing references in a flat `Vec`.
    struct MockSpace {
        space: Arc<AddressSpace>,
        refs: Vec<MockReference>,
    }

    impl TraceReferenceOperations for MockSpace {
        fn add_reference(&mut self, reference: &dyn TraceReference) -> Box<dyn TraceReference> {
            let copy = MockReference {
                from: reference.from_address(),
                to_range: reference.get_to_range(),
                ref_type: reference.reference_type(),
                source: reference.source(),
                operand_index: reference.operand_index(),
                primary: reference.is_primary(),
            };
            self.refs.push(copy.clone());
            Box::new(copy)
        }
        fn add_reference_for_lifespan(
            &mut self,
            _lifespan: &dyn Lifespan,
            reference: &dyn Reference,
        ) -> Box<dyn TraceReference> {
            let to = reference.to_address();
            let copy = MockReference {
                from: reference.from_address(),
                to_range: AddressRange::new(to.clone(), to),
                ref_type: reference.reference_type(),
                source: reference.source(),
                operand_index: reference.operand_index(),
                primary: reference.is_primary(),
            };
            self.refs.push(copy.clone());
            Box::new(copy)
        }
        fn add_memory_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            from_address: &Address,
            to_range: AddressRange,
            ref_type: RefType,
            source: SourceType,
            operand_index: i32,
        ) -> Box<dyn TraceReference> {
            let r = MockReference {
                from: from_address.clone(),
                to_range,
                ref_type,
                source,
                operand_index,
                primary: self.refs.iter().all(|existing| {
                    existing.from != *from_address || existing.operand_index != operand_index
                }),
            };
            self.refs.push(r.clone());
            Box::new(r)
        }
        fn add_offset_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_address: &Address,
            _to_addr_is_base: bool,
            _offset: i64,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceOffsetReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_shifted_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_address: &Address,
            _shift: i32,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceShiftedReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_register_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_register: &Register,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_stack_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_stack_offset: i32,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference(
            &self,
            _snap: i64,
            from_address: &Address,
            to_range: AddressRange,
            operand_index: i32,
        ) -> Option<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .find(|r| {
                    r.from == *from_address
                        && r.operand_index == operand_index
                        && r.to_range.min_address() == to_range.min_address()
                        && r.to_range.max_address() == to_range.max_address()
                })
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
        }
        fn get_reference_to_address(
            &self,
            _snap: i64,
            from_address: &Address,
            to_address: &Address,
            operand_index: i32,
        ) -> Option<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .find(|r| {
                    r.from == *from_address
                        && r.operand_index == operand_index
                        && r.to_range.contains(to_address)
                })
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
        }
        fn get_references_from(&self, _snap: i64, from_address: &Address) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| r.from == *from_address)
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }
        fn get_references_from_operand(
            &self,
            _snap: i64,
            from_address: &Address,
            operand_index: i32,
        ) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| r.from == *from_address && r.operand_index == operand_index)
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }
        fn get_references_from_range(
            &self,
            _span: &dyn Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| range.contains(&r.from))
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }
        fn get_primary_reference_from(
            &self,
            _snap: i64,
            from_address: &Address,
            operand_index: i32,
        ) -> Option<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .find(|r| r.from == *from_address && r.operand_index == operand_index && r.primary)
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
        }
        fn get_flow_references_from(&self, _snap: i64, from_address: &Address) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| r.from == *from_address && r.ref_type.is_flow())
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }
        fn clear_references_from(&mut self, _span: &dyn Lifespan, range: &AddressRange) {
            self.refs.retain(|r| !range.contains(&r.from));
        }
        fn get_references_to(&self, _snap: i64, to_address: &Address) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| r.to_range.contains(to_address))
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }
        fn clear_references_to(&mut self, _span: &dyn Lifespan, range: &AddressRange) {
            self.refs.retain(|r| range.intersect(&r.to_range).is_none());
        }
        fn get_references_to_range(
            &self,
            _span: &dyn Lifespan,
            range: &AddressRange,
            _order: Option<&dyn Rectangle2DDirection>,
        ) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| range.intersect(&r.to_range).is_some())
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }
        fn get_references_to_range_unordered(
            &self,
            span: &dyn Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceReference>> {
            self.get_references_to_range(span, range, None)
        }
        fn has_references_from(&self, snap: i64, from_address: &Address) -> bool {
            !self.get_references_from(snap, from_address).is_empty()
        }
        fn has_references_from_operand(&self, snap: i64, from_address: &Address, operand_index: i32) -> bool {
            !self.get_references_from_operand(snap, from_address, operand_index).is_empty()
        }
        fn has_flow_references_from(&self, snap: i64, from_address: &Address) -> bool {
            !self.get_flow_references_from(snap, from_address).is_empty()
        }
        fn has_references_to(&self, snap: i64, to_address: &Address) -> bool {
            !self.get_references_to(snap, to_address).is_empty()
        }
        fn get_reference_sources(&self, _span: &dyn Lifespan) -> Box<dyn AddressSetView> {
            let mut set = crate::program::model::address::AddressSet::new();
            for r in &self.refs {
                set.add_address(&r.from);
            }
            Box::new(set)
        }
        fn get_reference_destinations(&self, _span: &dyn Lifespan) -> Box<dyn AddressSetView> {
            let mut set = crate::program::model::address::AddressSet::new();
            for r in &self.refs {
                set.add_range_object(&r.to_range);
            }
            Box::new(set)
        }
        fn get_reference_count_from(&self, snap: i64, from_address: &Address) -> i32 {
            self.get_references_from(snap, from_address).len() as i32
        }
        fn get_reference_count_to(&self, snap: i64, to_address: &Address) -> i32 {
            self.get_references_to(snap, to_address).len() as i32
        }
    }

    impl TraceReferenceSpace for MockSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    /// The manager: an `AddressSpace`-keyed collection of `MockSpace`s. Proves
    /// [`TraceReferenceManager::get_reference_space`]'s create-if-absent semantics operate on
    /// real (not trivially-empty) per-space storage, that the register-space overloads are
    /// distinctly named and dispatch correctly, and that the trait (with its
    /// `TraceReferenceOperations` supertrait) remains object-safe behind `Box<dyn
    /// TraceReferenceManager>`.
    struct MockManager {
        spaces: Vec<MockSpace>,
        register_space: Option<MockSpace>,
    }

    impl TraceReferenceOperations for MockManager {
        fn add_reference(&mut self, reference: &dyn TraceReference) -> Box<dyn TraceReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_reference_for_lifespan(
            &mut self,
            _lifespan: &dyn Lifespan,
            _reference: &dyn Reference,
        ) -> Box<dyn TraceReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_memory_reference(
            &mut self,
            lifespan: &dyn Lifespan,
            from_address: &Address,
            to_range: AddressRange,
            ref_type: RefType,
            source: SourceType,
            operand_index: i32,
        ) -> Box<dyn TraceReference> {
            let space = from_address.space();
            let idx = self.spaces.iter().position(|s| s.space.name() == space.name()).unwrap_or_else(|| {
                self.spaces.push(MockSpace { space: space.clone(), refs: Vec::new() });
                self.spaces.len() - 1
            });
            self.spaces[idx].add_memory_reference(
                lifespan,
                from_address,
                to_range,
                ref_type,
                source,
                operand_index,
            )
        }
        fn add_offset_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_address: &Address,
            _to_addr_is_base: bool,
            _offset: i64,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceOffsetReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_shifted_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_address: &Address,
            _shift: i32,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceShiftedReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_register_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_register: &Register,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_stack_reference(
            &mut self,
            _lifespan: &dyn Lifespan,
            _from_address: &Address,
            _to_stack_offset: i32,
            _ref_type: RefType,
            _source: SourceType,
            _operand_index: i32,
        ) -> Box<dyn TraceReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference(
            &self,
            snap: i64,
            from_address: &Address,
            to_range: AddressRange,
            operand_index: i32,
        ) -> Option<Box<dyn TraceReference>> {
            self.spaces
                .iter()
                .find(|s| s.space.name() == from_address.space().name())
                .and_then(|s| s.get_reference(snap, from_address, to_range, operand_index))
        }
        fn get_reference_to_address(
            &self,
            snap: i64,
            from_address: &Address,
            to_address: &Address,
            operand_index: i32,
        ) -> Option<Box<dyn TraceReference>> {
            self.spaces
                .iter()
                .find(|s| s.space.name() == from_address.space().name())
                .and_then(|s| s.get_reference_to_address(snap, from_address, to_address, operand_index))
        }
        fn get_references_from(&self, snap: i64, from_address: &Address) -> Vec<Box<dyn TraceReference>> {
            self.spaces
                .iter()
                .find(|s| s.space.name() == from_address.space().name())
                .map(|s| s.get_references_from(snap, from_address))
                .unwrap_or_default()
        }
        fn get_references_from_operand(
            &self,
            _snap: i64,
            _from_address: &Address,
            _operand_index: i32,
        ) -> Vec<Box<dyn TraceReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_references_from_range(
            &self,
            _span: &dyn Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_primary_reference_from(
            &self,
            _snap: i64,
            _from_address: &Address,
            _operand_index: i32,
        ) -> Option<Box<dyn TraceReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_flow_references_from(&self, _snap: i64, _from_address: &Address) -> Vec<Box<dyn TraceReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_references_from(&mut self, _span: &dyn Lifespan, _range: &AddressRange) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_references_to(&self, _snap: i64, _to_address: &Address) -> Vec<Box<dyn TraceReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn clear_references_to(&mut self, _span: &dyn Lifespan, _range: &AddressRange) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_references_to_range(
            &self,
            _span: &dyn Lifespan,
            _range: &AddressRange,
            _order: Option<&dyn Rectangle2DDirection>,
        ) -> Vec<Box<dyn TraceReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_references_to_range_unordered(
            &self,
            _span: &dyn Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_references_from(&self, snap: i64, from_address: &Address) -> bool {
            !self.get_references_from(snap, from_address).is_empty()
        }
        fn has_references_from_operand(&self, _snap: i64, _from_address: &Address, _operand_index: i32) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_flow_references_from(&self, _snap: i64, _from_address: &Address) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_references_to(&self, _snap: i64, _to_address: &Address) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_sources(&self, _span: &dyn Lifespan) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_destinations(&self, _span: &dyn Lifespan) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_count_from(&self, snap: i64, from_address: &Address) -> i32 {
            self.get_references_from(snap, from_address).len() as i32
        }
        fn get_reference_count_to(&self, _snap: i64, _to_address: &Address) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceReferenceManager for MockManager {
        fn get_reference_space(
            &mut self,
            space: &Arc<AddressSpace>,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceReferenceSpace>> {
            if let Some(pos) = self.spaces.iter().position(|s| s.space.name() == space.name()) {
                return Some(Box::new(MockSpace {
                    space: self.spaces[pos].space.clone(),
                    refs: self.spaces[pos].refs.clone(),
                }));
            }
            if !create_if_absent {
                return None;
            }
            self.spaces.push(MockSpace { space: space.clone(), refs: Vec::new() });
            Some(Box::new(MockSpace { space: space.clone(), refs: Vec::new() }))
        }
        fn get_reference_register_space_for_thread(
            &mut self,
            _thread: &dyn TraceThread,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceReferenceSpace>> {
            if self.register_space.is_none() {
                if !create_if_absent {
                    return None;
                }
                let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
                self.register_space = Some(MockSpace { space, refs: Vec::new() });
            }
            let rs = self.register_space.as_ref().unwrap();
            Some(Box::new(MockSpace { space: rs.space.clone(), refs: rs.refs.clone() }))
        }
        fn get_reference_register_space_for_frame(
            &mut self,
            _frame: &dyn TraceStackFrame,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceReferenceSpace>> {
            self.get_reference_register_space_for_thread(&DummyThread, create_if_absent)
        }
    }

    struct DummyThread;
    impl TraceThread for DummyThread {}

    struct DummyFrame;
    impl TraceStackFrame for DummyFrame {}

    #[test]
    fn creates_and_reuses_reference_spaces() {
        let mut mgr = MockManager { spaces: Vec::new(), register_space: None };
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);

        assert!(mgr.get_reference_space(&ram, false).is_none());

        let from = ram.address(0x1000);
        let to_range = AddressRange::new(ram.address(0x2000), ram.address(0x2000));
        mgr.add_memory_reference(&DummySpan, &from, to_range, RefType::Data, SourceType::UserDefined, 0);

        let space = mgr.get_reference_space(&ram, true).expect("space should now exist");
        assert_eq!(space.get_address_space().name(), "ram");
        assert!(space.has_references_from(0, &from));
    }

    #[test]
    fn is_object_safe_and_supertrait_reachable() {
        let mut mgr = MockManager { spaces: Vec::new(), register_space: None };
        let mut boxed: Box<dyn TraceReferenceManager> = Box::new(mgr);

        // Register-space overloads dispatch distinctly and honor create-if-absent.
        assert!(boxed.get_reference_register_space_for_thread(&DummyThread, false).is_none());
        let reg_space = boxed
            .get_reference_register_space_for_thread(&DummyThread, true)
            .expect("should create the register space");
        assert_eq!(reg_space.get_address_space().name(), "register");
        assert!(boxed
            .get_reference_register_space_for_frame(&DummyFrame, false)
            .is_some());

        // Supertrait (TraceReferenceOperations) methods remain reachable.
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let from = ram.address(0x1000);
        let to_range = AddressRange::new(ram.address(0x2000), ram.address(0x2000));
        boxed.add_memory_reference(&DummySpan, &from, to_range, RefType::Data, SourceType::UserDefined, 0);
        assert!(boxed.has_references_from(0, &from));
    }
}
