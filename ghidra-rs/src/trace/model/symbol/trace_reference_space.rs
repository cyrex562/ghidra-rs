use crate::program::model::address::AddressSpace;
use crate::trace::model::symbol::trace_reference_operations::TraceReferenceOperations;
use std::sync::Arc;

/// The reference operations scoped to a single address space within a trace.
///
/// Port of `ghidra.trace.model.symbol.TraceReferenceSpace`.
///
/// It was selected as a dependency-cycle cut-point.
pub trait TraceReferenceSpace: TraceReferenceOperations {
    /// Get the address space to which this reference space is scoped.
    fn get_address_space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpaceType,
    };
    use crate::program::model::lang::Register;
    use crate::program::model::symbol::{RefType, Reference, SourceType, Symbol};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::symbol::trace_offset_reference::TraceOffsetReference;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_shifted_reference::TraceShiftedReference;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::Rectangle2DDirection;
    use std::any::Any;



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
        fn get_lifespan(&self) -> Lifespan {
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
        fn set_associated_symbol(&mut self, _symbol: Arc<dyn Symbol>) {}
        fn clear_associated_symbol(&mut self) {}
        fn delete(&mut self) {}
    }

    /// Stores references in the given address space as a flat `Vec`, proving the trait is
    /// object-safe and correctly scoped to a single [`AddressSpace`].
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
            _lifespan: Lifespan,
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
            _lifespan: Lifespan,
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
            _lifespan: Lifespan,
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
            _lifespan: Lifespan,
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
            _lifespan: Lifespan,
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
            _lifespan: Lifespan,
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
            _span: Lifespan,
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

        fn clear_references_from(&mut self, _span: Lifespan, range: &AddressRange) {
            self.refs.retain(|r| !range.contains(&r.from));
        }

        fn get_references_to(&self, _snap: i64, to_address: &Address) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| r.to_range.contains(to_address))
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }

        fn clear_references_to(&mut self, _span: Lifespan, range: &AddressRange) {
            self.refs.retain(|r| range.intersect(&r.to_range).is_none());
        }

        fn get_references_to_range(
            &self,
            _span: Lifespan,
            range: &AddressRange,
            _order: Option<&dyn Rectangle2DDirection>,
        ) -> Vec<Box<dyn TraceReference>> {
            self.refs
                .iter()
                .filter(|r| range.intersect(&r.to_range).is_some())
                .map(|r| Box::new(r.clone()) as Box<dyn TraceReference>)
                .collect()
        }

        fn get_reference_sources(&self, _span: Lifespan) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for r in &self.refs {
                set.add_address(&r.from);
            }
            Box::new(set)
        }

        fn get_reference_destinations(&self, _span: Lifespan) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
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

    #[test]
    fn usable_as_trait_object_and_reports_address_space() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut boxed: Box<dyn TraceReferenceSpace> = Box::new(MockSpace {
            space: space.clone(),
            refs: Vec::new(),
        });

        assert_eq!(boxed.get_address_space().name(), "ram");

        // Supertrait (TraceReferenceOperations) methods remain reachable.
        let span = Lifespan::span(0, 100);
        let from = space.address(0x1000);
        let to = space.address(0x2000);

        let added = boxed.add_memory_reference_to_address(
            span,
            &from,
            &to,
            RefType::Data,
            SourceType::UserDefined,
            0,
        );
        assert!(added.is_primary());
        assert!(boxed.has_references_from(10, &from));
        assert_eq!(boxed.get_reference_count_to(10, &to), 1);
    }
}
