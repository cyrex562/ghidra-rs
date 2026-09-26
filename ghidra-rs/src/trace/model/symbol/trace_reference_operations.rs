use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::program::model::lang::Register;
use crate::program::model::symbol::{RefType, Reference, SourceType};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::symbol::trace_offset_reference::TraceOffsetReference;
use crate::trace::model::symbol::trace_reference::TraceReference;
use crate::trace::model::symbol::trace_shifted_reference::TraceShiftedReference;
use crate::trace::seam_stubs::Rectangle2DDirection;

/// The operations for adding and retrieving references.
///
/// Port of `ghidra.trace.model.symbol.TraceReferenceOperations`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface overloads several methods on argument shape alone (e.g. `addReference`,
/// `addMemoryReference`, `getReference`, `getReferencesFrom`, `getReferencesToRange`), which Rust
/// cannot represent as same-named trait methods. Each overload is therefore given a distinct,
/// descriptive name below, following the convention set by
/// [`TraceEquateOperations`](crate::trace::model::symbol::trace_equate_operations::TraceEquateOperations).
///
/// Variable references are not (yet) supported by the trace model, mirroring the Java interface's
/// `// NOTE: Variable references are not (yet?) supported` comment.
pub trait TraceReferenceOperations {
    /// Add a (copy of the) given reference to this manager.
    fn add_reference(&mut self, reference: &dyn TraceReference) -> Box<dyn TraceReference>;

    /// Add a (copy of the) given reference to this manager, for the given lifespan.
    ///
    /// Mirrors the Java overload `addReference(Lifespan, Reference)`.
    fn add_reference_for_lifespan(
        &mut self,
        lifespan: Lifespan,
        reference: &dyn Reference,
    ) -> Box<dyn TraceReference>;

    /// Add a memory reference to the given "to" address range.
    ///
    /// Mirrors the Java overload `addMemoryReference(Lifespan, Address, AddressRange, RefType,
    /// SourceType, int)`.
    fn add_memory_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: &Address,
        to_range: AddressRange,
        ref_type: RefType,
        source: SourceType,
        operand_index: i32,
    ) -> Box<dyn TraceReference>;

    /// Add a memory reference to the given singleton "to" address.
    ///
    /// Mirrors the Java overload `addMemoryReference(Lifespan, Address, Address, RefType,
    /// SourceType, int)`, whose default body constructs a singleton `AddressRangeImpl` and
    /// delegates to [`Self::add_memory_reference`].
    fn add_memory_reference_to_address(
        &mut self,
        lifespan: Lifespan,
        from_address: &Address,
        to_address: &Address,
        ref_type: RefType,
        source: SourceType,
        operand_index: i32,
    ) -> Box<dyn TraceReference> {
        self.add_memory_reference(
            lifespan,
            from_address,
            AddressRange::new(to_address.clone(), to_address.clone()),
            ref_type,
            source,
            operand_index,
        )
    }

    /// Add an offset memory reference.
    ///
    /// `to_addr_is_base` indicates whether `to_address` incorporates the offset: `false` means
    /// `to_address = base + offset`; `true` means `to_address = base`.
    fn add_offset_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: &Address,
        to_address: &Address,
        to_addr_is_base: bool,
        offset: i64,
        ref_type: RefType,
        source: SourceType,
        operand_index: i32,
    ) -> Box<dyn TraceOffsetReference>;

    /// Add a shifted memory reference. `shift` is the number of bits to shift left.
    fn add_shifted_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: &Address,
        to_address: &Address,
        shift: i32,
        ref_type: RefType,
        source: SourceType,
        operand_index: i32,
    ) -> Box<dyn TraceShiftedReference>;

    /// Add a register reference.
    fn add_register_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: &Address,
        to_register: &Register,
        ref_type: RefType,
        source: SourceType,
        operand_index: i32,
    ) -> Box<dyn TraceReference>;

    /// Add a (static) stack reference.
    fn add_stack_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: &Address,
        to_stack_offset: i32,
        ref_type: RefType,
        source: SourceType,
        operand_index: i32,
    ) -> Box<dyn TraceReference>;

    /// Find the reference that matches the given parameters.
    ///
    /// It is not sufficient to *intersect* the to range; it must exactly match that given.
    fn get_reference(
        &self,
        snap: i64,
        from_address: &Address,
        to_range: AddressRange,
        operand_index: i32,
    ) -> Option<Box<dyn TraceReference>>;

    /// Find the reference that matches the given parameters, where the "to" side is a singleton
    /// address.
    ///
    /// It is not sufficient to *contain* the to address; the to range must be a singleton and
    /// exactly match that given. To match a range, see [`Self::get_reference`].
    ///
    /// Mirrors the Java overload `getReference(long, Address, Address, int)`, whose default body
    /// constructs a singleton `AddressRangeImpl` and delegates to [`Self::get_reference`].
    fn get_reference_to_address(
        &self,
        snap: i64,
        from_address: &Address,
        to_address: &Address,
        operand_index: i32,
    ) -> Option<Box<dyn TraceReference>> {
        self.get_reference(
            snap,
            from_address,
            AddressRange::new(to_address.clone(), to_address.clone()),
            operand_index,
        )
    }

    /// Find all references from the given snapshot and address.
    ///
    /// Mirrors the Java overload `getReferencesFrom(long, Address)`.
    fn get_references_from(&self, snap: i64, from_address: &Address) -> Vec<Box<dyn TraceReference>>;

    /// Find all references from the given snapshot, address, and operand index.
    ///
    /// Mirrors the Java overload `getReferencesFrom(long, Address, int)`.
    fn get_references_from_operand(
        &self,
        snap: i64,
        from_address: &Address,
        operand_index: i32,
    ) -> Vec<Box<dyn TraceReference>>;

    /// Find all references with from addresses contained in the given lifespan and address range.
    fn get_references_from_range(
        &self,
        span: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceReference>>;

    /// Get the primary reference matching the given snapshot, address, and operand index.
    fn get_primary_reference_from(
        &self,
        snap: i64,
        from_address: &Address,
        operand_index: i32,
    ) -> Option<Box<dyn TraceReference>>;

    /// Get all flow references from the given snapshot and address.
    fn get_flow_references_from(&self, snap: i64, from_address: &Address) -> Vec<Box<dyn TraceReference>>;

    /// Clear all references from the given lifespan and address range.
    ///
    /// Any reference intersecting the given "from" parameters will have its lifespan truncated to
    /// the start of the given lifespan.
    fn clear_references_from(&mut self, span: Lifespan, range: &AddressRange);

    /// Get all references whose to address (or range) contains the given snapshot and address.
    fn get_references_to(&self, snap: i64, to_address: &Address) -> Vec<Box<dyn TraceReference>>;

    /// Clear all references to the given lifespan and address range.
    ///
    /// Any reference intersecting the given "to" parameters will have its lifespan truncated to
    /// the start of the given lifespan.
    fn clear_references_to(&mut self, span: Lifespan, range: &AddressRange);

    /// Get all references whose to address range intersects the given lifespan and address
    /// range, in the given order.
    ///
    /// `order` mirrors the Java parameter: `None` means no particular order (spares the cost of
    /// sorting); `Some` selects one of the orderings documented on
    /// [`Rectangle2DDirection`]. "Secondary" sorting is not supported.
    fn get_references_to_range(
        &self,
        span: Lifespan,
        range: &AddressRange,
        order: Option<&dyn Rectangle2DDirection>,
    ) -> Vec<Box<dyn TraceReference>>;

    /// Get all references whose to address range intersects the given lifespan and address
    /// range, in no particular order.
    ///
    /// Mirrors the Java overload `getReferencesToRange(Lifespan, AddressRange)`, whose default
    /// body delegates to [`Self::get_references_to_range`] with a `null` order.
    fn get_references_to_range_unordered(
        &self,
        span: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceReference>> {
        self.get_references_to_range(span, range, None)
    }

    /// Check if there exists a reference from the given snapshot and address.
    ///
    /// Mirrors the Java overload `hasReferencesFrom(long, Address)`.
    fn has_references_from(&self, snap: i64, from_address: &Address) -> bool {
        !self.get_references_from(snap, from_address).is_empty()
    }

    /// Check if there exists a reference from the given snapshot, address, and operand.
    ///
    /// Mirrors the Java overload `hasReferencesFrom(long, Address, int)`.
    fn has_references_from_operand(&self, snap: i64, from_address: &Address, operand_index: i32) -> bool {
        !self.get_references_from_operand(snap, from_address, operand_index).is_empty()
    }

    /// Check if there exists a flow reference from the given snapshot and address.
    fn has_flow_references_from(&self, snap: i64, from_address: &Address) -> bool {
        !self.get_flow_references_from(snap, from_address).is_empty()
    }

    /// Check if there exists a reference to the given snapshot and address.
    fn has_references_to(&self, snap: i64, to_address: &Address) -> bool {
        !self.get_references_to(snap, to_address).is_empty()
    }

    /// Get an address set of all "from" addresses in any reference intersecting the given
    /// lifespan.
    fn get_reference_sources(&self, span: Lifespan) -> Box<dyn AddressSetView>;

    /// Get an address set of all "to" addresses in any reference intersecting the given lifespan.
    fn get_reference_destinations(&self, span: Lifespan) -> Box<dyn AddressSetView>;

    /// Count the number of references from the given snapshot and address.
    fn get_reference_count_from(&self, snap: i64, from_address: &Address) -> i32;

    /// Count the number of references to the given snapshot and address.
    fn get_reference_count_to(&self, snap: i64, to_address: &Address) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::Symbol;
    use crate::trace::model::trace::Trace;
    use std::any::Any;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
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

    /// Stores references as a flat `Vec`, ignoring span/lifespan scoping for simplicity since
    /// this mock only needs to prove the trait is object-safe and behaves sensibly for a single
    /// span of storage.
    struct MockOperations {
        refs: Vec<MockReference>,
    }

    impl MockOperations {
        fn new() -> Self {
            MockOperations { refs: Vec::new() }
        }
    }

    impl TraceReferenceOperations for MockOperations {
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



    #[test]
    fn add_and_query_memory_references() {
        let mut ops = MockOperations::new();
        let span = Lifespan::span(0, 100);
        let from = addr(0x1000);
        let to = addr(0x2000);

        let first = ops.add_memory_reference_to_address(
            span,
            &from,
            &to,
            RefType::Data,
            SourceType::UserDefined,
            0,
        );
        assert!(first.is_primary());
        assert_eq!(first.to_address(), to);

        // A second reference at the same from-address/operand is not primary.
        let second_to = addr(0x3000);
        let second = ops.add_memory_reference_to_address(
            span,
            &from,
            &second_to,
            RefType::Data,
            SourceType::UserDefined,
            0,
        );
        assert!(!second.is_primary());

        assert_eq!(ops.get_reference_count_from(10, &from), 2);
        assert!(ops.has_references_from(10, &from));
        assert!(ops.has_references_from_operand(10, &from, 0));
        assert!(!ops.has_references_from_operand(10, &from, 1));

        let found = ops
            .get_reference_to_address(10, &from, &to, 0)
            .expect("exact match should be found");
        assert_eq!(found.to_address(), to);
        assert!(ops.get_reference_to_address(10, &from, &addr(0x9000), 0).is_none());

        let primary = ops
            .get_primary_reference_from(10, &from, 0)
            .expect("primary reference should exist");
        assert_eq!(primary.to_address(), to);

        assert_eq!(ops.get_reference_count_to(10, &to), 1);
        assert!(ops.has_references_to(10, &to));
        assert!(!ops.has_references_to(10, &addr(0x4000)));
    }

    #[test]
    fn dyn_trait_object_supports_clearing_and_unordered_range_query() {
        let mut boxed: Box<dyn TraceReferenceOperations> = Box::new(MockOperations::new());
        let span = Lifespan::span(0, 100);
        let from = addr(0x1000);
        let to = addr(0x2000);

        boxed.add_memory_reference_to_address(span, &from, &to, RefType::Data, SourceType::UserDefined, 0);
        assert!(boxed.has_references_from(10, &from));

        let range = AddressRange::new(to.clone(), to.clone());
        let hits = boxed.get_references_to_range_unordered(span, &range);
        assert_eq!(hits.len(), 1);

        let clear_range = AddressRange::new(from.clone(), from.clone());
        boxed.clear_references_from(span, &clear_range);
        assert!(!boxed.has_references_from(10, &from));
        assert!(boxed.get_references_to_range_unordered(span, &range).is_empty());
    }
}
