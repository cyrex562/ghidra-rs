use crate::trace::model::symbol::trace_reference::TraceReference;

/// The database-backed [`TraceReference`].
///
/// Port of `ghidra.trace.database.symbol.DBTraceReference`.
///
/// It was selected as a dependency-cycle cut-point: other database-backed trace code (e.g. the
/// not-yet-ported `DBTraceReferenceSpace`, which stores and returns these) needs a name for "the
/// concrete, DB-backed flavor of `TraceReference`" without depending on this crate's eventual
/// concrete struct directly.
///
/// The Java class `implements TraceReference` and declares **no public method beyond overrides of
/// [`TraceReference`]/[`Reference`](crate::program::model::symbol::Reference)** -- every one of
/// `getTrace`, `delete`, `getLifespan`, `getStartSnap`, `getFromAddress`, `getToRange`,
/// `setPrimary`, `isPrimary`, `getSymbolID`, `getReferenceType`, `getOperandIndex`, `getSource`,
/// `setReferenceType`, `setAssociatedSymbol`, and `clearAssociatedSymbol` restates a member already
/// declared on one of those two interfaces. Consistent with
/// [`AbstractDBTraceSymbol`](crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol)'s
/// precedent for the same situation, these overrides are not redeclared here -- implementors
/// provide them directly in their `impl TraceReference for X` block, backed by whatever internal
/// state (e.g. a `DBTraceReferenceSpace` entry, a lock, the owning trace) stands in for the Java
/// class's private `ent` field:
/// - `getTrace()` covariantly narrows [`TraceReference::get_trace`]'s return type from `Trace` to
///   `DBTrace` (`ent.space.trace`); Rust has no covariant trait-method override, so implementors
///   just return their own trace handle as `Box<dyn Trace>`.
/// - `delete()` holds the space's write lock, removes the underlying record, and -- if this
///   reference was primary -- promotes the next remaining reference at the same from-address and
///   operand index to primary (firing the corresponding change events along the way).
/// - `setPrimary(boolean)` holds the write lock, demotes whatever reference was previously primary
///   at this from-address/operand index (if any), then marks this one primary.
/// - `getSymbolID`/`getReferenceType`/`getOperandIndex`/`getSource`/`setReferenceType` are plain
///   field accessors/mutators on the entry.
/// - `setAssociatedSymbol`/`clearAssociatedSymbol` validate (address match, lifespan intersection)
///   before updating the entry's stored symbol id and firing a `SYMBOL_ASSOCIATION_ADDED`/
///   `SYMBOL_ASSOCIATION_REMOVED` change event.
///
/// `hashCode()` (mimicking `ent.getX1().hashCode()`, i.e. the from-address's hash) is `Object`-level
/// bookkeeping, not part of the `TraceReference` contract, and is not modeled here.
///
/// Since it adds no new members, any [`TraceReference`] implementation automatically satisfies this
/// trait via the blanket impl below, mirroring how any `DBTraceReference` instance in Java is usable
/// wherever a `TraceReference` is expected -- and, going the other direction, giving callers that
/// specifically need "a `TraceReference` backed by this crate's trace database" a distinct type to
/// name.
pub trait DBTraceReference: TraceReference {}

impl<T: TraceReference + ?Sized> DBTraceReference for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, Reference, SourceType, Symbol};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use std::sync::{Arc, Mutex};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// Shared per-(from-address, operand-index) state, standing in for the slice of
    /// `DBTraceReferenceSpace` that `DBTraceReference::delete`/`setPrimary` consult: which
    /// reference (by id) is currently primary, and which ids remain live.
    struct SharedSpace {
        primary_id: Option<u32>,
        live_ids: Vec<u32>,
    }

    /// A minimal `TraceReference` reproducing the Java class's `delete()`/`setPrimary()` logic
    /// directly in its `impl TraceReference` block, per this trait's documented convention (no
    /// default is provided on `DBTraceReference` itself). Proves the blanket impl makes a
    /// realistic implementor usable as `Box<dyn DBTraceReference>`, and that the reproduced
    /// primary-promotion behavior actually works.
    struct MockDbTraceReference {
        id: u32,
        from: Address,
        to_range: AddressRange,
        operand_index: i32,
        ref_type: RefType,
        space: Arc<Mutex<SharedSpace>>,
    }

    impl Reference for MockDbTraceReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn from_address(&self) -> Address {
            self.from.clone()
        }
        fn to_address(&self) -> Address {
            self.to_range.min_address().clone()
        }
        fn is_primary(&self) -> bool {
            self.space.lock().unwrap().primary_id == Some(self.id)
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
            SourceType::Default
        }
    }

    impl TraceReference for MockDbTraceReference {
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
            // Mirrors `DBTraceReference.setPrimary(boolean)`: demote whatever was primary before,
            // then mark this one primary.
            if primary == Reference::is_primary(self) {
                return;
            }
            let mut space = self.space.lock().unwrap();
            space.primary_id = Some(self.id);
        }

        fn set_reference_type(&mut self, ref_type: RefType) {
            self.ref_type = ref_type;
        }

        fn set_associated_symbol(&mut self, _symbol: Arc<dyn Symbol>) {
            unimplemented!("not exercised by this smoke test")
        }

        fn clear_associated_symbol(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }

        fn delete(&mut self) {
            // Mirrors `DBTraceReference.delete()`: remove this entry, and if it was primary,
            // promote the next remaining reference (by id order) at the same from/operand key.
            let was_primary = Reference::is_primary(self);
            let mut space = self.space.lock().unwrap();
            space.live_ids.retain(|id| *id != self.id);
            if was_primary {
                space.primary_id = space.live_ids.first().copied();
            }
        }
    }

    fn make_ref(id: u32, space: &Arc<Mutex<SharedSpace>>) -> MockDbTraceReference {
        MockDbTraceReference {
            id,
            from: addr(0x400),
            to_range: AddressRange::new(addr(0x2000), addr(0x2000)),
            operand_index: 0,
            ref_type: RefType::Data,
            space: Arc::clone(space),
        }
    }

    #[test]
    fn usable_as_trait_object_via_blanket_impl() {
        let space = Arc::new(Mutex::new(SharedSpace {
            primary_id: Some(1),
            live_ids: vec![1],
        }));
        let boxed: Box<dyn DBTraceReference> = Box::new(make_ref(1, &space));
        assert!(boxed.is_primary());
        assert_eq!(boxed.get_to_range(), AddressRange::new(addr(0x2000), addr(0x2000)));
    }

    #[test]
    fn deleting_the_primary_reference_promotes_the_next_remaining_one() {
        let space = Arc::new(Mutex::new(SharedSpace {
            primary_id: Some(1),
            live_ids: vec![1, 2, 3],
        }));
        let mut first: Box<dyn DBTraceReference> = Box::new(make_ref(1, &space));
        let second = make_ref(2, &space);
        let third = make_ref(3, &space);

        assert!(first.is_primary());
        assert!(!Reference::is_primary(&second));
        assert!(!Reference::is_primary(&third));

        first.delete();

        assert_eq!(space.lock().unwrap().live_ids, vec![2, 3]);
        assert_eq!(space.lock().unwrap().primary_id, Some(2));
        assert!(Reference::is_primary(&second));
    }

    #[test]
    fn deleting_a_non_primary_reference_leaves_the_primary_unchanged() {
        let space = Arc::new(Mutex::new(SharedSpace {
            primary_id: Some(1),
            live_ids: vec![1, 2],
        }));
        let first = make_ref(1, &space);
        let mut second: Box<dyn DBTraceReference> = Box::new(make_ref(2, &space));

        second.delete();

        assert_eq!(space.lock().unwrap().live_ids, vec![1]);
        assert_eq!(space.lock().unwrap().primary_id, Some(1));
        assert!(Reference::is_primary(&first));
    }

    #[test]
    fn set_primary_swaps_which_reference_is_primary() {
        let space = Arc::new(Mutex::new(SharedSpace {
            primary_id: Some(1),
            live_ids: vec![1, 2],
        }));
        let mut first: Box<dyn DBTraceReference> = Box::new(make_ref(1, &space));
        let mut second: Box<dyn DBTraceReference> = Box::new(make_ref(2, &space));

        assert!(first.is_primary());
        second.set_primary(true);
        assert!(!first.is_primary());
        assert!(second.is_primary());
    }
}
