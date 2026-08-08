use crate::program::model::address::Address;
use crate::program::model::data::enum_::Enum;
use crate::program::model::pcode::Varnode;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::symbol::trace_equate_reference::TraceEquateReference;
use crate::trace::seam_stubs::TraceThread;

/// A named, scalar-valued substitution attached to one or more locations within a trace.
///
/// Port of `ghidra.trace.model.symbol.TraceEquate`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface's doc notes it is "like [`Equate`](crate::program::model::symbol::equate::Equate),
/// except that extending it would prevent references with snaps" -- i.e. every lookup/reference
/// method here is additionally scoped by a lifespan/snap and (optionally) a
/// [`TraceThread`](crate::trace::seam_stubs::TraceThread), unlike the plain, address-only
/// `Equate`. Because of that, `TraceEquate` is ported standalone rather than as a subtrait of
/// `Equate`.
///
/// The Java overloads of `addReference`/`getReference` (one taking an `int operandIndex`, the
/// other a `Varnode`) cannot be represented as same-named Rust methods (Rust has no overloading),
/// so each overload is given a distinct, descriptive name below, following the convention set by
/// [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView).
pub trait TraceEquate {
    /// Get the actual name of this equate.
    fn get_name(&self) -> &str;

    /// Get the display name of this equate.
    fn get_display_name(&self) -> String;

    /// Get the value substituted by this equate.
    fn get_value(&self) -> i64;

    /// Get the display value (as formatted text) of this equate.
    fn get_display_value(&self) -> String;

    /// Get the number of references to this equate.
    fn get_reference_count(&self) -> i32;

    /// Add a reference to this equate at the given operand of the instruction/data unit at the
    /// given address, effective for the given lifespan and (if applicable) thread.
    fn add_reference(
        &mut self,
        lifespan: Lifespan,
        thread: Option<Box<dyn TraceThread>>,
        address: Address,
        operand_index: i32,
    ) -> Box<dyn TraceEquateReference>;

    /// Add a reference to this equate at the given varnode, effective for the given lifespan and
    /// (if applicable) thread.
    ///
    /// Mirrors the Java overload `addReference(Lifespan, TraceThread, Address, Varnode)`.
    fn add_reference_varnode(
        &mut self,
        lifespan: Lifespan,
        thread: Option<Box<dyn TraceThread>>,
        address: Address,
        varnode: Varnode,
    ) -> Box<dyn TraceEquateReference>;

    /// Rename this equate.
    fn set_name(&mut self, new_name: &str);

    /// Get all references to this equate.
    fn get_references(&self) -> Vec<Box<dyn TraceEquateReference>>;

    /// Get the reference to this equate, if any, at the given operand of the instruction/data
    /// unit at the given address and snap.
    fn get_reference(
        &self,
        snap: i64,
        thread: Option<&dyn TraceThread>,
        address: &Address,
        operand_index: i32,
    ) -> Option<Box<dyn TraceEquateReference>>;

    /// Get the reference to this equate, if any, at the given varnode and snap.
    ///
    /// Mirrors the Java overload `getReference(long, TraceThread, Address, Varnode)`.
    fn get_reference_varnode(
        &self,
        snap: i64,
        thread: Option<&dyn TraceThread>,
        address: &Address,
        varnode: &Varnode,
    ) -> Option<Box<dyn TraceEquateReference>>;

    /// Check whether this equate is backed by a still-valid enum data type.
    fn has_valid_enum(&self) -> bool;

    /// Check whether this equate is backed by an enum data type at all.
    fn is_enum_based(&self) -> bool;

    /// Get the enum data type backing this equate, if any.
    fn get_enum(&self) -> Option<Box<dyn Enum>>;

    /// Delete this equate.
    fn delete(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};



    struct MockThread;

    impl TraceThread for MockThread {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[derive(Clone)]
    struct MockTraceEquateReference {
        address: Address,
        op_index: i32,
        start_snap: i64,
    }

    impl TraceEquateReference for MockTraceEquateReference {
        fn equate_reference(&self) -> crate::program::database::symbol::equate_store::EquateReference {
            crate::program::database::symbol::equate_store::EquateReference {
                address: self.address.clone(),
                op_index: Some(self.op_index as i16),
                dynamic_hash: None,
            }
        }

        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.start_snap, i64::MAX)
        }

        fn get_thread(&self) -> Box<dyn TraceThread> {
            Box::new(MockThread)
        }

        fn get_varnode(&self) -> Varnode {
            Varnode::new(self.address.clone(), 4)
        }

        fn delete(&mut self) {}
    }

    struct MockTraceEquate {
        name: String,
        value: i64,
        references: Vec<MockTraceEquateReference>,
        deleted: bool,
    }

    impl TraceEquate for MockTraceEquate {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_display_name(&self) -> String {
            self.name.clone()
        }

        fn get_value(&self) -> i64 {
            self.value
        }

        fn get_display_value(&self) -> String {
            format!("0x{:x}", self.value)
        }

        fn get_reference_count(&self) -> i32 {
            self.references.len() as i32
        }

        fn add_reference(
            &mut self,
            lifespan: Lifespan,
            _thread: Option<Box<dyn TraceThread>>,
            address: Address,
            operand_index: i32,
        ) -> Box<dyn TraceEquateReference> {
            let reference = MockTraceEquateReference {
                address,
                op_index: operand_index,
                start_snap: lifespan.lmin(),
            };
            self.references.push(reference.clone());
            Box::new(reference)
        }

        fn add_reference_varnode(
            &mut self,
            lifespan: Lifespan,
            thread: Option<Box<dyn TraceThread>>,
            address: Address,
            _varnode: Varnode,
        ) -> Box<dyn TraceEquateReference> {
            self.add_reference(lifespan, thread, address, -1)
        }

        fn set_name(&mut self, new_name: &str) {
            self.name = new_name.to_string();
        }

        fn get_references(&self) -> Vec<Box<dyn TraceEquateReference>> {
            self.references
                .iter()
                .cloned()
                .map(|r| Box::new(r) as Box<dyn TraceEquateReference>)
                .collect()
        }

        fn get_reference(
            &self,
            snap: i64,
            _thread: Option<&dyn TraceThread>,
            address: &Address,
            operand_index: i32,
        ) -> Option<Box<dyn TraceEquateReference>> {
            self.references
                .iter()
                .find(|r| {
                    r.address == *address && r.op_index == operand_index && r.start_snap <= snap
                })
                .cloned()
                .map(|r| Box::new(r) as Box<dyn TraceEquateReference>)
        }

        fn get_reference_varnode(
            &self,
            snap: i64,
            thread: Option<&dyn TraceThread>,
            address: &Address,
            _varnode: &Varnode,
        ) -> Option<Box<dyn TraceEquateReference>> {
            self.get_reference(snap, thread, address, -1)
        }

        fn has_valid_enum(&self) -> bool {
            false
        }

        fn is_enum_based(&self) -> bool {
            false
        }

        fn get_enum(&self) -> Option<Box<dyn Enum>> {
            None
        }

        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    fn make_equate() -> MockTraceEquate {
        MockTraceEquate {
            name: "FLAG".to_string(),
            value: 0x10,
            references: Vec::new(),
            deleted: false,
        }
    }

    #[test]
    fn add_reference_and_look_it_up_by_operand() {
        let mut equate = make_equate();
        let addr1 = addr(0x400);

        equate.add_reference(Lifespan::span(5, 100), None, addr1.clone(), 0);

        assert_eq!(equate.get_reference_count(), 1);
        let found = equate.get_reference(10, None, &addr1, 0);
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_lifespan().lmin(), 5);

        assert!(equate.get_reference(3, None, &addr1, 0).is_none());
        assert!(equate.get_reference(10, None, &addr1, 1).is_none());
    }

    #[test]
    fn dyn_trait_object_supports_mutators_and_lookups() {
        let mut boxed: Box<dyn TraceEquate> = Box::new(make_equate());

        assert_eq!(boxed.get_name(), "FLAG");
        assert_eq!(boxed.get_display_value(), "0x10");

        boxed.set_name("RENAMED");
        assert_eq!(boxed.get_name(), "RENAMED");

        let addr1 = addr(0x2000);
        boxed.add_reference_varnode(
            Lifespan::span(0, 50),
            None,
            addr1.clone(),
            Varnode::new(addr1.clone(), 4),
        );
        assert_eq!(boxed.get_references().len(), 1);

        assert!(!boxed.has_valid_enum());
        assert!(boxed.get_enum().is_none());

        boxed.delete();
    }
}
