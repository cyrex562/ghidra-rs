use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::symbol::trace_equate::TraceEquate;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Operations for querying and clearing equate references across a trace.
///
/// Port of `ghidra.trace.model.symbol.TraceEquateOperations`.
///
/// The Java interface's two `clearReferences` overloads (one taking an `AddressSetView`, the
/// other an `AddressRange`) and two `getReferenced` overloads (one taking an `operandIndex`, the
/// other not) cannot be represented as same-named Rust methods, so each is given a distinct,
/// descriptive name below, following the convention set by
/// [`TraceEquate`](crate::trace::model::symbol::trace_equate::TraceEquate).
pub trait TraceEquateOperations {
    /// Get the addresses which have at least one equate reference active during the given span.
    fn get_referring_addresses(&self, span: Lifespan) -> Box<dyn AddressSetView>;

    /// Clear all equate references in the given span and address set.
    ///
    /// Mirrors the Java overload `clearReferences(Lifespan, AddressSetView, TaskMonitor)`.
    fn clear_references(
        &mut self,
        span: Lifespan,
        asv: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Clear all equate references in the given span and address range.
    ///
    /// Mirrors the Java overload `clearReferences(Lifespan, AddressRange, TaskMonitor)`.
    fn clear_references_range(
        &mut self,
        span: Lifespan,
        range: &AddressRange,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Get the equate referenced by the given value, if any, at the given operand of the
    /// instruction/data unit at the given address and snap.
    fn get_referenced_by_value(
        &self,
        snap: i64,
        address: &Address,
        operand_index: i32,
        value: i64,
    ) -> Option<Box<dyn TraceEquate>>;

    /// Get the equates referenced by the given operand of the instruction/data unit at the given
    /// address and snap.
    ///
    /// Mirrors the Java overload `getReferenced(long, Address, int)`.
    fn get_referenced(&self, snap: i64, address: &Address, operand_index: i32) -> Vec<Box<dyn TraceEquate>>;

    /// Get the equates referenced by any operand of the instruction/data unit at the given
    /// address and snap.
    ///
    /// Mirrors the Java overload `getReferenced(long, Address)`.
    fn get_referenced_all_operands(&self, snap: i64, address: &Address) -> Vec<Box<dyn TraceEquate>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};



    struct NeverCancelled;

    impl TaskMonitor for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
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
            Ok(())
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

    #[derive(Clone)]
    struct MockEquate {
        name: String,
        value: i64,
    }

    impl TraceEquate for MockEquate {
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
            0
        }
        fn add_reference(
            &mut self,
            _lifespan: Lifespan,
            _thread: Option<Box<dyn crate::trace::seam_stubs::TraceThread>>,
            _address: Address,
            _operand_index: i32,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference> {
            unimplemented!()
        }
        fn add_reference_varnode(
            &mut self,
            _lifespan: Lifespan,
            _thread: Option<Box<dyn crate::trace::seam_stubs::TraceThread>>,
            _address: Address,
            _varnode: crate::program::model::pcode::Varnode,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference> {
            unimplemented!()
        }
        fn set_name(&mut self, new_name: &str) {
            self.name = new_name.to_string();
        }
        fn get_references(&self) -> Vec<Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference>> {
            Vec::new()
        }
        fn get_reference(
            &self,
            _snap: i64,
            _thread: Option<&dyn crate::trace::seam_stubs::TraceThread>,
            _address: &Address,
            _operand_index: i32,
        ) -> Option<Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference>> {
            None
        }
        fn get_reference_varnode(
            &self,
            _snap: i64,
            _thread: Option<&dyn crate::trace::seam_stubs::TraceThread>,
            _address: &Address,
            _varnode: &crate::program::model::pcode::Varnode,
        ) -> Option<Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference>> {
            None
        }
        fn has_valid_enum(&self) -> bool {
            false
        }
        fn is_enum_based(&self) -> bool {
            false
        }
        fn get_enum(&self) -> Option<Box<dyn crate::program::model::data::enum_::Enum>> {
            None
        }
        fn delete(&mut self) {}
    }

    /// Keys equates by `(address offset, operand_index)`; ignores snap/span scoping for
    /// simplicity since this mock only needs to prove the trait is object-safe and behaves
    /// sensibly for a single span of storage.
    struct MockOperations {
        by_operand: Vec<(i64, i32, MockEquate)>,
        referring: AddressSet,
    }

    impl TraceEquateOperations for MockOperations {
        fn get_referring_addresses(&self, _span: Lifespan) -> Box<dyn AddressSetView> {
            Box::new(self.referring.clone())
        }

        fn clear_references(
            &mut self,
            _span: Lifespan,
            asv: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.by_operand.retain(|(offset, _, _)| {
                let space = self.referring.min_address().unwrap().space().clone();
                !asv.contains(&Address::new(space, *offset))
            });
            Ok(())
        }

        fn clear_references_range(
            &mut self,
            _span: Lifespan,
            range: &AddressRange,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.by_operand.retain(|(offset, _, _)| {
                let space = range.min_address().space().clone();
                !range.contains(&Address::new(space, *offset))
            });
            Ok(())
        }

        fn get_referenced_by_value(
            &self,
            _snap: i64,
            address: &Address,
            operand_index: i32,
            value: i64,
        ) -> Option<Box<dyn TraceEquate>> {
            self.by_operand
                .iter()
                .find(|(offset, op, eq)| *offset == address.offset() && *op == operand_index && eq.value == value)
                .map(|(_, _, eq)| Box::new(eq.clone()) as Box<dyn TraceEquate>)
        }

        fn get_referenced(&self, _snap: i64, address: &Address, operand_index: i32) -> Vec<Box<dyn TraceEquate>> {
            self.by_operand
                .iter()
                .filter(|(offset, op, _)| *offset == address.offset() && *op == operand_index)
                .map(|(_, _, eq)| Box::new(eq.clone()) as Box<dyn TraceEquate>)
                .collect()
        }

        fn get_referenced_all_operands(&self, _snap: i64, address: &Address) -> Vec<Box<dyn TraceEquate>> {
            self.by_operand
                .iter()
                .filter(|(offset, _, _)| *offset == address.offset())
                .map(|(_, _, eq)| Box::new(eq.clone()) as Box<dyn TraceEquate>)
                .collect()
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_ops() -> MockOperations {
        let a = addr(0x1000);
        let b = addr(0x2000);
        let mut referring = AddressSet::new();
        referring.add_address(&a);
        referring.add_address(&b);
        MockOperations {
            by_operand: vec![
                (0x1000, 0, MockEquate { name: "A".into(), value: 1 }),
                (0x1000, 1, MockEquate { name: "B".into(), value: 2 }),
                (0x2000, 0, MockEquate { name: "C".into(), value: 3 }),
            ],
            referring,
        }
    }

    #[test]
    fn get_referenced_filters_by_operand_index() {
        let ops = make_ops();
        let span = Lifespan::span(0, 100);
        let a = addr(0x1000);

        let at_op0 = ops.get_referenced(10, &a, 0);
        assert_eq!(at_op0.len(), 1);
        assert_eq!(at_op0[0].get_name(), "A");

        let all = ops.get_referenced_all_operands(10, &a);
        assert_eq!(all.len(), 2);

        let by_value = ops.get_referenced_by_value(10, &a, 1, 2);
        assert!(by_value.is_some());
        assert_eq!(by_value.unwrap().get_name(), "B");

        let missing = ops.get_referenced_by_value(10, &a, 1, 999);
        assert!(missing.is_none());

        let _ = ops.get_referring_addresses(span);
    }

    #[test]
    fn dyn_trait_object_supports_clearing() {
        let mut boxed: Box<dyn TraceEquateOperations> = Box::new(make_ops());
        let span = Lifespan::span(0, 100);
        let monitor = NeverCancelled;

        let a = addr(0x1000);
        let mut set = AddressSet::new();
        set.add_address(&a);

        boxed
            .clear_references(span, &set, &monitor)
            .expect("clear should not be cancelled");
        assert!(boxed.get_referenced_all_operands(10, &a).is_empty());

        let b = addr(0x2000);
        assert_eq!(boxed.get_referenced_all_operands(10, &b).len(), 1);

        let range = AddressRange::new(b.clone(), b.clone());
        boxed
            .clear_references_range(span, &range, &monitor)
            .expect("clear range should not be cancelled");
        assert!(boxed.get_referenced_all_operands(10, &b).is_empty());
    }
}
