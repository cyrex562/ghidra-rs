use crate::program::model::address::AddressSpace;
use crate::trace::model::symbol::trace_equate_operations::TraceEquateOperations;
use std::sync::Arc;

/// The equate operations scoped to a single address space within a trace.
///
/// Port of `ghidra.trace.model.symbol.TraceEquateSpace`.
///
/// It was selected as a dependency-cycle cut-point.
pub trait TraceEquateSpace: TraceEquateOperations {
    /// Get the address space to which this equate space is scoped.
    fn get_address_space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpaceType,
    };
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::symbol::trace_equate::TraceEquate;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;



    struct MockSpace {
        space: Arc<AddressSpace>,
        referring: AddressSet,
    }

    impl TraceEquateOperations for MockSpace {
        fn get_referring_addresses(&self, _span: Lifespan) -> Box<dyn AddressSetView> {
            Box::new(self.referring.clone())
        }

        fn clear_references(
            &mut self,
            _span: Lifespan,
            _asv: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn clear_references_range(
            &mut self,
            _span: Lifespan,
            _range: &AddressRange,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn get_referenced_by_value(
            &self,
            _snap: i64,
            _address: &Address,
            _operand_index: i32,
            _value: i64,
        ) -> Option<Box<dyn TraceEquate>> {
            None
        }

        fn get_referenced(&self, _snap: i64, _address: &Address, _operand_index: i32) -> Vec<Box<dyn TraceEquate>> {
            Vec::new()
        }

        fn get_referenced_all_operands(&self, _snap: i64, _address: &Address) -> Vec<Box<dyn TraceEquate>> {
            Vec::new()
        }
    }

    impl TraceEquateSpace for MockSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    #[test]
    fn usable_as_trait_object_and_reports_address_space() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mut referring = AddressSet::new();
        referring.add_address(&space.address(0x1000));

        let boxed: Box<dyn TraceEquateSpace> = Box::new(MockSpace {
            space: space.clone(),
            referring,
        });

        assert_eq!(boxed.get_address_space().name(), "ram");

        // Supertrait (TraceEquateOperations) methods remain reachable.
        let lifespan = Lifespan::span(0, 100);
        let referring = boxed.get_referring_addresses(lifespan);
        assert!(referring.contains(&space.address(0x1000)));
    }
}
