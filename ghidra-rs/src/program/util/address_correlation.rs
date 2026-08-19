use crate::program::model::address::Address;
use crate::program::seam_stubs::AddressCorrelationRangeLike;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Interface representing the address mapping for any means of correlating addresses
/// between a source program and a destination program.
pub trait AddressCorrelation: Send + Sync {
    /// Returns the address range in the destination program that correlates to the
    /// corresponding range in the source program.
    ///
    /// # Arguments
    /// * `source_address` - the source program address
    /// * `monitor` - the task monitor
    ///
    /// # Returns
    /// The destination program address range, or `None` if no address range is mapped.
    ///
    /// # Errors
    /// Returns `CancelledException` if the monitor is cancelled.
    fn get_correlated_destination_range(
        &self,
        source_address: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn AddressCorrelationRangeLike>>, CancelledException>;

    /// This method is no longer part of the API. Leaving a default implementation to reduce
    /// breaking clients.
    ///
    /// # Returns
    /// The simple class name of the implementing type, mirroring `getClass().getSimpleName()`.
    fn get_name(&self) -> String
    where
        Self: Sized,
    {
        let full = std::any::type_name::<Self>();
        full.rsplit("::").next().unwrap_or(full).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct FixedRange {
        min: Address,
        range: crate::program::model::address::AddressRange,
        name: String,
    }

    impl AddressCorrelationRangeLike for FixedRange {
        fn min_address(&self) -> Address {
            self.min.clone()
        }

        fn range(&self) -> crate::program::model::address::AddressRange {
            self.range.clone()
        }

        fn correlator_name(&self) -> String {
            self.name.clone()
        }
    }

    struct ConstantCorrelation {
        space: std::sync::Arc<AddressSpace>,
    }

    impl AddressCorrelation for ConstantCorrelation {
        fn get_correlated_destination_range(
            &self,
            source_address: &Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn AddressCorrelationRangeLike>>, CancelledException> {
            monitor.check_cancelled()?;
            if source_address.offset() == 0 {
                return Ok(None);
            }
            let min = Address::new(self.space.clone(), 0x2000);
            let max = Address::new(self.space.clone(), 0x2010);
            let range = crate::program::model::address::AddressRange::new(min.clone(), max);
            Ok(Some(Box::new(FixedRange {
                min,
                range,
                name: "ConstantCorrelation".to_string(),
            })))
        }
    }

    fn test_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn trait_object_creation() {
        let corr = ConstantCorrelation { space: test_space() };
        let _: Box<dyn AddressCorrelation> = Box::new(corr);
    }

    #[test]
    fn maps_nonzero_source_to_destination_range() {
        let space = test_space();
        let corr = ConstantCorrelation { space: space.clone() };
        let monitor = crate::util::task::DummyMonitor;
        let source = Address::new(space, 0x1000);
        let result = corr
            .get_correlated_destination_range(&source, &monitor)
            .expect("not cancelled")
            .expect("range present");
        assert_eq!(result.min_address().offset(), 0x2000);
        assert_eq!(result.correlator_name(), "ConstantCorrelation");
    }

    #[test]
    fn zero_source_has_no_mapping() {
        let space = test_space();
        let corr = ConstantCorrelation { space: space.clone() };
        let monitor = crate::util::task::DummyMonitor;
        let source = Address::new(space, 0);
        let result = corr
            .get_correlated_destination_range(&source, &monitor)
            .expect("not cancelled");
        assert!(result.is_none());
    }

    #[test]
    fn get_name_defaults_to_simple_type_name() {
        let corr = ConstantCorrelation { space: test_space() };
        assert_eq!(corr.get_name(), "ConstantCorrelation");
    }
}
