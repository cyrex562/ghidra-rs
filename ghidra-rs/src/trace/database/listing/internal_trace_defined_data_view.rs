//! Port of `ghidra.trace.database.listing.InternalTraceDefinedDataView`.

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::Register;
use crate::program::util::code_unit_insertion_exception::CodeUnitInsertionException;
use crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter;
use crate::trace::database::listing::internal_trace_base_defined_units_view::InternalTraceBaseDefinedUnitsView;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_defined_data_view::TraceDefinedDataView;
use crate::trace::model::listing::trace_data::TraceData;
use crate::trace::seam_stubs::{TraceBasedDataTypeManager, TracePlatform, TraceRegisterUtils};

/// An internal view of defined data units with platform-aware create methods.
///
/// Port of `ghidra.trace.database.listing.InternalTraceDefinedDataView`.
///
/// This trait adds abstract methods that return `DBTraceDataAdapter` (narrowing the return type
/// from [`TraceDefinedDataView`]'s `Box<dyn TraceData>`), and provides default implementations
/// for the public overloads that automatically resolve a `DataType`'s platform.
///
/// It was selected as a dependency-cycle cut-point.
pub trait InternalTraceDefinedDataView: TraceDefinedDataView + InternalTraceBaseDefinedUnitsView {
    /// Create a data unit of unspecified length starting at the given address, on the given platform.
    ///
    /// Mirrors the Java abstract method overload
    /// `create(Lifespan, Address, TracePlatform, DataType)`.
    fn create(
        &mut self,
        lifespan: Lifespan,
        address: &Address,
        platform: &dyn TracePlatform,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn DBTraceDataAdapter>, CodeUnitInsertionException>;

    /// Create a data unit starting at the given address, on the given platform.
    ///
    /// Mirrors the Java abstract method overload
    /// `create(Lifespan, Address, TracePlatform, DataType, int)`.
    fn create_with_length(
        &mut self,
        lifespan: Lifespan,
        address: &Address,
        platform: &dyn TracePlatform,
        data_type: &dyn DataType,
        length: i32,
    ) -> Result<Box<dyn DBTraceDataAdapter>, CodeUnitInsertionException>;

    /// Determine the platform for a given data type.
    ///
    /// If the data type's manager is a [`TraceBasedDataTypeManager`] belonging to this trace,
    /// return its platform. Otherwise, return the trace's host platform.
    ///
    /// Mirrors `InternalTraceDefinedDataView.getPlatformOf(DataType)`.
    ///
    /// Note: Since the full implementation of [`TraceBasedDataTypeManager`] with
    /// `getTrace()` and `getPlatform()` methods is not yet ported, this always returns
    /// the host platform. Concrete implementers will override this method.
    fn get_platform_of(&self, _data_type: &dyn DataType) -> Box<dyn TracePlatform> {
        self.get_trace().get_platform_manager().get_host_platform()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_is_object_safe() {
        let _: Option<Box<dyn InternalTraceDefinedDataView>> = None;
    }
}
