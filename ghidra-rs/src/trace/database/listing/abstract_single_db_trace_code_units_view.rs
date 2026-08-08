//! Port of `ghidra.trace.database.listing.AbstractSingleDBTraceCodeUnitsView`.

use crate::trace::seam_stubs::AbstractBaseDBTraceCodeUnitsView;

/// An abstract implementation of a single-type view.
///
/// Port of `ghidra.trace.database.listing.AbstractSingleDBTraceCodeUnitsView`.
///
/// The Java class declares no members beyond forwarding its constructor to
/// [`AbstractBaseDBTraceCodeUnitsView`] (its superclass); it exists purely as a marker/upper
/// bound so that composed views (`AbstractComposedDBTraceCodeUnitsView`) can hold several
/// distinct single-type views polymorphically. Mirrored here as a marker supertrait for the same
/// reason.
pub trait AbstractSingleDBTraceCodeUnitsView: AbstractBaseDBTraceCodeUnitsView {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct MockSingleView {
        space: Arc<AddressSpace>,
    }

    impl AbstractBaseDBTraceCodeUnitsView for MockSingleView {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    impl AbstractSingleDBTraceCodeUnitsView for MockSingleView {}

    #[test]
    fn heterogeneous_single_views_are_usable_through_the_common_upper_bound() {
        let instructions_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let data_space = AddressSpace::new("data", 32, 1, AddressSpaceType::Ram, 1);

        // Two distinct "single" views (e.g. an instructions view and a data view in the real
        // hierarchy), stored through the common upper bound, as `AbstractComposedDBTraceCodeUnitsView`
        // would.
        let views: Vec<Box<dyn AbstractSingleDBTraceCodeUnitsView>> = vec![
            Box::new(MockSingleView { space: instructions_space.clone() }),
            Box::new(MockSingleView { space: data_space.clone() }),
        ];

        assert_eq!(views[0].get_space().name(), "ram");
        assert_eq!(views[1].get_space().name(), "data");
        assert!(!Arc::ptr_eq(&views[0].get_space(), &views[1].get_space()));
    }
}
