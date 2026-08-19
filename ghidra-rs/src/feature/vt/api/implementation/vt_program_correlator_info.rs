use crate::framework::options::Options;
use crate::program::model::address::AddressSetView;

/// Information about a program correlator used in version tracking.
///
/// This trait provides metadata and configuration details about a correlator
/// that can be used to establish correspondences between different versions
/// of a program.
pub trait VtProgramCorrelatorInfo {
    /// Returns the human-readable name of this correlator.
    fn get_name(&self) -> &str;

    /// Returns the fully qualified class name of the correlator implementation.
    fn get_correlator_class_name(&self) -> &str;

    /// Returns the options associated with this correlator.
    fn get_options(&self) -> &dyn Options;

    /// Returns the address set in the destination program covered by this correlator.
    fn get_destination_address_set(&self) -> &dyn AddressSetView;

    /// Returns the address set in the source program covered by this correlator.
    fn get_source_address_set(&self) -> &dyn AddressSetView;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::ImmutableAddressSet;

    struct MockCorrelatorInfo {
        name: String,
        class_name: String,
        options: MockOptions,
        dest_set: ImmutableAddressSet,
        src_set: ImmutableAddressSet,
    }

    struct MockOptions;

    impl Options for MockOptions {}

    impl VtProgramCorrelatorInfo for MockCorrelatorInfo {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_correlator_class_name(&self) -> &str {
            &self.class_name
        }

        fn get_options(&self) -> &dyn Options {
            &self.options
        }

        fn get_destination_address_set(&self) -> &dyn AddressSetView {
            &self.dest_set
        }

        fn get_source_address_set(&self) -> &dyn AddressSetView {
            &self.src_set
        }
    }

    #[test]
    fn test_trait_object_trait_bounds() {
        let mock = MockCorrelatorInfo {
            name: "Test Correlator".to_string(),
            class_name: "com.example.TestCorrelator".to_string(),
            options: MockOptions,
            dest_set: ImmutableAddressSet::empty(),
            src_set: ImmutableAddressSet::empty(),
        };

        let correlator: &dyn VtProgramCorrelatorInfo = &mock;

        assert_eq!(correlator.get_name(), "Test Correlator");
        assert_eq!(
            correlator.get_correlator_class_name(),
            "com.example.TestCorrelator"
        );
    }

    #[test]
    fn test_get_name() {
        let mock = MockCorrelatorInfo {
            name: "Function Matcher".to_string(),
            class_name: "ghidra.feature.vt.api.correlator.FunctionMatchCorrelator".to_string(),
            options: MockOptions,
            dest_set: ImmutableAddressSet::empty(),
            src_set: ImmutableAddressSet::empty(),
        };

        assert_eq!(mock.get_name(), "Function Matcher");
    }

    #[test]
    fn test_get_correlator_class_name() {
        let mock = MockCorrelatorInfo {
            name: "Test".to_string(),
            class_name: "ghidra.feature.vt.api.correlator.TestCorrelator".to_string(),
            options: MockOptions,
            dest_set: ImmutableAddressSet::empty(),
            src_set: ImmutableAddressSet::empty(),
        };

        assert_eq!(
            mock.get_correlator_class_name(),
            "ghidra.feature.vt.api.correlator.TestCorrelator"
        );
    }

    #[test]
    fn test_multiple_implementations() {
        let mock1 = MockCorrelatorInfo {
            name: "Correlator 1".to_string(),
            class_name: "Class1".to_string(),
            options: MockOptions,
            dest_set: ImmutableAddressSet::empty(),
            src_set: ImmutableAddressSet::empty(),
        };

        let mock2 = MockCorrelatorInfo {
            name: "Correlator 2".to_string(),
            class_name: "Class2".to_string(),
            options: MockOptions,
            dest_set: ImmutableAddressSet::empty(),
            src_set: ImmutableAddressSet::empty(),
        };

        assert_eq!(mock1.get_name(), "Correlator 1");
        assert_eq!(mock2.get_name(), "Correlator 2");
        assert_ne!(
            mock1.get_correlator_class_name(),
            mock2.get_correlator_class_name()
        );
    }
}
