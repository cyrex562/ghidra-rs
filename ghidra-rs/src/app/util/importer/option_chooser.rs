//! Chooses which [`Option`](crate::app::seam_stubs::Option) options to use.
//!
//! Port of `ghidra.app.util.importer.OptionChooser`.

use crate::app::seam_stubs::{Option, Pair};
use crate::program::model::address::factory::AddressFactory;

/// Chooses which [`Option`](crate::app::seam_stubs::Option) options to use.
///
/// Port of the Java `@FunctionalInterface`. This is a genuine extension point with one
/// implementor in-repo ([`DefaultOptions`]).
pub trait OptionChooser {
    /// Chooses which [`Option`](crate::app::seam_stubs::Option) options to use.
    ///
    /// # Arguments
    ///
    /// * `option_choices` - A list of available [`Option`](crate::app::seam_stubs::Option)s
    /// * `address_factory` - The address factory
    ///
    /// # Returns
    ///
    /// The list of [`Option`](crate::app::seam_stubs::Option)s to use
    fn choose(
        &self,
        option_choices: &[Box<dyn Option>],
        address_factory: &dyn AddressFactory,
    ) -> Vec<Box<dyn Option>>;

    /// Gets the [`Loader`](crate::app::util::opinion::loader::Loader) arguments associated
    /// with this [`OptionChooser`].
    ///
    /// # Returns
    ///
    /// The loader arguments (empty by default).
    fn get_args(&self) -> Vec<Box<dyn Pair>> {
        vec![]
    }
}

/// Chooses all options, unchanged.
///
/// Port of `OptionChooser.DEFAULT_OPTIONS`, implemented as a default lambda in Java.
pub struct DefaultOptions;

impl OptionChooser for DefaultOptions {
    fn choose(
        &self,
        option_choices: &[Box<dyn Option>],
        _address_factory: &dyn AddressFactory,
    ) -> Vec<Box<dyn Option>> {
        option_choices
            .iter()
            .map(|opt| opt.copy())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubOption {
        name: String,
    }

    impl crate::app::seam_stubs::Option for StubOption {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_value(&self) -> Box<dyn std::any::Any> {
            Box::new("test".to_string())
        }

        fn copy(&self) -> Box<dyn crate::app::seam_stubs::Option> {
            Box::new(StubOption {
                name: self.name.clone(),
            })
        }
    }

    struct StubAddressFactory;

    impl AddressFactory for StubAddressFactory {
        fn get_address(&self, _addr_string: &str) -> std::option::Option<crate::program::model::address::Address> {
            None
        }

        fn get_all_addresses(&self, _addr_string: &str) -> Vec<crate::program::model::address::Address> {
            vec![]
        }

        fn get_all_addresses_case(
            &self,
            _addr_string: &str,
            _case_sensitive: bool,
        ) -> Vec<crate::program::model::address::Address> {
            vec![]
        }

        fn get_default_address_space(
            &self,
        ) -> std::option::Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }

        fn get_address_spaces(&self) -> Vec<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            vec![]
        }

        fn get_address_space_by_name(&self, _name: &str) -> std::option::Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }

        fn get_address_space_by_id(&self, _id: i32) -> std::option::Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }

        fn get_all_address_spaces(&self) -> Vec<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            vec![]
        }

        fn get_num_address_spaces(&self) -> usize {
            0
        }

        fn is_valid_address(&self, _address: &crate::program::model::address::Address) -> bool {
            false
        }

        fn get_index(&self, _address: &crate::program::model::address::Address) -> i64 {
            0
        }

        fn get_physical_space(&self, space: &std::sync::Arc<crate::program::model::address::AddressSpace>) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
            space.clone()
        }

        fn get_physical_spaces(&self) -> Vec<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            vec![]
        }

        fn address(&self, _space_id: i32, _offset: i64) -> std::option::Option<crate::program::model::address::Address> {
            None
        }

        fn get_stack_space(&self) -> std::option::Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }

        fn get_constant_space(&self) -> std::option::Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }

        fn get_unique_space(&self) -> std::option::Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }

        fn get_register_space(&self) -> std::option::Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
            None
        }

        fn get_constant_address(&self, _offset: i64) -> std::option::Option<crate::program::model::address::Address> {
            None
        }

        fn get_address_set_range(
            &self,
            _min: &crate::program::model::address::Address,
            _max: &crate::program::model::address::Address,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn get_address_set(&self) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }

        fn old_get_address_from_long(&self, _value: i64) -> std::option::Option<crate::program::model::address::Address> {
            None
        }

        fn has_multiple_memory_spaces(&self) -> bool {
            false
        }
    }

    #[test]
    fn default_options_returns_all_choices() {
        let choices: Vec<Box<dyn Option>> = vec![
            Box::new(StubOption {
                name: "opt1".to_string(),
            }),
            Box::new(StubOption {
                name: "opt2".to_string(),
            }),
        ];

        let chooser = DefaultOptions;
        let result = chooser.choose(&choices, &StubAddressFactory);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].get_name(), "opt1");
        assert_eq!(result[1].get_name(), "opt2");
    }

    #[test]
    fn default_options_get_args_returns_empty() {
        let chooser = DefaultOptions;
        assert!(chooser.get_args().is_empty());
    }
}
