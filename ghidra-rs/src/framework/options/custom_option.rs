//! Port of `ghidra.framework.options.CustomOption`.

use crate::framework::options::g_properties::GProperties;

/// Key which corresponds to the custom option implementation class.
///
/// The use of this key/value within the stored state information is reserved for use by the
/// option storage implementation and should be ignored by [`CustomOption::read_state`]
/// implementations.
///
/// Stands in for `CustomOption.CUSTOM_OPTION_CLASS_NAME_KEY`.
pub const CUSTOM_OPTION_CLASS_NAME_KEY: &str = "CUSTOM_OPTION_CLASS";

/// A user-defined option value type that knows how to persist and restore its own state.
///
/// Port of `ghidra.framework.options.CustomOption`.
///
pub trait CustomOption: std::fmt::Display {
    /// Read state from the given properties.
    fn read_state(&mut self, properties: &GProperties);

    /// Write state into the given properties.
    fn write_state(&self, properties: &mut GProperties);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    struct IntOption(i32);

    impl fmt::Display for IntOption {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl CustomOption for IntOption {
        fn read_state(&mut self, properties: &GProperties) {
            self.0 = properties.get_int("value", -1);
        }

        fn write_state(&self, properties: &mut GProperties) {
            properties.put_int("value", self.0);
        }
    }

    #[test]
    fn object_safe_and_round_trips_via_dyn() {
        let option: Box<dyn CustomOption> = Box::new(IntOption(42));
        let mut props = GProperties::new("p");
        option.write_state(&mut props);
        let mut restored: Box<dyn CustomOption> = Box::new(IntOption(0));
        restored.read_state(&props);
        assert_eq!(restored.to_string(), "42");
    }
}
