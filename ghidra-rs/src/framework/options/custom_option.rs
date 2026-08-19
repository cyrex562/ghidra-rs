//! Port of `ghidra.framework.options.CustomOption`.

use crate::framework::seam_stubs::GProperties;

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
/// This trait was promoted from a minimal placeholder (see `framework::seam_stubs`) that had no
/// methods, so there are no prior implementations to keep compiling as a superset.
pub trait CustomOption: std::fmt::Display {
    /// Read state from the given properties.
    fn read_state(&mut self, properties: &dyn GProperties);

    /// Write state into the given properties.
    fn write_state(&self, properties: &mut dyn GProperties);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    struct FakeProperties;
    impl GProperties for FakeProperties {}

    struct IntOption(i32);

    impl fmt::Display for IntOption {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl CustomOption for IntOption {
        fn read_state(&mut self, _properties: &dyn GProperties) {
            self.0 = 42;
        }

        fn write_state(&self, _properties: &mut dyn GProperties) {}
    }

    #[test]
    fn object_safe_and_round_trips_via_dyn() {
        let mut option: Box<dyn CustomOption> = Box::new(IntOption(0));
        let mut props = FakeProperties;
        option.write_state(&mut props);
        option.read_state(&props);
        assert_eq!(option.to_string(), "42");
    }
}
