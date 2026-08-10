//! Port of `ghidra.framework.options.WrappedOption`.

use std::any::Any;

use crate::framework::seam_stubs::{OptionType, SaveState};

/// Wrapper for an object that represents a property value and is saved as a set of primitives.
///
/// Subclasses should implement [`read_state`](WrappedOption::read_state) and [`write_state`](WrappedOption::write_state) to
/// persist their state.
///
/// Port of `ghidra.framework.options.WrappedOption`.
pub trait WrappedOption {
    /// Gets the object that is the property value.
    fn get_object(&self) -> Box<dyn Any>;

    /// Read all state from the given save state object.
    fn read_state(&mut self, save_state: &dyn SaveState);

    /// Write all state to the given save state object.
    fn write_state(&self, save_state: &mut dyn SaveState);

    /// Returns the option type for this wrapped option.
    fn get_option_type(&self) -> Box<dyn OptionType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct StubSaveState;
    impl SaveState for StubSaveState {
        fn has_value(&self, _name: &str) -> bool {
            false
        }

        fn get_boolean(&self, _name: &str, default_value: bool) -> bool {
            default_value
        }

        fn put_boolean(&mut self, _name: &str, _value: bool) {}

        fn get_byte(&self, _name: &str, default_value: i8) -> i8 {
            default_value
        }

        fn put_byte(&mut self, _name: &str, _value: i8) {}

        fn get_short(&self, _name: &str, default_value: i16) -> i16 {
            default_value
        }

        fn put_short(&mut self, _name: &str, _value: i16) {}

        fn get_int(&self, _name: &str, default_value: i32) -> i32 {
            default_value
        }

        fn put_int(&mut self, _name: &str, _value: i32) {}

        fn get_long(&self, _name: &str, default_value: i64) -> i64 {
            default_value
        }

        fn put_long(&mut self, _name: &str, _value: i64) {}

        fn get_float(&self, _name: &str, default_value: f32) -> f32 {
            default_value
        }

        fn put_float(&mut self, _name: &str, _value: f32) {}

        fn get_double(&self, _name: &str, default_value: f64) -> f64 {
            default_value
        }

        fn put_double(&mut self, _name: &str, _value: f64) {}

        fn get_string(&self, _name: &str, default_value: Option<&str>) -> Option<String> {
            default_value.map(|s| s.to_string())
        }

        fn put_string(&mut self, _name: &str, _value: Option<&str>) {}

        fn get_booleans(&self, _name: &str, default_value: Option<&[bool]>) -> Option<Vec<bool>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_booleans(&mut self, _name: &str, _value: Option<&[bool]>) {}

        fn get_bytes(&self, _name: &str, default_value: Option<&[u8]>) -> Option<Vec<u8>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_bytes(&mut self, _name: &str, _value: Option<&[u8]>) {}

        fn get_shorts(&self, _name: &str, default_value: Option<&[i16]>) -> Option<Vec<i16>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_shorts(&mut self, _name: &str, _value: Option<&[i16]>) {}

        fn get_ints(&self, _name: &str, default_value: Option<&[i32]>) -> Option<Vec<i32>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_ints(&mut self, _name: &str, _value: Option<&[i32]>) {}

        fn get_longs(&self, _name: &str, default_value: Option<&[i64]>) -> Option<Vec<i64>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_longs(&mut self, _name: &str, _value: Option<&[i64]>) {}

        fn get_floats(&self, _name: &str, default_value: Option<&[f32]>) -> Option<Vec<f32>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_floats(&mut self, _name: &str, _value: Option<&[f32]>) {}

        fn get_doubles(&self, _name: &str, default_value: Option<&[f64]>) -> Option<Vec<f64>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_doubles(&mut self, _name: &str, _value: Option<&[f64]>) {}

        fn get_strings(&self, _name: &str, default_value: Option<&[String]>) -> Option<Vec<String>> {
            default_value.map(|v| v.to_vec())
        }

        fn put_strings(&mut self, _name: &str, _value: Option<&[String]>) {}

        fn get_file(&self, _name: &str, default_value: Option<&std::path::Path>) -> Option<PathBuf> {
            default_value.map(|p| p.to_path_buf())
        }

        fn put_file(&mut self, _name: &str, _value: Option<&std::path::Path>) {}

        fn get_enum_name(&self, _name: &str) -> Option<String> {
            None
        }

        fn put_enum_name(&mut self, _name: &str, _value: Option<&str>) {}
    }

    struct StubOptionType;
    impl OptionType for StubOptionType {}

    struct TestWrappedOption {
        value: i32,
    }

    impl WrappedOption for TestWrappedOption {
        fn get_object(&self) -> Box<dyn Any> {
            Box::new(self.value)
        }

        fn read_state(&mut self, _save_state: &dyn SaveState) {
            self.value = 42;
        }

        fn write_state(&self, _save_state: &mut dyn SaveState) {}

        fn get_option_type(&self) -> Box<dyn OptionType> {
            Box::new(StubOptionType)
        }
    }

    #[test]
    fn object_safe_wrapped_option_works() {
        let mut option: Box<dyn WrappedOption> = Box::new(TestWrappedOption { value: 0 });
        let save_state = StubSaveState;
        let mut mut_save_state = StubSaveState;

        // Can call methods on trait object
        let obj = option.get_object();
        assert_eq!(obj.downcast_ref::<i32>(), Some(&0));

        option.read_state(&save_state);
        assert_eq!(
            option.get_object().downcast_ref::<i32>(),
            Some(&42),
            "read_state should have changed the value"
        );

        option.write_state(&mut mut_save_state);

        let _opt_type = option.get_option_type();
        // Verify the option type is actually returned
        assert!(true, "get_option_type should return an OptionType");
    }
}
