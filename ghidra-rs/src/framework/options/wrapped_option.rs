//! Port of `ghidra.framework.options.WrappedOption`.

use std::any::Any;

use crate::framework::options::option_type::OptionType;
use crate::framework::options::SaveState;

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
    fn read_state(&mut self, save_state: &SaveState);

    /// Write all state to the given save state object.
    fn write_state(&self, save_state: &mut SaveState);

    /// Returns the option type for this wrapped option.
    fn get_option_type(&self) -> OptionType;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestWrappedOption {
        value: i32,
    }

    impl WrappedOption for TestWrappedOption {
        fn get_object(&self) -> Box<dyn Any> {
            Box::new(self.value)
        }

        fn read_state(&mut self, _save_state: &SaveState) {
            self.value = 42;
        }

        fn write_state(&self, _save_state: &mut SaveState) {}

        fn get_option_type(&self) -> OptionType {
            OptionType::IntType
        }
    }

    #[test]
    fn object_safe_wrapped_option_works() {
        let mut option: Box<dyn WrappedOption> = Box::new(TestWrappedOption { value: 0 });
        let save_state = SaveState::new();
        let mut mut_save_state = SaveState::new();

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

        assert_eq!(option.get_option_type(), OptionType::IntType);
    }
}
