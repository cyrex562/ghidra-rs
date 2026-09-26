use crate::app::util::bin::struct_converter::StructConverter;

/// Represents thread state information in a Mach-O thread command.
///
/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadState`.
pub trait ThreadState: StructConverter {
    /// Returns the instruction pointer for this thread state.
    ///
    /// # Returns
    /// The instruction pointer value
    fn get_instruction_pointer(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockThreadState {
        instruction_pointer: i64,
    }

    impl MockThreadState {
        fn new(instruction_pointer: i64) -> Self {
            Self {
                instruction_pointer,
            }
        }
    }

    impl StructConverter for MockThreadState {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl ThreadState for MockThreadState {
        fn get_instruction_pointer(&self) -> i64 {
            self.instruction_pointer
        }
    }

    #[test]
    fn trait_can_be_implemented() {
        let _state: &dyn ThreadState = &MockThreadState::new(0x1000);
    }

    #[test]
    fn trait_is_object_safe() {
        fn _use_trait_object(_: &dyn ThreadState) {}
        _use_trait_object(&MockThreadState::new(0x2000));
    }

    #[test]
    fn get_instruction_pointer_returns_correct_value() {
        let state = MockThreadState::new(0x4000);
        assert_eq!(state.get_instruction_pointer(), 0x4000);
    }

    #[test]
    fn get_instruction_pointer_zero() {
        let state = MockThreadState::new(0);
        assert_eq!(state.get_instruction_pointer(), 0);
    }

    #[test]
    fn get_instruction_pointer_large_value() {
        let state = MockThreadState::new(0x7fffffffffffffff);
        assert_eq!(state.get_instruction_pointer(), 0x7fffffffffffffff);
    }

    #[test]
    fn struct_converter_trait_is_implemented() {
        let state: Box<dyn ThreadState> = Box::new(MockThreadState::new(0x5000));
        assert!(state.to_data_type().is_ok());
    }

    #[test]
    fn multiple_instances_have_different_values() {
        let state1 = MockThreadState::new(0x1000);
        let state2 = MockThreadState::new(0x2000);
        assert_ne!(state1.get_instruction_pointer(), state2.get_instruction_pointer());
    }
}
