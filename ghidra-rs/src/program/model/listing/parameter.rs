use crate::program::model::listing::AutoParameterType;
use crate::program::seam_stubs::{DataType, Variable};

/// The name Ghidra assigns to the synthetic return-storage parameter.
pub const RETURN_NAME: &str = "<RETURN>";

/// Ordinal used for the synthetic return-storage parameter.
pub const RETURN_ORDINAL: i32 = -1;

/// Ordinal used for a parameter that has not yet been assigned a position.
pub const UNASSIGNED_ORDINAL: i32 = -2;

/// Interface for function parameters.
pub trait Parameter: Variable {
    /// Returns the ordinal (index) of this parameter within the function signature.
    fn get_ordinal(&self) -> i32;

    /// Returns true if this parameter is automatically generated based upon the associated
    /// function calling convention and function signature. An example of such a parameter
    /// include the "__return_storage_ptr__" parameter.
    fn is_auto_parameter(&self) -> bool;

    /// If this is an auto-parameter this method will indicate its type.
    /// Returns the auto-parameter type, or `None` if not applicable.
    fn get_auto_parameter_type(&self) -> Option<AutoParameterType>;

    /// If this parameter which was forced by the associated calling convention to be passed as
    /// a pointer instead of its original formal type.
    /// Returns true if this parameter was forced to be passed as a pointer instead of its
    /// original formal type.
    fn is_forced_indirect(&self) -> bool;

    /// Get the original formal signature data type before a possible forced indirect was
    /// possibly imposed by the function's calling convention. `get_data_type` (from
    /// [`Variable`]) will always return the effective data type which corresponds to the
    /// allocated variable storage.
    ///
    /// This type will only differ from the effective data type if this parameter
    /// `is_forced_indirect`.
    fn get_formal_data_type(&self) -> Box<dyn DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl DataType for MockDataType {}

    struct MockVariable;

    impl Variable for MockVariable {}

    struct MockParameter {
        ordinal: i32,
        auto_parameter_type: Option<AutoParameterType>,
        forced_indirect: bool,
    }

    impl Variable for MockParameter {}

    impl Parameter for MockParameter {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }

        fn is_auto_parameter(&self) -> bool {
            self.auto_parameter_type.is_some()
        }

        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            self.auto_parameter_type
        }

        fn is_forced_indirect(&self) -> bool {
            self.forced_indirect
        }

        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
    }

    #[test]
    fn ordinary_parameter_is_not_auto() {
        let param = MockParameter {
            ordinal: 0,
            auto_parameter_type: None,
            forced_indirect: false,
        };
        assert_eq!(param.get_ordinal(), 0);
        assert!(!param.is_auto_parameter());
        assert_eq!(param.get_auto_parameter_type(), None);
        assert!(!param.is_forced_indirect());
    }

    #[test]
    fn auto_parameter_reports_its_type() {
        let param = MockParameter {
            ordinal: RETURN_ORDINAL,
            auto_parameter_type: Some(AutoParameterType::ReturnStoragePtr),
            forced_indirect: true,
        };
        assert!(param.is_auto_parameter());
        assert_eq!(
            param.get_auto_parameter_type(),
            Some(AutoParameterType::ReturnStoragePtr)
        );
        assert!(param.is_forced_indirect());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let param: Box<dyn Parameter> = Box::new(MockParameter {
            ordinal: UNASSIGNED_ORDINAL,
            auto_parameter_type: None,
            forced_indirect: false,
        });
        assert_eq!(param.get_ordinal(), UNASSIGNED_ORDINAL);
        let _formal_type: Box<dyn DataType> = param.get_formal_data_type();
    }
}
