/// Maximum number of characters allowed in a label string produced by a data type.
pub const MAX_LABEL_STRING_LENGTH: i32 = 32;

/// Controls how a data type is rendered as a label string.
///
/// Implementations choose whether to use an abbreviated representation and what
/// maximum label length to apply.  Mirrors `DataTypeDisplayOptions` from the Java source.
pub trait DataTypeDisplayOptions {
    /// Returns the maximum number of characters to include in a label string.
    fn get_label_string_length(&self) -> i32;

    /// Returns `true` if the data type should be rendered in an abbreviated form.
    fn use_abbreviated_form(&self) -> bool;
}

/// Default [`DataTypeDisplayOptions`] implementation.
///
/// Uses the full (non-abbreviated) form and caps label strings at
/// [`MAX_LABEL_STRING_LENGTH`] characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DefaultDataTypeDisplayOptions;

impl DataTypeDisplayOptions for DefaultDataTypeDisplayOptions {
    fn get_label_string_length(&self) -> i32 {
        MAX_LABEL_STRING_LENGTH
    }

    fn use_abbreviated_form(&self) -> bool {
        false
    }
}

/// Singleton default options: full form, label length capped at [`MAX_LABEL_STRING_LENGTH`].
pub const DEFAULT: DefaultDataTypeDisplayOptions = DefaultDataTypeDisplayOptions;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_label_string_length_is_32() {
        assert_eq!(MAX_LABEL_STRING_LENGTH, 32);
    }

    #[test]
    fn default_returns_max_label_length() {
        assert_eq!(DEFAULT.get_label_string_length(), MAX_LABEL_STRING_LENGTH);
    }

    #[test]
    fn default_does_not_use_abbreviated_form() {
        assert!(!DEFAULT.use_abbreviated_form());
    }

    #[test]
    fn default_usable_as_trait_object() {
        let opts: &dyn DataTypeDisplayOptions = &DEFAULT;
        assert_eq!(opts.get_label_string_length(), 32);
        assert!(!opts.use_abbreviated_form());
    }

    #[test]
    fn custom_implementation_can_override_both_values() {
        struct Abbreviated;
        impl DataTypeDisplayOptions for Abbreviated {
            fn get_label_string_length(&self) -> i32 {
                16
            }
            fn use_abbreviated_form(&self) -> bool {
                true
            }
        }
        let opts = Abbreviated;
        assert_eq!(opts.get_label_string_length(), 16);
        assert!(opts.use_abbreviated_form());
    }
}
