/// A trait for converting typed data to a `String` representation.
///
/// Corresponds to `docking.widgets.DataToStringConverter`.
pub trait DataToStringConverter<T> {
    fn get_string(&self, t: T) -> String;
}

/// A [`DataToStringConverter`] for `String` that returns the value unchanged.
///
/// Corresponds to the static `stringDataToStringConverter` field in the Java source.
pub struct StringDataToStringConverter;

impl DataToStringConverter<String> for StringDataToStringConverter {
    fn get_string(&self, t: String) -> String {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_converter_returns_value_unchanged() {
        let converter = StringDataToStringConverter;
        assert_eq!(converter.get_string("hello".to_string()), "hello");
    }

    #[test]
    fn string_converter_empty_string() {
        let converter = StringDataToStringConverter;
        assert_eq!(converter.get_string(String::new()), "");
    }

    #[test]
    fn custom_impl_compiles_and_works() {
        struct IntConverter;
        impl DataToStringConverter<i32> for IntConverter {
            fn get_string(&self, t: i32) -> String {
                t.to_string()
            }
        }
        let c = IntConverter;
        assert_eq!(c.get_string(42), "42");
        assert_eq!(c.get_string(-1), "-1");
    }
}
