/// A trait for transforming a String into a value of type T.
/// Mirrors the Java interface `ghidra.app.script.StringTransformer<T>`.
pub trait StringTransformer<T> {
    /// Applies the transformation to the given string.
    fn apply(&self, s: &str) -> T;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UppercaseTransformer;
    impl StringTransformer<String> for UppercaseTransformer {
        fn apply(&self, s: &str) -> String {
            s.to_uppercase()
        }
    }

    struct LowercaseTransformer;
    impl StringTransformer<String> for LowercaseTransformer {
        fn apply(&self, s: &str) -> String {
            s.to_lowercase()
        }
    }

    struct LengthTransformer;
    impl StringTransformer<usize> for LengthTransformer {
        fn apply(&self, s: &str) -> usize {
            s.len()
        }
    }

    #[test]
    fn test_uppercase_transform() {
        let transformer = UppercaseTransformer;
        assert_eq!(transformer.apply("hello"), "HELLO");
        assert_eq!(transformer.apply("HeLLo"), "HELLO");
        assert_eq!(transformer.apply(""), "");
    }

    #[test]
    fn test_lowercase_transform() {
        let transformer = LowercaseTransformer;
        assert_eq!(transformer.apply("HELLO"), "hello");
        assert_eq!(transformer.apply("HeLLo"), "hello");
        assert_eq!(transformer.apply(""), "");
    }

    #[test]
    fn test_length_transform() {
        let transformer = LengthTransformer;
        assert_eq!(transformer.apply("hello"), 5);
        assert_eq!(transformer.apply(""), 0);
        assert_eq!(transformer.apply("test"), 4);
    }

    #[test]
    fn test_unicode_handling() {
        let transformer = LengthTransformer;
        // In Rust, len() returns byte length, not character count
        assert_eq!(transformer.apply("é"), 2); // é is 2 bytes in UTF-8

        let uppercase = UppercaseTransformer;
        assert_eq!(uppercase.apply("café"), "CAFÉ");
    }
}
