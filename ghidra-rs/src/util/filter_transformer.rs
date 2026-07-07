/// Transforms a value of type `T` into a list of strings.
///
/// Port of `ghidra.util.FilterTransformer`.
pub trait FilterTransformer<T> {
    /// Transforms `t` into a list of string representations used for filtering.
    fn transform(&self, t: T) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DebugTransformer;

    impl FilterTransformer<i32> for DebugTransformer {
        fn transform(&self, t: i32) -> Vec<String> {
            vec![t.to_string(), format!("0x{:x}", t)]
        }
    }

    struct IdentityTransformer;

    impl FilterTransformer<String> for IdentityTransformer {
        fn transform(&self, t: String) -> Vec<String> {
            vec![t]
        }
    }

    #[test]
    fn transform_returns_multiple_strings() {
        let tf = DebugTransformer;
        let result = tf.transform(255);
        assert_eq!(result, vec!["255".to_string(), "0xff".to_string()]);
    }

    #[test]
    fn transform_zero() {
        let tf = DebugTransformer;
        let result = tf.transform(0);
        assert_eq!(result, vec!["0".to_string(), "0x0".to_string()]);
    }

    #[test]
    fn transform_negative() {
        let tf = DebugTransformer;
        let result = tf.transform(-1);
        assert_eq!(result, vec!["-1".to_string(), "0xffffffff".to_string()]);
    }

    #[test]
    fn transform_string_identity() {
        let tf = IdentityTransformer;
        let result = tf.transform("hello".to_string());
        assert_eq!(result, vec!["hello".to_string()]);
    }

    #[test]
    fn trait_object_dispatch() {
        let tf: &dyn FilterTransformer<i32> = &DebugTransformer;
        let result = tf.transform(1);
        assert_eq!(result[0], "1");
    }
}
