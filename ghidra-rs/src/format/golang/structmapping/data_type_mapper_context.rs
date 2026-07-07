/// Context passed to StructureMapping logic when binding a structure's fields
/// to a Rust struct's fields.
///
/// Corresponds to `DataTypeMapperContext` in the Java source.
pub trait DataTypeMapperContext {
    /// Tests if a field should be included when creating bindings between a
    /// structure and a class.
    ///
    /// `present_when` is a free-form string interpreted by each
    /// `DataTypeMapper` implementation.  Returns `true` if the field should
    /// be bound, `false` otherwise.
    fn is_field_present(&self, present_when: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::DataTypeMapperContext;

    struct AlwaysPresent;
    struct NeverPresent;
    struct ConditionalPresent {
        required_tag: &'static str,
    }

    impl DataTypeMapperContext for AlwaysPresent {
        fn is_field_present(&self, _present_when: &str) -> bool {
            true
        }
    }

    impl DataTypeMapperContext for NeverPresent {
        fn is_field_present(&self, _present_when: &str) -> bool {
            false
        }
    }

    impl DataTypeMapperContext for ConditionalPresent {
        fn is_field_present(&self, present_when: &str) -> bool {
            present_when == self.required_tag
        }
    }

    #[test]
    fn always_present_returns_true_for_any_tag() {
        let ctx = AlwaysPresent;
        assert!(ctx.is_field_present("some_tag"));
        assert!(ctx.is_field_present(""));
        assert!(ctx.is_field_present("go1.18"));
    }

    #[test]
    fn never_present_returns_false_for_any_tag() {
        let ctx = NeverPresent;
        assert!(!ctx.is_field_present("some_tag"));
        assert!(!ctx.is_field_present(""));
    }

    #[test]
    fn conditional_present_matches_exact_tag() {
        let ctx = ConditionalPresent { required_tag: "go1.18" };
        assert!(ctx.is_field_present("go1.18"));
        assert!(!ctx.is_field_present("go1.17"));
        assert!(!ctx.is_field_present(""));
    }

    #[test]
    fn trait_is_object_safe_via_box() {
        let _boxed: Box<dyn DataTypeMapperContext> = Box::new(AlwaysPresent);
    }
}
