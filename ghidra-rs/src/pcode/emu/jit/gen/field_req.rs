/// A field request for a pre-fetched or pre-constructed element.
///
/// Corresponds to `ghidra.pcode.emu.jit.gen.FieldReq`.
///
/// In the Java source the type parameter is bounded by `BNonVoid` to ensure the
/// field type is a valid non-void JVM bytecode type. That bound is omitted here
/// until `Types` (`BNonVoid`) is ported; `T` carries the field-type information
/// structurally for sub-traits and implementors.
pub trait FieldReq<T> {
    /// Derive a suitable name for the field.
    fn name(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NamedField {
        field_name: String,
    }

    impl FieldReq<u32> for NamedField {
        fn name(&self) -> String {
            self.field_name.clone()
        }
    }

    #[test]
    fn name_returns_field_name() {
        let req = NamedField {
            field_name: "myField".to_string(),
        };
        assert_eq!(req.name(), "myField");
    }

    #[test]
    fn name_returns_empty_string_when_empty() {
        let req = NamedField {
            field_name: String::new(),
        };
        assert_eq!(req.name(), "");
    }

    #[test]
    fn different_type_params_can_implement_field_req() {
        struct IntField;
        struct StrField;

        impl FieldReq<i32> for IntField {
            fn name(&self) -> String {
                "intField".to_string()
            }
        }

        impl FieldReq<String> for StrField {
            fn name(&self) -> String {
                "strField".to_string()
            }
        }

        let int_req = IntField;
        let str_req = StrField;
        assert_eq!(int_req.name(), "intField");
        assert_eq!(str_req.name(), "strField");
    }
}
