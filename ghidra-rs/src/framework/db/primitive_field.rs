use super::illegal_field_access_exception::IllegalFieldAccessException;

/// Base contract for all primitive-value `Field`s.
///
/// Mirrors the abstract `db.PrimitiveField` class, which extends `db.Field` and layers an
/// explicit null state on top of a primitive value. When a `PrimitiveField` associated with a
/// `SparseRecord` has a null state it will have a zero (0) value.
pub trait PrimitiveField {
    /// Returns `true` if this field is currently in a null state.
    fn is_null(&self) -> bool;

    /// Sets this field to a null state.
    ///
    /// Returns an error if the field instance is immutable, mirroring `Field.checkImmutable()`.
    fn set_null(&mut self) -> Result<(), IllegalFieldAccessException>;

    /// Invoked prior to setting the field's primitive value. Performs an immutable check and
    /// clears the null state.
    ///
    /// Returns an error if the field instance is immutable, mirroring `Field.checkImmutable()`.
    fn updating_primitive_value(&mut self) -> Result<(), IllegalFieldAccessException>;

    /// Returns the field's value formatted as a string, used to build [`Self::to_display_string`].
    ///
    /// Mirrors the abstract `Field.getValueAsString()` method.
    fn get_value_as_string(&self) -> String;

    /// Returns the simple type name used to build [`Self::to_display_string`], mirroring
    /// `getClass().getSimpleName()` as used by `PrimitiveField.toString()`.
    fn type_name(&self) -> &str;

    /// Default display implementation matching `PrimitiveField.toString()`:
    /// `"<TypeName>(NULL): <value>"` when null, otherwise `"<TypeName>: <value>"`.
    fn to_display_string(&self) -> String {
        let null_state = if self.is_null() { "(NULL)" } else { "" };
        format!("{}{}: {}", self.type_name(), null_state, self.get_value_as_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockIntField {
        value: i32,
        is_null: bool,
        immutable: bool,
    }

    impl PrimitiveField for MockIntField {
        fn is_null(&self) -> bool {
            self.is_null
        }

        fn set_null(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.is_null = true;
            Ok(())
        }

        fn updating_primitive_value(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.is_null = false;
            Ok(())
        }

        fn get_value_as_string(&self) -> String {
            self.value.to_string()
        }

        fn type_name(&self) -> &str {
            "MockIntField"
        }
    }

    #[test]
    fn test_object_safety_and_display() {
        let mut field: Box<dyn PrimitiveField> =
            Box::new(MockIntField { value: 42, is_null: false, immutable: false });

        assert!(!field.is_null());
        assert_eq!(field.to_display_string(), "MockIntField: 42");

        field.set_null().unwrap();
        assert!(field.is_null());
        assert_eq!(field.to_display_string(), "MockIntField(NULL): 42");

        field.updating_primitive_value().unwrap();
        assert!(!field.is_null());
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field = MockIntField { value: 7, is_null: false, immutable: true };
        assert!(field.set_null().is_err());
        assert!(field.updating_primitive_value().is_err());
    }
}
