use super::binary_field::BinaryField;
use super::illegal_field_access_exception::IllegalFieldAccessException;

/// Abstract base for unsigned fixed-length fields whose value is specified with a byte array.
///
/// Port of `db.FixedField`, an `abstract class FixedField extends BinaryField`. This field
/// behaves similarly to a [`super::primitive_field::PrimitiveField`] in that a null "state" (see
/// [`Self::is_fixed_null`]) is supported for sparse-record-column use with a zero (0) value;
/// unlike the variable-length [`BinaryField`] it composes over, a null *value* (i.e. the data
/// byte array itself) is never permitted.
///
/// Note on scope: within the real Ghidra `db` package, `FixedField`'s **only** subclass is
/// `FixedField10` (`db.FixedField10`) -- it is *not* an ancestor of `LongField`/`IntField`/
/// `ShortField`/`BooleanField`, which each extend `PrimitiveField` directly (verified against the
/// actual Java source; those four sibling ports document this explicitly too). It is ported here
/// standalone, composed over [`BinaryField`] via Rust supertrait composition (not Rust-level
/// inheritance -- see this crate's composition-over-inheritance convention), as its own
/// object-safe trait / cycle cut-point, mirroring the pattern established by
/// [`super::byte_field::ByteField`] and [`BinaryField`] itself.
///
/// # Method-name shadowing caveat
///
/// Java's `FixedField` *overrides* `BinaryField`'s `isNull()`/`setNull()`/`truncate()` (the
/// override relationship is exactly what makes the null-state and truncation behavior differ from
/// plain `BinaryField`). Rust has no method-override mechanism for supertraits: a subtrait cannot
/// redeclare a supertrait method under the same name without introducing call-site ambiguity for
/// any type implementing both. To keep this trait object-safe and unambiguous, the
/// `FixedField`-specific null/truncate semantics are exposed under distinct names --
/// [`Self::is_fixed_null`], [`Self::set_fixed_null`], [`Self::truncate_fixed`] -- rather than
/// reusing [`BinaryField::is_null`]/[`BinaryField::set_null`]/[`BinaryField::truncate`]. Callers
/// working with a `dyn FixedField` **must** use the `_fixed` names: the inherited `BinaryField`
/// methods are still callable (and still compile), but they answer based on `get_binary_data()`
/// being `Some`/`None`, which for a `FixedField` (whose data is never absent) does not track the
/// same null-state and would silently give a wrong answer.
pub trait FixedField: BinaryField {
    /// Returns `true` if this field is currently in a null "state" for sparse-record purposes.
    /// This is tracked independently of the (always-present) underlying data value -- see the
    /// trait-level doc comment. Mirrors `FixedField.isNull()`.
    fn is_fixed_null(&self) -> bool;

    /// Sets this field to a null "state" without necessarily altering its underlying data value.
    /// Mirrors `FixedField.setNull()`: performs an immutable check and sets the null-state flag,
    /// but (unlike `BinaryField::set_null()`) does not clear/zero the stored data array itself --
    /// callers that want a canonical zeroed value on null must do so themselves, exactly as
    /// concrete Java subclasses (e.g. `FixedField10.setNull()`) additionally zero their own
    /// cached fields.
    fn set_fixed_null(&mut self) -> Result<(), IllegalFieldAccessException>;

    /// Invoked prior to setting the field's primitive value: performs an immutable check and
    /// clears the null state. Mirrors `FixedField.updatingValue()`.
    fn updating_value(&mut self) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a copy of this field, detached from any underlying buffer. Mirrors
    /// `FixedField.copyField()` (redeclared `abstract` over `BinaryField.copyField()`, narrowing
    /// its return type).
    fn copy_fixed_field(&self) -> Box<dyn FixedField>;

    /// Constructs a new, empty fixed-length field. Mirrors `FixedField.newField()` (redeclared
    /// `abstract` over `BinaryField.newField()`, narrowing its return type).
    fn new_fixed_field(&self) -> Box<dyn FixedField>;

    /// Returns the minimum representable value for this fixed-length field type. Mirrors
    /// `FixedField.getMinValue()` (redeclared `abstract` over `BinaryField.getMinValue()`; unlike
    /// `BinaryField`'s own always-`None`/unsupported default, concrete `FixedField` subclasses
    /// (e.g. `FixedField10`) provide a real value).
    fn get_fixed_min_value(&self) -> Box<dyn FixedField>;

    /// Returns the maximum representable value for this fixed-length field type. Mirrors
    /// `FixedField.getMaxValue()` (redeclared `abstract` over `BinaryField.getMaxValue()`; see
    /// [`Self::get_fixed_min_value`]).
    fn get_fixed_max_value(&self) -> Box<dyn FixedField>;

    /// Always `false`: a fixed-length field is not variable length. Mirrors
    /// `FixedField.isVariableLength()` (`final` in Java).
    fn is_fixed_variable_length(&self) -> bool {
        false
    }

    /// Fixed-length fields may not be truncated.
    ///
    /// Mirrors `FixedField.truncate(int)`, which unconditionally throws
    /// `UnsupportedOperationException` in Java. We reuse [`IllegalFieldAccessException`] as the
    /// error type here (rather than introducing a distinct "unsupported operation" error type
    /// purely for this one always-failing method) to stay consistent with every other fallible
    /// method in this field-trait family; the Java exception type actually thrown is
    /// `UnsupportedOperationException`, not `IllegalFieldAccessException` -- this is a deliberate
    /// pragmatic substitution, not a behavioral claim that the two are the same Java exception.
    fn truncate_fixed(&mut self, _length: usize) -> Result<(), IllegalFieldAccessException> {
        Err(IllegalFieldAccessException::with_message(
            "FixedField may not be truncated (Field.truncate() is UnsupportedOperationException in Java)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::field::FieldType;

    struct MockFixedField {
        data: Vec<u8>,
        fixed_null: bool,
        immutable: bool,
    }

    impl MockFixedField {
        fn new(data: Vec<u8>) -> Self {
            Self { data, fixed_null: false, immutable: false }
        }

        fn immutable(data: Vec<u8>) -> Self {
            Self { data, fixed_null: false, immutable: true }
        }
    }

    impl BinaryField for MockFixedField {
        fn get_binary_data(&self) -> Option<&[u8]> {
            Some(&self.data)
        }

        fn set_binary_data(&mut self, data: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            match data {
                None => {
                    // A FixedField's underlying value is never permitted to be null; a `None`
                    // here just means "reset to zero", mirroring how FixedField10's own
                    // constructor treats a null `data` argument as a zero value.
                    self.data.iter_mut().for_each(|b| *b = 0);
                }
                Some(d) => {
                    self.data.clear();
                    self.data.extend_from_slice(d);
                }
            }
            self.fixed_null = false;
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn BinaryField> {
            Box::new(MockFixedField::new(self.data.clone()))
        }

        fn new_field(&self) -> Box<dyn BinaryField> {
            Box::new(MockFixedField::new(vec![0; self.data.len()]))
        }

        fn get_field_type(&self) -> FieldType {
            FieldType::Fixed(self.data.len() as u32)
        }
    }

    impl FixedField for MockFixedField {
        fn is_fixed_null(&self) -> bool {
            self.fixed_null
        }

        fn set_fixed_null(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.fixed_null = true;
            Ok(())
        }

        fn updating_value(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.fixed_null = false;
            Ok(())
        }

        fn copy_fixed_field(&self) -> Box<dyn FixedField> {
            let mut copy = MockFixedField::new(self.data.clone());
            copy.fixed_null = self.fixed_null;
            Box::new(copy)
        }

        fn new_fixed_field(&self) -> Box<dyn FixedField> {
            Box::new(MockFixedField::new(vec![0; self.data.len()]))
        }

        fn get_fixed_min_value(&self) -> Box<dyn FixedField> {
            Box::new(MockFixedField::immutable(vec![0; self.data.len()]))
        }

        fn get_fixed_max_value(&self) -> Box<dyn FixedField> {
            Box::new(MockFixedField::immutable(vec![0xff; self.data.len()]))
        }
    }

    #[test]
    fn test_is_variable_length_always_false() {
        let field: Box<dyn FixedField> = Box::new(MockFixedField::new(vec![1, 2, 3, 4]));
        assert!(!field.is_fixed_variable_length());
    }

    #[test]
    fn test_fixed_null_state_independent_of_data() {
        let mut field: Box<dyn FixedField> = Box::new(MockFixedField::new(vec![1, 2, 3, 4]));
        assert!(!field.is_fixed_null());

        field.set_fixed_null().unwrap();
        assert!(field.is_fixed_null());
        // Data is left alone by `set_fixed_null` (unlike `BinaryField::set_null`, which would
        // clear the data to `None`) -- the underlying value is still there.
        assert_eq!(field.get_binary_data(), Some(&[1u8, 2, 3, 4][..]));

        field.updating_value().unwrap();
        assert!(!field.is_fixed_null());
    }

    #[test]
    fn test_truncate_fixed_always_fails() {
        let mut field: Box<dyn FixedField> = Box::new(MockFixedField::new(vec![1, 2, 3, 4]));
        assert!(field.truncate_fixed(2).is_err());
        // Data is unchanged since truncation never actually happens.
        assert_eq!(field.get_binary_data(), Some(&[1u8, 2, 3, 4][..]));
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn FixedField> = Box::new(MockFixedField::immutable(vec![1, 2]));
        assert!(field.set_fixed_null().is_err());
        assert!(field.updating_value().is_err());
        assert!(BinaryField::set_binary_data(field.as_mut(), Some(&[3, 4])).is_err());
    }

    #[test]
    fn test_copy_and_new_fixed_field() {
        let field: Box<dyn FixedField> = Box::new(MockFixedField::new(vec![9, 9]));
        let copy = field.copy_fixed_field();
        assert_eq!(copy.get_binary_data(), Some(&[9u8, 9][..]));

        let fresh = field.new_fixed_field();
        assert_eq!(fresh.get_binary_data(), Some(&[0u8, 0][..]));
    }

    #[test]
    fn test_min_max_value() {
        let field: Box<dyn FixedField> = Box::new(MockFixedField::new(vec![0, 0]));
        assert_eq!(field.get_fixed_min_value().get_binary_data(), Some(&[0u8, 0][..]));
        assert_eq!(field.get_fixed_max_value().get_binary_data(), Some(&[0xffu8, 0xff][..]));
    }

    /// Demonstrates the method-name-shadowing caveat documented on the trait: calling the
    /// inherited `BinaryField::is_null()` on a `dyn FixedField` does *not* reflect
    /// `is_fixed_null()`'s state, because `BinaryField::is_null()`'s default implementation checks
    /// whether `get_binary_data()` is `None` -- which, for a `FixedField`, is never true.
    #[test]
    fn test_inherited_binary_field_is_null_does_not_track_fixed_null_state() {
        let mut field: Box<dyn FixedField> = Box::new(MockFixedField::new(vec![1, 2, 3, 4]));
        field.set_fixed_null().unwrap();

        assert!(field.is_fixed_null()); // correct FixedField null-state
        assert!(!BinaryField::is_null(field.as_ref())); // stale BinaryField view: data is still Some
    }
}
