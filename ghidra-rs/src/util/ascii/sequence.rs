//! A recognized run of characters, tagged with the string data type that would represent it.
//!
//! Java source: `ghidra.util.ascii.Sequence`.
use std::any::Any;
use std::fmt;

use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;

/// A recognized run of bytes from `start` to `end` (inclusive), tagged with the string data type
/// that would represent it and whether it is null-terminated.
///
/// Port of `ghidra.util.ascii.Sequence`.
pub struct Sequence {
    start: i64,
    end: i64,
    null_terminated: bool,
    string_data_type: Box<dyn AbstractStringDataType>,
}

impl Sequence {
    /// Constructs a sequence spanning `[start, end]`, described by `string_data_type`.
    ///
    /// Port of `Sequence(long, long, AbstractStringDataType, boolean)`.
    pub fn new(
        start: i64,
        end: i64,
        string_data_type: Box<dyn AbstractStringDataType>,
        null_terminated: bool,
    ) -> Self {
        Self { start, end, string_data_type, null_terminated }
    }

    /// The starting offset of this sequence. Port of `getStart()`.
    pub fn get_start(&self) -> i64 {
        self.start
    }

    /// The ending (inclusive) offset of this sequence. Port of `getEnd()`.
    pub fn get_end(&self) -> i64 {
        self.end
    }

    /// Whether this sequence is null-terminated. Port of `isNullTerminated()`.
    pub fn is_null_terminated(&self) -> bool {
        self.null_terminated
    }

    /// The string data type that would represent this sequence. Port of `getStringDataType()`.
    pub fn get_string_data_type(&self) -> &dyn AbstractStringDataType {
        self.string_data_type.as_ref()
    }

    /// The length, in bytes, of this sequence.
    ///
    /// Port of `getLength()`: `(int) (end - start + 1)`. Preserves Java's narrowing `long` ->
    /// `int` cast (a two's-complement truncation to the low 32 bits) rather than checking for
    /// overflow; `as i32` on an `i64` performs the identical truncation.
    pub fn get_length(&self) -> i32 {
        (self.end - self.start + 1) as i32
    }
}

/// Returns the [`std::any::TypeId`] of the concrete value behind a `dyn AbstractStringDataType`,
/// via the trait's `Any` supertrait (see that trait's docs for why it was grown).
fn as_any(v: &dyn AbstractStringDataType) -> &dyn Any {
    v
}

impl PartialEq for Sequence {
    /// Port of `equals(Object)`.
    ///
    /// Java compares `stringDataType.getClass() == other.stringDataType.getClass()`: runtime
    /// *class* identity, not `DataType::is_equivalent` or any other notion of "same kind of
    /// type." `TypeId` equality on the two trait objects' concrete types is the direct Rust
    /// equivalent.
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
            && self.end == other.end
            && self.null_terminated == other.null_terminated
            && as_any(self.string_data_type.as_ref()).type_id()
                == as_any(other.string_data_type.as_ref()).type_id()
    }
}

impl fmt::Debug for Sequence {
    /// A manual `Debug` impl, since `string_data_type: Box<dyn AbstractStringDataType>` has no
    /// `Debug` supertrait to derive from.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sequence")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("null_terminated", &self.null_terminated)
            .field("string_data_type", &self.string_data_type.get_display_name())
            .finish()
    }
}

impl fmt::Display for Sequence {
    /// Port of `toString()`: `"(" + start + "," + end + "," + stringDataType.getDisplayName() +
    /// "," + nullTerminated + ")"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({},{},{},{})",
            self.start,
            self.end,
            self.string_data_type.get_display_name(),
            self.null_terminated
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::data::string_layout_enum::StringLayoutEnum;
    use crate::program::model::mem::MemBuffer;

    /// Fallback used by the mocks' `Dynamic::get_replacement_base_type`, mirroring
    /// [`AbstractStringDataType`]'s own test module (that method is not optional even though the
    /// underlying Java field may be `null`).
    struct NoReplacementDataType;
    impl DataType for NoReplacementDataType {}

    /// Two minimal, *distinct concrete types* implementing [`AbstractStringDataType`], both
    /// reporting the same display name -- real Ghidra string types (`StringDataType`,
    /// `TerminatedStringDataType`, ...) are each their own concrete Rust type too, which is what
    /// `Sequence::eq`'s `TypeId` comparison actually keys on, not the display name.
    struct MockStringTypeA;
    struct MockStringTypeB;

    macro_rules! impl_mock_string_data_type {
        ($t:ty) => {
            impl DataType for $t {
                fn get_name(&self) -> String {
                    "char".to_string()
                }
            }
            impl BuiltInDataType for $t {
                fn get_c_type_declaration(
                    &self,
                    _data_organization: Option<&dyn DataOrganization>,
                ) -> Option<String> {
                    None
                }
                fn set_default_settings(&mut self, _settings: &dyn Settings) {}
            }
            impl Dynamic for $t {
                fn get_dynamic_length(&self, _buf: &dyn MemBuffer, _max_length: i32) -> i32 {
                    -1
                }
                fn get_replacement_base_type(&self) -> Box<dyn DataType> {
                    Box::new(NoReplacementDataType)
                }
            }
            impl DataTypeWithCharset for $t {
                fn string_data_instance(
                    &self,
                    _settings: &dyn Settings,
                    _buf: &dyn MemBuffer,
                ) -> Box<dyn StringDataInstance> {
                    Box::new(crate::program::model::data::string_data_instance::null_instance())
                }
            }
            impl AbstractStringDataType for $t {
                fn mnemonic(&self) -> String {
                    "char".to_string()
                }
                fn description(&self) -> String {
                    "mock string".to_string()
                }
                fn default_label(&self) -> String {
                    "STR".to_string()
                }
                fn default_label_prefix(&self) -> String {
                    "STR_".to_string()
                }
                fn default_abbrev_label_prefix(&self) -> String {
                    "s_".to_string()
                }
                fn get_string_layout(&self) -> StringLayoutEnum {
                    StringLayoutEnum::NullTerminatedUnbounded
                }
                fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
                    None
                }
            }
        };
    }

    impl_mock_string_data_type!(MockStringTypeA);
    impl_mock_string_data_type!(MockStringTypeB);

    fn sequence(start: i64, end: i64, null_terminated: bool) -> Sequence {
        Sequence::new(start, end, Box::new(MockStringTypeA), null_terminated)
    }

    #[test]
    fn accessors_return_the_constructor_arguments() {
        let seq = sequence(10, 19, true);
        assert_eq!(seq.get_start(), 10);
        assert_eq!(seq.get_end(), 19);
        assert!(seq.is_null_terminated());
        assert_eq!(seq.get_string_data_type().get_display_name(), "char");
    }

    #[test]
    fn get_length_is_inclusive_span() {
        assert_eq!(sequence(0, 0, false).get_length(), 1);
        assert_eq!(sequence(10, 19, false).get_length(), 10);
        assert_eq!(sequence(100, 100, false).get_length(), 1);
    }

    #[test]
    fn get_length_truncates_like_javas_narrowing_cast() {
        // A span whose length doesn't fit in an i32 truncates to the low 32 bits, exactly as
        // Java's `(int) (end - start + 1)` would, rather than saturating or panicking.
        let seq = sequence(0, i64::MAX - 1, false); // end - start + 1 == i64::MAX
        let expected = i64::MAX as i32;
        assert_eq!(seq.get_length(), expected);
    }

    #[test]
    fn display_matches_javas_tostring_format() {
        let seq = sequence(3, 7, true);
        assert_eq!(seq.to_string(), "(3,7,char,true)");
        let seq2 = sequence(0, 0, false);
        assert_eq!(seq2.to_string(), "(0,0,char,false)");
    }

    #[test]
    fn equal_sequences_with_the_same_concrete_data_type_are_equal() {
        let a = sequence(0, 9, true);
        let b = sequence(0, 9, true);
        assert_eq!(a, b);
    }

    #[test]
    fn sequences_differing_in_start_end_or_null_terminated_are_not_equal() {
        let base = sequence(0, 9, true);
        assert_ne!(base, sequence(1, 9, true));
        assert_ne!(base, sequence(0, 10, true));
        assert_ne!(base, sequence(0, 9, false));
    }

    #[test]
    fn sequences_with_different_concrete_data_types_are_not_equal_even_with_the_same_display_name() {
        // Faithful to the Java quirk: equals() compares getClass(), not getDisplayName() or
        // is_equivalent(); two different concrete AbstractStringDataType implementors that
        // happen to render the same display name are still unequal.
        let a = Sequence::new(0, 9, Box::new(MockStringTypeA), true);
        let b = Sequence::new(0, 9, Box::new(MockStringTypeB), true);
        assert_eq!(a.get_string_data_type().get_display_name(), b.get_string_data_type().get_display_name());
        assert_ne!(a, b);
    }

    #[test]
    fn debug_format_includes_every_field() {
        let seq = sequence(1, 2, true);
        let debug = format!("{seq:?}");
        assert!(debug.contains("start"));
        assert!(debug.contains('1'));
        assert!(debug.contains("char"));
        assert!(debug.contains("true"));
    }
}
