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
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::string_data_type::StringDataType;
    use crate::program::model::data::terminated_string_data_type::TerminatedStringDataType;

    fn sequence(start: i64, end: i64, null_terminated: bool) -> Sequence {
        Sequence::new(start, end, Box::new(StringDataType::new(None)), null_terminated)
    }

    #[test]
    fn accessors_return_the_constructor_arguments() {
        let seq = sequence(10, 19, true);
        assert_eq!(seq.get_start(), 10);
        assert_eq!(seq.get_end(), 19);
        assert!(seq.is_null_terminated());
        assert_eq!(seq.get_string_data_type().get_display_name(), "string");
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
        assert_eq!(seq.to_string(), "(3,7,string,true)");
        let seq2 = sequence(0, 0, false);
        assert_eq!(seq2.to_string(), "(0,0,string,false)");
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
    fn sequences_with_different_concrete_data_types_are_not_equal() {
        // Java's equals() compares the string data types' getClass().
        let a = Sequence::new(0, 9, Box::new(StringDataType::new(None)), true);
        let b = Sequence::new(0, 9, Box::new(TerminatedStringDataType::new(None)), true);
        assert_ne!(a, b);
        assert_eq!(a, Sequence::new(0, 9, Box::new(StringDataType::new(None)), true));
    }

    #[test]
    fn debug_format_includes_every_field() {
        let seq = sequence(1, 2, true);
        let debug = format!("{seq:?}");
        assert!(debug.contains("start"));
        assert!(debug.contains('1'));
        assert!(debug.contains("string"));
        assert!(debug.contains("true"));
    }
}
