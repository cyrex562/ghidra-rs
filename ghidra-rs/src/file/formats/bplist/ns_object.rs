use std::fmt;

use crate::app::util::bin::struct_converter::StructConverter;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure::Structure;
use crate::program::model::listing::{Data, Program};
use crate::util::big_endian_data_converter;
use crate::util::data_converter::DataConverter;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Common behavior shared by binary property list object values.
///
/// Port of `ghidra.file.formats.bplist.NSObject`. `getType()` and `toString()` were declared
/// `abstract` in Java; `getType()` is a required trait method here, and `toString()` is
/// represented via the `Display` supertrait bound (see `AnnotationHandler` for the same
/// convention).
pub trait NsObject: StructConverter + fmt::Display {
    /// Returns the type name of this object.
    ///
    /// Port of `NSObject.getType()`.
    fn get_type(&self) -> String;

    /// Returns the data converter used to interpret this object's raw bytes.
    ///
    /// All data is stored big endian in a binary plist.
    ///
    /// Port of `NSObject.converter`.
    fn converter(&self) -> &'static dyn DataConverter {
        &big_endian_data_converter::INSTANCE
    }

    /// Adds the object descriptor header fields to `structure`, sized according to `size`.
    ///
    /// Port of `NSObject.addHeader(Structure, int)`.
    ///
    /// # Panics
    /// Panics if `size` is `0xffff` or greater, mirroring the `RuntimeException` thrown by the
    /// Java source for an unexpected size.
    ///
    /// # Errors
    /// Returns `Err` if `structure` rejects one of the header fields.
    fn add_header(&self, structure: &mut dyn Structure, size: i32) -> Result<(), String> {
        if size < 0xf {
            structure.add_with_name(
                Box::new(BytePlaceholderDataType),
                Some("objectDescriptor".to_string()),
                None,
            )?;
        } else if size < 0xff {
            structure.add_with_name(
                Box::new(BytePlaceholderDataType),
                Some("objectDescriptor".to_string()),
                None,
            )?;
            structure.add_with_name(
                Box::new(BytePlaceholderDataType),
                Some("indicator".to_string()),
                None,
            )?;
            structure.add_with_name(
                Box::new(BytePlaceholderDataType),
                Some("length".to_string()),
                None,
            )?;
        } else if size < 0xffff {
            structure.add_with_name(
                Box::new(BytePlaceholderDataType),
                Some("objectDescriptor".to_string()),
                None,
            )?;
            structure.add_with_name(
                Box::new(BytePlaceholderDataType),
                Some("indicator".to_string()),
                None,
            )?;
            structure.add_with_name(
                Box::new(WordPlaceholderDataType),
                Some("length".to_string()),
                None,
            )?;
        } else {
            panic!("unexpected size in {}", std::any::type_name::<Self>());
        }
        Ok(())
    }

    /// Marks up `object_data` in `program`. The base implementation does nothing; concrete
    /// object types override this to add markup specific to their layout.
    ///
    /// Port of `NSObject.markup(Data, Program, TaskMonitor)`.
    fn markup(
        &self,
        object_data: &mut dyn Data,
        program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let _ = (object_data, program, monitor);
        Ok(())
    }

    /// Reads `component`'s bytes and interprets them the way Java's
    /// `new BigInteger(bytes).longValue()` would: sign-extended if fewer than 8 bytes were read,
    /// or truncated to the low-order 8 bytes if more were read.
    ///
    /// Returns `-1` if the component's bytes could not be read.
    ///
    /// Port of `NSObject.getValue(Data)`.
    fn get_value(&self, component: &dyn Data) -> i64 {
        match component.get_bytes() {
            Ok(bytes) => big_integer_long_value(&bytes),
            Err(_) => -1,
        }
    }
}

/// Mirrors `new BigInteger(bytes).longValue()`: interprets `bytes` as a big-endian, two's
/// complement integer of arbitrary length, then narrows to the low-order 64 bits.
fn big_integer_long_value(bytes: &[u8]) -> i64 {
    let Some(&first) = bytes.first() else {
        return 0;
    };
    let negative = first & 0x80 != 0;
    let mut buf = if negative { [0xffu8; 8] } else { [0u8; 8] };
    let len = bytes.len();
    if len >= 8 {
        buf.copy_from_slice(&bytes[len - 8..]);
    } else {
        buf[8 - len..].copy_from_slice(bytes);
    }
    i64::from_be_bytes(buf)
}

/// Minimal stand-in for `ghidra.program.model.data.ByteDataType.dataType`, used until
/// `ByteDataType` is ported.
struct BytePlaceholderDataType;

impl DataType for BytePlaceholderDataType {
    fn get_length(&self) -> i32 {
        1
    }

    fn get_name(&self) -> String {
        "byte".to_string()
    }
}

/// Minimal stand-in for `ghidra.program.model.data.WordDataType.dataType`, used until
/// `WordDataType` is ported.
struct WordPlaceholderDataType;

impl DataType for WordPlaceholderDataType {
    fn get_length(&self) -> i32 {
        2
    }

    fn get_name(&self) -> String {
        "word".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::struct_converter::ToDataTypeError;
    use crate::program::model::data::composite::Composite;

    struct MockStructure;
    impl DataType for MockStructure {}
    impl Composite for MockStructure {}
    impl Structure for MockStructure {}

    struct MockObject(&'static str);

    impl fmt::Display for MockObject {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl StructConverter for MockObject {
        fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
            Ok(Box::new(BytePlaceholderDataType))
        }
    }

    impl NsObject for MockObject {
        fn get_type(&self) -> String {
            "Mock".to_string()
        }
    }

    #[test]
    fn get_type_and_display() {
        let obj = MockObject("hello");
        assert_eq!(obj.get_type(), "Mock");
        assert_eq!(obj.to_string(), "hello");
    }

    #[test]
    fn converter_is_big_endian() {
        let obj = MockObject("x");
        assert!(obj.converter().is_big_endian());
    }

    #[test]
    fn add_header_small_size() {
        let obj = MockObject("x");
        let mut structure = MockStructure;
        assert!(obj.add_header(&mut structure, 0x5).is_ok());
    }

    #[test]
    fn add_header_medium_size() {
        let obj = MockObject("x");
        let mut structure = MockStructure;
        assert!(obj.add_header(&mut structure, 0x50).is_ok());
    }

    #[test]
    fn add_header_large_size() {
        let obj = MockObject("x");
        let mut structure = MockStructure;
        assert!(obj.add_header(&mut structure, 0x5000).is_ok());
    }

    #[test]
    #[should_panic(expected = "unexpected size")]
    fn add_header_oversized_panics() {
        let obj = MockObject("x");
        let mut structure = MockStructure;
        let _ = obj.add_header(&mut structure, 0xffff);
    }

    #[test]
    fn big_integer_long_value_empty() {
        assert_eq!(big_integer_long_value(&[]), 0);
    }

    #[test]
    fn big_integer_long_value_single_positive_byte() {
        assert_eq!(big_integer_long_value(&[0x7f]), 0x7f);
    }

    #[test]
    fn big_integer_long_value_single_negative_byte() {
        // 0xff as a signed byte is -1; BigInteger sign-extends it to a full long.
        assert_eq!(big_integer_long_value(&[0xff]), -1);
    }

    #[test]
    fn big_integer_long_value_four_bytes_positive() {
        assert_eq!(big_integer_long_value(&[0x00, 0x00, 0x01, 0x00]), 0x100);
    }

    #[test]
    fn big_integer_long_value_eight_bytes_round_trip() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(big_integer_long_value(&bytes), 0x0102_0304_0506_0708i64);
    }

    #[test]
    fn big_integer_long_value_truncates_beyond_eight_bytes() {
        // A leading 0x00 sign byte plus 8 magnitude bytes: BigInteger.longValue() keeps only
        // the low-order 64 bits, dropping the leading sign byte entirely.
        let bytes = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(big_integer_long_value(&bytes), -1);
    }
}
