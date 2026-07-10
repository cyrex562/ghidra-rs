use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_with_charset::DataTypeEncodeError;
use crate::docking::settings::settings::Settings;
use crate::program::seam_stubs::MemBuffer;

/// Port of `ghidra.program.model.data.IntegerDataTypeTest`.
///
/// The Java class is a concrete JUnit test rather than a formal `interface`, but it sits in the
/// dependency cycle around [`AbstractIntegerDataType`] (not yet ported) and the already-ported
/// [`DataType`] encode/decode contract. Rather than pull in `AbstractIntegerDataType`'s static
/// factories (`getUnsignedDataType`/`getSignedDataType`) and the concrete `ByteMemBufferImpl` /
/// `SettingsImpl` / `FormatSettingsDefinition` helpers the test used to build its fixtures, this
/// trait extracts the fixture-building contract as an object-safe seam: every method the test's
/// `@Test` methods depended on (the two factories, buffer construction, and one accessor per
/// `FormatSettingsDefinition.DEF_*` constant) becomes a required trait method, and every `@Test`
/// method becomes a default method that runs the same assertions against them. This needs no new
/// stub in `seam_stubs.rs`: every referenced core type (`DataType`, [`MemBuffer`], [`Settings`],
/// [`DataTypeEncodeError`]) is already a real port or an existing stub.
///
/// A future concrete fixture -- once `AbstractIntegerDataType`, `ByteMemBufferImpl`, and
/// `SettingsImpl` are ported -- implements the required methods and gets all ten conformance
/// checks for free.
pub trait IntegerDataTypeTest {
    /// Stands in for `AbstractIntegerDataType.getUnsignedDataType(length, null)`.
    fn unsigned_data_type(&self, length: i32) -> Box<dyn DataType>;

    /// Stands in for `AbstractIntegerDataType.getSignedDataType(length, null)`.
    fn signed_data_type(&self, length: i32) -> Box<dyn DataType>;

    /// Stands in for the private static `buf(boolean, int...)` helper, which wrapped
    /// `new ByteMemBufferImpl(Address.NO_ADDRESS, bytes(vals), bigEndian)`.
    fn buf(&self, big_endian: bool, bytes: &[u8]) -> Box<dyn MemBuffer>;

    /// Stands in for the private static `HEX` field (`format(FormatSettingsDefinition.DEF_HEX)`).
    fn hex_settings(&self) -> Box<dyn Settings>;

    /// Stands in for the private static `DEC` field
    /// (`format(FormatSettingsDefinition.DEF_DECIMAL)`).
    fn dec_settings(&self) -> Box<dyn Settings>;

    /// Stands in for the private static `BIN` field (`format(FormatSettingsDefinition.DEF_BINARY)`).
    fn bin_settings(&self) -> Box<dyn Settings>;

    /// Stands in for the private static `OCT` field (`format(FormatSettingsDefinition.DEF_OCTAL)`).
    fn oct_settings(&self) -> Box<dyn Settings>;

    /// Stands in for the private static `CHR` field (`format(FormatSettingsDefinition.DEF_CHAR)`).
    fn char_settings(&self) -> Box<dyn Settings>;

    /// Port of `testEncodeValueUnsignedByteBE`.
    fn test_encode_value_unsigned_byte_be(&self) {
        let dt = self.unsigned_data_type(1);
        let be = self.buf(true, &[0]);
        let hex = self.hex_settings();

        assert_eq!(dt.encode_value(&(0xffu8 as i8), &*be, &*hex, 1).unwrap(), vec![0xff]);
        assert_eq!(dt.encode_value(&(-1i8), &*be, &*hex, 1).unwrap(), vec![0xff]);

        assert!(dt.encode_value(&0x100i16, &*be, &*hex, 1).is_err());
        assert!(dt.encode_value(&(-1i16), &*be, &*hex, 1).is_err());

        assert_eq!(dt.encode_value(&0xffi32, &*be, &*hex, 1).unwrap(), vec![0xff]);
        // This fails, because (int) -1 is 4294967295 when treated unsigned.
        assert!(dt.encode_value(&(-1i32), &*be, &*hex, 1).is_err());
    }

    /// Port of `testEncodeRepresentationUnsignedByteHexBE`.
    fn test_encode_representation_unsigned_byte_hex_be(&self) {
        let dt = self.unsigned_data_type(1);
        let be = self.buf(true, &[0]);
        let hex = self.hex_settings();

        // Sanity check: renders unsigned.
        assert_eq!(dt.get_representation(&*self.buf(true, &[0x80]), &*hex, 1), "80h");

        assert_eq!(dt.encode_representation("0h", &*be, &*hex, 1).unwrap(), vec![0x00]);
        assert_eq!(dt.encode_representation("7fh", &*be, &*hex, 1).unwrap(), vec![0x7f]);
        assert_eq!(dt.encode_representation("80h", &*be, &*hex, 1).unwrap(), vec![0x80]);
        assert_eq!(dt.encode_representation("ffh", &*be, &*hex, 1).unwrap(), vec![0xff]);

        assert!(dt.encode_representation("100h", &*be, &*hex, 1).is_err());
        assert!(dt.encode_representation("-1h", &*be, &*hex, 1).is_err());
    }

    /// Port of `testEncodeRepresentationSignedShortHexBE`.
    fn test_encode_representation_signed_short_hex_be(&self) {
        let dt = self.signed_data_type(2);
        let be = self.buf(true, &[0]);
        let hex = self.hex_settings();

        // Sanity check: negative hex values render unsigned.
        assert_eq!(dt.get_representation(&*self.buf(true, &[0x80, 0x00]), &*hex, 2), "8000h");

        assert_eq!(dt.encode_representation("0h", &*be, &*hex, 2).unwrap(), vec![0x00, 0x00]);
        assert_eq!(dt.encode_representation("7fffh", &*be, &*hex, 2).unwrap(), vec![0x7f, 0xff]);
        assert_eq!(dt.encode_representation("8000h", &*be, &*hex, 2).unwrap(), vec![0x80, 0x00]);
        assert_eq!(dt.encode_representation("ffffh", &*be, &*hex, 2).unwrap(), vec![0xff, 0xff]);

        assert_eq!(dt.encode_representation("-1h", &*be, &*hex, 2).unwrap(), vec![0xff, 0xff]);
        assert_eq!(dt.encode_representation("-8000h", &*be, &*hex, 2).unwrap(), vec![0x80, 0x00]);

        assert!(dt.encode_representation("10000h", &*be, &*hex, 2).is_err());
        assert!(dt.encode_representation("-8001h", &*be, &*hex, 2).is_err());
    }

    /// Port of `testEncodeRepresentationSignedShortHexLE`.
    fn test_encode_representation_signed_short_hex_le(&self) {
        let dt = self.signed_data_type(2);
        let le = self.buf(false, &[0]);
        let hex = self.hex_settings();

        // Sanity check: negative hex values render unsigned.
        assert_eq!(dt.get_representation(&*self.buf(false, &[0x00, 0x80]), &*hex, 2), "8000h");

        assert_eq!(dt.encode_representation("0h", &*le, &*hex, 2).unwrap(), vec![0x00, 0x00]);
        assert_eq!(dt.encode_representation("7fffh", &*le, &*hex, 2).unwrap(), vec![0xff, 0x7f]);
        assert_eq!(dt.encode_representation("8000h", &*le, &*hex, 2).unwrap(), vec![0x00, 0x80]);
        assert_eq!(dt.encode_representation("ffffh", &*le, &*hex, 2).unwrap(), vec![0xff, 0xff]);

        assert_eq!(dt.encode_representation("-1h", &*le, &*hex, 2).unwrap(), vec![0xff, 0xff]);
        assert_eq!(dt.encode_representation("-8000h", &*le, &*hex, 2).unwrap(), vec![0x00, 0x80]);

        assert!(dt.encode_representation("10000h", &*le, &*hex, 2).is_err());
        assert!(dt.encode_representation("-8001h", &*le, &*hex, 2).is_err());
    }

    /// Port of `testEncodeRepresentationUnsignedShortHexBE`.
    fn test_encode_representation_unsigned_short_hex_be(&self) {
        let dt = self.unsigned_data_type(2);
        let be = self.buf(true, &[0]);
        let hex = self.hex_settings();

        // Sanity check: renders unsigned.
        assert_eq!(dt.get_representation(&*self.buf(true, &[0x80, 0x00]), &*hex, 2), "8000h");

        assert_eq!(dt.encode_representation("0h", &*be, &*hex, 2).unwrap(), vec![0x00, 0x00]);
        assert_eq!(dt.encode_representation("7fffh", &*be, &*hex, 2).unwrap(), vec![0x7f, 0xff]);
        assert_eq!(dt.encode_representation("8000h", &*be, &*hex, 2).unwrap(), vec![0x80, 0x00]);
        assert_eq!(dt.encode_representation("ffffh", &*be, &*hex, 2).unwrap(), vec![0xff, 0xff]);

        assert!(dt.encode_representation("-1h", &*be, &*hex, 2).is_err());
        assert!(dt.encode_representation("-8000h", &*be, &*hex, 2).is_err());
        assert!(dt.encode_representation("10000h", &*be, &*hex, 2).is_err());
        assert!(dt.encode_representation("-8001h", &*be, &*hex, 2).is_err());
    }

    /// Port of `testEncodeRepresentationSignedShortDecBE`.
    fn test_encode_representation_signed_short_dec_be(&self) {
        let dt = self.signed_data_type(2);
        let be = self.buf(true, &[0]);
        let dec = self.dec_settings();

        // Sanity check: negative hex values render signed.
        assert_eq!(dt.get_representation(&*self.buf(true, &[0x80, 0x00]), &*dec, 2), "-32768");

        assert_eq!(dt.encode_representation("0", &*be, &*dec, 2).unwrap(), vec![0x00, 0x00]);
        assert_eq!(dt.encode_representation("32767", &*be, &*dec, 2).unwrap(), vec![0x7f, 0xff]);
        assert_eq!(dt.encode_representation("-32768", &*be, &*dec, 2).unwrap(), vec![0x80, 0x00]);
        assert_eq!(dt.encode_representation("-1", &*be, &*dec, 2).unwrap(), vec![0xff, 0xff]);

        assert!(dt.encode_representation("32768", &*be, &*dec, 2).is_err());
        assert!(dt.encode_representation("-32769", &*be, &*dec, 2).is_err());
    }

    /// Port of `testEncodeRepresentationUnsignedShortDecBE`.
    fn test_encode_representation_unsigned_short_dec_be(&self) {
        let dt = self.unsigned_data_type(2);
        let be = self.buf(true, &[0]);
        let dec = self.dec_settings();

        // Sanity check: renders unsigned.
        assert_eq!(dt.get_representation(&*self.buf(true, &[0x80, 0x00]), &*dec, 2), "32768");

        assert_eq!(dt.encode_representation("0", &*be, &*dec, 2).unwrap(), vec![0x00, 0x00]);
        assert_eq!(dt.encode_representation("32767", &*be, &*dec, 2).unwrap(), vec![0x7f, 0xff]);
        assert_eq!(dt.encode_representation("32768", &*be, &*dec, 2).unwrap(), vec![0x80, 0x00]);
        assert_eq!(dt.encode_representation("65535", &*be, &*dec, 2).unwrap(), vec![0xff, 0xff]);

        assert!(dt.encode_representation("-1", &*be, &*dec, 2).is_err());
        assert!(dt.encode_representation("65536", &*be, &*dec, 2).is_err());
    }

    /// Port of `testEncodeRepresentationSignedShortBinBE`.
    ///
    /// Note: faithfully mirrors the Java original, which (despite its name) exercises
    /// `getUnsignedDataType`, not `getSignedDataType`.
    fn test_encode_representation_signed_short_bin_be(&self) {
        let dt = self.unsigned_data_type(2);
        let be = self.buf(true, &[0]);
        let bin = self.bin_settings();

        assert_eq!(dt.get_representation(&*self.buf(true, &[0x01, 0x03]), &*bin, 2), "100000011b");
        assert_eq!(dt.encode_representation("100000011b", &*be, &*bin, 2).unwrap(), vec![0x01, 0x03]);
    }

    /// Port of `testEncodeRepresentationSignedShortOctBE`.
    ///
    /// Note: faithfully mirrors the Java original, which (despite its name) exercises
    /// `getUnsignedDataType`, not `getSignedDataType`.
    fn test_encode_representation_signed_short_oct_be(&self) {
        let dt = self.unsigned_data_type(2);
        let be = self.buf(true, &[0]);
        let oct = self.oct_settings();

        assert_eq!(dt.get_representation(&*self.buf(true, &[0x01, 0x03]), &*oct, 2), "403o");
        assert_eq!(dt.encode_representation("403o", &*be, &*oct, 2).unwrap(), vec![0x01, 0x03]);
    }

    /// Port of `testEncodeRepresentationChar`.
    fn test_encode_representation_char(&self) {
        let stype = self.signed_data_type(1);
        let utype = self.unsigned_data_type(1);
        let be = self.buf(true, &[0]);
        let chr = self.char_settings();

        assert_eq!(stype.get_representation(&*self.buf(true, &[0x41]), &*chr, 1), "'A'");
        assert_eq!(utype.get_representation(&*self.buf(true, &[0x41]), &*chr, 1), "'A'");

        assert_eq!(stype.encode_representation("'A'", &*be, &*chr, 1).unwrap(), vec![0x41]);
        assert_eq!(utype.encode_representation("'A'", &*be, &*chr, 1).unwrap(), vec![0x41]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    /// Minimal `DataType` that implements just enough unsigned-byte encode logic to prove the
    /// trait's fixture contract is real and drives an actual `DataType` implementation, not just
    /// a compile-time check.
    struct MockUnsignedByte;

    impl DataType for MockUnsignedByte {
        fn is_encodable(&self) -> bool {
            true
        }

        fn encode_value(
            &self,
            value: &dyn Any,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> Result<Vec<u8>, DataTypeEncodeError> {
            let as_i32 = if let Some(b) = value.downcast_ref::<i8>() {
                *b as u8 as i32
            } else if value.downcast_ref::<i16>().is_some() {
                return Err(DataTypeEncodeError("short does not fit in 1 byte".to_string()));
            } else if let Some(i) = value.downcast_ref::<i32>() {
                *i
            } else {
                return Err(DataTypeEncodeError("unsupported value type".to_string()));
            };
            if !(0..=0xff).contains(&as_i32) {
                return Err(DataTypeEncodeError("value out of unsigned byte range".to_string()));
            }
            Ok(vec![as_i32 as u8])
        }
    }

    struct MockBuf;
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockFixture;

    impl IntegerDataTypeTest for MockFixture {
        fn unsigned_data_type(&self, _length: i32) -> Box<dyn DataType> {
            Box::new(MockUnsignedByte)
        }

        fn signed_data_type(&self, _length: i32) -> Box<dyn DataType> {
            Box::new(MockUnsignedByte)
        }

        fn buf(&self, _big_endian: bool, _bytes: &[u8]) -> Box<dyn MemBuffer> {
            Box::new(MockBuf)
        }

        fn hex_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }

        fn dec_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }

        fn bin_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }

        fn oct_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }

        fn char_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
    }

    #[test]
    fn usable_as_trait_object_and_runs_a_conformance_check() {
        let fixture: &dyn IntegerDataTypeTest = &MockFixture;
        fixture.test_encode_value_unsigned_byte_be();
    }
}
