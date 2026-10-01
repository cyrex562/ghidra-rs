//! Port of `ghidra.program.model.data.UnsignedLeb128DataType`.

use crate::program::model::data::abstract_leb128_data_type::leb128_data_type;

leb128_data_type! {
    /// A Unsigned Little Endian Base 128 (LEB128) encoded number: a variable-length integer.
    ///
    /// Port of `ghidra.program.model.data.UnsignedLeb128DataType`.
    UnsignedLeb128DataType { name: "uleb128", signed: false, description: "Unsigned LEB128-Encoded Number", }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::abstract_leb128_data_type::AbstractLeb128DataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::string_data_instance::test_support::{mb, SettingsBuilder};
    use crate::program::model::scalar::scalar::Scalar;

    #[test]
    fn java_constants() {
        let dt = UnsignedLeb128DataType::instance();
        assert_eq!(dt.get_name(), "uleb128");
        assert_eq!(dt.get_description(), "Unsigned LEB128-Encoded Number");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("uleb128"));
        assert_eq!(dt.get_length(), -1);
        assert_eq!(dt.leb128_is_signed(), false);
        assert!(dt.can_specify_length());
        assert_eq!(dt.get_replacement_base_type().get_name(), "byte");
        // Mutability + FORMAT (hex).
        assert_eq!(dt.get_settings_definitions().len(), 2);
        assert!(dt.is_equivalent(&UnsignedLeb128DataType::new(None)));
    }

    #[test]
    fn decodes_values() {
        let dt = UnsignedLeb128DataType::new(None);
        let s = SettingsBuilder::new();
        // 0xE5 0x8E 0x26 is the canonical LEB128 example: 624485 unsigned.
        let buf = mb(false, &[0xE5, 0x8E, 0x26, 0xFF]);
        assert_eq!(dt.get_dynamic_length(&buf, -1), 3);
        let value = dt.get_value(&buf, &s, -1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 624485);
        assert_eq!(dt.get_representation(&buf, &s, -1), "98765h");
        // 0x7F is -1 signed, 127 unsigned.
        let neg = mb(false, &[0x7F]);
        assert_eq!(dt.get_representation(&neg, &s, -1), if false { "-1h" } else { "7Fh" });
        // A run that never terminates within 10 bytes has no value.
        let bad = mb(false, &[0x80; 12]);
        assert_eq!(dt.get_representation(&bad, &s, -1), "??");
    }
}
