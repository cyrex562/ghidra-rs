use super::field::{FieldType, UnsupportedFieldException};
use std::collections::HashSet;

/// Separator used between packed field names. Mirrors `Schema.NAME_SEPARATOR`.
const NAME_SEPARATOR: char = ';';

/// Marks the end of the plain field-type list within an encoded field-type byte array, before
/// any extension data (e.g. the sparse-column list). Mirrors `Schema.FIELD_EXTENSION_INDICATOR`.
const FIELD_EXTENSION_INDICATOR: u8 = 0xFF; // -1 as a byte

/// Extension-type tag identifying a following sparse-column-index list. Mirrors
/// `Schema.SPARSE_FIELD_LIST_EXTENSION`.
const SPARSE_FIELD_LIST_EXTENSION: u8 = 1;

#[derive(Debug)]
pub struct Schema {
    version: i32,
    key_type: FieldType,
    key_name: String,
    fields: Vec<FieldType>,
    field_names: Vec<String>,
    sparse_columns: HashSet<usize>,
    force_variable_key_nodes: bool,
}

impl Schema {
    pub fn new(
        version: i32,
        key_type: FieldType,
        key_name: String,
        fields: Vec<FieldType>,
        field_names: Vec<String>,
        sparse_columns: Vec<usize>,
    ) -> Self {
        if fields.len() != field_names.len() {
            panic!("field_names and fields lengths differ");
        }

        Self {
            version,
            key_type,
            key_name,
            fields,
            field_names,
            sparse_columns: sparse_columns.into_iter().collect(),
            force_variable_key_nodes: false,
        }
    }

    pub fn get_version(&self) -> i32 {
        self.version
    }

    pub fn get_key_type(&self) -> FieldType {
        self.key_type
    }

    pub fn get_key_name(&self) -> &str {
        &self.key_name
    }

    pub fn get_field_count(&self) -> usize {
        self.fields.len()
    }

    pub fn get_field_type(&self, index: usize) -> FieldType {
        self.fields[index]
    }

    pub fn get_field_name(&self, index: usize) -> &str {
        &self.field_names[index]
    }

    pub fn is_sparse_column(&self, index: usize) -> bool {
        self.sparse_columns.contains(&index)
    }

    pub fn use_long_key_nodes(&self) -> bool {
        !self.force_variable_key_nodes && self.key_type == FieldType::Long
    }

    pub fn use_variable_key_nodes(&self) -> bool {
        self.force_variable_key_nodes || self.key_type.is_variable_length()
    }

    pub fn use_fixed_key_nodes(&self) -> bool {
        !self.use_variable_key_nodes() && !self.use_long_key_nodes()
    }

    pub fn is_variable_length(&self) -> bool {
        if !self.sparse_columns.is_empty() {
            return true;
        }
        for field in &self.fields {
            if field.is_variable_length() {
                return true;
            }
        }
        false
    }

    pub fn get_fixed_record_length(&self) -> usize {
        let mut len = 0;
        for field in &self.fields {
            len += match field {
                FieldType::Byte => 1,
                FieldType::Short => 2,
                FieldType::Int => 4,
                FieldType::Long => 8,
                FieldType::Boolean => 1,
                FieldType::Fixed(l) => *l as usize,
                _ => 0, // Variable length
            };
        }
        len
    }

    /// Force this schema to use variable-length key nodes.
    ///
    /// Port of `Schema.forceUseOfVariableLengthKeyNodes()`: a work-around for legacy schemas
    /// which employ primitive fixed-length keys other than `LongField` and improperly employ a
    /// variable-length-key storage scheme. Although rare, this may be necessary to ensure
    /// backward compatibility with legacy DB storage.
    pub fn force_use_of_variable_length_key_nodes(&mut self) {
        self.force_variable_key_nodes = true;
    }

    /// The `Field` type-tag byte for this schema's key type. Mirrors `Schema.getEncodedKeyFieldType()`.
    pub fn get_encoded_key_field_type(&self) -> u8 {
        self.key_type.to_byte()
    }

    /// Get this schema's column field types as an encoded byte array (one type-tag byte per
    /// column, followed by a sparse-column-index extension when this schema has sparse columns).
    /// Mirrors `Schema.getEncodedFieldTypes()`.
    pub fn get_encoded_field_types(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = self.fields.iter().map(|f| f.to_byte()).collect();
        if !self.sparse_columns.is_empty() {
            encoded.push(FIELD_EXTENSION_INDICATOR);
            encoded.push(SPARSE_FIELD_LIST_EXTENSION);
            // Iterate in a deterministic (ascending) order: `HashSet` iteration order is
            // otherwise unspecified, and Java's real `Set<Integer>` (a `LinkedHashSet`-backed
            // `Set.copyOf` result) iterates in an implementation-defined but stable order --
            // sorting here keeps this port's encoding reproducible without claiming to match
            // Java's exact (and itself unspecified-by-contract) column ordering.
            let mut cols: Vec<usize> = self.sparse_columns.iter().copied().collect();
            cols.sort_unstable();
            for col in cols {
                encoded.push(col as u8);
            }
        }
        encoded
    }

    /// Get the packed list of this schema's key name followed by its data field names, separated
    /// by `;`. Mirrors `Schema.getPackedFieldNames()`.
    pub fn get_packed_field_names(&self) -> String {
        let mut buf = String::new();
        buf.push_str(&self.key_name);
        buf.push(NAME_SEPARATOR);
        for name in &self.field_names {
            buf.push_str(name);
            buf.push(NAME_SEPARATOR);
        }
        buf
    }

    /// Construct a `Schema` by decoding a version, key type, field types, and packed field-name
    /// list previously produced by [`Self::get_encoded_key_field_type`],
    /// [`Self::get_encoded_field_types`], and [`Self::get_packed_field_names`].
    ///
    /// Port of the package-private `Schema(int version, byte encodedKeyFieldType, byte[]
    /// encodedFieldTypes, String packedFieldNames)` constructor, used when reconstructing a
    /// schema from a stored [`super::table_record::TableRecord`].
    pub fn from_encoded(
        version: i32,
        encoded_key_field_type: u8,
        encoded_field_types: &[u8],
        packed_field_names: &str,
    ) -> Result<Schema, UnsupportedFieldException> {
        let key_type = FieldType::from_byte(encoded_key_field_type)?;

        let mut names: Vec<String> = packed_field_names
            .split(NAME_SEPARATOR)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if names.is_empty() {
            return Err(UnsupportedFieldException::with_message(
                "packed field names missing key name",
            ));
        }
        let key_name = names.remove(0);
        let field_names = names;

        let mut fields = Vec::new();
        let mut sparse_columns = Vec::new();
        let mut index = 0usize;
        while index < encoded_field_types.len() {
            let b = encoded_field_types[index];
            index += 1;
            if b == FIELD_EXTENSION_INDICATOR {
                break;
            }
            fields.push(FieldType::from_byte(b)?);
        }
        while index < encoded_field_types.len() {
            let extension_type = encoded_field_types[index];
            index += 1;
            if extension_type == SPARSE_FIELD_LIST_EXTENSION {
                while index < encoded_field_types.len()
                    && encoded_field_types[index] != FIELD_EXTENSION_INDICATOR
                {
                    sparse_columns.push(encoded_field_types[index] as usize);
                    index += 1;
                }
            } else {
                return Err(UnsupportedFieldException::with_message(format!(
                    "Unsupported field extension type: {}",
                    extension_type
                )));
            }
        }

        if field_names.len() != fields.len() {
            return Err(UnsupportedFieldException::with_message(
                "fieldNames and column types differ in length",
            ));
        }

        let schema = Schema::new(version, key_type, key_name, fields, field_names, sparse_columns);
        Ok(schema)
    }
}

#[cfg(test)]
mod encode_decode_tests {
    use super::*;

    #[test]
    fn test_encode_decode_round_trip_no_sparse_columns() {
        let schema = Schema::new(
            3,
            FieldType::Long,
            "TableNum".to_string(),
            vec![FieldType::String, FieldType::Int, FieldType::Binary],
            vec!["Name".to_string(), "Version".to_string(), "Data".to_string()],
            vec![],
        );

        let key_byte = schema.get_encoded_key_field_type();
        let field_bytes = schema.get_encoded_field_types();
        let names = schema.get_packed_field_names();
        assert_eq!(names, "TableNum;Name;Version;Data;");

        let decoded = Schema::from_encoded(3, key_byte, &field_bytes, &names).unwrap();
        assert_eq!(decoded.get_version(), 3);
        assert_eq!(decoded.get_key_type(), FieldType::Long);
        assert_eq!(decoded.get_key_name(), "TableNum");
        assert_eq!(decoded.get_field_count(), 3);
        assert_eq!(decoded.get_field_type(0), FieldType::String);
        assert_eq!(decoded.get_field_type(1), FieldType::Int);
        assert_eq!(decoded.get_field_type(2), FieldType::Binary);
        assert_eq!(decoded.get_field_name(0), "Name");
        assert!(!decoded.is_sparse_column(0));
    }

    #[test]
    fn test_encode_decode_round_trip_with_sparse_columns() {
        let schema = Schema::new(
            1,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int, FieldType::String, FieldType::Byte],
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            vec![1, 2],
        );

        let field_bytes = schema.get_encoded_field_types();
        // type bytes for Int(2), String(4), Byte(0), then extension indicator (0xFF),
        // extension type (SPARSE_FIELD_LIST_EXTENSION=1), then sorted column indexes.
        assert_eq!(field_bytes, vec![2, 4, 0, 0xFF, 1, 1, 2]);

        let decoded = Schema::from_encoded(
            1,
            schema.get_encoded_key_field_type(),
            &field_bytes,
            &schema.get_packed_field_names(),
        )
        .unwrap();
        assert!(decoded.is_sparse_column(1));
        assert!(decoded.is_sparse_column(2));
        assert!(!decoded.is_sparse_column(0));
    }

    #[test]
    fn test_from_encoded_rejects_unsupported_field_type() {
        let err = Schema::from_encoded(1, 0, &[42], "Key;Col;").unwrap_err();
        assert_eq!(err.to_string(), "Unsupported field type: 42");
    }

    #[test]
    fn test_force_use_of_variable_length_key_nodes() {
        let mut schema = Schema::new(
            0,
            FieldType::Byte,
            "Key".to_string(),
            vec![],
            vec![],
            vec![],
        );
        assert!(schema.use_fixed_key_nodes());
        schema.force_use_of_variable_length_key_nodes();
        assert!(schema.use_variable_key_nodes());
        assert!(!schema.use_fixed_key_nodes());
    }
}
