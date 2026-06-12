use super::field::FieldType;
use std::collections::HashSet;

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
}
