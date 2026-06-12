use super::buffer::Buffer;
use super::field::{Field, FieldType};
use super::schema::Schema;
use std::sync::Arc;

#[derive(Clone)]
pub struct DBRecord {
    schema: Arc<Schema>,
    key: Field,
    fields: Vec<Field>,
    dirty: bool,
}

impl DBRecord {
    pub fn new(schema: Arc<Schema>, key: Field) -> Self {
        // Validate key type
        if key.get_type() != schema.get_key_type() {
            panic!("Invalid key type for schema");
        }

        let mut fields = Vec::with_capacity(schema.get_field_count());
        for i in 0..schema.get_field_count() {
            let field_type = schema.get_field_type(i);
            let field = match field_type {
                FieldType::Byte => Field::Byte(Some(0)),
                FieldType::Short => Field::Short(Some(0)),
                FieldType::Int => Field::Int(Some(0)),
                FieldType::Long => Field::Long(Some(0)),
                FieldType::String => Field::String(None),
                FieldType::Binary => Field::Binary(None),
                FieldType::Boolean => Field::Boolean(Some(false)),
                FieldType::Fixed(len) => Field::Fixed(Some(vec![0; len as usize])),
            };
            fields.push(field);
        }

        Self {
            schema,
            key,
            fields,
            dirty: false,
        }
    }

    pub fn get_key(&self) -> &Field {
        &self.key
    }

    pub fn set_key(&mut self, key: Field) {
        if key.get_type() != self.schema.get_key_type() {
            panic!("Invalid key type for schema");
        }
        self.key = key;
        self.dirty = true;
    }

    pub fn get_field(&self, index: usize) -> &Field {
        &self.fields[index]
    }

    pub fn set_field(&mut self, index: usize, field: Field) {
        if field.get_type() != self.schema.get_field_type(index) {
            panic!("Invalid field type for column {}", index);
        }
        self.fields[index] = field;
        self.dirty = true;
    }

    pub fn get_field_count(&self) -> usize {
        self.fields.len()
    }

    pub fn get_string(&self, index: usize) -> Option<&str> {
        if let Field::String(s) = &self.fields[index] {
            s.as_deref()
        } else {
            None
        }
    }

    pub fn set_string(&mut self, index: usize, value: Option<String>) {
        self.set_field(index, Field::String(value));
    }

    pub fn get_long(&self, index: usize) -> Option<i64> {
        if let Field::Long(v) = self.fields[index] {
            v
        } else {
            None
        }
    }

    pub fn set_long(&mut self, index: usize, value: i64) {
        self.set_field(index, Field::Long(Some(value)));
    }

    pub fn get_int(&self, index: usize) -> Option<i32> {
        if let Field::Int(v) = self.fields[index] {
            v
        } else {
            None
        }
    }

    pub fn set_int(&mut self, index: usize, value: i32) {
        self.set_field(index, Field::Int(Some(value)));
    }

    pub fn get_byte(&self, index: usize) -> Option<i8> {
        if let Field::Byte(v) = self.fields[index] {
            v
        } else {
            None
        }
    }

    pub fn set_byte(&mut self, index: usize, value: i8) {
        self.set_field(index, Field::Byte(Some(value)));
    }

    pub fn get_bool(&self, index: usize) -> Option<bool> {
        if let Field::Boolean(v) = self.fields[index] {
            v
        } else {
            None
        }
    }

    pub fn set_bool(&mut self, index: usize, value: bool) {
        self.set_field(index, Field::Boolean(Some(value)));
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn set_dirty(&mut self, dirty: bool) {
        self.dirty = dirty;
    }

    pub fn length(&self) -> usize {
        let mut len = 0;
        for field in &self.fields {
            len += field.length();
        }
        len
    }

    pub fn write(&self, buf: &mut dyn Buffer, offset: usize) -> usize {
        let mut cur_off = offset;
        for i in 0..self.fields.len() {
            let written = self.fields[i].write(buf, cur_off);
            if written < 0 {
                panic!("Buffer overflow writing record");
            }
            cur_off = written as usize;
        }
        cur_off - offset
    }

    pub fn read(&mut self, buf: &dyn Buffer, offset: usize) -> usize {
        let mut cur_off = offset;
        for i in 0..self.fields.len() {
            let (f, len) = Field::read(buf, cur_off, self.schema.get_field_type(i));
            self.fields[i] = f;
            cur_off += len;
        }
        self.dirty = false;
        cur_off - offset
    }
}
