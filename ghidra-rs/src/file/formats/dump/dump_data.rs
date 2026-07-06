use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::program::model::data::data_type::DataType;

/// Describes a piece of data to be created within a memory dump.
///
/// Mirrors `ghidra.file.formats.dump.DumpData`.
pub struct DumpData {
    dt: Option<Box<dyn DataType>>,
    offset: i64,
    name: String,
    generate_symbol: bool,
    generate_fragment: bool,
    size: i64,
    space: Option<Arc<AddressSpace>>,
}

impl DumpData {
    /// Creates a `DumpData` from a datatype, using its display name and generating a fragment
    /// but not a symbol.
    pub fn new(offset: i64, dt: Box<dyn DataType>) -> Self {
        let name = dt.get_display_name();
        Self::with_options(offset, dt, name, false, true)
    }

    /// Creates a `DumpData` from a datatype with an explicit name, generating both a symbol and
    /// a fragment.
    pub fn with_name(offset: i64, dt: Box<dyn DataType>, name: String) -> Self {
        Self::with_options(offset, dt, name, true, true)
    }

    /// Creates a `DumpData` from a datatype with an explicit name and symbol/fragment
    /// generation flags.
    pub fn with_options(
        offset: i64,
        dt: Box<dyn DataType>,
        name: String,
        generate_symbol: bool,
        generate_fragment: bool,
    ) -> Self {
        let size = dt.get_length() as i64;
        Self {
            dt: Some(dt),
            offset,
            name,
            generate_symbol,
            generate_fragment,
            size,
            space: None,
        }
    }

    /// Creates a `DumpData` with no datatype, an explicit name and size, generating both a
    /// symbol and a fragment.
    pub fn sized(offset: i64, name: String, size: i32) -> Self {
        Self {
            dt: None,
            offset,
            name,
            generate_symbol: true,
            generate_fragment: true,
            size: size as i64,
            space: None,
        }
    }

    pub fn get_data_type(&self) -> Option<&dyn DataType> {
        self.dt.as_deref()
    }

    pub fn set_data_type(&mut self, dt: Box<dyn DataType>) {
        self.dt = Some(dt);
    }

    pub fn get_offset(&self) -> i64 {
        self.offset
    }

    pub fn set_offset(&mut self, offset: i64) {
        self.offset = offset;
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn is_generate_symbol(&self) -> bool {
        self.generate_symbol
    }

    pub fn set_generate_symbol(&mut self, generate_symbol: bool) {
        self.generate_symbol = generate_symbol;
    }

    pub fn is_generate_fragment(&self) -> bool {
        self.generate_fragment
    }

    pub fn set_generate_fragment(&mut self, generate_fragment: bool) {
        self.generate_fragment = generate_fragment;
    }

    pub fn set_size(&mut self, size: i32) {
        self.size = size as i64;
    }

    pub fn get_size(&self) -> i64 {
        self.size
    }

    pub fn get_address_space(&self) -> Option<Arc<AddressSpace>> {
        self.space.clone()
    }

    pub fn set_address_space(&mut self, space: Arc<AddressSpace>) {
        self.space = Some(space);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    struct MockDataType {
        display_name: String,
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_display_name(&self) -> String {
            self.display_name.clone()
        }

        fn get_length(&self) -> i32 {
            self.length
        }
    }

    fn mock_dt(display_name: &str, length: i32) -> Box<dyn DataType> {
        Box::new(MockDataType {
            display_name: display_name.to_string(),
            length,
        })
    }

    #[test]
    fn new_uses_display_name_and_length_without_symbol() {
        let d = DumpData::new(0x100, mock_dt("dword", 4));
        assert_eq!(d.get_offset(), 0x100);
        assert_eq!(d.get_name(), "dword");
        assert_eq!(d.get_size(), 4);
        assert!(!d.is_generate_symbol());
        assert!(d.is_generate_fragment());
        assert_eq!(d.get_data_type().unwrap().get_display_name(), "dword");
    }

    #[test]
    fn with_name_generates_symbol_and_fragment() {
        let d = DumpData::with_name(0x200, mock_dt("dword", 4), "myField".to_string());
        assert_eq!(d.get_name(), "myField");
        assert_eq!(d.get_size(), 4);
        assert!(d.is_generate_symbol());
        assert!(d.is_generate_fragment());
    }

    #[test]
    fn with_options_honors_explicit_flags() {
        let d = DumpData::with_options(
            0x300,
            mock_dt("qword", 8),
            "explicit".to_string(),
            false,
            false,
        );
        assert_eq!(d.get_name(), "explicit");
        assert_eq!(d.get_size(), 8);
        assert!(!d.is_generate_symbol());
        assert!(!d.is_generate_fragment());
    }

    #[test]
    fn sized_has_no_data_type() {
        let d = DumpData::sized(0x400, "raw".to_string(), 16);
        assert!(d.get_data_type().is_none());
        assert_eq!(d.get_name(), "raw");
        assert_eq!(d.get_size(), 16);
        assert!(d.is_generate_symbol());
        assert!(d.is_generate_fragment());
    }

    #[test]
    fn setters_update_fields() {
        let mut d = DumpData::sized(0, String::new(), 0);
        d.set_offset(0x10);
        d.set_name("renamed".to_string());
        d.set_generate_symbol(true);
        d.set_generate_fragment(false);
        d.set_size(32);
        d.set_data_type(mock_dt("word", 2));

        assert_eq!(d.get_offset(), 0x10);
        assert_eq!(d.get_name(), "renamed");
        assert!(d.is_generate_symbol());
        assert!(!d.is_generate_fragment());
        assert_eq!(d.get_size(), 32);
        assert_eq!(d.get_data_type().unwrap().get_display_name(), "word");
    }

    #[test]
    fn address_space_defaults_to_none_and_can_be_set() {
        let mut d = DumpData::sized(0, String::new(), 0);
        assert!(d.get_address_space().is_none());

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        d.set_address_space(space.clone());
        assert_eq!(d.get_address_space().unwrap().get_name(), "ram");
    }
}
