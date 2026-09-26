//! Test fixtures for the structure mapping framework: a byte-array reader, a program whose
//! data type manager holds hand-built Go structures, and simple data types.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::format::elf::info::elf_info_item::ProviderBinaryReader;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;
use crate::program::model::listing::Program;

use super::data_type_mapper::DataTypeMapper;
use super::data_type_mapper_context::DataTypeMapperContext;

struct VecStore(Vec<u8>);

impl GByteStore for VecStore {
    fn length(&mut self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn is_valid_index(&mut self, index: u64) -> bool {
        (index as usize) < self.0.len()
    }
    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        self.0
            .get(index as usize)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "past end"))
    }
    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        let start = index as usize;
        self.0
            .get(start..start + length)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "past end"))
    }
    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// A reader over `bytes`, positioned at 0.
pub fn byte_reader(bytes: Vec<u8>, little_endian: bool) -> Box<dyn BinaryReader> {
    Box::new(ProviderBinaryReader::new(Rc::new(RefCell::new(VecStore(bytes))), little_endian))
}

/// A plain fixed-length data type (an integer, for the tests' purposes).
#[derive(Clone)]
pub struct SimpleDataType {
    pub name: &'static str,
    pub length: i32,
}

impl DataType for SimpleDataType {
    fn get_name(&self) -> String {
        self.name.to_string()
    }
    fn get_length(&self) -> i32 {
        self.length
    }
    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.name == dt.get_name() && self.length == dt.get_length()
    }
    fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(self.clone())
    }
    fn copy_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(self.clone())
    }
}

/// `SimpleDataType` in a box.
pub fn simple(name: &'static str, length: i32) -> Box<dyn DataType> {
    Box::new(SimpleDataType { name, length })
}

/// A structure named `name` with the given `(field name, data type)` components.
pub fn structure(name: &str, fields: Vec<(&str, Box<dyn DataType>)>) -> StructureDataTypeImpl {
    let mut s = StructureDataTypeImpl::new(name, 0);
    for (field_name, dt) in fields {
        crate::program::model::data::composite::Composite::add_with_name(
            &mut s,
            dt,
            Some(field_name.to_string()),
            None,
        )
        .expect("add field");
    }
    s
}

/// The data types a [`TestDtm`] serves, shared by every handle to it.
pub type TypeStore = Arc<Mutex<Vec<Arc<dyn Fn() -> Box<dyn DataType> + Send + Sync>>>>;

/// A data type manager that finds data types by name in the root category.
pub struct TestDtm {
    types: TypeStore,
}

impl DataTypeManager for TestDtm {
    fn get_data_type_in_category(&self, path: &CategoryPath, name: &str) -> Option<Box<dyn DataType>> {
        if !path.is_root() {
            return None;
        }
        let types = self.types.lock().unwrap();
        types.iter().map(|f| f()).find(|dt| dt.get_name() == name)
    }
}

/// A program with an image base in a 64-bit `ram` space and a [`TestDtm`].
pub struct TestProgram {
    space: Arc<AddressSpace>,
    types: TypeStore,
}

impl crate::framework::model::DomainObject for TestProgram {}

impl Program for TestProgram {
    fn get_name(&self) -> String {
        "structmapping-test".to_string()
    }
    fn get_language_id(&self) -> String {
        "test:LE:64:default".to_string()
    }
    fn get_image_base(&self) -> Option<Address> {
        Some(Address::new(self.space.clone(), 0))
    }
    fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        Some(Box::new(TestDtm { types: self.types.clone() }))
    }
}

/// Registers a data type factory with a program built by [`test_program`].
pub fn add_type(types: &TypeStore, f: impl Fn() -> Box<dyn DataType> + Send + Sync + 'static) {
    types.lock().unwrap().push(Arc::new(f));
}

/// A program holding the data types built by `types`, plus a handle to add more.
pub fn test_program(types: Vec<Arc<dyn Fn() -> Box<dyn DataType> + Send + Sync>>) -> (Arc<dyn Program>, TypeStore) {
    let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1);
    let store: TypeStore = Arc::new(Mutex::new(types));
    let program: Arc<dyn Program> = Arc::new(TestProgram { space, types: store.clone() });
    (program, store)
}

/// A mapper over [`test_program`] that searches the root category.
pub fn test_mapper(types: Vec<Arc<dyn Fn() -> Box<dyn DataType> + Send + Sync>>) -> DataTypeMapper {
    let (program, _) = test_program(types);
    let mut mapper = DataTypeMapper::new(program, None).expect("mapper");
    mapper.add_program_search_category_path(&[crate::program::model::data::category_path::ROOT.clone()]);
    mapper
}

/// A [`DataTypeMapperContext`] that treats `presentWhen` strings as a set of enabled tags;
/// the empty string is always present.
pub struct TagContext(pub Vec<&'static str>);

impl DataTypeMapperContext for TagContext {
    fn is_field_present(&self, present_when: &str) -> bool {
        present_when.is_empty() || self.0.contains(&present_when)
    }
}
