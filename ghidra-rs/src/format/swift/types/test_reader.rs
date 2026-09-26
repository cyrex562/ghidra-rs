//! Test-only in-memory [`BinaryReader`] shared by the Swift type-metadata structure tests.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::GByteStore;

struct VecStore(Vec<u8>);

impl GByteStore for VecStore {
    fn length(&mut self) -> io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn is_valid_index(&mut self, index: u64) -> bool {
        index < self.0.len() as u64
    }
    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        self.0
            .get(index as usize)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"))
    }
    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        let start = index as usize;
        let end = start + length;
        if end > self.0.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end"));
        }
        Ok(self.0[start..end].to_vec())
    }
    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
    }
    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
    }
}

/// Little-endian reader over a byte vector.
pub(crate) struct VecReader {
    store: Rc<RefCell<VecStore>>,
    index: u64,
    little_endian: bool,
}

impl VecReader {
    /// A little-endian reader positioned at `index` over `bytes`.
    pub(crate) fn new(bytes: Vec<u8>, index: u64) -> Self {
        VecReader { store: Rc::new(RefCell::new(VecStore(bytes))), index, little_endian: true }
    }
}

impl BinaryReader for VecReader {
    fn length(&self) -> io::Result<u64> {
        self.store.borrow_mut().length()
    }
    fn is_valid_index(&self, index: u64) -> bool {
        self.store.borrow_mut().is_valid_index(index)
    }
    fn get_pointer_index(&self) -> u64 {
        self.index
    }
    fn set_pointer_index(&mut self, index: u64) -> u64 {
        std::mem::replace(&mut self.index, index)
    }
    fn is_little_endian(&self) -> bool {
        self.little_endian
    }
    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.little_endian = is_little_endian;
    }
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.store.borrow_mut().read_byte(index)
    }
    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        self.store.borrow_mut().read_bytes(index, n_elements)
    }
    fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
        self.store.clone()
    }
    fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
        Box::new(VecReader {
            store: self.store.clone(),
            index: new_index,
            little_endian: self.little_endian,
        })
    }
}
