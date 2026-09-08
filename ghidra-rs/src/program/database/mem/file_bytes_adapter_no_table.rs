//! Port of the class `ghidra.program.database.mem.FileBytesAdapterNoTable`.
//!
//! Stand-in `FileBytesAdapter` used to access older databases (predating the "File Bytes" table)
//! for read-only and upgrade purposes: there is no table to read, so every query returns empty/
//! `None`/`false`, and the only mutating method (`create_file_bytes`) is unsupported. Mirrors
//! `ghidra.program.database.mem.FileBytesAdapterNoTable` field-for-field (it has none) and
//! method-for-method.

use std::io;
use std::sync::Arc;

use crate::framework::db::DBBuffer;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::file_bytes_adapter::{FileBytesAdapter, FileBytesAdapterError};
use crate::util::task::TaskMonitor;

/// Stand-in `FileBytesAdapter` used when no "File Bytes" table exists yet. Mirrors
/// `ghidra.program.database.mem.FileBytesAdapterNoTable`.
#[derive(Default)]
pub struct FileBytesAdapterNoTable;

impl FileBytesAdapterNoTable {
    /// Mirrors `FileBytesAdapterNoTable(DBHandle)`. Takes no handle since this adapter never
    /// touches the database (there is no table to touch).
    pub fn new() -> Self {
        Self
    }
}

impl FileBytesAdapter for FileBytesAdapterNoTable {
    fn create_file_bytes(
        &mut self,
        _filename: &str,
        _offset: i64,
        _size: i64,
        _is: &mut dyn io::Read,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn FileBytes>, FileBytesAdapterError> {
        // Mirrors Java's `throw new UnsupportedOperationException()`.
        Err(FileBytesAdapterError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "FileBytesAdapterNoTable does not support creating file bytes",
        )))
    }

    fn get_buffer(&self, _buffer_id: i32) -> io::Result<Option<Box<dyn DBBuffer>>> {
        // Mirrors `getBuffer(int)` returning `null` unconditionally.
        Ok(None)
    }

    fn get_buffer_with_shadow(
        &self,
        _buffer_id: i32,
        _shadow_buffer: Box<dyn DBBuffer>,
    ) -> io::Result<Option<Box<dyn DBBuffer>>> {
        Ok(None)
    }

    fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
        Vec::new()
    }

    fn refresh(&mut self) -> io::Result<()> {
        // Mirrors `refresh()` doing nothing.
        Ok(())
    }

    fn delete_file_bytes(&mut self, _file_bytes: &Arc<dyn FileBytes>) -> io::Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn create_file_bytes_is_unsupported() {
        let mut adapter = FileBytesAdapterNoTable::new();
        let mut reader: &[u8] = &[1, 2, 3];
        let monitor = DummyMonitor;
        let result = adapter.create_file_bytes("a.bin", 0, 3, &mut reader, &monitor);
        match result {
            Err(FileBytesAdapterError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            other => panic!("expected Unsupported io error, got {}", other.is_ok()),
        }
    }

    #[test]
    fn get_buffer_always_returns_none() {
        let adapter = FileBytesAdapterNoTable::new();
        assert!(adapter.get_buffer(0).unwrap().is_none());
        assert!(adapter.get_buffer(-1).unwrap().is_none());
    }

    #[test]
    fn get_all_file_bytes_is_always_empty() {
        let adapter = FileBytesAdapterNoTable::new();
        assert!(adapter.get_all_file_bytes().is_empty());
    }

    #[test]
    fn refresh_is_a_no_op() {
        let mut adapter = FileBytesAdapterNoTable::new();
        assert!(adapter.refresh().is_ok());
    }

    #[test]
    fn delete_file_bytes_always_reports_not_found() {
        let mut adapter = FileBytesAdapterNoTable::new();
        struct Dummy;
        impl FileBytes for Dummy {
            fn get_filename(&self) -> &str {
                "x"
            }
            fn get_file_offset(&self) -> i64 {
                0
            }
            fn get_size(&self) -> i64 {
                0
            }
            fn get_modified_byte(&self, _offset: i64) -> Result<u8, crate::program::database::mem::file_bytes::FileBytesError> {
                unimplemented!()
            }
            fn get_original_byte(&self, _offset: i64) -> Result<u8, crate::program::database::mem::file_bytes::FileBytesError> {
                unimplemented!()
            }
            fn get_modified_bytes_range(&self, _o: i64, _b: &mut [u8], _off: usize, _l: usize) -> Result<usize, crate::program::database::mem::file_bytes::FileBytesError> {
                unimplemented!()
            }
            fn get_original_bytes_range(&self, _o: i64, _b: &mut [u8], _off: usize, _l: usize) -> Result<usize, crate::program::database::mem::file_bytes::FileBytesError> {
                unimplemented!()
            }
            fn put_byte(&self, _o: i64, _b: u8) -> Result<(), crate::program::database::mem::file_bytes::FileBytesError> {
                unimplemented!()
            }
            fn put_bytes_range(&self, _o: i64, _b: &[u8], _off: usize, _l: usize) -> Result<usize, crate::program::database::mem::file_bytes::FileBytesError> {
                unimplemented!()
            }
        }
        let fb: Arc<dyn FileBytes> = Arc::new(Dummy);
        assert!(!adapter.delete_file_bytes(&fb).unwrap());
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut adapter: Box<dyn FileBytesAdapter> = Box::new(FileBytesAdapterNoTable::new());
        assert!(adapter.refresh().is_ok());
        assert!(adapter.get_all_file_bytes().is_empty());
    }
}
