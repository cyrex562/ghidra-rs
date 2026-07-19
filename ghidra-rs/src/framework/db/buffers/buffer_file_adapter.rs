use std::io;

use crate::framework::db::buffer::DataBuffer;
use crate::framework::db::buffers::{InputBlockStream, OutputBlockStream};
use crate::util::task::TaskMonitor;

/// A `BufferFile` implementation which wraps a `BufferFileHandle`.
///
/// Mirrors `db.buffers.BufferFileAdapter`. The Java class holds a single `BufferFileHandle` field
/// and delegates every `BufferFile` method to it; here that relationship is expressed as a trait
/// so callers can depend on "a `BufferFile`-like adapter" without needing a concrete
/// `BufferFileHandle` in scope, breaking the `BufferFile`/`BufferFileHandle` dependency cycle.
/// Implementations are expected to hold a `BufferFileHandle` (or equivalent) and delegate
/// accordingly, deciding `is_remote()` and the block-stream access path themselves.
pub trait BufferFileAdapter {
    /// See `BufferFile::is_read_only()`.
    fn is_read_only(&self) -> io::Result<bool>;

    /// See `BufferFile::set_read_only()`.
    fn set_read_only(&self) -> io::Result<bool>;

    /// See `BufferFile::get_parameter(name)`.
    fn get_parameter(&self, name: &str) -> io::Result<i32>;

    /// See `BufferFile::set_parameter(name, value)`.
    fn set_parameter(&self, name: &str, value: i32) -> io::Result<()>;

    /// See `BufferFile::clear_parameters()`.
    fn clear_parameters(&self) -> io::Result<()>;

    /// See `BufferFile::get_parameter_names()`.
    fn get_parameter_names(&self) -> io::Result<Vec<String>>;

    /// See `BufferFile::get_buffer_size()`.
    fn get_buffer_size(&self) -> io::Result<usize>;

    /// See `BufferFile::get_index_count()`.
    fn get_index_count(&self) -> io::Result<usize>;

    /// See `BufferFile::get_free_indexes()`.
    fn get_free_indexes(&self) -> io::Result<Vec<i32>>;

    /// See `BufferFile::set_free_indexes(indexes)`.
    fn set_free_indexes(&self, indexes: &[i32]) -> io::Result<()>;

    /// See `BufferFile::close()`.
    fn close(&self) -> io::Result<()>;

    /// See `BufferFile::delete()`.
    fn delete(&self) -> io::Result<bool>;

    /// See `BufferFile::dispose()`. The Java implementation swallows errors raised by an
    /// already-disposed or disconnected remote handle (logging anything else); implementations
    /// should apply the same best-effort semantics.
    fn dispose(&self);

    /// See `BufferFile::get(buf, index)`. The buffer-reuse parameter from the Java signature is
    /// dropped, matching `BufferFileHandle::get`.
    fn get(&self, index: i32) -> io::Result<DataBuffer>;

    /// See `BufferFile::put(buf, index)`.
    fn put(&self, buf: &DataBuffer, index: i32) -> io::Result<()>;

    /// Determine if this file is remotely accessed.
    fn is_remote(&self) -> bool;

    /// Obtain a direct stream to read all blocks of this buffer file.
    fn get_input_block_stream(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn InputBlockStream>>;

    /// Obtain a direct stream to write blocks to this buffer file.
    ///
    /// `block_count` is the number of blocks to be written.
    fn get_output_block_stream(
        &self,
        block_count: i32,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn OutputBlockStream>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBufferFileAdapter {
        read_only: bool,
        remote: bool,
    }

    impl BufferFileAdapter for MockBufferFileAdapter {
        fn is_read_only(&self) -> io::Result<bool> {
            Ok(self.read_only)
        }

        fn set_read_only(&self) -> io::Result<bool> {
            Ok(true)
        }

        fn get_parameter(&self, _name: &str) -> io::Result<i32> {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such parameter"))
        }

        fn set_parameter(&self, _name: &str, _value: i32) -> io::Result<()> {
            Ok(())
        }

        fn clear_parameters(&self) -> io::Result<()> {
            Ok(())
        }

        fn get_parameter_names(&self) -> io::Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn get_buffer_size(&self) -> io::Result<usize> {
            Ok(4096)
        }

        fn get_index_count(&self) -> io::Result<usize> {
            Ok(0)
        }

        fn get_free_indexes(&self) -> io::Result<Vec<i32>> {
            Ok(Vec::new())
        }

        fn set_free_indexes(&self, _indexes: &[i32]) -> io::Result<()> {
            Ok(())
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }

        fn delete(&self) -> io::Result<bool> {
            Ok(!self.read_only)
        }

        fn dispose(&self) {}

        fn get(&self, index: i32) -> io::Result<DataBuffer> {
            Ok(DataBuffer::from_data(index, vec![0u8; 4]))
        }

        fn put(&self, _buf: &DataBuffer, _index: i32) -> io::Result<()> {
            Ok(())
        }

        fn is_remote(&self) -> bool {
            self.remote
        }

        fn get_input_block_stream(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<Box<dyn InputBlockStream>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "no stream"))
        }

        fn get_output_block_stream(
            &self,
            _block_count: i32,
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<Box<dyn OutputBlockStream>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "no stream"))
        }
    }

    #[test]
    fn test_buffer_file_adapter_object_safety() {
        let adapter: Box<dyn BufferFileAdapter> =
            Box::new(MockBufferFileAdapter { read_only: false, remote: true });

        assert!(!adapter.is_read_only().unwrap());
        assert!(adapter.set_read_only().unwrap());
        assert!(adapter.get_parameter("x").is_err());
        assert_eq!(adapter.get_buffer_size().unwrap(), 4096);
        assert!(adapter.is_remote());
        assert!(adapter.get(1).is_ok());
        adapter.dispose();
    }
}
