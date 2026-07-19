use std::io;

use crate::framework::db::buffer::DataBuffer;
use crate::framework::db::buffers::{BlockStreamHandle, InputBlockStream, OutputBlockStream};

/// Facilitates access to a `BufferFile`.
///
/// Mirrors `db.buffers.BufferFileHandle`. Implementations may be remote (RMI) handles, so every
/// method is declared to return `io::Result` even where the corresponding `BufferFile` method
/// does not (e.g. `is_read_only`, `get_free_indexes`).
pub trait BufferFileHandle {
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

    /// See `BufferFile::get(buf, index)`.
    fn get(&self, index: i32) -> io::Result<DataBuffer>;

    /// See `BufferFile::put(buf, index)`.
    fn put(&self, buf: &DataBuffer, index: i32) -> io::Result<()>;

    /// See `BufferFile::dispose()`.
    fn dispose(&self) -> io::Result<()>;

    /// Provides local access to an input block stream. This method should only be used if the
    /// associated `BufferFileAdapter::is_remote()` is `false`.
    fn get_input_block_stream(&self) -> io::Result<Box<dyn InputBlockStream>>;

    /// Provides local access to an output block stream. This method should only be used if the
    /// associated `BufferFileAdapter::is_remote()` is `false`.
    fn get_output_block_stream(&self, block_count: i32)
        -> io::Result<Box<dyn OutputBlockStream>>;

    /// Get an input block stream handle which will facilitate access to a remote
    /// `InputBlockStream`. The handle will facilitate use of a remote streaming interface. This
    /// method should only be used if the associated `BufferFileAdapter::is_remote()` is `true`.
    fn get_input_block_stream_handle(&self) -> io::Result<Box<dyn BlockStreamHandle>>;

    /// Get an output block stream handle which will facilitate access to a remote
    /// `OutputBlockStream`. The handle will facilitate use of a remote streaming interface. This
    /// method should only be used if the associated `BufferFileAdapter::is_remote()` is `true`.
    fn get_output_block_stream_handle(
        &self,
        block_count: i32,
    ) -> io::Result<Box<dyn BlockStreamHandle>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffers::BlockStream;
    use crate::framework::seam_stubs::BufferFileBlock;
    use crate::util::task::TaskMonitor;

    struct MockBlockStream;

    impl BlockStream for MockBlockStream {
        fn get_block_size(&self) -> usize {
            4096
        }

        fn get_block_count(&self) -> usize {
            1
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockBlockStreamHandle;

    impl BlockStreamHandle for MockBlockStreamHandle {
        fn open_block_stream(&self, _monitor: &dyn TaskMonitor) -> io::Result<Box<dyn BlockStream>> {
            Ok(Box::new(MockBlockStream))
        }
    }

    struct MockInputBlockStream;

    impl BlockStream for MockInputBlockStream {
        fn get_block_size(&self) -> usize {
            4096
        }

        fn get_block_count(&self) -> usize {
            1
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl InputBlockStream for MockInputBlockStream {
        fn read_block(&mut self) -> io::Result<Option<Box<dyn BufferFileBlock>>> {
            Ok(None)
        }

        fn includes_header_block(&self) -> bool {
            true
        }
    }

    struct MockOutputBlockStream;

    impl BlockStream for MockOutputBlockStream {
        fn get_block_size(&self) -> usize {
            4096
        }

        fn get_block_count(&self) -> usize {
            1
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl OutputBlockStream for MockOutputBlockStream {
        fn write_block(&mut self, _block: Box<dyn BufferFileBlock>) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockBufferFileHandle {
        read_only: bool,
    }

    impl BufferFileHandle for MockBufferFileHandle {
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
            Ok(true)
        }

        fn get(&self, index: i32) -> io::Result<DataBuffer> {
            Ok(DataBuffer::from_data(index, vec![0u8; 4]))
        }

        fn put(&self, _buf: &DataBuffer, _index: i32) -> io::Result<()> {
            Ok(())
        }

        fn dispose(&self) -> io::Result<()> {
            Ok(())
        }

        fn get_input_block_stream(&self) -> io::Result<Box<dyn InputBlockStream>> {
            Ok(Box::new(MockInputBlockStream))
        }

        fn get_output_block_stream(
            &self,
            _block_count: i32,
        ) -> io::Result<Box<dyn OutputBlockStream>> {
            Ok(Box::new(MockOutputBlockStream))
        }

        fn get_input_block_stream_handle(&self) -> io::Result<Box<dyn BlockStreamHandle>> {
            Ok(Box::new(MockBlockStreamHandle))
        }

        fn get_output_block_stream_handle(
            &self,
            _block_count: i32,
        ) -> io::Result<Box<dyn BlockStreamHandle>> {
            Ok(Box::new(MockBlockStreamHandle))
        }
    }

    #[test]
    fn test_buffer_file_handle_object_safety() {
        let handle: Box<dyn BufferFileHandle> = Box::new(MockBufferFileHandle { read_only: false });

        assert!(!handle.is_read_only().unwrap());
        assert!(handle.set_read_only().unwrap());
        assert!(handle.get_parameter("x").is_err());
        assert!(handle.get_buffer_size().unwrap() == 4096);
        assert!(handle.get_input_block_stream().is_ok());
        assert!(handle.get_output_block_stream(1).is_ok());
        assert!(handle.get_input_block_stream_handle().is_ok());
        assert!(handle.get_output_block_stream_handle(1).is_ok());
    }
}
