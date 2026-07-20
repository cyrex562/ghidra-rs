use std::io;

use crate::framework::db::buffers::{BlockStreamHandle, BufferFileHandle, InputBlockStream};

/// Facilitates access to a `ManagedBufferFile`.
///
/// Mirrors `db.buffers.ManagedBufferFileHandle`, which extends `BufferFileHandle`. Like
/// `BufferFileHandle`, implementations may be remote (RMI) handles, so every method is declared
/// to return `io::Result` and takes `&self` even where the corresponding `ManagedBufferFile`
/// method takes `&mut self`.
pub trait ManagedBufferFileHandle: BufferFileHandle {
    /// See `ManagedBufferFile::get_save_file()`.
    fn get_save_file(&self) -> io::Result<Option<Box<dyn ManagedBufferFileHandle>>>;

    /// See `ManagedBufferFile::save_completed(commit)`.
    fn save_completed(&self, commit: bool) -> io::Result<()>;

    /// See `ManagedBufferFile::can_save()`.
    fn can_save(&self) -> io::Result<bool>;

    /// See `ManagedBufferFile::set_version_comment(comment)`.
    fn set_version_comment(&self, comment: &str) -> io::Result<()>;

    /// See `ManagedBufferFile::get_next_change_data_file(get_first)`.
    fn get_next_change_data_file(
        &self,
        get_first: bool,
    ) -> io::Result<Option<Box<dyn BufferFileHandle>>>;

    /// See `ManagedBufferFile::get_save_change_data_file()`.
    fn get_save_change_data_file(&self) -> io::Result<Option<Box<dyn BufferFileHandle>>>;

    /// See `ManagedBufferFile::get_checkin_id()`.
    fn get_checkin_id(&self) -> io::Result<i64>;

    /// See `ManagedBufferFile::get_forward_mod_map_data(old_version)`.
    fn get_forward_mod_map_data(&self, old_version: i32) -> io::Result<Vec<u8>>;

    /// Provides local access to an input block stream for a given change map. This method should
    /// only be used if the associated `BufferFileAdapter::is_remote()` is `false`.
    fn get_input_block_stream(
        &self,
        change_map_data: &[u8],
    ) -> io::Result<Box<dyn InputBlockStream>>;

    /// Get an input block stream handle, for a given change map, which will facilitate access to
    /// a remote `InputBlockStream`. The handle will facilitate use of a remote streaming
    /// interface. This method should only be used if the associated
    /// `BufferFileAdapter::is_remote()` is `true`.
    fn get_input_block_stream_handle(
        &self,
        change_map_data: &[u8],
    ) -> io::Result<Box<dyn BlockStreamHandle>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;
    use crate::framework::db::buffers::{BlockStream, OutputBlockStream};
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

    struct MockInputBlockStream {
        blocks_remaining: usize,
    }

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
            if self.blocks_remaining == 0 {
                return Ok(None);
            }
            self.blocks_remaining -= 1;
            Ok(Some(Box::new(MockBufferFileBlock)))
        }

        fn includes_header_block(&self) -> bool {
            true
        }
    }

    struct MockBufferFileBlock;

    impl BufferFileBlock for MockBufferFileBlock {}

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

    struct MockBufferFileHandle;

    impl BufferFileHandle for MockBufferFileHandle {
        fn is_read_only(&self) -> io::Result<bool> {
            Ok(false)
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
            Ok(Box::new(MockInputBlockStream { blocks_remaining: 1 }))
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

    struct MockManagedBufferFileHandle {
        checkin_id: i64,
        has_save_file: bool,
    }

    impl BufferFileHandle for MockManagedBufferFileHandle {
        fn is_read_only(&self) -> io::Result<bool> {
            Ok(false)
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
            Ok(Box::new(MockInputBlockStream { blocks_remaining: 1 }))
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

    impl ManagedBufferFileHandle for MockManagedBufferFileHandle {
        fn get_save_file(&self) -> io::Result<Option<Box<dyn ManagedBufferFileHandle>>> {
            if !self.has_save_file {
                return Ok(None);
            }
            Ok(Some(Box::new(MockManagedBufferFileHandle {
                checkin_id: self.checkin_id,
                has_save_file: false,
            })))
        }

        fn save_completed(&self, _commit: bool) -> io::Result<()> {
            Ok(())
        }

        fn can_save(&self) -> io::Result<bool> {
            Ok(self.has_save_file)
        }

        fn set_version_comment(&self, _comment: &str) -> io::Result<()> {
            Ok(())
        }

        fn get_next_change_data_file(
            &self,
            _get_first: bool,
        ) -> io::Result<Option<Box<dyn BufferFileHandle>>> {
            Ok(Some(Box::new(MockBufferFileHandle)))
        }

        fn get_save_change_data_file(&self) -> io::Result<Option<Box<dyn BufferFileHandle>>> {
            Ok(None)
        }

        fn get_checkin_id(&self) -> io::Result<i64> {
            Ok(self.checkin_id)
        }

        fn get_forward_mod_map_data(&self, _old_version: i32) -> io::Result<Vec<u8>> {
            Ok(vec![0xFF, 0x00])
        }

        fn get_input_block_stream(
            &self,
            _change_map_data: &[u8],
        ) -> io::Result<Box<dyn InputBlockStream>> {
            Ok(Box::new(MockInputBlockStream { blocks_remaining: 1 }))
        }

        fn get_input_block_stream_handle(
            &self,
            _change_map_data: &[u8],
        ) -> io::Result<Box<dyn BlockStreamHandle>> {
            Ok(Box::new(MockBlockStreamHandle))
        }
    }

    #[test]
    fn test_managed_buffer_file_handle_object_safety() {
        let handle: Box<dyn ManagedBufferFileHandle> =
            Box::new(MockManagedBufferFileHandle { checkin_id: 7, has_save_file: true });

        assert!(handle.is_read_only().unwrap() == false);
        assert_eq!(handle.get_checkin_id().unwrap(), 7);
        assert!(handle.can_save().unwrap());
        assert!(handle.set_version_comment("v1").is_ok());
        assert!(handle.save_completed(true).is_ok());

        let save_file = handle.get_save_file().unwrap();
        assert!(save_file.is_some());
        let save_file = save_file.unwrap();
        assert!(!save_file.can_save().unwrap());
        assert_eq!(save_file.get_checkin_id().unwrap(), 7);

        assert!(handle.get_next_change_data_file(true).unwrap().is_some());
        assert!(handle.get_save_change_data_file().unwrap().is_none());
        assert_eq!(handle.get_forward_mod_map_data(1).unwrap(), vec![0xFF, 0x00]);

        let mut stream = handle.get_input_block_stream(&[1, 2, 3]).unwrap();
        assert!(stream.includes_header_block());
        assert!(stream.read_block().unwrap().is_some());

        assert!(handle.get_input_block_stream_handle(&[1, 2, 3]).is_ok());
    }
}
