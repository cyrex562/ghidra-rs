use std::io;

use crate::framework::db::buffers::{BufferFileAdapter, InputBlockStream, ManagedBufferFile};
use crate::util::task::TaskMonitor;

/// A `ManagedBufferFile` implementation which wraps a `ManagedBufferFileHandle`.
///
/// Mirrors `db.buffers.ManagedBufferFileAdapter`, which extends `BufferFileAdapter` and
/// implements `ManagedBufferFile`; here that relationship is expressed as a trait combining both
/// supertraits so callers can depend on "a `ManagedBufferFile`-like adapter" without needing a
/// concrete `ManagedBufferFileHandle` in scope. Implementations are expected to hold a
/// `ManagedBufferFileHandle` (or equivalent) and delegate accordingly.
pub trait ManagedBufferFileAdapter: BufferFileAdapter + ManagedBufferFile {
    /// Obtain a direct stream to read modified blocks of this buffer file based upon the
    /// specified change map.
    ///
    /// Mirrors the package-private `ManagedBufferFileAdapter.getInputBlockStream(byte[],
    /// TaskMonitor)`, which dispatches to a remote streaming handle when the wrapped handle is
    /// remote, or reads directly otherwise; implementations should apply the same
    /// `is_remote()`-driven dispatch themselves. This shadows the single-argument
    /// `BufferFileAdapter::get_input_block_stream`, which streams all blocks rather than just
    /// those identified by `change_map_data`.
    fn get_input_block_stream(
        &self,
        change_map_data: &[u8],
        monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn InputBlockStream>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;
    use crate::framework::db::buffers::{BufferFile, OutputBlockStream};
    use crate::framework::seam_stubs::BufferFileBlock;
    use crate::util::task::DummyMonitor;

    struct MockInputBlockStream {
        blocks_remaining: usize,
    }

    impl crate::framework::db::buffers::BlockStream for MockInputBlockStream {
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

    impl crate::framework::db::buffers::BlockStream for MockOutputBlockStream {
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

    struct MockManagedBufferFileAdapter {
        read_only: bool,
        remote: bool,
        checkin_id: i64,
    }

    impl BufferFileAdapter for MockManagedBufferFileAdapter {
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
            Ok(Box::new(MockInputBlockStream { blocks_remaining: 2 }))
        }

        fn get_output_block_stream(
            &self,
            _block_count: i32,
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<Box<dyn OutputBlockStream>> {
            Ok(Box::new(MockOutputBlockStream))
        }
    }

    impl ManagedBufferFile for MockManagedBufferFileAdapter {
        fn get_next_change_data_file(
            &mut self,
            _get_first: bool,
        ) -> io::Result<Option<Box<dyn BufferFile>>> {
            Ok(None)
        }

        fn get_save_change_data_file(&mut self) -> io::Result<Option<Box<dyn BufferFile>>> {
            Ok(None)
        }

        fn get_forward_mod_map_data(&self, _old_version: i32) -> io::Result<Vec<u8>> {
            Ok(vec![0xAA])
        }

        fn get_save_file(&mut self) -> io::Result<Option<Box<dyn ManagedBufferFile>>> {
            Ok(None)
        }

        fn save_completed(&mut self, _commit: bool) -> io::Result<()> {
            Ok(())
        }

        fn can_save(&self) -> io::Result<bool> {
            Ok(!self.read_only)
        }

        fn set_version_comment(&mut self, _comment: &str) -> io::Result<()> {
            Ok(())
        }

        fn get_checkin_id(&self) -> io::Result<i64> {
            Ok(self.checkin_id)
        }
    }

    impl ManagedBufferFileAdapter for MockManagedBufferFileAdapter {
        fn get_input_block_stream(
            &self,
            change_map_data: &[u8],
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<Box<dyn InputBlockStream>> {
            Ok(Box::new(MockInputBlockStream { blocks_remaining: change_map_data.len() }))
        }
    }

    #[test]
    fn test_managed_buffer_file_adapter_object_safety() {
        let mut adapter: Box<dyn ManagedBufferFileAdapter> =
            Box::new(MockManagedBufferFileAdapter { read_only: false, remote: true, checkin_id: 9 });

        assert!(!adapter.is_read_only().unwrap());
        assert!(adapter.is_remote());
        assert_eq!(adapter.get_checkin_id().unwrap(), 9);
        assert!(adapter.can_save().unwrap());
        assert!(adapter.set_version_comment("v1").is_ok());
        assert!(adapter.save_completed(true).is_ok());
        assert_eq!(adapter.get_forward_mod_map_data(1).unwrap(), vec![0xAA]);
        assert!(adapter.get_save_file().unwrap().is_none());
        assert!(adapter.get_next_change_data_file(true).unwrap().is_none());
        assert!(adapter.get_save_change_data_file().unwrap().is_none());

        let monitor = DummyMonitor;

        // Adapter-specific stream, keyed by the change map.
        let mut change_stream = adapter.get_input_block_stream(&[1, 2, 3], &monitor).unwrap();
        assert!(change_stream.read_block().unwrap().is_some());
        assert!(change_stream.read_block().unwrap().is_some());
        assert!(change_stream.read_block().unwrap().is_some());
        assert!(change_stream.read_block().unwrap().is_none());

        // Shadowed supertrait method (all blocks, no change map) still reachable via UFCS.
        let mut full_stream =
            BufferFileAdapter::get_input_block_stream(&*adapter, &monitor).unwrap();
        assert!(full_stream.read_block().unwrap().is_some());
    }
}
