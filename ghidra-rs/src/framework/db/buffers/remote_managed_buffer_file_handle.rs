use std::io;

use crate::framework::db::buffers::ManagedBufferFileHandle;

/// Facilitates access to a `ManagedBufferFile` via RMI.
///
/// Mirrors `db.buffers.RemoteManagedBufferFileHandle`. In Java this interface re-declares every
/// method of both [`BufferFileHandle`](crate::framework::db::buffers::BufferFileHandle) and
/// [`ManagedBufferFileHandle`] verbatim; that re-declaration exists only so the JDK's RMI stub
/// generator marshals each method for remote invocation (a quirk of
/// `RemoteObjectInvocationHandler` since OpenJDK 11.0.6). Rust has no RMI layer and
/// [`ManagedBufferFileHandle`]'s methods already return `io::Result` for every operation, so there
/// is no distinct signature to restate here: `RemoteManagedBufferFileHandle` is declared as a
/// supertrait-bound marker, and every `ManagedBufferFileHandle` (and `BufferFileHandle`) method
/// remains reachable through it unchanged.
pub trait RemoteManagedBufferFileHandle: ManagedBufferFileHandle {}

/// Blanket impl: any local `ManagedBufferFileHandle` is usable wherever a remote handle is
/// expected, mirroring how the Java interface adds no behavior beyond `ManagedBufferFileHandle`
/// itself.
impl<T: ManagedBufferFileHandle + ?Sized> RemoteManagedBufferFileHandle for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;
    use crate::framework::db::buffers::{
        BlockStreamHandle, BufferFileHandle, InputBlockStream, OutputBlockStream,
    };
    use crate::framework::seam_stubs::BufferFileBlock;
    use crate::util::task::TaskMonitor;

    struct MockBlockStream;

    impl crate::framework::db::buffers::BlockStream for MockBlockStream {
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
        fn open_block_stream(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<Box<dyn crate::framework::db::buffers::BlockStream>> {
            Ok(Box::new(MockBlockStream))
        }
    }

    struct MockInputBlockStream;

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
            Ok(None)
        }

        fn includes_header_block(&self) -> bool {
            true
        }
    }

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

    /// Stands in for a remote managed-buffer-file connection: every operation is `Ok`, mirroring
    /// what an RMI stub would report for a healthy connection.
    struct MockRemoteManagedBufferFileHandle {
        checkin_id: i64,
        has_save_file: bool,
    }

    impl BufferFileHandle for MockRemoteManagedBufferFileHandle {
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

    impl ManagedBufferFileHandle for MockRemoteManagedBufferFileHandle {
        fn get_save_file(&self) -> io::Result<Option<Box<dyn ManagedBufferFileHandle>>> {
            if !self.has_save_file {
                return Ok(None);
            }
            Ok(Some(Box::new(MockRemoteManagedBufferFileHandle {
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
            Ok(None)
        }

        fn get_save_change_data_file(&self) -> io::Result<Option<Box<dyn BufferFileHandle>>> {
            Ok(None)
        }

        fn get_checkin_id(&self) -> io::Result<i64> {
            Ok(self.checkin_id)
        }

        fn get_forward_mod_map_data(&self, _old_version: i32) -> io::Result<Vec<u8>> {
            Ok(vec![0xAB, 0xCD])
        }

        fn get_input_block_stream(
            &self,
            _change_map_data: &[u8],
        ) -> io::Result<Box<dyn InputBlockStream>> {
            Ok(Box::new(MockInputBlockStream))
        }

        fn get_input_block_stream_handle(
            &self,
            _change_map_data: &[u8],
        ) -> io::Result<Box<dyn BlockStreamHandle>> {
            Ok(Box::new(MockBlockStreamHandle))
        }
    }

    #[test]
    fn test_remote_managed_buffer_file_handle_object_safety() {
        // Proves RemoteManagedBufferFileHandle is object-safe and that a local
        // ManagedBufferFileHandle automatically satisfies the "remote" trait, exercising real
        // behavior through methods reachable via both supertrait bounds.
        let handle: Box<dyn RemoteManagedBufferFileHandle> =
            Box::new(MockRemoteManagedBufferFileHandle { checkin_id: 42, has_save_file: true });

        // ManagedBufferFileHandle-level behavior.
        assert!(handle.can_save().unwrap());
        assert_eq!(handle.get_checkin_id().unwrap(), 42);
        assert!(handle.set_version_comment("v2").is_ok());
        assert!(handle.save_completed(true).is_ok());
        assert_eq!(handle.get_forward_mod_map_data(1).unwrap(), vec![0xAB, 0xCD]);

        let save_file = handle.get_save_file().unwrap();
        assert!(save_file.is_some());
        assert!(!save_file.unwrap().can_save().unwrap());

        // BufferFileHandle-level behavior, reachable through the ManagedBufferFileHandle
        // supertrait bound.
        assert!(!handle.is_read_only().unwrap());
        assert!(handle.set_read_only().unwrap());
        assert!(handle.get_parameter("missing").is_err());
        let buf = handle.get(7).unwrap();
        assert_eq!(buf.get_id(), 7);
        assert!(handle.put(&buf, 7).is_ok());
        assert!(handle.get_input_block_stream(&[1, 2, 3]).is_ok());
        assert!(handle.get_input_block_stream_handle(&[1, 2, 3]).is_ok());
        assert!(handle.delete().unwrap());
        assert!(handle.dispose().is_ok());
        assert!(handle.close().is_ok());
    }
}
