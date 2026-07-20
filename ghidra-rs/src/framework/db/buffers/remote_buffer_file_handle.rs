use std::io;

use crate::framework::db::buffers::BufferFileHandle;

/// Facilitates access to a remote `BufferFile` via RMI.
///
/// Mirrors `db.buffers.RemoteBufferFileHandle`. In Java this interface re-declares every method
/// of [`BufferFileHandle`] verbatim; that re-declaration exists only so the JDK's RMI stub
/// generator marshals each method for remote invocation (a quirk of
/// `RemoteObjectInvocationHandler` since OpenJDK 11.0.6). Rust has no RMI layer and
/// [`BufferFileHandle`]'s methods already return `io::Result` for every operation, so there is no
/// distinct signature to restate here: `RemoteBufferFileHandle` is declared as a supertrait-bound
/// marker, and every `BufferFileHandle` method remains reachable through it unchanged.
pub trait RemoteBufferFileHandle: BufferFileHandle {}

/// Blanket impl: any local `BufferFileHandle` is usable wherever a remote handle is expected,
/// mirroring how the Java interface adds no behavior beyond `BufferFileHandle` itself.
impl<T: BufferFileHandle + ?Sized> RemoteBufferFileHandle for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;
    use crate::framework::db::buffers::{BlockStreamHandle, InputBlockStream, OutputBlockStream};
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

    /// Stands in for a remote buffer-file connection: every operation is `Ok`, mirroring what an
    /// RMI stub would report for a healthy connection.
    struct MockRemoteBufferFileHandle {
        read_only: bool,
    }

    impl BufferFileHandle for MockRemoteBufferFileHandle {
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
    fn test_remote_buffer_file_handle_object_safety() {
        // Proves RemoteBufferFileHandle is object-safe and that a local handle automatically
        // satisfies the "remote" trait, exercising real behavior through every method reachable
        // via the supertrait bound.
        let handle: Box<dyn RemoteBufferFileHandle> =
            Box::new(MockRemoteBufferFileHandle { read_only: false });

        assert!(!handle.is_read_only().unwrap());
        assert!(handle.set_read_only().unwrap());
        assert!(handle.get_parameter("missing").is_err());
        assert!(handle.get_buffer_size().unwrap() == 4096);
        assert_eq!(handle.get_index_count().unwrap(), 0);
        assert!(handle.get_free_indexes().unwrap().is_empty());
        assert!(handle.set_free_indexes(&[1, 2]).is_ok());

        let buf = handle.get(7).unwrap();
        assert_eq!(buf.get_id(), 7);
        assert!(handle.put(&buf, 7).is_ok());

        assert!(handle.get_input_block_stream().is_ok());
        assert!(handle.get_output_block_stream(1).is_ok());
        assert!(handle.get_input_block_stream_handle().is_ok());
        assert!(handle.get_output_block_stream_handle(1).is_ok());

        assert!(handle.delete().unwrap());
        assert!(handle.dispose().is_ok());
        assert!(handle.close().is_ok());
    }
}
