use std::io;

use crate::framework::db::buffers::BlockStream;
use crate::util::task::TaskMonitor;

/// A handle used to establish a remote [`BlockStream`] connection.
///
/// Mirrors `db.buffers.BlockStreamHandle<T extends BlockStream>`. The Java generic parameter is
/// represented here as a `Box<dyn BlockStream>` return so this trait stays object-safe (no
/// generic type parameter on the trait itself).
pub trait BlockStreamHandle {
    /// Invoked by the client to establish the remote connection and return the opened block
    /// stream.
    ///
    /// `monitor` allows cancellation of the transfer.
    fn open_block_stream(&self, monitor: &dyn TaskMonitor) -> io::Result<Box<dyn BlockStream>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBlockStream;

    impl BlockStream for MockBlockStream {
        fn get_block_size(&self) -> usize {
            4096
        }

        fn get_block_count(&self) -> usize {
            10
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

    #[test]
    fn test_block_stream_handle_object_safety() {
        use crate::util::task::DummyMonitor;

        let handle: Box<dyn BlockStreamHandle> = Box::new(MockBlockStreamHandle);
        let monitor = DummyMonitor;

        let stream = handle.open_block_stream(&monitor).unwrap();
        assert_eq!(stream.get_block_size(), 4096);
        assert_eq!(stream.get_block_count(), 10);
    }
}
