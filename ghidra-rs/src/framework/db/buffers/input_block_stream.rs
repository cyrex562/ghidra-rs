use std::io;

use crate::framework::db::buffers::BlockStream;
use crate::framework::seam_stubs::BufferFileBlock;

/// A `BufferFile` input block stream.
///
/// Mirrors `db.buffers.InputBlockStream`. The nature of the stream and the block sequence is
/// determined by the particular instance. `BufferFileBlock` is not yet ported, so `readBlock`
/// returns a boxed [`BufferFileBlock`] placeholder trait object to keep this trait object-safe.
pub trait InputBlockStream: BlockStream {
    /// Read next block from stream.
    ///
    /// Returns `None` if no more blocks are available.
    fn read_block(&mut self) -> io::Result<Option<Box<dyn BufferFileBlock>>>;

    /// Determine if header block included in stream. Some stream implementations do not include
    /// or don't have access to the buffer file header block and may be excluded. If header is
    /// required, it will need to be reconstructed by setting the free index list and all buffer
    /// file parameters.
    fn includes_header_block(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBufferFileBlock;

    impl BufferFileBlock for MockBufferFileBlock {}

    struct MockInputBlockStream {
        blocks_remaining: usize,
    }

    impl BlockStream for MockInputBlockStream {
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

    #[test]
    fn test_input_block_stream_object_safety() {
        let mut stream: Box<dyn InputBlockStream> =
            Box::new(MockInputBlockStream { blocks_remaining: 1 });

        assert_eq!(stream.get_block_count(), 10);
        assert!(stream.includes_header_block());
        assert!(stream.read_block().unwrap().is_some());
        assert!(stream.read_block().unwrap().is_none());
    }
}
