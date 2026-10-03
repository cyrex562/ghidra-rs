use std::io;

use crate::framework::db::buffers::BlockStream;
use crate::framework::seam_stubs::BufferFileBlock;

/// A `BufferFile` output block stream.
///
/// Mirrors `db.buffers.OutputBlockStream`. The nature of the stream and the block sequence is
/// determined by the particular instance. `BufferFileBlock` is not yet ported, so `write_block`
/// takes a boxed [`BufferFileBlock`] placeholder trait object to keep this trait object-safe.
pub trait OutputBlockStream: BlockStream {
    /// Write the specified block to the corresponding BufferFile.
    ///
    /// `block` is a BufferFile block which corresponds to a specific block index.
    fn write_block(&mut self, block: Box<dyn BufferFileBlock>) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBufferFileBlock;

    impl BufferFileBlock for MockBufferFileBlock {}

    struct MockOutputBlockStream {
        blocks_written: usize,
    }

    impl BlockStream for MockOutputBlockStream {
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

    impl OutputBlockStream for MockOutputBlockStream {
        fn write_block(&mut self, _block: Box<dyn BufferFileBlock>) -> io::Result<()> {
            self.blocks_written += 1;
            Ok(())
        }
    }

    #[test]
    fn test_output_block_stream_object_safety() {
        let mut stream: Box<dyn OutputBlockStream> =
            Box::new(MockOutputBlockStream { blocks_written: 0 });

        assert_eq!(stream.get_block_count(), 10);
        assert!(stream.write_block(Box::new(MockBufferFileBlock)).is_ok());
    }
}
