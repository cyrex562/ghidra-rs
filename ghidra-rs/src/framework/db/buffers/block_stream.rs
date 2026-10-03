use std::io;

/// A `BufferFile` block stream.
///
/// Mirrors `db.buffers.BlockStream`, which extends `java.io.Closeable`; `close` is folded into
/// this trait so implementors (and callers holding a `Box<dyn BlockStream>`) don't need a second
/// supertrait.
pub trait BlockStream {
    /// Get the raw block size.
    fn get_block_size(&self) -> usize;

    /// Get the number of blocks to be transferred.
    fn get_block_count(&self) -> usize;

    /// Close the block stream, releasing any underlying resources.
    fn close(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBlockStream {
        block_size: usize,
        block_count: usize,
        closed: bool,
    }

    impl BlockStream for MockBlockStream {
        fn get_block_size(&self) -> usize {
            self.block_size
        }

        fn get_block_count(&self) -> usize {
            self.block_count
        }

        fn close(&mut self) -> io::Result<()> {
            self.closed = true;
            Ok(())
        }
    }

    #[test]
    fn test_block_stream_object_safety() {
        let mut stream: Box<dyn BlockStream> =
            Box::new(MockBlockStream { block_size: 4096, block_count: 10, closed: false });

        assert_eq!(stream.get_block_size(), 4096);
        assert_eq!(stream.get_block_count(), 10);
        assert!(stream.close().is_ok());
    }
}
