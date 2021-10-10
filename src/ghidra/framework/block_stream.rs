use crate::ghidra::closeable::Closeable;

pub trait Blockstream: Closeable {
    // get the raw block size
    fn get_block_size() -> isize;
    // get the number of blocks to be transferred
    fn get_block_count() -> isize;
}
