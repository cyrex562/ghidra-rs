use crate::ghidra::framework::block_stream::Blockstream;

pub trait BlockstreamHandle: Blockstream {
    /// inovked by the client to establish the remote connection and return the opened block stream
    /// returnes the connected/open block stream
    fn open_block_stream<T>() -> T;
}
