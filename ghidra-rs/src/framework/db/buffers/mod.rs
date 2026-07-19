use crate::framework::db::buffer::DataBuffer;
pub mod block_stream;
pub mod block_stream_handle;
pub mod buffer_file_adapter;
pub mod buffer_file_handle;
pub mod buffer_file_manager;
pub mod input_block_stream;
pub mod local_buffer_file;
pub mod managed_buffer_file;
pub mod output_block_stream;
pub use block_stream::BlockStream;
pub use block_stream_handle::BlockStreamHandle;
pub use buffer_file_adapter::BufferFileAdapter;
pub use buffer_file_handle::BufferFileHandle;
pub use buffer_file_manager::BufferFileManager;
pub use input_block_stream::InputBlockStream;
pub use local_buffer_file::LocalBufferFile;
pub use managed_buffer_file::ManagedBufferFile;
pub use output_block_stream::OutputBlockStream;

use std::io;

pub trait BufferFile {
    fn is_read_only(&self) -> bool;
    fn set_read_only(&mut self) -> io::Result<bool>;

    fn get_buffer_size(&self) -> usize;
    fn get_index_count(&self) -> usize;
    fn get_free_indexes(&self) -> Vec<i32>;
    fn set_free_indexes(&mut self, indexes: &[i32]) -> io::Result<()>;

    fn get_parameter(&self, name: &str) -> Option<i32>;
    fn set_parameter(&mut self, name: &str, value: i32);
    fn get_parameter_names(&self) -> Vec<String>;

    fn get(&self, index: i32) -> io::Result<DataBuffer>;
    fn put(&mut self, buf: &DataBuffer, index: i32) -> io::Result<()>;

    fn close(&mut self) -> io::Result<()>;
    fn delete(&mut self) -> io::Result<bool>;
}
