use crate::ghidra::framework::buffer_file::BufferFile;
use crate::ghidra::framework::buffer_file_handle::BufferFileHandle;
use crate::ghidra::framework::data_buffer::DataBuffer;

#[derive(Clone,Debug,Default)]
pub struct BufferFileAdapter {
    pub buffer_file_handle: BufferFileHandle,
}

impl BufferFileAdapter {
    pub fn new(remote_buffer_file: &BufferFileHandle) -> BufferFileAdapter {
        BufferFileAdapter {
            buffer_file_handle: remote_buffer_file.clone(),
        }
    }
}

impl BufferFile for BufferFileAdapter {
    fn is_read_only(&self) -> bool {
        self.buffer_file_handle.is_read_only()
    }

    fn set_read_only(&mut self) -> bool {
        self.buffer_file_handle.set_read_only()
    }

    fn get_parameter(&self, name: &String) -> u32 {
        self.buffer_file_handle.get_parameter(name)
    }

    fn set_parameter(&mut self, name: &String, value: u32) {
        self.buffer_file_handle.set_parameter(name, value);
    }

    fn clear_parameters(&mut self) {
        self.buffer_file_handle.clear_parameters();
    }

    fn get_parameter_names(&self) -> Vec<String>{
        self.buffer_file_handle.get_parameter_names()
    }

    fn get_buffer_size(&self) -> isize {
        self.buffer_file_handle.get_buffer_size()
    }

    fn get_index_count(&self) -> isize {
        self.buffer_file_handle.get_index_count()
    }

    fn get_free_indexes(&self) -> Vec<isize> {
        self.buffer_file_handle.get_free_indexes()
    }

    fn set_free_indexes(&mut self, indexes: &[isize]) {
        self.buffer_file_handle.set_free_indexes()
    }

    fn close(&mut self) {
        self.buffer_file_handle.close()
    }

    fn delete(&mut self) -> bool {
        self.buffer_file_handle.delete()
    }

    fn dispose(&mut self) {
        self.buffer_file_handle.dispose()
    }

    fn get(&self, buf: &DataBuffer, index: isize) -> DataBuffer {
        self.buffer_file_handle.get(buf, index)
    }

    fn put(&self, buf: &DataBuffer, index: isize) {
        self.buffer_file_handle.put(buf, index)
    }
}
