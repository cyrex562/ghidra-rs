use crate::ghidra::framework::buffer_file::BufferFile;

#[derive(Clone,Debug,Default)]
pub struct BufferFileHandle {

}

impl BufferFile for BufferFileHandle {
    fn is_read_only(&self) -> bool {
        todo!()
    }

    fn set_read_only(&mut self) -> bool {
        todo!()
    }

    fn get_parameter(&self, name: &String) -> u32 {
        todo!()
    }

    fn set_parameter(&mut self, name: &String, value: u32) {
        todo!()
    }

    fn clear_parameters(&mut self) {
        todo!()
    }

    fn get_parameter_names(&self) -> Vec<String> {
        todo!()
    }

    fn get_buffer_size(&self) -> isize {
        todo!()
    }

    fn get_index_count(&self) -> isize {
        todo!()
    }

    fn get_free_indexes(&self) -> Vec<isize> {
        todo!()
    }

    fn set_free_indexes(&mut self, indexes: &[isize]) {
        todo!()
    }

    fn close(&mut self) {
        todo!()
    }

    fn delete(&mut self) -> bool {
        todo!()
    }

    fn dispose(&mut self) {
        todo!()
    }

    fn get(&self, buf: &DataBuffer, index: isize) -> DataBuffer {
        todo!()
    }

    fn put(&self, buf: &DataBuffer, index: isize) {
        todo!()
    }
}
