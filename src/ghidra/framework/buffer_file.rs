pub trait BufferFile {
    /// returns true if the file cannot be modified via the buffer put method
    fn is_read_only(&self) -> bool;
    /// if the file is open read-write the modified contents are flushed and the file is re-opened read-only. this function is also used to commit a new version if the file has been modified for update
    /// returns true if successfully transitioned from read-write to read-only
    fn set_read_only(&mut self) -> bool;
    /// get a stored value for a named parameter
    /// returns an integer value
    fn get_parameter(&self, name: &String) -> u32;
    /// set a named parameter
    fn set_parameter(&mut self, name: &String, value: u32);
    /// delete all named parameters
    fn clear_parameters(&mut self);
    /// get a list of all parameter names
    fn get_parameter_names(&self) -> Vec<String>;
    /// return the actual size of a user data buffer. Should be used when constructing DataBuffer objects
    fn get_buffer_size(&self) -> isize;
    /// returns the number of allocated buffer indexes. When a new buffer is allocated, and the file size grows, the buffer will remain allocated although it may be added to the list of free-indexes. A file will never shrink in size due to this permanent allocation.
    fn get_index_count(&self) -> isize;
    /// returns the list of free indexes sored by value. The management of the free-index-list is implementation specific.
    fn get_free_indexes(&self) -> Vec<isize>;
    /// sets the list of free buffer indexes
    fn set_free_indexes(&mut self, indexes: &[isize]);
    /// close the buffer file. if the file was open for write access, all buffers are flushed and the fiel header updated. once closed, this object is immediately disposed and may no longer be used.
    fn close(&mut self);
    /// delete this buffer file if writeable. Once deleted, this object is immediately disposed and may no longer be used.
    fn delete(&mut self) -> bool;
    /// dispose of this buffer file object. if file is not readonly and has not been closed, an attempt will be made to delete the associated file(s). Once disposed, it may no longer be used.
    fn dispose(&mut self);
    /// get the specified buffer.
    fn get(&self, buf: &DataBuffer, index: isize) -> DataBuffer;
    /// store a data buffer at the specified index
    fn put(&self, buf: &DataBuffer, index: isize);

}
