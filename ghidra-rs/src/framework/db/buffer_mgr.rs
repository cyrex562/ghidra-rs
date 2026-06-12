use super::buffer::DataBuffer;
use std::io;
use std::sync::{Arc, RwLock};

pub struct BufferMgr {
    buffer_size: usize,
    buffers: Vec<Option<Arc<RwLock<DataBuffer>>>>,
}

impl BufferMgr {
    pub const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffer_size,
            buffers: Vec::new(),
        }
    }

    pub fn create_buffer(&mut self) -> io::Result<i32> {
        let id = self.buffers.len() as i32;
        let buf = DataBuffer::new(id, self.buffer_size);
        self.buffers.push(Some(Arc::new(RwLock::new(buf))));
        Ok(id)
    }

    pub fn get_buffer(&self, id: i32) -> io::Result<Arc<RwLock<DataBuffer>>> {
        self.buffers
            .get(id as usize)
            .and_then(|b| b.as_ref())
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Buffer not found"))
    }

    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    pub fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }

    pub fn delete_buffer(&mut self, id: i32) -> io::Result<()> {
        if let Some(slot) = self.buffers.get_mut(id as usize) {
            *slot = None;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Buffer not found"))
        }
    }
}
