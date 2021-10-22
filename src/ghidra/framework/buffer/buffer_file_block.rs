use std::convert::TryInto;

pub struct BufferFileBlock {
    pub block_index: isize,
    pub buffer: Vec<u8>,
}

impl BufferFileBlock {
    pub fn new(block_index: isize, buffer: &Vec<u8>) -> BufferFileBlock {
        BufferFileBlock {
            block_index, buffer: buffer.clone()
        }
    }

    pub fn from_block_stream(bytes: &Vec<u8>) -> BufferFileBlock {
       let  block_index = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as isize;
        let mut buffer: Vec<u8>  = vec![0;bytes.len()];
        buffer.clone_from_slice(&bytes[4..]);
        BufferFileBlock {
            buffer,
            block_index
        }
    }

    pub fn size(&self) -> isize {
        self.buffer.len() as isize
    }

    pub fn get_index(&self) -> isize {
        self.block_index
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.buffer.clone()
    }


}
