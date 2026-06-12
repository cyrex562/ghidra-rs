use super::buffer::{Buffer, DataBuffer};
use super::buffer_mgr::BufferMgr;
use std::io;
use std::sync::{Arc, RwLock};

pub const CHAINED_BUFFER_INDEX_NODE: u8 = 8;
pub const CHAINED_BUFFER_DATA_NODE: u8 = 9;

const XOR_MASK_BYTES: &[u8] = &[
    0x59, 0xea, 0x67, 0x23, 0xda, 0xb8, 0x00, 0xb8, 0xc3, 0x48, 0xdd, 0x8b, 0x21, 0xd6, 0x94, 0x78,
    0x35, 0xab, 0x2b, 0x7e, 0xb2, 0x4f, 0x82, 0x4e, 0x0e, 0x16, 0xc4, 0x57, 0x12, 0x8e, 0x7e, 0xe6,
    0xb6, 0xbd, 0x56, 0x91, 0x57, 0x72, 0xe6, 0x91, 0xdc, 0x52, 0x2e, 0xf2, 0x1a, 0xb7, 0xd6, 0x6f,
    0xda, 0xde, 0xe8, 0x48, 0xb1, 0xbb, 0x50, 0x6f, 0xf4, 0xdd, 0x11, 0xee, 0xf2, 0x67, 0xfe, 0x48,
    0x8d, 0xae, 0x69, 0x1a, 0xe0, 0x26, 0x8c, 0x24, 0x8e, 0x17, 0x76, 0x51, 0xe2, 0x60, 0xd7, 0xe6,
    0x83, 0x65, 0xd5, 0xf0, 0x7f, 0xf2, 0xa0, 0xd6, 0x4b, 0xbd, 0x24, 0xd8, 0xab, 0xea, 0x9e, 0xa6,
    0x48, 0x94, 0x3e, 0x7b, 0x2c, 0xf4, 0xce, 0xdc, 0x69, 0x11, 0xf8, 0x3c, 0xa7, 0x3f, 0x5d, 0x77,
    0x94, 0x3f, 0xe4, 0x8e, 0x48, 0x20, 0xdb, 0x56, 0x32, 0xc1, 0x87, 0x01, 0x2e, 0xe3, 0x7f, 0x40,
];

const NODE_TYPE_SIZE: usize = 1;
const DATA_LENGTH_SIZE: usize = 4;
const ID_SIZE: usize = 4;

const NODE_TYPE_OFFSET: usize = 0;
const DATA_LENGTH_OFFSET: usize = NODE_TYPE_SIZE;
const NEXT_INDEX_ID_OFFSET: usize = DATA_LENGTH_OFFSET + DATA_LENGTH_SIZE;

const INDEX_BASE_OFFSET: usize = NEXT_INDEX_ID_OFFSET + ID_SIZE;

const DATA_BASE_OFFSET_NONINDEXED: usize = NODE_TYPE_SIZE + DATA_LENGTH_SIZE;
const DATA_BASE_OFFSET_INDEXED: usize = NODE_TYPE_SIZE;

pub struct ChainedBuffer {
    buffer_mgr: Arc<RwLock<BufferMgr>>,
    size: usize,
    first_buffer_id: i32,
    use_xor_mask: bool,
    read_only: bool,

    index_buffer_id_table: Option<Vec<i32>>,
    data_buffer_id_table: Vec<i32>,
    indexes_per_buffer: usize,

    data_base_offset: usize,
    data_space: usize,

    uninitialized_data_source: Option<Arc<dyn Buffer + Send + Sync>>,
    uninitialized_data_source_offset: usize,
}

impl ChainedBuffer {
    pub fn new(
        size: usize,
        enable_obfuscation: bool,
        uninitialized_data_source: Option<Arc<dyn Buffer + Send + Sync>>,
        uninitialized_data_source_offset: usize,
        buffer_mgr_arc: Arc<RwLock<BufferMgr>>,
    ) -> io::Result<Self> {
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Zero length buffer not permitted",
            ));
        }

        let first_buffer_id;
        let buffer_size;
        {
            let mut buffer_mgr = buffer_mgr_arc.write().unwrap();
            buffer_size = buffer_mgr.get_buffer_size();
            first_buffer_id = buffer_mgr.create_buffer()?;
        }

        let mut me = Self {
            buffer_mgr: buffer_mgr_arc.clone(),
            size,
            first_buffer_id,
            use_xor_mask: enable_obfuscation,
            read_only: false,
            index_buffer_id_table: None,
            data_buffer_id_table: Vec::new(),
            indexes_per_buffer: 0,
            data_base_offset: 0,
            data_space: 0,
            uninitialized_data_source,
            uninitialized_data_source_offset,
        };

        let data_base_offset_nonindexed = DATA_BASE_OFFSET_NONINDEXED;
        let data_space_nonindexed = buffer_size - data_base_offset_nonindexed;

        if size <= data_space_nonindexed {
            me.data_base_offset = data_base_offset_nonindexed;
            me.data_space = data_space_nonindexed;
            me.data_buffer_id_table = vec![first_buffer_id];

            let bm = me.buffer_mgr.read().unwrap();
            let first_buffer_arc = bm.get_buffer(first_buffer_id)?;
            let mut first_buffer = first_buffer_arc.write().unwrap();

            me.initialize_allocated_buffer(0, &mut *first_buffer)?;
            first_buffer.put_byte(NODE_TYPE_OFFSET, CHAINED_BUFFER_DATA_NODE);
            first_buffer.put_int(
                DATA_LENGTH_OFFSET,
                me.get_obfuscation_data_length_field_value(),
            );
        } else {
            let bm_arc = me.buffer_mgr.clone();
            let mut bm = bm_arc.write().unwrap();
            let first_buffer_arc = bm.get_buffer(first_buffer_id)?;
            let mut first_buffer = first_buffer_arc.write().unwrap();
            me.create_index(&mut *first_buffer, &mut *bm)?;
        }

        Ok(me)
    }

    pub fn from_existing(
        buffer_mgr_arc: Arc<RwLock<BufferMgr>>,
        buffer_id: i32,
        uninitialized_data_source: Option<Arc<dyn Buffer + Send + Sync>>,
        uninitialized_data_source_offset: usize,
    ) -> io::Result<Self> {
        let (size, use_xor_mask, node_type);
        {
            let buffer_mgr = buffer_mgr_arc.read().unwrap();
            let first_buffer_arc = buffer_mgr.get_buffer(buffer_id)?;
            let first_buffer = first_buffer_arc.read().unwrap();

            let data_length_field = first_buffer.get_int(DATA_LENGTH_OFFSET);
            use_xor_mask = data_length_field < 0;
            size = (data_length_field & 0x7FFFFFFF) as usize;
            node_type = first_buffer.get_byte(NODE_TYPE_OFFSET);
        }

        let mut me = Self {
            buffer_mgr: buffer_mgr_arc.clone(),
            size,
            first_buffer_id: buffer_id,
            use_xor_mask,
            read_only: false,
            index_buffer_id_table: None,
            data_buffer_id_table: Vec::new(),
            indexes_per_buffer: 0,
            data_base_offset: 0,
            data_space: 0,
            uninitialized_data_source,
            uninitialized_data_source_offset,
        };

        let buffer_mgr = buffer_mgr_arc.read().unwrap();
        let first_buffer_arc = buffer_mgr.get_buffer(buffer_id)?;
        let first_buffer = first_buffer_arc.read().unwrap();

        if node_type == CHAINED_BUFFER_INDEX_NODE {
            me.build_index(&*first_buffer, &*buffer_mgr)?;
        } else if node_type == CHAINED_BUFFER_DATA_NODE {
            me.data_base_offset = DATA_BASE_OFFSET_NONINDEXED;
            me.data_space = first_buffer.length() - me.data_base_offset;
            me.data_buffer_id_table = vec![buffer_id];
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Buffer"));
        }

        Ok(me)
    }

    fn get_obfuscation_data_length_field_value(&self) -> i32 {
        let mut val = self.size as i32;
        if self.use_xor_mask {
            val |= i32::MIN;
        }
        val
    }

    fn xor_mask_byte(&self, buffer_offset: usize, byte_value: u8) -> u8 {
        let mask_byte = XOR_MASK_BYTES[buffer_offset % XOR_MASK_BYTES.len()];
        byte_value ^ mask_byte
    }

    fn allocate_index(&mut self, buffer: &dyn Buffer) -> usize {
        self.data_base_offset = DATA_BASE_OFFSET_INDEXED;
        self.data_space = buffer.length() - self.data_base_offset;
        let index_count = (self.size + self.data_space - 1) / self.data_space;
        self.indexes_per_buffer = (buffer.length() - INDEX_BASE_OFFSET) / ID_SIZE;
        self.data_buffer_id_table = vec![-1; index_count];
        index_count
    }

    fn create_index(
        &mut self,
        first_index_buffer: &mut dyn Buffer,
        buffer_mgr: &mut BufferMgr,
    ) -> io::Result<()> {
        first_index_buffer.put_byte(NODE_TYPE_OFFSET, CHAINED_BUFFER_INDEX_NODE);
        first_index_buffer.put_int(
            DATA_LENGTH_OFFSET,
            self.get_obfuscation_data_length_field_value(),
        );
        first_index_buffer.put_int(NEXT_INDEX_ID_OFFSET, -1);

        let index_count = self.allocate_index(first_index_buffer);
        let index_buffer_count =
            (index_count + self.indexes_per_buffer - 1) / self.indexes_per_buffer;
        let mut index_buffer_id_table = vec![-1; index_buffer_count];

        index_buffer_id_table[0] = self.first_buffer_id;

        // Initialize first index buffer entries to -1
        for i in 0..self.indexes_per_buffer {
            first_index_buffer.put_int(INDEX_BASE_OFFSET + i * ID_SIZE, -1);
        }

        let mut current_index_buffer_id = self.first_buffer_id;

        for i in 1..index_buffer_count {
            let next_buf_id = buffer_mgr.create_buffer()?;
            index_buffer_id_table[i] = next_buf_id;

            if i == 1 {
                // The first buffer is already locked as first_index_buffer
                first_index_buffer.put_int(NEXT_INDEX_ID_OFFSET, next_buf_id);
            } else {
                let current_buf_arc = buffer_mgr.get_buffer(current_index_buffer_id)?;
                let mut current_buf = current_buf_arc.write().unwrap();
                current_buf.put_int(NEXT_INDEX_ID_OFFSET, next_buf_id);
            }

            {
                let next_buf_arc = buffer_mgr.get_buffer(next_buf_id)?;
                let mut next_buf = next_buf_arc.write().unwrap();
                next_buf.put_byte(NODE_TYPE_OFFSET, CHAINED_BUFFER_INDEX_NODE);
                next_buf.put_int(DATA_LENGTH_OFFSET, -1);
                next_buf.put_int(NEXT_INDEX_ID_OFFSET, -1);
                for j in 0..self.indexes_per_buffer {
                    next_buf.put_int(INDEX_BASE_OFFSET + j * ID_SIZE, -1);
                }
            }
            current_index_buffer_id = next_buf_id;
        }

        self.index_buffer_id_table = Some(index_buffer_id_table);
        Ok(())
    }

    fn build_index(
        &mut self,
        first_index_buffer: &dyn Buffer,
        buffer_mgr: &BufferMgr,
    ) -> io::Result<()> {
        let index_count = self.allocate_index(first_index_buffer);
        let index_buffer_count =
            (index_count + self.indexes_per_buffer - 1) / self.indexes_per_buffer;
        let mut index_buffer_id_table = vec![-1; index_buffer_count];

        let mut current_buffer_id = self.first_buffer_id;
        let mut index = 0;

        for i in 0..index_buffer_count {
            index_buffer_id_table[i] = current_buffer_id;
            let buf_arc = buffer_mgr.get_buffer(current_buffer_id)?;
            let buf = buf_arc.read().unwrap();

            for j in 0..self.indexes_per_buffer {
                if index >= index_count {
                    break;
                }
                self.data_buffer_id_table[index] = buf.get_int(INDEX_BASE_OFFSET + j * ID_SIZE);
                index += 1;
            }

            if i < index_buffer_count - 1 {
                current_buffer_id = buf.get_int(NEXT_INDEX_ID_OFFSET);
            }
        }

        self.index_buffer_id_table = Some(index_buffer_id_table);
        Ok(())
    }

    fn initialize_allocated_buffer(
        &self,
        chain_index: usize,
        buf: &mut dyn Buffer,
    ) -> io::Result<()> {
        let offset = chain_index * self.data_space;
        let mut len = self.size - offset;
        if len >= self.data_space {
            len = self.data_space;
        } else {
            let zeroes = vec![0u8; buf.length()];
            buf.put(0, &zeroes);
        }

        let mut data = vec![0u8; len];
        if let Some(ref source) = self.uninitialized_data_source {
            source.get(self.uninitialized_data_source_offset + offset, &mut data);
        }

        if self.use_xor_mask {
            for i in 0..len {
                data[i] = self.xor_mask_byte(i, data[i]);
            }
        }
        buf.put(self.data_base_offset, &data);
        Ok(())
    }

    fn get_data_buffer(&mut self, index: usize) -> io::Result<Arc<RwLock<DataBuffer>>> {
        let buffer_id = if self.data_buffer_id_table.is_empty() && index == 0 {
            self.first_buffer_id
        } else {
            self.data_buffer_id_table[index]
        };

        if buffer_id < 0 {
            let new_id;
            {
                let mut bm = self.buffer_mgr.write().unwrap();
                new_id = bm.create_buffer()?;
            }
            let bm = self.buffer_mgr.read().unwrap();
            let buf_arc = bm.get_buffer(new_id)?;
            {
                let mut buf = buf_arc.write().unwrap();
                self.initialize_allocated_buffer(index, &mut *buf)?;
                buf.put_byte(NODE_TYPE_OFFSET, CHAINED_BUFFER_DATA_NODE);
            }

            self.data_buffer_id_table[index] = new_id;

            // Update index buffer
            if let Some(ref index_table) = self.index_buffer_id_table {
                let index_buf_id = index_table[index / self.indexes_per_buffer];
                let index_offset = INDEX_BASE_OFFSET + (index % self.indexes_per_buffer) * ID_SIZE;
                let index_buf_arc = bm.get_buffer(index_buf_id)?;
                let mut index_buf = index_buf_arc.write().unwrap();
                index_buf.put_int(index_offset, new_id);
            }

            Ok(buf_arc)
        } else {
            self.buffer_mgr.read().unwrap().get_buffer(buffer_id)
        }
    }

    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    pub fn delete(&mut self) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Read-only buffer",
            ));
        }
        let mut bm = self.buffer_mgr.write().unwrap();

        for &id in &self.data_buffer_id_table {
            if id >= 0 {
                bm.delete_buffer(id)?;
            }
        }
        self.data_buffer_id_table.clear();

        if let Some(ref index_table) = self.index_buffer_id_table {
            for &id in index_table {
                if id >= 0 {
                    bm.delete_buffer(id)?;
                }
            }
        }
        self.index_buffer_id_table = None;
        self.size = 0;
        self.first_buffer_id = -1;
        Ok(())
    }

    pub fn set_size(&mut self, new_size: usize, preserve_data: bool) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Read-only buffer",
            ));
        }
        if self.uninitialized_data_source.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Buffer size may not be changed when using uninitialized data source",
            ));
        }

        if new_size > self.size {
            self.grow(new_size, preserve_data)?;
        } else if new_size < self.size {
            self.shrink(new_size, preserve_data)?;
        }
        Ok(())
    }

    fn grow(&mut self, new_size: usize, preserve_data: bool) -> io::Result<()> {
        let old_size = self.size;
        self.size = new_size;

        if self.data_buffer_id_table.len() == 1 {
            if new_size > self.data_space {
                // Transition to indexed
                let bm_arc = self.buffer_mgr.clone();
                let mut bm = bm_arc.write().unwrap();
                let first_buffer_arc = bm.get_buffer(self.first_buffer_id)?;
                let mut first_buffer = first_buffer_arc.write().unwrap();

                let mut new_first_data_buf_id = -1;
                if preserve_data {
                    new_first_data_buf_id = bm.create_buffer()?;
                    let new_first_data_buf_arc = bm.get_buffer(new_first_data_buf_id)?;
                    let mut new_first_data_buf = new_first_data_buf_arc.write().unwrap();
                    new_first_data_buf.copy_data(
                        DATA_BASE_OFFSET_INDEXED,
                        &*first_buffer,
                        DATA_BASE_OFFSET_NONINDEXED,
                        old_size,
                    );

                    let indexed_data_space = new_first_data_buf.length() - DATA_BASE_OFFSET_INDEXED;
                    if new_size > old_size {
                        let zeroes_len =
                            std::cmp::min(indexed_data_space - old_size, new_size - old_size);
                        if zeroes_len > 0 {
                            let mut zeroes = vec![0u8; zeroes_len];
                            if self.use_xor_mask {
                                for (i, b) in zeroes.iter_mut().enumerate() {
                                    *b = self.xor_mask_byte(old_size + i, *b);
                                }
                            }
                            new_first_data_buf.put(DATA_BASE_OFFSET_INDEXED + old_size, &zeroes);
                        }
                    }
                }

                self.create_index(&mut *first_buffer, &mut *bm)?;

                if preserve_data {
                    self.data_buffer_id_table[0] = new_first_data_buf_id;
                    // The first index buffer is self.first_buffer_id, which is already locked as first_buffer
                    first_buffer.put_int(INDEX_BASE_OFFSET, new_first_data_buf_id);
                }
                return Ok(());
            }

            // Adjust stored size in single buffer
            let bm = self.buffer_mgr.read().unwrap();
            let first_buffer_arc = bm.get_buffer(self.first_buffer_id)?;
            let mut first_buffer = first_buffer_arc.write().unwrap();
            first_buffer.put_int(
                DATA_LENGTH_OFFSET,
                self.get_obfuscation_data_length_field_value(),
            );
        } else {
            // Already using an index
            let new_index_count = (new_size + self.data_space - 1) / self.data_space;
            let new_index_buffer_count =
                (new_index_count + self.indexes_per_buffer - 1) / self.indexes_per_buffer;

            self.data_buffer_id_table.resize(new_index_count, -1);

            let mut bm = self.buffer_mgr.write().unwrap();
            if let Some(ref mut index_table) = self.index_buffer_id_table {
                let old_index_buffer_count = index_table.len();
                if old_index_buffer_count < new_index_buffer_count {
                    let mut current_index_buffer_id = index_table[old_index_buffer_count - 1];
                    for _ in old_index_buffer_count..new_index_buffer_count {
                        let next_buf_id = bm.create_buffer()?;
                        index_table.push(next_buf_id);

                        {
                            let current_buf_arc = bm.get_buffer(current_index_buffer_id)?;
                            let mut current_buf = current_buf_arc.write().unwrap();
                            current_buf.put_int(NEXT_INDEX_ID_OFFSET, next_buf_id);
                        }

                        {
                            let next_buf_arc = bm.get_buffer(next_buf_id)?;
                            let mut next_buf = next_buf_arc.write().unwrap();
                            next_buf.put_byte(NODE_TYPE_OFFSET, CHAINED_BUFFER_INDEX_NODE);
                            next_buf.put_int(DATA_LENGTH_OFFSET, -1);
                            next_buf.put_int(NEXT_INDEX_ID_OFFSET, -1);
                            for j in 0..self.indexes_per_buffer {
                                next_buf.put_int(INDEX_BASE_OFFSET + j * ID_SIZE, -1);
                            }
                        }
                        current_index_buffer_id = next_buf_id;
                    }
                }
            }

            let first_buffer_arc = bm.get_buffer(self.first_buffer_id)?;
            let mut first_buffer = first_buffer_arc.write().unwrap();
            first_buffer.put_int(
                DATA_LENGTH_OFFSET,
                self.get_obfuscation_data_length_field_value(),
            );
        }
        Ok(())
    }

    fn shrink(&mut self, new_size: usize, preserve_data: bool) -> io::Result<()> {
        self.size = new_size;

        if self.data_buffer_id_table.len() == 1 {
            let bm = self.buffer_mgr.read().unwrap();
            let first_buffer_arc = bm.get_buffer(self.first_buffer_id)?;
            let mut first_buffer = first_buffer_arc.write().unwrap();
            first_buffer.put_int(
                DATA_LENGTH_OFFSET,
                self.get_obfuscation_data_length_field_value(),
            );
        } else if !self.shrink_to_single_buffer(preserve_data)? {
            let new_index_count = (new_size + self.data_space - 1) / self.data_space;
            let new_index_buffer_count =
                (new_index_count + self.indexes_per_buffer - 1) / self.indexes_per_buffer;

            let mut bm = self.buffer_mgr.write().unwrap();
            let old_index_count = self.data_buffer_id_table.len();
            for i in new_index_count..old_index_count {
                let id = self.data_buffer_id_table[i];
                if id >= 0 {
                    bm.delete_buffer(id)?;
                }
            }
            self.data_buffer_id_table.truncate(new_index_count);

            if let Some(ref mut index_table) = self.index_buffer_id_table {
                let old_index_buffer_count = index_table.len();
                if old_index_buffer_count > new_index_buffer_count {
                    for i in new_index_buffer_count..old_index_buffer_count {
                        bm.delete_buffer(index_table[i])?;
                    }
                    index_table.truncate(new_index_buffer_count);
                    // Update next index ID of the new last index buffer
                    let last_id = index_table[new_index_buffer_count - 1];
                    let last_buf_arc = bm.get_buffer(last_id)?;
                    let mut last_buf = last_buf_arc.write().unwrap();
                    last_buf.put_int(NEXT_INDEX_ID_OFFSET, -1);
                }
            }

            let first_buffer_arc = bm.get_buffer(self.first_buffer_id)?;
            let mut first_buffer = first_buffer_arc.write().unwrap();
            first_buffer.put_int(
                DATA_LENGTH_OFFSET,
                self.get_obfuscation_data_length_field_value(),
            );
        }
        Ok(())
    }

    fn shrink_to_single_buffer(&mut self, preserve_data: bool) -> io::Result<bool> {
        let mut bm = self.buffer_mgr.write().unwrap();
        let buffer_size = bm.get_buffer_size();
        let single_data_space = buffer_size - DATA_BASE_OFFSET_NONINDEXED;

        if self.size > single_data_space {
            return Ok(false);
        }

        let first_buffer_arc = bm.get_buffer(self.first_buffer_id)?;
        let mut first_buffer = first_buffer_arc.write().unwrap();

        first_buffer.put_byte(NODE_TYPE_OFFSET, CHAINED_BUFFER_DATA_NODE);
        first_buffer.put_int(
            DATA_LENGTH_OFFSET,
            self.get_obfuscation_data_length_field_value(),
        );

        if preserve_data && self.data_buffer_id_table[0] >= 0 {
            let old_first_data_id = self.data_buffer_id_table[0];
            if old_first_data_id != self.first_buffer_id {
                let old_first_data_arc = bm.get_buffer(old_first_data_id)?;
                let old_first_data = old_first_data_arc.read().unwrap();
                first_buffer.copy_data(
                    DATA_BASE_OFFSET_NONINDEXED,
                    &*old_first_data,
                    DATA_BASE_OFFSET_INDEXED,
                    self.size,
                );
            }
        }

        // Delete all data buffers
        for &id in &self.data_buffer_id_table {
            if id >= 0 && id != self.first_buffer_id {
                bm.delete_buffer(id)?;
            }
        }

        // Delete all except first index buffer
        if let Some(ref index_table) = self.index_buffer_id_table {
            for &id in index_table {
                if id >= 0 && id != self.first_buffer_id {
                    bm.delete_buffer(id)?;
                }
            }
        }

        self.data_base_offset = DATA_BASE_OFFSET_NONINDEXED;
        self.data_space = single_data_space;
        self.data_buffer_id_table = vec![self.first_buffer_id];
        self.index_buffer_id_table = None;

        Ok(true)
    }

    pub fn split(&mut self, offset: usize) -> io::Result<Self> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Read-only buffer",
            ));
        }
        if offset >= self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid offset",
            ));
        }

        let mut new_cb = Self::new(
            self.size - offset,
            self.use_xor_mask,
            self.uninitialized_data_source.clone(),
            self.uninitialized_data_source_offset + offset,
            self.buffer_mgr.clone(),
        )?;

        let mut temp = vec![0u8; self.size - offset];
        self.get(offset, &mut temp);
        new_cb.put(0, &temp);

        self.shrink(offset, true)?;
        Ok(new_cb)
    }

    pub fn append(&mut self, mut other: ChainedBuffer) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Read-only buffer",
            ));
        }
        if self.uninitialized_data_source.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Buffer size may not be changed when using uninitialized data source",
            ));
        }
        if self.use_xor_mask != other.use_xor_mask {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Incompatible obfuscation settings",
            ));
        }

        let old_size = self.size;
        let mut temp = vec![0u8; other.size];
        other.get(0, &mut temp);

        self.grow(self.size + other.size, true)?;
        self.put(old_size, &temp);

        other.delete()?;
        Ok(())
    }
}

impl Buffer for ChainedBuffer {
    fn get_id(&self) -> i32 {
        self.first_buffer_id
    }

    fn length(&self) -> usize {
        self.size
    }

    fn get(&self, mut offset: usize, bytes: &mut [u8]) {
        let mut length = bytes.len();
        let mut bytes_offset = 0;

        let mut index = offset / self.data_space;
        let mut buffer_data_offset = offset % self.data_space;

        while length > 0 {
            let available = self.data_space - buffer_data_offset;
            let len = std::cmp::min(available, length);

            let id = self.data_buffer_id_table[index];
            if id < 0 {
                if let Some(ref source) = self.uninitialized_data_source {
                    source.get(
                        self.uninitialized_data_source_offset + offset,
                        &mut bytes[bytes_offset..bytes_offset + len],
                    );
                } else {
                    for b in &mut bytes[bytes_offset..bytes_offset + len] {
                        *b = 0;
                    }
                }
            } else {
                let bm = self.buffer_mgr.read().unwrap();
                let buf_arc = bm.get_buffer(id).unwrap();
                let buf = buf_arc.read().unwrap();
                buf.get(
                    self.data_base_offset + buffer_data_offset,
                    &mut bytes[bytes_offset..bytes_offset + len],
                );

                if self.use_xor_mask {
                    for i in 0..len {
                        bytes[bytes_offset + i] =
                            self.xor_mask_byte(buffer_data_offset + i, bytes[bytes_offset + i]);
                    }
                }
            }

            bytes_offset += len;
            offset += len;
            length -= len;
            index += 1;
            buffer_data_offset = 0;
        }
    }

    fn get_byte(&self, offset: usize) -> u8 {
        let mut b = [0u8; 1];
        self.get(offset, &mut b);
        b[0]
    }

    fn get_short(&self, offset: usize) -> i16 {
        let mut b = [0u8; 2];
        self.get(offset, &mut b);
        i16::from_be_bytes(b)
    }

    fn get_int(&self, offset: usize) -> i32 {
        let mut b = [0u8; 4];
        self.get(offset, &mut b);
        i32::from_be_bytes(b)
    }

    fn get_long(&self, offset: usize) -> i64 {
        let mut b = [0u8; 8];
        self.get(offset, &mut b);
        i64::from_be_bytes(b)
    }

    fn put(&mut self, mut offset: usize, bytes: &[u8]) -> isize {
        if self.read_only {
            return -1;
        }
        let mut length = bytes.len();
        let mut bytes_offset = 0;

        let mut index = offset / self.data_space;
        let mut buffer_data_offset = offset % self.data_space;

        while length > 0 {
            let available = self.data_space - buffer_data_offset;
            let len = std::cmp::min(available, length);

            let buf_arc = self.get_data_buffer(index).unwrap();
            let mut buf = buf_arc.write().unwrap();

            if self.use_xor_mask {
                let mut xor_data = vec![0u8; len];
                for i in 0..len {
                    xor_data[i] =
                        self.xor_mask_byte(buffer_data_offset + i, bytes[bytes_offset + i]);
                }
                buf.put(self.data_base_offset + buffer_data_offset, &xor_data);
            } else {
                buf.put(
                    self.data_base_offset + buffer_data_offset,
                    &bytes[bytes_offset..bytes_offset + len],
                );
            }

            bytes_offset += len;
            offset += len;
            length -= len;
            index += 1;
            buffer_data_offset = 0;
        }
        offset as isize
    }

    fn put_byte(&mut self, offset: usize, b: u8) -> isize {
        self.put(offset, &[b])
    }

    fn put_short(&mut self, offset: usize, v: i16) -> isize {
        self.put(offset, &v.to_be_bytes())
    }

    fn put_int(&mut self, offset: usize, v: i32) -> isize {
        self.put(offset, &v.to_be_bytes())
    }

    fn put_long(&mut self, offset: usize, v: i64) -> isize {
        self.put(offset, &v.to_be_bytes())
    }

    fn move_data(&mut self, from: usize, to: usize, len: usize) {
        let mut temp = vec![0u8; len];
        self.get(from, &mut temp);
        self.put(to, &temp);
    }

    fn copy_data(
        &mut self,
        to_offset: usize,
        from_buf: &dyn Buffer,
        from_offset: usize,
        len: usize,
    ) {
        let mut temp = vec![0u8; len];
        from_buf.get(from_offset, &mut temp);
        self.put(to_offset, &temp);
    }
}
