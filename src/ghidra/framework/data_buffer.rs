use std::cmp::min;

pub const DATA_BUFFER_SERIAL_VERSION_UID: u64 = 3;
pub const DATA_BUFFER_COMPRESSED_SERIAL_OUTPUT_PROPERTY: String = "db.buffers.DataBuffer.compressedOutput".to_string();
// private static boolean enableCompressedSerializationOutput =
// 		Boolean.parseBoolean(System.getProperty(COMPRESSED_SERIAL_OUTPUT_PROPERTY, "false"));
pub const DATA_BUFFER_ENABLE_COMPRESSED_SERIALIZATION_OUTPUT: bool = false;
pub const DATA_BUFFER_FORMAT_VERSION: u32 = 0xea;


pub fn enable_compression_serialization_output(enable: bool) {
    todo!()
    // System.setProperty(COMPRESSED_SERIAL_OUTPUT_PROPERTY, Boolean.toString(enable));
    // 		enableCompressedSerializationOutput = enable;
}

pub fn using_compressed_serialization_output(enable: bool) -> bool {
    return DATA_BUFFER_ENABLE_COMPRESSED_SERIALIZATION_OUTPUT;
}

#[derive(Debug,Default,Clone)]
pub struct DataBuffer {
    pub id: i64,
    pub data: Vec<u8>,
    pub dirty: bool,
    pub empty: bool,
}

impl DataBuffer {
    fn new() -> DataBuffer {
        DataBuffer::default()
    }

    fn new_with_size(buf_size: usize) -> DataBuffer {
        let mut db: DataBuffer = DataBuffer::default();
        db.data = Vec::new();
        db.data.reserve(buf_size);
        db
    }

    fn new_with_buf(data: &Vec<u8>) -> DataBuffer {
        let mut db: DataBuffer = DataBuffer::default();
        db.data = data.clone();
        db
    }

    fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn set_data(&mut self, data: &Vec<u8>) {
        self.data = data.clone()
    }

    fn get_id(&self) -> i64 {
        self.id
    }

    fn set_id(&mut self, id: i64) {
        self.id = id
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }

    fn set_dirty(&mut self, dirty: bool) {
        self.dirty = dirty
    }

    fn is_empty(&self) -> bool {
        self.empty
    }

    fn set_empty(&mut self, empty: bool) {
        self.empty = empty
    }

    fn length(&self) -> usize {
        self.data.len()
    }

    fn get(&self, offset:isize, bytes: &mut Vec<u8>, data_offset: isize, length: isize) {
        for i in 0..length {
            bytes[i+offset] = self.data[i+data_offset]
        }
    }

    fn get2(&self, offset: isize, bytes: &mut Vec<u8>) {
        for i in 0..self.data.len() - offset {
            bytes[i] = self.data[offset+i]
        }
    }

    fn get3(&self, offset: isize, length: isize) -> Vec<u8> {
        let out: Vec<u8> = Vec::new();
        for i in 0..length {
            out[i] = self.data[offset+i]
        }
        out
    }

    fn get_byte(&self, offset: isize) -> u8 {
        self.data[offset]
    }

    fn get_u16(&self, offset: isize) -> u16 {
        let mut x: [u8;2] = [self.data[offset], self.data[offset+1]];
        u16::from_le_bytes(x)
    }

    fn get_u32(&self, offset: isize) -> u32 {
        let mut x: [u8;4] = self.data[offset..offset+3];
        u32::from_le_bytes(x)
    }

    fn get_u64(&self, offset:isize) -> u64 {
        let mut x: [u8;8] = self.data[offset..offset+7];
        u64::from_le_bytes(x)
    }

    fn put(&mut self, offset: isize, bytes: &Vec<u8>, data_offset: isize, length: isize) -> isize {
        self.dirty = true;
        for i in 0..length {
            self.data[i+data_offset] = bytes[i+offset]
        }
        offset + length
    }

    fn put2(&mut self, offset: isize, bytes: &Vec<u8>) -> isize {
        self.dirty = true;
        for i in 0 .. bytes.len() {
            self.data[i+offset] = bytes[i]
        }
        offset + bytes.len()
    }

    fn put_u8(&mut self, offset: isize, byte: u8) -> isize {
        self.data[offset] = byte;
        offset +1
    }

    fn put_u16(&mut self, offset: isize, val: u16) -> isize {
        let bytes: [u8;2] = val.to_be_bytes();
        self.data[offset] = bytes[0];
        self.data[offset+1] = bytes[1];
        offset + 2
    }

    fn put_u32(&mut self, offset: isize, val: u32) -> isize {
        let bytes: [u8;4] = val.to_le_bytes();
        self.data[offset] = bytes[0];
        self.data[offset+1] = bytes[1];
        self.data[offset+2] = bytes[2];
        self.data[offset+3] = bytes[3];
        return offset + 4
    }

    fn put_u64(&mut self, offset: isize, val: u64) -> isize {
        let bytes: [u8;8] = val.to_le_bytes();
        for i in 0..8 {
            self.data[offset+i] = bytes[i];
        }
        return offset + 8
    }

    fn clear(&mut self) {
        self.data.clear()
    }

    fn move_data(&mut self, src: isize, dst: isize, length: isize) {

        for i in 0 .. length {
            self.data[src+i] = self.data[dst+i]
        }
    }

    fn copy_data(&mut self, offset: isize, buf: &DataBuffer, buf_offset: isize, length: isize) {
        for i in 0 .. length {
            self.data[offset+i] = buf.data[i]
        }
    }

    fn write_external(&self, out: &mut ObjectOutput) {
        let mut compress = DATA_BUFFER_ENABLE_COMPRESSED_SERIALIZATION_OUTPUT;
        let mut compressed_data: Vec<u8> = Vec::new();
        let mut compressed_len: isize = -1;
        if self.empty || self.data.is_empty() {
            compress = false;
        }
        out.write_u32(DATA_BUFFER_FORMAT_VERSION);
        out.write_bool(compress);
        out.write_i64(self.id);
        out.write_bool(self.dirty);
        out.write_bool(self.empty)
        if self.data.is_empty() {
            out.write_i32(-1);
        } else {
            out.write_usize(data.len());
            if compress {
                out.write_isize(compressed_len);
                out.write(compressed_data, 0, compressed_len);
            } else if self.data.is_empty() == false {
                out.write(self.data);
            }
        }
    }

    fn deflate_data(data: &Vec<u8>, compressed_data: &mut Vec<u8>) -> isize {
        let deflate: Deflater = Deflater::new(DEFLATER_BEST_COMPRESSION, true);
        deflate.set_strategy(DEFLATER_HUFFMAN_ONLY);
        deflate.set_input(data, 0, data.len());
        deflate.finish();
        let mut compressed_data_offset: isize = 0;

        while deflate.finished() == false && compressed_data_offset < compressed_data.len() {
            compressed_data_offset += deflate.deflate(compressed_data, compressed_data_offset, compressed_data.len() - compressed_data_offset, DEFLATER_SYNC_FLUSH);
        }

        if deflate.finished() == false {
            return -1;
        }

        compressed_data_offset
    }

    fn read_external(&mut self, in_obj: &ObjectInput) {
        let format_version: u32 = in_obj.read_u32();
        if format_version != DATA_BUFFER_FORMAT_VERSION {
            // TODO: throw error
        }
        let mut compressed = in_obj.read_bool();
        self.id = in_obj.read_i64();
        self.dirty = in_obj.read_bool();
        self.empty = in_obj.read_bool();
        let mut len: isize = in_obj.read_isize();
        self.data.clear();
        if len >= 0 {
            self.data.clear();
            if self.compressed {
                let compressed_len: isize = in_obj.read_isize();
                let mut compressed_data: Vec<u8> = Vec::new();
                in_obj.read_fully(&mut compressed_data);
                self.inflate_data(&compressed_data, data)
            } else {
                in_obj.read_fully(data);
            }
        }
    }

    fn unsigned_compare_to(&self, other_data: &Vec<u8>, mut offset: isize, len: isize) -> isize {
        let other_len: isize = other_data.len() as isize;
        let mut other_offset: isize = 0;
        let mut n: isize = std::cmp::min(other_len, self.len);
        while n -= 1 != 0 {
            let mut b: u8 = self.data[offset += 1] & 0xff;
            let mut other_byte: u8 = other_data[other_offset += 1] & 0xff;
            if b != other_byte {
                return (b - other_byte) as isize;
            }
        }
        self.len - other_len
    }

    fn inflate_data(&mut self, compressed_data: &Vec<u8>, data: &mut Vec<u8>) {
        let inflater: Inflater = Inflater::new(true);
        let mut off: isize = 0;
        while !inflater.finished() && off < self.data.len() as isize {
            off += inflater.inflate(data, off, self.data.len() - off);
            if infalter.needs_dictionary() {
                // TODO: throw error
            }
        }
        if !inflater.finished() {
            // TODO: throw error
        }
    }
}
