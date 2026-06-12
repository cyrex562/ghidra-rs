pub trait Buffer {
    fn get_id(&self) -> i32;
    fn length(&self) -> usize;
    fn get(&self, offset: usize, bytes: &mut [u8]);
    fn get_byte(&self, offset: usize) -> u8;
    fn get_short(&self, offset: usize) -> i16;
    fn get_int(&self, offset: usize) -> i32;
    fn get_long(&self, offset: usize) -> i64;

    fn put(&mut self, offset: usize, bytes: &[u8]) -> isize;
    fn put_byte(&mut self, offset: usize, b: u8) -> isize;
    fn put_short(&mut self, offset: usize, v: i16) -> isize;
    fn put_int(&mut self, offset: usize, v: i32) -> isize;
    fn put_long(&mut self, offset: usize, v: i64) -> isize;

    fn move_data(&mut self, from: usize, to: usize, len: usize);
    fn copy_data(
        &mut self,
        to_offset: usize,
        from_buf: &dyn Buffer,
        from_offset: usize,
        len: usize,
    );
}

pub struct DataBuffer {
    id: i32,
    data: Vec<u8>,
}

impl DataBuffer {
    pub fn new(id: i32, size: usize) -> Self {
        Self {
            id,
            data: vec![0; size],
        }
    }

    pub fn from_data(id: i32, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    pub fn get_data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Buffer for DataBuffer {
    fn get_id(&self) -> i32 {
        self.id
    }

    fn length(&self) -> usize {
        self.data.len()
    }

    fn get(&self, offset: usize, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.data[offset..offset + bytes.len()]);
    }

    fn get_byte(&self, offset: usize) -> u8 {
        self.data[offset]
    }

    fn get_short(&self, offset: usize) -> i16 {
        i16::from_be_bytes([self.data[offset], self.data[offset + 1]])
    }

    fn get_int(&self, offset: usize) -> i32 {
        i32::from_be_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    fn get_long(&self, offset: usize) -> i64 {
        i64::from_be_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
            self.data[offset + 4],
            self.data[offset + 5],
            self.data[offset + 6],
            self.data[offset + 7],
        ])
    }

    fn put(&mut self, offset: usize, bytes: &[u8]) -> isize {
        if offset + bytes.len() > self.data.len() {
            return -1;
        }
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        (offset + bytes.len()) as isize
    }

    fn put_byte(&mut self, offset: usize, b: u8) -> isize {
        if offset + 1 > self.data.len() {
            return -1;
        }
        self.data[offset] = b;
        (offset + 1) as isize
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
        self.data.copy_within(from..from + len, to);
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
        self.data[to_offset..to_offset + len].copy_from_slice(&temp);
    }
}
