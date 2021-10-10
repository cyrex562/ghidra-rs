pub trait Buffer {
    /// get this buffer's ID
    fn get_id() -> i64;
    /// get the length of the buffer in bytes.
    fn length() -> usize;
    /// get the byte data located at the specified offset and store into the provded array
    fn get(offset: isize, bytes: &mut [u8]);
    /// get data at the specified offset and store it in the provided array at the specified offset
    fn get_offset(offset: isize, data: &mut [u8], data_offset: isize, length: isize);
    /// get the 8-bit byte value located at the specified offset
    fn get_byte(offset: isize) -> u8;
    /// get a 32-bit unsigned int value located at the specified offset
    fn get_u32(offset: isize) -> u32;
    /// get a 16-bit unsigned value located at the specified offset
    fn get_u16(offset: isize) -> u16;
    /// get a 64-bit unsigned value located at the specified offset
    fn get_u64(offset: isize) -> u64;
    /// put a specified number of bytes from the provided array into the buffer at the specified offset; also specify the number of bytes to store
    fn put(offset: isize, data: &[u8], data_offset: isize, length: isize) -> isize;
    /// put a byte into the buffer at the specified offset
    fn put_byte(offset: isize, byte: u8) -> isize;
    /// put a u32
    fn put_u32(offset: isize, item: u32) -> isize;
    /// put a u16
    fn put_u16(offset: isize, item: u16) -> isize;
    /// put a u64
    fn put_u64(offset: isize, ite: u64) -> isize;
}
