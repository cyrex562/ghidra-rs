/// The content store to back a simulated file.
///
/// Corresponds to `ghidra.pcode.emu.sys.EmuFileContents`.
pub trait EmuFileContents<T> {
    /// Copy values from the file into the given buffer.
    ///
    /// `offset` is the byte offset in the file to start reading from, `file_size` is the total
    /// size of the file. Returns the number of bytes (not necessarily concrete) read.
    fn read(&self, offset: i64, buf: &mut T, file_size: i64) -> i64;

    /// Write values from the given buffer into the file.
    ///
    /// `offset` is the byte offset in the file to start writing at, `cur_size` is the current
    /// size of the file. Returns the number of bytes (not necessarily concrete) written.
    fn write(&mut self, offset: i64, buf: &T, cur_size: i64) -> i64;

    /// Erase the contents.
    ///
    /// The file's size will be set to 0. If the contents are expensive to store they should be
    /// released here.
    fn truncate(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecFileContents {
        data: Vec<u8>,
    }

    impl VecFileContents {
        fn new() -> Self {
            Self { data: vec![] }
        }
    }

    impl EmuFileContents<Vec<u8>> for VecFileContents {
        fn read(&self, offset: i64, buf: &mut Vec<u8>, file_size: i64) -> i64 {
            let start = offset as usize;
            let end = (file_size as usize).min(self.data.len());
            if start >= end {
                return 0;
            }
            let slice = &self.data[start..end];
            buf.extend_from_slice(slice);
            slice.len() as i64
        }

        fn write(&mut self, offset: i64, buf: &Vec<u8>, _cur_size: i64) -> i64 {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                self.data.resize(end, 0);
            }
            self.data[start..end].copy_from_slice(buf);
            buf.len() as i64
        }

        fn truncate(&mut self) {
            self.data.clear();
        }
    }

    #[test]
    fn write_then_read_full() {
        let mut f = VecFileContents::new();
        let src = vec![1u8, 2, 3, 4];
        let written = f.write(0, &src, 0);
        assert_eq!(written, 4);

        let mut dst = vec![];
        let read = f.read(0, &mut dst, 4);
        assert_eq!(read, 4);
        assert_eq!(dst, src);
    }

    #[test]
    fn read_with_offset() {
        let mut f = VecFileContents::new();
        f.write(0, &vec![10u8, 20, 30, 40], 0);

        let mut dst = vec![];
        let read = f.read(2, &mut dst, 4);
        assert_eq!(read, 2);
        assert_eq!(dst, vec![30u8, 40]);
    }

    #[test]
    fn truncate_clears_contents() {
        let mut f = VecFileContents::new();
        f.write(0, &vec![1u8, 2, 3], 0);
        f.truncate();

        let mut dst = vec![];
        let read = f.read(0, &mut dst, 3);
        assert_eq!(read, 0);
        assert!(dst.is_empty());
    }

    #[test]
    fn write_at_offset() {
        let mut f = VecFileContents::new();
        f.write(0, &vec![0u8; 4], 0);
        f.write(1, &vec![99u8, 100], 4);

        let mut dst = vec![];
        f.read(0, &mut dst, 4);
        assert_eq!(dst, vec![0u8, 99, 100, 0]);
    }

    #[test]
    fn read_beyond_file_size_returns_zero() {
        let mut f = VecFileContents::new();
        f.write(0, &vec![5u8, 6, 7], 0);

        let mut dst = vec![];
        let read = f.read(10, &mut dst, 3);
        assert_eq!(read, 0);
    }
}
