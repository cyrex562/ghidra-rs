//! Port of `ghidra.pcode.emu.sys.BytesEmuFileContents`.

use crate::pcode::emu::sys::emu_file_contents::EmuFileContents;
use crate::pcode::emu::sys::emu_io_exception::EmuIOException;

const INIT_CONTENT_SIZE: usize = 1024;

/// A concrete in-memory bytes store for simulated file contents.
///
/// Port of `ghidra.pcode.emu.sys.BytesEmuFileContents`.
///
/// Note that currently, the total contents cannot exceed [`i32::MAX`] bytes, matching Java's
/// comment that the file must remain less than 2GB in size (a Java array size limit).
///
/// [`EmuFileContents::read`]/[`EmuFileContents::write`] have no `Result` in their signature --
/// they return a plain byte count, matching Java's unchecked-exception style (p-code execution
/// exceptions, including [`EmuIOException`], extend `RuntimeException`, meant to unwind out of the
/// emulator's dispatch loop rather than be handled locally at each call site). This port therefore
/// panics with the same message text Java's `EmuIOException` would carry, the closest analogue a
/// `Result`-less trait allows to that unchecked-throw behavior.
///
/// Java marks every method `synchronized`; this port relies on `&self`/`&mut self` (`read` takes
/// `&self` since it never mutates `content`; `write`/`truncate` take `&mut self`) to get the same
/// exclusivity guarantee from the type system instead, so no internal lock is needed here -- a
/// caller sharing one instance across threads is responsible for external synchronization, same as
/// any other `&mut self`-requiring Rust type.
pub struct BytesEmuFileContents {
    content: Vec<u8>,
}

impl BytesEmuFileContents {
    /// Port of the field initializer `protected byte[] content = new byte[INIT_CONTENT_SIZE];`.
    pub fn new() -> Self {
        Self { content: vec![0u8; INIT_CONTENT_SIZE] }
    }
}

impl Default for BytesEmuFileContents {
    fn default() -> Self {
        Self::new()
    }
}

impl EmuFileContents<Vec<u8>> for BytesEmuFileContents {
    /// Port of `read(long offset, byte[] buf, long fileSize)`.
    ///
    /// `buf` is treated the same way as Java's fixed-size destination array: its length is the
    /// requested read size, and only the first `len` bytes (the return value) are overwritten --
    /// anything beyond that in `buf` is left as-is, matching `System.arraycopy`'s behavior of
    /// never touching the tail of the destination array.
    ///
    /// # Panics
    /// Panics (mirroring Java's unchecked [`EmuIOException`]) if `offset` exceeds [`i32::MAX`] or
    /// if the computed read length is negative (`offset` past `file_size`). Also panics
    /// (mirroring Java's unchecked `ArrayIndexOutOfBoundsException`, which the real class does
    /// *not* guard against) if `offset + len` exceeds the actual backing buffer size -- Java's
    /// `getChunk`/callers are expected to keep `file_size` consistent with what has actually been
    /// written via [`EmuFileContents::write`]; this port makes no attempt to "fix" that missing
    /// bounds check.
    fn read(&self, offset: i64, buf: &mut Vec<u8>, file_size: i64) -> i64 {
        // We're using an in-memory array, so limited to int offsets.
        if offset > i32::MAX as i64 {
            panic!("{}", EmuIOException::new("Offset is past end of file"));
        }
        let len = (buf.len() as i64).min(file_size - offset);
        if len < 0 {
            panic!("{}", EmuIOException::new("Offset is past end of file"));
        }
        let off = offset as usize;
        let len_usize = len as usize;
        buf[..len_usize].copy_from_slice(&self.content[off..off + len_usize]);
        len
    }

    /// Port of `write(long offset, byte[] buf, long curSize)`.
    ///
    /// # Preserved quirk: growth doubles capacity exactly once per call
    ///
    /// Java grows the backing array by doubling it *at most once* per call
    /// (`content.length * 2`), not in a loop until it's actually big enough. A single write whose
    /// `offset + buf.length` exceeds even the doubled capacity therefore still overruns the
    /// backing array on the final `arraycopy`, throwing (unchecked) `ArrayIndexOutOfBoundsException`
    /// -- reproduced here as-is via the same panicking slice-index out-of-bounds, rather than
    /// "fixed" to grow in a loop until sufficient. See this module's
    /// `write_far_beyond_doubled_capacity_panics_matching_javas_single_doubling_bug` test.
    ///
    /// # Panics
    /// Panics (mirroring Java's unchecked [`EmuIOException`]) if the computed new size exceeds
    /// [`i32::MAX`] or overflows negative. Also panics per the preserved quirk above.
    fn write(&mut self, offset: i64, buf: &Vec<u8>, cur_size: i64) -> i64 {
        let new_size = offset + buf.len() as i64;
        if new_size > i32::MAX as i64 || new_size < 0 {
            panic!(
                "{}",
                EmuIOException::new(format!("File size cannot exceed {} bytes", i32::MAX))
            );
        }
        if new_size > self.content.len() as i64 {
            let mut grown = vec![0u8; self.content.len() * 2];
            let cur = cur_size as usize;
            grown[..cur].copy_from_slice(&self.content[..cur]);
            self.content = grown;
        }
        let off = offset as usize;
        self.content[off..off + buf.len()].copy_from_slice(buf);
        buf.len() as i64
    }

    /// Port of `truncate()`.
    fn truncate(&mut self) {
        if self.content.len() > INIT_CONTENT_SIZE {
            self.content = vec![0u8; INIT_CONTENT_SIZE];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_with_init_content_size_zero_bytes() {
        let f = BytesEmuFileContents::new();
        assert_eq!(f.content.len(), INIT_CONTENT_SIZE);
        assert!(f.content.iter().all(|&b| b == 0));
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut f = BytesEmuFileContents::new();
        let src = vec![1u8, 2, 3, 4];
        let written = f.write(0, &src, 0);
        assert_eq!(written, 4);

        let mut dst = vec![0u8; 4];
        let read = f.read(0, &mut dst, 4);
        assert_eq!(read, 4);
        assert_eq!(dst, src);
    }

    #[test]
    fn read_only_fills_the_first_len_bytes_of_buf() {
        // Java: arraycopy writes only `len` bytes starting at index 0 of `buf`; anything beyond
        // `len` (here, because `file_size` is smaller than `buf.len()`) is left untouched.
        let mut f = BytesEmuFileContents::new();
        f.write(0, &vec![0xAAu8, 0xBB, 0xCC, 0xDD], 0);

        let mut dst = vec![0xFFu8; 4];
        let read = f.read(0, &mut dst, 2);
        assert_eq!(read, 2);
        assert_eq!(&dst[0..2], &[0xAA, 0xBB]);
        // Untouched tail retains its prior contents.
        assert_eq!(&dst[2..4], &[0xFF, 0xFF]);
    }

    #[test]
    fn read_with_offset() {
        let mut f = BytesEmuFileContents::new();
        f.write(0, &vec![10u8, 20, 30, 40], 0);

        let mut dst = vec![0u8; 2];
        let read = f.read(2, &mut dst, 4);
        assert_eq!(read, 2);
        assert_eq!(dst, vec![30u8, 40]);
    }

    #[test]
    fn read_offset_past_file_size_panics() {
        let f = BytesEmuFileContents::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut dst = vec![0u8; 4];
            f.read(10, &mut dst, 3);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn truncate_resets_to_init_content_size() {
        let mut f = BytesEmuFileContents::new();
        // Grow past INIT_CONTENT_SIZE first.
        let big = vec![7u8; INIT_CONTENT_SIZE + 100];
        f.write(0, &big, 0);
        assert!(f.content.len() > INIT_CONTENT_SIZE);

        f.truncate();
        assert_eq!(f.content.len(), INIT_CONTENT_SIZE);
    }

    #[test]
    fn truncate_leaves_small_content_unchanged() {
        let mut f = BytesEmuFileContents::new();
        assert_eq!(f.content.len(), INIT_CONTENT_SIZE);
        f.truncate();
        assert_eq!(f.content.len(), INIT_CONTENT_SIZE);
    }

    #[test]
    fn write_grows_capacity_by_doubling() {
        let mut f = BytesEmuFileContents::new();
        assert_eq!(f.content.len(), INIT_CONTENT_SIZE);

        let data = vec![9u8; INIT_CONTENT_SIZE + 1];
        f.write(0, &data, 0);
        // Doubled exactly once, since INIT_CONTENT_SIZE+1 <= INIT_CONTENT_SIZE*2.
        assert_eq!(f.content.len(), INIT_CONTENT_SIZE * 2);

        let mut dst = vec![0u8; data.len()];
        let read = f.read(0, &mut dst, data.len() as i64);
        assert_eq!(read as usize, data.len());
        assert_eq!(dst, data);
    }

    #[test]
    fn write_preserves_existing_bytes_up_to_cur_size_when_growing() {
        let mut f = BytesEmuFileContents::new();
        f.write(0, &vec![1u8, 2, 3], 0);
        // Grow by writing far enough out to force doubling, passing the correct curSize so the
        // existing 3 bytes get preserved by the grow's arraycopy.
        let tail = vec![9u8; INIT_CONTENT_SIZE];
        f.write(3, &tail, 3);

        let mut dst = vec![0u8; 3];
        f.read(0, &mut dst, 3);
        assert_eq!(dst, vec![1u8, 2, 3]);
    }

    /// Preserved Java quirk (see [`BytesEmuFileContents::write`]'s own docs): growth doubles
    /// capacity *once* per call, not in a loop until sufficient. A write whose required size
    /// exceeds even the doubled capacity overruns the backing buffer.
    #[test]
    fn write_far_beyond_doubled_capacity_panics_matching_javas_single_doubling_bug() {
        let mut f = BytesEmuFileContents::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // INIT_CONTENT_SIZE*2 is the most one doubling can provide; ask for much more than
            // that in a single write.
            let huge = vec![0u8; INIT_CONTENT_SIZE * 3];
            f.write(0, &huge, 0);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn write_size_exceeding_i32_max_panics() {
        let mut f = BytesEmuFileContents::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let buf = vec![0u8; 4];
            f.write(i32::MAX as i64, &buf, 0);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn default_matches_new() {
        let f = BytesEmuFileContents::default();
        assert_eq!(f.content.len(), INIT_CONTENT_SIZE);
    }
}
